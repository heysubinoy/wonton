//! Tests for the key agent (PLAN.md §8.2, §14). These bind a real `UnixListener` to a unique
//! temp-directory socket per test and spawn the daemon's accept loop in-process, then talk to it
//! over the same socket via the client — no `std::process::Command` auto-spawn (that path is for
//! the "am I already running" UX, not for these behavioral tests).
//!
//! The security-relevant properties under test: unlock succeeds/fails-closed, operations are
//! denied while locked, a DEK unwrapped for the wrong identity is rejected, `Lock` wipes state,
//! a malformed line doesn't crash the connection, and the socket is 0600.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use wonton_crypto::{
    generate_dek, generate_identity, verify, wrap_dek, PublicIdentity, WrappedPrivateKey,
};

use super::client::{self, ClientError};
use super::daemon;
use super::protocol::Argon2ParamsWire;

const PASS: &[u8] = b"correct horse battery staple";

/// A unique socket path per test (parallel-safe): pid + atomic counter + nanosecond timestamp.
fn unique_socket_path() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "wonton-agent-test-{}-{n}-{nanos}.sock",
        std::process::id()
    ))
}

/// Bind + spawn an in-process daemon; return its socket path.
async fn spawn_daemon() -> PathBuf {
    let path = unique_socket_path();
    let listener = daemon::bind_listener(&path).await.expect("bind");
    tokio::spawn(daemon::serve(listener, daemon::new_state()));
    path
}

/// Encode `generate_identity`'s output into the wire form the `Login` request expects:
/// `wrapped_privkey_b64 = base64(nonce || ciphertext)`, plus the mirrored Argon2 params.
fn wire_identity(wrapped: &WrappedPrivateKey) -> (String, Argon2ParamsWire) {
    let mut blob = wrapped.nonce.to_vec();
    blob.extend_from_slice(&wrapped.ciphertext);
    let params = Argon2ParamsWire {
        salt_b64: STANDARD.encode(wrapped.argon2_params.salt),
        m_cost_kib: wrapped.argon2_params.m_cost_kib,
        t_cost: wrapped.argon2_params.t_cost,
        p_cost: wrapped.argon2_params.p_cost,
    };
    (STANDARD.encode(&blob), params)
}

/// Make a fresh identity and its login wire form.
fn identity_fixture() -> (PublicIdentity, String, Argon2ParamsWire) {
    let (public, wrapped) = generate_identity(PASS);
    let (wrapped_b64, params) = wire_identity(&wrapped);
    (public, wrapped_b64, params)
}

async fn do_login(path: &std::path::Path) -> PublicIdentity {
    let (public, wrapped_b64, params) = identity_fixture();
    client::login(path, wrapped_b64, params, String::from_utf8(PASS.to_vec()).unwrap())
        .await
        .expect("login should succeed with the right passphrase");
    public
}

#[tokio::test]
async fn ping_pong_round_trips() {
    let path = spawn_daemon().await;
    client::ping(&path).await.expect("ping should pong");
}

#[tokio::test]
async fn login_succeeds_and_public_identity_matches_generation() {
    let path = spawn_daemon().await;
    let public = do_login(&path).await;

    let keys = client::public_identity(&path).await.expect("public identity");
    assert_eq!(keys.ed25519_pubkey_b64, STANDARD.encode(public.ed25519_pubkey));
    assert_eq!(keys.x25519_pubkey_b64, STANDARD.encode(public.x25519_pubkey));
}

#[tokio::test]
async fn wrong_passphrase_fails_closed_and_leaves_agent_locked() {
    let path = spawn_daemon().await;
    let (_public, wrapped_b64, params) = identity_fixture();

    let err = client::login(&path, wrapped_b64, params, "the wrong passphrase".to_string())
        .await
        .expect_err("wrong passphrase must fail");
    assert!(matches!(err, ClientError::Agent(_)), "got {err:?}");

    // Still locked afterward.
    let status = client::status(&path).await.expect("status");
    assert!(!status.unlocked);
    // And a subsequent operation is denied.
    let sign_err = client::sign(&path, STANDARD.encode(b"x")).await.expect_err("locked");
    assert!(matches!(sign_err, ClientError::Agent(_)));
}

#[tokio::test]
async fn sign_before_login_fails_and_after_login_verifies() {
    let path = spawn_daemon().await;

    // Before login: fail closed.
    let err = client::sign(&path, STANDARD.encode(b"message")).await.expect_err("locked");
    assert!(matches!(err, ClientError::Agent(_)));

    // After login: a real signature that verifies under the identity's public key.
    let public = do_login(&path).await;
    let message = b"tree_hash|parent|author|ts|message";
    let sig_b64 = client::sign(&path, STANDARD.encode(message)).await.expect("sign");
    let sig_bytes = STANDARD.decode(&sig_b64).unwrap();
    let sig: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
    verify(&public.ed25519_pubkey, message, &sig).expect("signature must verify");
}

#[tokio::test]
async fn unwrap_dek_then_encrypt_decrypt_round_trips() {
    let path = spawn_daemon().await;
    let public = do_login(&path).await;

    // Seal a DEK for THIS identity and have the agent cache it under a context.
    let dek = generate_dek();
    let sealed = wrap_dek(&dek, &public.x25519_pubkey);
    let ctx = "acme/dev".to_string();
    client::unwrap_dek(&path, ctx.clone(), STANDARD.encode(&sealed.0))
        .await
        .expect("unwrap should succeed for our own identity");

    // Status now shows the cached context.
    let status = client::status(&path).await.unwrap();
    assert!(status.unlocked);
    assert_eq!(status.cached_contexts, vec![ctx.clone()]);

    // Encrypt then decrypt under that cached DEK.
    let plaintext = b"DATABASE_URL=postgres://user:pw@host/db";
    let enc = client::encrypt_value(&path, ctx.clone(), STANDARD.encode(plaintext))
        .await
        .expect("encrypt");
    let dec_b64 = client::decrypt_value(&path, ctx.clone(), enc.nonce_b64, enc.ciphertext_b64)
        .await
        .expect("decrypt");
    assert_eq!(STANDARD.decode(&dec_b64).unwrap(), plaintext);
}

#[tokio::test]
async fn unwrap_dek_for_a_different_identity_fails_closed() {
    let path = spawn_daemon().await;
    let _public = do_login(&path).await;

    // Seal a DEK for a DIFFERENT identity's public key — our resident identity can't open it.
    let (other_public, _other_wrapped) = generate_identity(b"someone else");
    let dek = generate_dek();
    let sealed = wrap_dek(&dek, &other_public.x25519_pubkey);

    let err = client::unwrap_dek(&path, "x".to_string(), STANDARD.encode(&sealed.0))
        .await
        .expect_err("unwrap for a different identity must fail");
    assert!(matches!(err, ClientError::Agent(_)), "got {err:?}");
}

#[tokio::test]
async fn encrypt_and_decrypt_for_uncached_context_fail_closed() {
    let path = spawn_daemon().await;
    let _public = do_login(&path).await;

    let enc_err = client::encrypt_value(&path, "never-unwrapped".to_string(), STANDARD.encode(b"x"))
        .await
        .expect_err("no cached DEK");
    assert!(matches!(enc_err, ClientError::Agent(_)));

    let dec_err = client::decrypt_value(
        &path,
        "never-unwrapped".to_string(),
        STANDARD.encode([0u8; 24]),
        STANDARD.encode(b"ciphertext"),
    )
    .await
    .expect_err("no cached DEK");
    assert!(matches!(dec_err, ClientError::Agent(_)));
}

#[tokio::test]
async fn lock_wipes_identity_and_cached_deks() {
    let path = spawn_daemon().await;
    let public = do_login(&path).await;

    // Cache a DEK so there's something to wipe.
    let dek = generate_dek();
    let sealed = wrap_dek(&dek, &public.x25519_pubkey);
    let ctx = "acme/prod".to_string();
    client::unwrap_dek(&path, ctx.clone(), STANDARD.encode(&sealed.0)).await.unwrap();
    let enc = client::encrypt_value(&path, ctx.clone(), STANDARD.encode(b"v")).await.unwrap();

    // Before lock: unlocked with the cached context.
    let before = client::status(&path).await.unwrap();
    assert!(before.unlocked);
    assert_eq!(before.cached_contexts, vec![ctx.clone()]);

    client::lock(&path).await.expect("lock");

    // After lock: locked, no cached contexts.
    let after = client::status(&path).await.unwrap();
    assert!(!after.unlocked);
    assert!(after.cached_contexts.is_empty());

    // Every operation now fails closed.
    assert!(matches!(
        client::sign(&path, STANDARD.encode(b"m")).await.unwrap_err(),
        ClientError::Agent(_)
    ));
    assert!(matches!(
        client::encrypt_value(&path, ctx.clone(), STANDARD.encode(b"v")).await.unwrap_err(),
        ClientError::Agent(_)
    ));
    assert!(matches!(
        client::decrypt_value(&path, ctx.clone(), enc.nonce_b64, enc.ciphertext_b64)
            .await
            .unwrap_err(),
        ClientError::Agent(_)
    ));
}

#[tokio::test]
async fn malformed_line_errors_that_request_but_keeps_connection_alive() {
    let path = spawn_daemon().await;

    // Talk raw over one connection: send garbage, then a valid Ping on the SAME connection.
    let stream = UnixStream::connect(&path).await.unwrap();
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    write_half.write_all(b"this is not json\n").await.unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert!(line.contains("\"result\":\"Error\""), "got: {line}");

    // The daemon is still responsive on this same connection.
    write_half.write_all(b"{\"op\":\"Ping\"}\n").await.unwrap();
    let mut line2 = String::new();
    reader.read_line(&mut line2).await.unwrap();
    assert!(line2.contains("\"result\":\"Pong\""), "got: {line2}");
}

#[tokio::test]
async fn socket_file_is_0600_after_bind() {
    let path = spawn_daemon().await;
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    // Only the owner-rw bits (and the socket file-type bits) — no group/other access.
    assert_eq!(mode & 0o777, 0o600, "socket mode was {:o}", mode & 0o777);
}
