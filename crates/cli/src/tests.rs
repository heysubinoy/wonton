//! End-to-end tests for the identity / context commands (PLAN.md §8, §14). Each test drives the
//! command *logic* in `crate::commands` directly (not the compiled binary) against BOTH a real
//! `wonton-server` (bound to an ephemeral port over a temp-file SQLite DB, mirroring
//! `wonton-sync`'s integration tests) and a real in-process agent daemon (over a temp socket,
//! mirroring `crate::agent::tests`), using a temp config path so nothing touches the real
//! `~/.config/wonton`.
//!
//! `.wonton` marker discovery and config save/load round-trips are covered by unit tests in
//! `crate::config`; these tests focus on the networked flows (`login`, `use`) plus `link`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use wonton_crypto::{generate_dek, wrap_dek};
use wonton_shared::{CreateEnvRequest, CreateStoreRequest, GrantKeyRequest};
use wonton_sync::SyncClient;

use crate::agent::{client as agent, daemon};
use crate::commands;
use crate::config::Config;

/// A unique temp path per call (parallel-safe): pid + atomic counter + nanosecond timestamp.
fn unique(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!(
        "wonton-cli-test-{tag}-{}-{n}-{nanos}",
        std::process::id()
    ))
}

/// Start a real `wonton-server` over a fresh temp-file DB; return its base URL. The router owns
/// the pool, so we keep no separate handle.
async fn start_server() -> String {
    let db = unique("db");
    let url = format!("sqlite://{}", db.display());
    let pool = wonton_server::connect(&url).await.expect("connect + migrate");
    let router = wonton_server::build_router(pool);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("http://{addr}")
}

/// Bind + spawn an in-process agent daemon; return its socket path.
async fn spawn_agent() -> PathBuf {
    let path = unique("agent").with_extension("sock");
    let listener = daemon::bind_listener(&path).await.expect("bind agent socket");
    tokio::spawn(daemon::serve(listener, daemon::new_state()));
    path
}

fn temp_config_path() -> PathBuf {
    unique("cfg").join("config.toml")
}

/// A first-time `login` on a brand-new username registers, unlocks the agent, and ends with a
/// valid cached session token + user_id in config.
#[tokio::test]
async fn login_registers_new_user_and_caches_session() {
    let base = start_server().await;
    let socket = spawn_agent().await;
    let config_path = temp_config_path();

    commands::login(&config_path, &socket, Some(base.clone()), "alice", "pw-alice".into())
        .await
        .expect("first login should register + succeed");

    let config = Config::load_from(&config_path).unwrap();
    let id = config.find_identity("alice").expect("identity persisted");
    assert_eq!(id.username, "alice");
    assert_eq!(id.server_url, base);
    assert!(!id.user_id.is_empty(), "user_id should be populated");
    assert!(id.session_token.is_some(), "session token should be cached");
    assert!(id.session_expires_at.unwrap() > 0);
    assert!(!id.wrapped_privkey_b64.is_empty());

    let status = agent::status(&socket).await.unwrap();
    assert!(status.unlocked, "agent should be unlocked after login");
}

/// `login` on an already-registered username does NOT re-register (no duplicate-username 409)
/// and still ends up with a valid token. Also exercises omitting `--server` on a repeat login
/// (the stored server URL is reused).
#[tokio::test]
async fn login_existing_user_does_not_reregister() {
    let base = start_server().await;
    let socket = spawn_agent().await;
    let config_path = temp_config_path();

    commands::login(&config_path, &socket, Some(base.clone()), "bob", "pw-bob".into())
        .await
        .expect("initial login registers bob");

    // Lock, then log in again WITHOUT --server (reused from config). Must take the existing-user
    // path (login_start succeeds), not attempt a second register (which would 409).
    agent::lock(&socket).await.unwrap();
    commands::login(&config_path, &socket, None, "bob", "pw-bob".into())
        .await
        .expect("second login on an existing user should succeed without re-registering");

    let config = Config::load_from(&config_path).unwrap();
    let id = config.find_identity("bob").unwrap();
    assert_eq!(id.server_url, base, "server URL reused from config");
    assert!(id.session_token.is_some());
    let status = agent::status(&socket).await.unwrap();
    assert!(status.unlocked);
}

/// Provision a store + env, grant the logged-in identity a real wrapped DEK, then `context add`
/// + `use`: `use` succeeds and the agent's status afterward shows the context cached.
#[tokio::test]
async fn context_add_and_use_unwraps_the_dek() {
    let base = start_server().await;
    let socket = spawn_agent().await;
    let config_path = temp_config_path();

    commands::login(&config_path, &socket, Some(base.clone()), "carol", "pw-carol".into())
        .await
        .unwrap();
    let id = Config::load_from(&config_path)
        .unwrap()
        .find_identity("carol")
        .unwrap()
        .clone();

    // As carol (admin of the env she creates), provision and grant herself a DEK — mirroring what
    // a real `wonton share` would do in a later phase.
    let mut client = SyncClient::new(&base);
    client.set_token(id.session_token.clone().unwrap());
    client
        .create_store(&CreateStoreRequest { name: "acme".into() })
        .await
        .unwrap();
    client
        .create_env("acme", &CreateEnvRequest { name: "dev".into() })
        .await
        .unwrap();

    let dek = generate_dek();
    let x_bytes = STANDARD.decode(&id.x25519_pubkey_b64).unwrap();
    let x25519: [u8; 32] = x_bytes.as_slice().try_into().unwrap();
    let sealed = wrap_dek(&dek, &x25519);
    client
        .grant_key(
            "acme",
            "dev",
            &GrantKeyRequest {
                user_id: id.user_id.clone(),
                dek_version: 1,
                sealed_box: STANDARD.encode(&sealed.0),
            },
        )
        .await
        .unwrap();

    commands::context_add(&config_path, "acme-dev", "acme", "dev", "carol").unwrap();
    commands::use_context(&config_path, &socket, "acme-dev")
        .await
        .expect("use should unwrap the granted DEK");

    let status = agent::status(&socket).await.unwrap();
    assert!(
        status.cached_contexts.contains(&"acme-dev".to_string()),
        "agent should have cached the context's DEK, got {:?}",
        status.cached_contexts
    );
    let config = Config::load_from(&config_path).unwrap();
    assert_eq!(config.current_context.as_deref(), Some("acme-dev"));

    // Re-using an already-cached context is cheap and still succeeds.
    commands::use_context(&config_path, &socket, "acme-dev")
        .await
        .expect("re-use of a cached context should succeed");
}

/// `use` on a context where no wrapped-DEK entry exists for the identity fails with a clear
/// "you don't have access" error (not a crash / generic 404). Here the user is a member (admin of
/// the env she created) so `list_keys` succeeds, but no DEK was ever granted to her.
#[tokio::test]
async fn use_without_a_granted_dek_reports_no_access() {
    let base = start_server().await;
    let socket = spawn_agent().await;
    let config_path = temp_config_path();

    commands::login(&config_path, &socket, Some(base.clone()), "dave", "pw-dave".into())
        .await
        .unwrap();
    let id = Config::load_from(&config_path)
        .unwrap()
        .find_identity("dave")
        .unwrap()
        .clone();

    let mut client = SyncClient::new(&base);
    client.set_token(id.session_token.clone().unwrap());
    client
        .create_store(&CreateStoreRequest { name: "acme".into() })
        .await
        .unwrap();
    client
        .create_env("acme", &CreateEnvRequest { name: "prod".into() })
        .await
        .unwrap();
    // NOTE: no grant_key — dave has no wrapped DEK for prod.

    commands::context_add(&config_path, "acme-prod", "acme", "prod", "dave").unwrap();
    let err = commands::use_context(&config_path, &socket, "acme-prod")
        .await
        .expect_err("use must fail with no granted DEK");
    assert!(
        err.to_string().contains("don't have access"),
        "expected an access error, got: {err}"
    );

    // The context was NOT selected on failure.
    let config = Config::load_from(&config_path).unwrap();
    assert_eq!(config.current_context, None);
}

/// `context add` refuses to reference an identity that isn't in the config.
#[tokio::test]
async fn context_add_rejects_unknown_identity() {
    let config_path = temp_config_path();
    let err = commands::context_add(&config_path, "ctx", "acme", "dev", "ghost")
        .expect_err("unknown identity should be rejected");
    assert!(err.to_string().contains("no identity named 'ghost'"), "got: {err}");
}

/// `link` writes a `.wonton` marker, is idempotent for the same context, and refuses to clobber a
/// marker naming a different context.
#[tokio::test]
async fn link_writes_marker_and_refuses_to_clobber_a_different_context() {
    let config_path = temp_config_path();
    // Seed two contexts (they need an identity to exist first).
    let mut config = Config::default();
    config.upsert_identity(crate::config::Identity {
        name: "u".into(),
        username: "u".into(),
        server_url: "http://x".into(),
        user_id: "uid".into(),
        ed25519_pubkey_b64: "e".into(),
        x25519_pubkey_b64: "x".into(),
        wrapped_privkey_b64: "w".into(),
        argon2_salt_b64: "s".into(),
        argon2_m_cost_kib: 19456,
        argon2_t_cost: 2,
        argon2_p_cost: 1,
        session_token: None,
        session_expires_at: None,
    });
    config.upsert_context(crate::config::Context {
        name: "one".into(),
        store: "acme".into(),
        environment: "dev".into(),
        identity: "u".into(),
    });
    config.upsert_context(crate::config::Context {
        name: "two".into(),
        store: "acme".into(),
        environment: "prod".into(),
        identity: "u".into(),
    });
    config.save_to(&config_path).unwrap();

    let dir = unique("linkdir");
    std::fs::create_dir_all(&dir).unwrap();

    commands::link(&config_path, &dir, "one").expect("first link writes the marker");
    assert_eq!(
        crate::config::find_wonton_context(&dir),
        Some("one".to_string())
    );

    // Idempotent for the same context.
    commands::link(&config_path, &dir, "one").expect("relinking the same context is fine");

    // Refuses a different context.
    let err = commands::link(&config_path, &dir, "two").expect_err("must not clobber");
    assert!(err.to_string().contains("refusing to overwrite"), "got: {err}");

    let _ = std::fs::remove_dir_all(&dir);
}
