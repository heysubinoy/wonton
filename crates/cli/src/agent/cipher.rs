//! [`AgentCipher`] — the agent-backed adapter implementing `wonton-vcs`'s per-value
//! [`ValueEncryptor`] / [`ValueDecryptor`] / [`CommitSigner`] seams (PROGRESS.md §3.6).
//!
//! Every encrypt / decrypt / sign is delegated to the resident `wonton-agent` over its Unix
//! socket, using the DEK already cached for `context` (via a prior `wonton use`). **The raw DEK
//! and the identity's private key never cross back into this process** — the agent returns only
//! non-secret results (a nonce+ciphertext, a plaintext, a signature). This is the whole point of
//! `wonton-vcs`'s trait seams: the CLI can `commit`/`diff` without ever holding key material.
//!
//! ## Async → sync bridge
//! `wonton-vcs`'s traits are synchronous, but the agent client is async. We bridge with
//! [`tokio::task::block_in_place`] + [`tokio::runtime::Handle::block_on`]. This is sound because
//! `main.rs` runs on tokio's default **multi-threaded** runtime (`#[tokio::main]` with the `full`
//! feature); `block_in_place` moves the current task's blocking work aside so the runtime can make
//! progress on its other worker threads while the nested `block_on` drives the agent round-trip.
//! Tests that exercise this must therefore use `#[tokio::test(flavor = "multi_thread")]`. There is
//! deliberately **no** `flavor = "current_thread"` anywhere in this crate — that would make
//! `block_in_place` panic; if you ever find one, it is a bug to flag, not to work around.

use std::future::Future;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use wonton_crypto::EncryptedValue;
use wonton_vcs::{CommitSigner, ValueDecryptor, ValueEncryptor, VcsError};

use crate::agent::client as agent;

/// An agent-backed value cipher + commit signer for one `context` (the opaque cached-DEK key,
/// e.g. a context name). Cheap to construct; holds no secret material of its own.
pub struct AgentCipher {
    pub socket: PathBuf,
    pub context: String,
}

impl AgentCipher {
    pub fn new(socket: impl Into<PathBuf>, context: impl Into<String>) -> Self {
        Self {
            socket: socket.into(),
            context: context.into(),
        }
    }

    /// Drive an async agent-client future to completion from a synchronous trait method. See the
    /// module docs for why this is sound (multi-threaded runtime only).
    fn block_on<F: Future>(fut: F) -> F::Output {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut))
    }
}

impl ValueEncryptor for AgentCipher {
    fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedValue, VcsError> {
        let plaintext_b64 = STANDARD.encode(plaintext);
        let enc = Self::block_on(agent::encrypt_value(
            &self.socket,
            self.context.clone(),
            plaintext_b64,
        ))
        .map_err(|e| VcsError::Cipher(e.to_string()))?;

        let nonce_bytes = STANDARD
            .decode(&enc.nonce_b64)
            .map_err(|e| VcsError::Cipher(format!("agent returned a non-base64 nonce: {e}")))?;
        let nonce: [u8; 24] = nonce_bytes.as_slice().try_into().map_err(|_| {
            VcsError::Cipher(format!(
                "agent returned a {}-byte nonce, expected 24",
                nonce_bytes.len()
            ))
        })?;
        let ciphertext = STANDARD.decode(&enc.ciphertext_b64).map_err(|e| {
            VcsError::Cipher(format!("agent returned non-base64 ciphertext: {e}"))
        })?;
        Ok(EncryptedValue { nonce, ciphertext })
    }
}

impl ValueDecryptor for AgentCipher {
    fn decrypt(&self, value: &EncryptedValue) -> Result<Vec<u8>, VcsError> {
        let nonce_b64 = STANDARD.encode(value.nonce);
        let ciphertext_b64 = STANDARD.encode(&value.ciphertext);
        let plaintext_b64 = Self::block_on(agent::decrypt_value(
            &self.socket,
            self.context.clone(),
            nonce_b64,
            ciphertext_b64,
        ))
        .map_err(|e| VcsError::Cipher(e.to_string()))?;
        STANDARD
            .decode(&plaintext_b64)
            .map_err(|e| VcsError::Cipher(format!("agent returned non-base64 plaintext: {e}")))
    }
}

impl CommitSigner for AgentCipher {
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], VcsError> {
        let message_b64 = STANDARD.encode(message);
        let sig_b64 = Self::block_on(agent::sign(&self.socket, message_b64))
            .map_err(|e| VcsError::Cipher(e.to_string()))?;
        let sig_bytes = STANDARD
            .decode(&sig_b64)
            .map_err(|e| VcsError::Cipher(format!("agent returned a non-base64 signature: {e}")))?;
        let sig: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
            VcsError::Cipher(format!(
                "agent returned a {}-byte signature, expected 64",
                sig_bytes.len()
            ))
        })?;
        Ok(sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use wonton_crypto::{generate_dek, generate_identity, wrap_dek};

    use crate::agent::client as agent;
    use crate::agent::daemon;
    use crate::agent::protocol::Argon2ParamsWire;

    fn unique_sock() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir()
            .join(format!("wonton-cipher-test-{}-{n}-{nanos}", std::process::id()))
            .with_extension("sock")
    }

    /// Spawn an in-process agent, log a fresh identity in, and unwrap a random DEK into `context`.
    /// Returns the socket path.
    async fn agent_with_dek(context: &str) -> PathBuf {
        let path = unique_sock();
        let listener = daemon::bind_listener(&path).await.expect("bind agent socket");
        tokio::spawn(daemon::serve(listener, daemon::new_state()));

        // Generate an identity, unlock it in the agent.
        let passphrase = b"pw-cipher";
        let (public, wrapped) = generate_identity(passphrase);
        let blob = [wrapped.nonce.as_slice(), wrapped.ciphertext.as_slice()].concat();
        let params = Argon2ParamsWire {
            salt_b64: STANDARD.encode(wrapped.argon2_params.salt),
            m_cost_kib: wrapped.argon2_params.m_cost_kib,
            t_cost: wrapped.argon2_params.t_cost,
            p_cost: wrapped.argon2_params.p_cost,
        };
        agent::login(&path, STANDARD.encode(&blob), params, String::from_utf8_lossy(passphrase).into_owned())
            .await
            .expect("agent login");

        // Seal a fresh DEK for this identity and have the agent unwrap+cache it under `context`.
        let dek = generate_dek();
        let sealed = wrap_dek(&dek, &public.x25519_pubkey);
        agent::unwrap_dek(&path, context.to_string(), STANDARD.encode(&sealed.0))
            .await
            .expect("agent unwrap dek");
        path
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn encrypt_then_decrypt_round_trips() {
        let socket = agent_with_dek("ctx").await;
        let cipher = AgentCipher::new(socket, "ctx");

        // Trait methods are sync; call them on a blocking-capable worker thread.
        let plaintext = b"super-secret-value".to_vec();
        let (encrypted, decrypted) = tokio::task::spawn_blocking(move || {
            let enc = cipher.encrypt(&plaintext).unwrap();
            let dec = cipher.decrypt(&enc).unwrap();
            (enc, dec)
        })
        .await
        .unwrap();

        assert_eq!(decrypted, b"super-secret-value");
        assert_eq!(encrypted.nonce.len(), 24);
        assert!(!encrypted.ciphertext.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sign_returns_a_64_byte_signature() {
        let socket = agent_with_dek("ctx").await;
        let cipher = AgentCipher::new(socket, "ctx");
        let sig = tokio::task::spawn_blocking(move || cipher.sign(b"message-to-sign").unwrap())
            .await
            .unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn encrypt_without_cached_dek_fails_closed() {
        // Agent unlocked but no DEK cached for "missing".
        let socket = agent_with_dek("ctx").await;
        let cipher = AgentCipher::new(socket, "missing");
        let err = tokio::task::spawn_blocking(move || cipher.encrypt(b"x").unwrap_err())
            .await
            .unwrap();
        assert!(matches!(err, VcsError::Cipher(_)), "got {err:?}");
    }
}
