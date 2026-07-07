//! Wire protocol shared by the agent daemon and the agent client.
//!
//! The transport is **newline-delimited JSON** over a Unix domain socket: exactly one JSON
//! object per line for each request, and one JSON object per line for each response. Defining
//! both shapes in this single module means the daemon and the client physically cannot drift.
//!
//! # The one non-negotiable invariant
//! No [`Response`] variant ever carries raw secret key material — not the identity seed, not an
//! unwrapped `Dek`, not an `UnlockedIdentity`. The agent performs *operations* (sign, unwrap,
//! encrypt, decrypt) and returns only non-secret *results* (a signature, a nonce+ciphertext, a
//! plaintext value). This is the entire reason the agent exists: raw key material stays confined
//! to the one long-lived process and is never re-serialized into a short-lived CLI invocation.
//! If you ever find yourself adding a field here that holds seed/DEK/private-key bytes, stop.

use serde::{Deserialize, Serialize};

/// Argon2id parameters mirrored on the wire (a serde-friendly twin of
/// `wonton_crypto::Argon2Params`, which the client doesn't serialize directly). The daemon
/// reconstructs a real `Argon2Params` from this to call `wonton_crypto::unlock`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2ParamsWire {
    /// base64 of the 16-byte Argon2id salt.
    pub salt_b64: String,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

/// A request from a CLI process to the agent daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum Request {
    /// Liveness check.
    Ping,
    /// Unlock the resident identity. The agent reconstructs a `WrappedPrivateKey` from
    /// `wrapped_privkey_b64` (base64 of `nonce(24) || ciphertext`) plus `argon2_params`, calls
    /// `wonton_crypto::unlock(&wrapped, passphrase)`, and retains the `UnlockedIdentity`. The
    /// passphrase crosses this local, 0600-permissioned socket once and is dropped by the agent
    /// immediately after the unlock attempt — never cached.
    Login {
        wrapped_privkey_b64: String,
        argon2_params: Argon2ParamsWire,
        passphrase: String,
    },
    /// Return the resident identity's public keys, or an error if locked.
    PublicIdentity,
    /// Sign `message_b64` with the resident identity's Ed25519 key. Returns the 64-byte
    /// signature, base64. Errors if locked.
    Sign { message_b64: String },
    /// Unwrap `sealed_box_b64` (a `crypto_box` sealed DEK) with the resident identity's X25519
    /// secret and CACHE the resulting DEK keyed by `context` (an opaque CLI-chosen string, e.g.
    /// "store/env"). Does NOT return the DEK. Errors if locked, or if the box doesn't open for
    /// this identity.
    UnwrapDek {
        context: String,
        sealed_box_b64: String,
    },
    /// Encrypt `plaintext_b64` under the DEK cached for `context`. Returns nonce_b64 +
    /// ciphertext_b64. Errors if no DEK is cached for that context.
    EncryptValue {
        context: String,
        plaintext_b64: String,
    },
    /// Decrypt nonce_b64/ciphertext_b64 under the DEK cached for `context`. Returns
    /// plaintext_b64. Errors if no DEK is cached, or on an AEAD auth failure (fails closed).
    DecryptValue {
        context: String,
        nonce_b64: String,
        ciphertext_b64: String,
    },
    /// Generate a fresh random DEK and CACHE it under `context` (overwriting any existing entry
    /// for that context — this is how a rotation stages a brand-new DEK under a temp context
    /// alongside the still-cached old one). Does NOT return the DEK. Requires an unlocked identity
    /// (fail-closed posture, matching every other op — see the daemon impl).
    GenerateDek { context: String },
    /// Wrap the DEK cached under `context` for a *third party's* X25519 public key
    /// (`crypto_box_seal` is anonymous — it needs no sender secret key, just the recipient's
    /// public key and the DEK bytes, both already agent-side). Returns only the sealed box
    /// ([`Response::SealedDek`]); the raw DEK never crosses the socket. Errors if locked, if no
    /// DEK is cached for `context`, or if the recipient key is malformed.
    WrapDekForRecipient {
        context: String,
        recipient_x25519_pubkey_b64: String,
    },
    /// Wipe the resident identity and every cached DEK.
    Lock,
    /// Report whether unlocked, and which context names currently have a cached DEK.
    Status,
}

/// A response from the agent daemon to a CLI process. See the module-level invariant: no
/// variant ever carries raw secret key material.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result")]
pub enum Response {
    Pong,
    Ok,
    Error {
        message: String,
    },
    PublicIdentity {
        ed25519_pubkey_b64: String,
        x25519_pubkey_b64: String,
    },
    Signature {
        signature_b64: String,
    },
    EncryptedValue {
        nonce_b64: String,
        ciphertext_b64: String,
    },
    PlaintextValue {
        plaintext_b64: String,
    },
    /// A DEK sealed for a recipient's X25519 public key (`crypto_box` sealed box). This is
    /// ciphertext-equivalent — safe to cross the socket — never the raw DEK. Answers
    /// [`Request::WrapDekForRecipient`].
    SealedDek {
        sealed_box_b64: String,
    },
    Status {
        unlocked: bool,
        cached_contexts: Vec<String>,
    },
}
