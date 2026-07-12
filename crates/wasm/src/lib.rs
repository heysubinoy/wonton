//! `wasm-bindgen` bindings over `wonton-crypto` (+ the pure, I/O-free parts of `wonton-objects`)
//! for the read-only browser dashboard. This crate is a **thin bindings layer, not new
//! cryptography** — every operation below calls the existing, already-tested `wonton-crypto`
//! primitive; nothing here re-derives a security property.
//!
//! ## What this crate deliberately does NOT do
//! `wonton_objects::LocalObjectStore` is filesystem-backed (`std::fs`) and has no browser
//! equivalent, and `wonton-vcs`'s `log`/`diff` take that concrete type. Rather than refactor
//! those stable, already-tested crates to thread an abstract store through their public API
//! just for this, this crate stays a pure **per-operation** adapter — mirroring
//! `crates/cli/src/agent/cipher.rs`'s `AgentCipher`, which is *also* just a per-value
//! encrypt/decrypt/sign adapter, not a history walker. The DAG walk itself (fetching objects
//! over HTTP, deciding which commit/tree/blob to fetch next) is TypeScript's job — the same
//! split as the CLI, where `commands.rs` (not the agent) owns orchestration.
//!
//! ## Key custody
//! [`IdentityHandle`]/[`DekHandle`] hold raw key material only inside WASM linear memory. The
//! only way to get anything out is via their methods (`sign`, `decrypt_blob`, ...) — never a
//! raw key. Nothing in this crate writes to `localStorage`/IndexedDB; that policy lives in the
//! TypeScript caller (see the dashboard's README), not here, since WASM has no access to those
//! browser APIs unless the caller hands bytes back to JS.
//!
//! ## Two layers, and why
//! `wasm_bindgen::JsValue` panics if actually constructed outside a real wasm32 runtime — so a
//! plain `cargo test` on this crate can't exercise any function whose error path builds one.
//! Every operation is therefore implemented once as a plain-Rust `..._impl` function/method
//! (returns [`OpError`], a normal `Display`-able error, tested natively below) and exposed a
//! second time as a thin `#[wasm_bindgen]` wrapper that only ever does `.map_err(Into::into)` at
//! the boundary. The wrappers are trivial by construction; `wasm-pack test --headless` (see the
//! crate's dev notes) is what actually exercises them in a real JS engine.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use wasm_bindgen::prelude::*;
use wonton_crypto::{
    decrypt_value, sign as crypto_sign, unlock, unwrap_dek, verify, Argon2Params, Dek, EncryptedValue, SealedDek, UnlockedIdentity,
    WrappedPrivateKey,
};
use wonton_objects::{Blob, Commit, Hash, Tree};

/// A plain, `Display`-able error for every operation in this crate — never leaks *why*
/// cryptographically (mirrors `wonton_crypto::CryptoError`'s own coarseness), just enough to
/// tell a user "wrong passphrase" from "malformed input" from "tampered data".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpError(String);

impl std::fmt::Display for OpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for OpError {}
impl From<OpError> for JsValue {
    fn from(e: OpError) -> JsValue {
        JsValue::from_str(&e.0)
    }
}
fn op_err(msg: impl std::fmt::Display) -> OpError {
    OpError(msg.to_string())
}

fn decode_b64(s: &str) -> Result<Vec<u8>, OpError> {
    STANDARD.decode(s).map_err(|e| op_err(format!("invalid base64: {e}")))
}

/// Mirrors the wire shape `GET /auth/login/start` (and a stored registration response) already
/// return: a 16-byte salt (base64) plus the three Argon2id cost parameters. Same framing the CLI
/// agent's `Argon2ParamsWire` uses — nothing browser-specific about it.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct Argon2ParamsInput {
    salt_b64: String,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
}

#[wasm_bindgen]
impl Argon2ParamsInput {
    #[wasm_bindgen(constructor)]
    pub fn new(salt_b64: String, m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Argon2ParamsInput {
        Argon2ParamsInput {
            salt_b64,
            m_cost_kib,
            t_cost,
            p_cost,
        }
    }
}

fn unlock_identity_impl(wrapped_privkey_b64: &str, params: &Argon2ParamsInput, passphrase: &str) -> Result<UnlockedIdentity, OpError> {
    let blob = decode_b64(wrapped_privkey_b64)?;
    if blob.len() < 24 {
        return Err(op_err("wrapped_privkey_b64 is too short to contain a 24-byte nonce"));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(24);
    let nonce: [u8; 24] = nonce_bytes.try_into().map_err(|_| op_err("malformed nonce"))?;
    let salt_bytes = decode_b64(&params.salt_b64)?;
    let salt: [u8; 16] = salt_bytes.as_slice().try_into().map_err(|_| op_err("argon2 salt must be 16 bytes"))?;

    let wrapped = WrappedPrivateKey {
        argon2_params: Argon2Params {
            salt,
            m_cost_kib: params.m_cost_kib,
            t_cost: params.t_cost,
            p_cost: params.p_cost,
        },
        nonce,
        ciphertext: ciphertext.to_vec(),
    };
    unlock(&wrapped, passphrase.as_bytes()).map_err(|_| op_err("wrong passphrase, or corrupted key data"))
}

/// Unlock a passphrase-wrapped identity — the browser-side equivalent of `wonton login`'s
/// unlock step. `wrapped_privkey_b64` is the exact `base64(nonce(24) || ciphertext)` blob the
/// server already returns from `/auth/login/start` — same wire framing the CLI uses, so this
/// can drive the CLI's existing challenge-response login unchanged (see [`IdentityHandle::sign`]).
#[wasm_bindgen]
pub fn unlock_identity(wrapped_privkey_b64: &str, params: &Argon2ParamsInput, passphrase: &str) -> Result<IdentityHandle, JsValue> {
    Ok(IdentityHandle(unlock_identity_impl(wrapped_privkey_b64, params, passphrase)?))
}

/// An unlocked identity, held only inside WASM linear memory for the lifetime of this handle
/// (i.e. for the browser tab's session — see the crate/module docs on key custody).
#[wasm_bindgen]
#[derive(Debug)]
pub struct IdentityHandle(UnlockedIdentity);

impl IdentityHandle {
    fn sign_impl(&self, message_b64: &str) -> Result<String, OpError> {
        let message = decode_b64(message_b64)?;
        Ok(STANDARD.encode(crypto_sign(&self.0, &message)))
    }

    fn unwrap_dek_impl(&self, sealed_box_b64: &str) -> Result<Dek, OpError> {
        let bytes = decode_b64(sealed_box_b64)?;
        unwrap_dek(&SealedDek(bytes), &self.0)
            .map_err(|_| op_err("could not unwrap this DEK (not the intended recipient, or a tampered sealed box)"))
    }
}

#[wasm_bindgen]
impl IdentityHandle {
    pub fn ed25519_pubkey_b64(&self) -> String {
        STANDARD.encode(self.0.public().ed25519_pubkey)
    }

    pub fn x25519_pubkey_b64(&self) -> String {
        STANDARD.encode(self.0.public().x25519_pubkey)
    }

    /// Sign a base64-encoded message, returning a base64-encoded 64-byte Ed25519 signature —
    /// exactly the shape `POST /auth/login/complete` expects (it signs the base64
    /// `challenge_nonce` from `/auth/login/start` verbatim, same as the CLI's `agent::sign`).
    pub fn sign(&self, message_b64: &str) -> Result<String, JsValue> {
        Ok(self.sign_impl(message_b64)?)
    }

    /// Unwrap a base64 sealed box (a branch's wrapped DEK entry, as `GET .../keys` returns it)
    /// into a [`DekHandle`]. Fails closed (wrong recipient, tampered box) — see
    /// `wonton_crypto::unwrap_dek`'s docs.
    pub fn unwrap_dek(&self, sealed_box_b64: &str) -> Result<DekHandle, JsValue> {
        Ok(DekHandle(self.unwrap_dek_impl(sealed_box_b64)?))
    }
}

/// An unwrapped branch DEK, held only in WASM linear memory. The only operation is
/// [`DekHandle::decrypt_blob`] — the raw key never crosses the JS boundary.
#[wasm_bindgen]
#[derive(Debug)]
pub struct DekHandle(Dek);

impl DekHandle {
    fn decrypt_blob_impl(&self, blob_bytes_b64: &str, expected_hash_hex: &str) -> Result<String, OpError> {
        let bytes = decode_b64(blob_bytes_b64)?;
        let expected_hash = Hash::from_hex(expected_hash_hex).map_err(|_| op_err("malformed expected hash"))?;
        if Hash::of(&bytes) != expected_hash {
            return Err(op_err("blob bytes do not match the requested hash — possible tampering"));
        }
        let blob = Blob::from_bytes(&bytes).map_err(|e| op_err(format!("malformed blob object: {e}")))?;
        let value = EncryptedValue {
            nonce: blob.nonce,
            ciphertext: blob.ciphertext,
        };
        let plaintext = decrypt_value(&self.0, &value).map_err(|_| op_err("decryption failed: wrong key, or tampered ciphertext"))?;
        String::from_utf8(plaintext).map_err(|_| op_err("decrypted value is not valid UTF-8"))
    }
}

#[wasm_bindgen]
impl DekHandle {
    /// Decrypt one blob object's bytes (exactly as `GET /objects/{hash}` returns them,
    /// base64-encoded by the caller) and return the plaintext as a UTF-8 string. Hash-verifies
    /// first (same fail-closed discipline as `LocalObjectStore::get`), then AEAD-decrypts. Never
    /// returns garbage on failure — an error, always.
    pub fn decrypt_blob(&self, blob_bytes_b64: &str, expected_hash_hex: &str) -> Result<String, JsValue> {
        Ok(self.decrypt_blob_impl(blob_bytes_b64, expected_hash_hex)?)
    }
}

/// Verified, decoded fields of one commit, returned after [`verify_commit`] succeeds — so the
/// caller (TypeScript) can continue the history walk (`parent_hashes_hex`) and fetch/decrypt the
/// tree without re-parsing the commit object itself.
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedCommitInfo {
    pub tree_hash_hex: String,
    pub parent_hashes_hex: Vec<String>,
    pub author_id: String,
    pub timestamp: f64,
    pub message: String,
}

fn verify_commit_impl(commit_bytes_b64: &str, expected_hash_hex: &str, signer_ed25519_pubkey_b64: &str) -> Result<VerifiedCommitInfo, OpError> {
    let bytes = decode_b64(commit_bytes_b64)?;
    let expected_hash = Hash::from_hex(expected_hash_hex).map_err(|_| op_err("malformed expected hash"))?;
    if Hash::of(&bytes) != expected_hash {
        return Err(op_err("commit bytes do not match the requested hash — possible tampering"));
    }
    let commit = Commit::from_bytes(&bytes).map_err(|e| op_err(format!("malformed commit object: {e}")))?;

    let pubkey_bytes = decode_b64(signer_ed25519_pubkey_b64)?;
    let pubkey: [u8; 32] = pubkey_bytes.as_slice().try_into().map_err(|_| op_err("signer pubkey must be 32 bytes"))?;
    let signature: [u8; 64] = commit
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| op_err(format!("malformed signature: expected 64 bytes, got {}", commit.signature.len())))?;
    let message = commit.fields.signing_bytes().map_err(|e| op_err(format!("could not reconstruct signed bytes: {e}")))?;
    verify(&pubkey, &message, &signature).map_err(|_| op_err("commit signature verification failed"))?;

    Ok(VerifiedCommitInfo {
        tree_hash_hex: commit.fields.tree_hash.to_hex(),
        parent_hashes_hex: commit.fields.parent_hashes.iter().map(Hash::to_hex).collect(),
        author_id: commit.fields.author_id.to_string(),
        timestamp: commit.fields.timestamp as f64,
        message: commit.fields.message,
    })
}

/// Verify one commit's content-hash integrity and Ed25519 signature — the same per-commit check
/// `wonton_vcs::log`'s walk performs, exposed standalone since the walk itself (fetching each
/// commit over HTTP, deciding when to stop) lives in TypeScript — see this crate's module docs.
/// `commit_bytes_b64` is the raw object body exactly as `GET /objects/{hash}` returns it;
/// `expected_hash_hex` is the hash it was fetched by.
#[wasm_bindgen]
pub fn verify_commit(commit_bytes_b64: &str, expected_hash_hex: &str, signer_ed25519_pubkey_b64: &str) -> Result<VerifiedCommitInfo, JsValue> {
    Ok(verify_commit_impl(commit_bytes_b64, expected_hash_hex, signer_ed25519_pubkey_b64)?)
}

fn parse_tree_impl(tree_bytes_b64: &str, expected_hash_hex: &str) -> Result<Vec<(String, String)>, OpError> {
    let bytes = decode_b64(tree_bytes_b64)?;
    let expected_hash = Hash::from_hex(expected_hash_hex).map_err(|_| op_err("malformed expected hash"))?;
    if Hash::of(&bytes) != expected_hash {
        return Err(op_err("tree bytes do not match the requested hash — possible tampering"));
    }
    let tree = Tree::from_bytes(&bytes).map_err(|e| op_err(format!("malformed tree object: {e}")))?;
    Ok(tree.entries.into_iter().map(|(k, h)| (k, h.to_hex())).collect())
}

/// Parse a tree object's bytes (as `GET /objects/{hash}` returns them, base64-encoded) into its
/// `key -> blob_hash_hex` entries as a JS `Map`. Trees are unencrypted structure (only blob
/// *contents* are encrypted — key names are plaintext by design, same as the CLI/server), so
/// this needs no key at all, just a hash check.
#[wasm_bindgen]
pub fn parse_tree(tree_bytes_b64: &str, expected_hash_hex: &str) -> Result<js_sys::Map, JsValue> {
    let entries = parse_tree_impl(tree_bytes_b64, expected_hash_hex)?;
    let map = js_sys::Map::new();
    for (key, hash_hex) in entries {
        map.set(&JsValue::from_str(&key), &JsValue::from_str(&hash_hex));
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    //! Every test here exercises the plain-Rust `..._impl` layer directly — never a `JsValue` —
    //! so `cargo test -p wonton-wasm` runs natively with no wasm32 target or browser needed.
    //! `wasm-pack test --headless` (see the crate's dev notes) is the additional check that the
    //! thin `#[wasm_bindgen]` wrappers actually work in a real JS engine.
    use super::*;
    use wonton_crypto::{encrypt_value, generate_dek, generate_identity, wrap_dek};

    fn wire_wrapped_privkey_b64(wrapped: &WrappedPrivateKey) -> String {
        let mut blob = wrapped.nonce.to_vec();
        blob.extend_from_slice(&wrapped.ciphertext);
        STANDARD.encode(blob)
    }

    fn params_input(wrapped: &WrappedPrivateKey) -> Argon2ParamsInput {
        Argon2ParamsInput::new(
            STANDARD.encode(wrapped.argon2_params.salt),
            wrapped.argon2_params.m_cost_kib,
            wrapped.argon2_params.t_cost,
            wrapped.argon2_params.p_cost,
        )
    }

    #[test]
    fn unlock_sign_and_pubkeys_round_trip() {
        let (public, wrapped) = generate_identity(b"correct horse battery staple");
        let identity = unlock_identity_impl(&wire_wrapped_privkey_b64(&wrapped), &params_input(&wrapped), "correct horse battery staple").unwrap();
        let handle = IdentityHandle(identity);
        assert_eq!(handle.ed25519_pubkey_b64(), STANDARD.encode(public.ed25519_pubkey));
        assert_eq!(handle.x25519_pubkey_b64(), STANDARD.encode(public.x25519_pubkey));

        let message_b64 = STANDARD.encode(b"a challenge nonce");
        let sig_b64 = handle.sign_impl(&message_b64).unwrap();
        let sig_bytes: [u8; 64] = STANDARD.decode(&sig_b64).unwrap().try_into().unwrap();
        wonton_crypto::verify(&public.ed25519_pubkey, b"a challenge nonce", &sig_bytes).expect("signature must verify against the real public key");
    }

    #[test]
    fn unlock_with_wrong_passphrase_fails_closed() {
        let (_public, wrapped) = generate_identity(b"real passphrase");
        let err = unlock_identity_impl(&wire_wrapped_privkey_b64(&wrapped), &params_input(&wrapped), "wrong passphrase").unwrap_err();
        assert!(err.to_string().contains("wrong passphrase"));
    }

    #[test]
    fn unwrap_dek_and_decrypt_blob_round_trip() {
        let (public, wrapped) = generate_identity(b"pw");
        let identity = unlock_identity_impl(&wire_wrapped_privkey_b64(&wrapped), &params_input(&wrapped), "pw").unwrap();
        let handle = IdentityHandle(identity);

        let dek = generate_dek();
        let sealed = wrap_dek(&dek, &public.x25519_pubkey);
        let dek_handle = DekHandle(handle.unwrap_dek_impl(&STANDARD.encode(&sealed.0)).unwrap());

        let encrypted = encrypt_value(&dek, b"sk-live-secret-value");
        let blob = Blob::new(encrypted.nonce, encrypted.ciphertext);
        let blob_bytes = blob.to_bytes().unwrap();
        let hash = Hash::of(&blob_bytes);

        let plaintext = dek_handle.decrypt_blob_impl(&STANDARD.encode(&blob_bytes), &hash.to_hex()).unwrap();
        assert_eq!(plaintext, "sk-live-secret-value");
    }

    #[test]
    fn unwrap_dek_for_the_wrong_recipient_fails_closed() {
        let (_alice_public, alice_wrapped) = generate_identity(b"alice-pw");
        let alice_identity = unlock_identity_impl(&wire_wrapped_privkey_b64(&alice_wrapped), &params_input(&alice_wrapped), "alice-pw").unwrap();
        let alice = IdentityHandle(alice_identity);

        let (bob_public, _bob_wrapped) = generate_identity(b"bob-pw");
        let dek = generate_dek();
        let sealed_for_bob = wrap_dek(&dek, &bob_public.x25519_pubkey);

        let err = alice.unwrap_dek_impl(&STANDARD.encode(&sealed_for_bob.0)).unwrap_err();
        assert!(err.to_string().contains("could not unwrap"));
    }

    #[test]
    fn decrypt_blob_rejects_a_hash_mismatch() {
        let (public, wrapped) = generate_identity(b"pw");
        let identity = unlock_identity_impl(&wire_wrapped_privkey_b64(&wrapped), &params_input(&wrapped), "pw").unwrap();
        let handle = IdentityHandle(identity);
        let dek = generate_dek();
        let sealed = wrap_dek(&dek, &public.x25519_pubkey);
        let dek_handle = DekHandle(handle.unwrap_dek_impl(&STANDARD.encode(&sealed.0)).unwrap());

        let encrypted = encrypt_value(&dek, b"value");
        let blob = Blob::new(encrypted.nonce, encrypted.ciphertext);
        let blob_bytes = blob.to_bytes().unwrap();
        let wrong_hash = Hash::of(b"not the real blob bytes");

        let err = dek_handle.decrypt_blob_impl(&STANDARD.encode(&blob_bytes), &wrong_hash.to_hex()).unwrap_err();
        assert!(err.to_string().contains("do not match"));
    }

    #[test]
    fn verify_commit_round_trips_and_rejects_a_wrong_signer() {
        use uuid::Uuid;
        use wonton_objects::CommitFields;

        let (public, wrapped) = generate_identity(b"author-pw");
        let identity = unlock_identity_impl(&wire_wrapped_privkey_b64(&wrapped), &params_input(&wrapped), "author-pw").unwrap();
        let handle = IdentityHandle(identity);

        let fields = CommitFields {
            tree_hash: Hash::of(b"a tree"),
            parent_hashes: vec![],
            author_id: Uuid::nil(),
            timestamp: 1_700_000_000,
            message: "seed".to_string(),
        };
        let signing_bytes = fields.signing_bytes().unwrap();
        let sig_b64 = handle.sign_impl(&STANDARD.encode(&signing_bytes)).unwrap();
        let commit = Commit {
            fields,
            signature: STANDARD.decode(&sig_b64).unwrap(),
        };
        let commit_bytes = commit.to_bytes().unwrap();
        let hash = Hash::of(&commit_bytes);

        let info = verify_commit_impl(&STANDARD.encode(&commit_bytes), &hash.to_hex(), &STANDARD.encode(public.ed25519_pubkey)).unwrap();
        assert_eq!(info.message, "seed");
        assert!(info.parent_hashes_hex.is_empty());

        // A different signer's pubkey must fail verification, not silently pass.
        let (other_public, _) = generate_identity(b"someone-else");
        let err = verify_commit_impl(&STANDARD.encode(&commit_bytes), &hash.to_hex(), &STANDARD.encode(other_public.ed25519_pubkey)).unwrap_err();
        assert!(err.to_string().contains("verification failed"));
    }

    #[test]
    fn parse_tree_round_trips_entries() {
        let mut tree = Tree::new();
        tree.insert("KEY_A", Hash::of(b"blob-a"));
        tree.insert("KEY_B", Hash::of(b"blob-b"));
        let bytes = tree.to_bytes().unwrap();
        let hash = Hash::of(&bytes);

        let mut entries = parse_tree_impl(&STANDARD.encode(&bytes), &hash.to_hex()).unwrap();
        entries.sort();
        assert_eq!(entries, vec![("KEY_A".to_string(), Hash::of(b"blob-a").to_hex()), ("KEY_B".to_string(), Hash::of(b"blob-b").to_hex())]);
    }

    #[test]
    fn parse_tree_rejects_a_hash_mismatch() {
        let mut tree = Tree::new();
        tree.insert("KEY", Hash::of(b"blob"));
        let bytes = tree.to_bytes().unwrap();
        let wrong_hash = Hash::of(b"not the real tree bytes");

        let err = parse_tree_impl(&STANDARD.encode(&bytes), &wrong_hash.to_hex()).unwrap_err();
        assert!(err.to_string().contains("do not match"));
    }
}
