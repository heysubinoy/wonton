//! # wonton-crypto
//!
//! The cryptographic core of Wonton. This crate implements envelope
//! encryption and nothing else: it knows how to derive keys from a passphrase, generate and
//! wrap Data Encryption Keys (DEKs), encrypt/decrypt individual secret values, and sign/
//! verify commit objects. It has **zero internal dependencies** and is usable standalone.
//!
//! ## Primitives (use exactly these, never substitute)
//! - **Value encryption:** XChaCha20-Poly1305 (AEAD), 24-byte random nonce per message.
//! - **DEK wrapping:** X25519 `crypto_box` sealed box (anonymous sender, libsodium
//!   `crypto_box_seal` semantics).
//! - **Passphrase KDF:** Argon2id, parameters stored alongside the wrapped key.
//! - **Signatures:** Ed25519.
//! - **Hashing (key derivation only):** BLAKE2b-256, for deriving the X25519 seed from the
//!   Ed25519 seed. Content-addressing hashing lives in `wonton-objects`, not here.
//!
//! ## Security posture
//! - Nonces are always generated internally via `OsRng`; callers can never supply one for a
//!   value. A `(key, nonce)` pair is never reused.
//! - Every decrypt/verify fails closed: a bad auth tag or bad signature returns
//!   [`CryptoError`], never a panic and never partial/garbage plaintext.
//! - Secret-holding types ([`Dek`], [`UnlockKey`], [`UnlockedIdentity`]) wipe their bytes on
//!   drop via `ZeroizeOnDrop` and never derive an unredacted `Debug`.
//! - Tag/signature comparisons are constant-time (delegated to the AEAD/signature crates,
//!   which check tags in constant time).

mod aead;
mod dek;
mod identity;
mod kdf;
mod rng;
mod sign;

pub use aead::{decrypt_value, encrypt_value, generate_dek, Dek, EncryptedValue};
pub use dek::{unwrap_dek, wrap_dek, SealedDek};
pub use identity::{
    generate_identity, unlock, PublicIdentity, UnlockedIdentity, WrappedPrivateKey,
};
pub use kdf::{derive_unlock_key, Argon2Params, UnlockKey};
pub use sign::{sign, verify};

/// Errors returned by every fallible operation in this crate. Decryption, unwrapping,
/// unlocking, and verification all funnel their failures through here so callers get a
/// `Result` and can never accidentally proceed on a cryptographic failure ("fail closed").
/// The variants are intentionally coarse — they never leak *why* a
/// decryption failed (e.g. which byte), only that it did.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// An AEAD open/decrypt failed: wrong key, tampered ciphertext, wrong nonce, or a bad
    /// Poly1305 tag. Also returned by `unlock` on a wrong passphrase (the Argon2id KDF
    /// itself cannot detect a wrong passphrase — the AEAD tag check is what catches it).
    #[error("decryption failed: bad key, nonce, or authentication tag")]
    DecryptionFailed,

    /// A `crypto_box` sealed-box open failed: the sealed DEK was tampered with, or it was
    /// sealed for a different recipient's public key than the secret key used to open it.
    #[error("dek unwrap failed: tampered sealed box or wrong recipient key")]
    UnwrapFailed,

    /// An Ed25519 signature failed verification, or a signature/key was malformed.
    #[error("signature verification failed")]
    SignatureInvalid,

    /// The supplied Argon2id parameters were rejected by the KDF (e.g. out of the allowed
    /// range for memory/iterations/parallelism).
    #[error("invalid argon2 parameters: {0}")]
    InvalidKdfParams(String),

    /// A byte slice supplied by the caller had the wrong length to be a key, nonce, or
    /// signature.
    #[error("invalid length for {what}: expected {expected}, got {actual}")]
    InvalidLength {
        what: &'static str,
        expected: usize,
        actual: usize,
    },
}
