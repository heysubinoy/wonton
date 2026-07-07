//! Per-value symmetric encryption with XChaCha20-Poly1305. This is the
//! primitive behind every secret value in Wonton's data model: a
//! `blob` is `nonce || ciphertext || tag`, which is exactly what [`EncryptedValue`] holds
//! (the 16-byte Poly1305 tag is appended to `ciphertext` in AEAD "combined" mode).
//!
//! The 24-byte extended nonce is what makes random nonce generation safe here: with 192 bits
//! of nonce space, `OsRng` collisions are negligible, so — unlike AES-GCM's 96-bit nonce —
//! we can and do generate a fresh random nonce per call without a counter. Callers never
//! supply a nonce.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::rng::random_array;
use crate::CryptoError;

/// Nonce length for XChaCha20-Poly1305 (192 bits).
pub(crate) const NONCE_LEN: usize = 24;
/// DEK / AEAD key length (256 bits).
pub(crate) const KEY_LEN: usize = 32;

/// A 256-bit Data Encryption Key (DEK). One per environment in the data model: all of an
/// environment's values are encrypted under it, and it is itself wrapped per-user via
/// [`crate::wrap_dek`].
///
/// The raw key is wiped from memory on drop (`ZeroizeOnDrop`) and never exposed to `Debug`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Dek([u8; KEY_LEN]);

impl Dek {
    /// Wrap raw key bytes as a DEK. Used internally by `unwrap_dek` after a sealed box is
    /// opened; also useful for tests. Prefer [`generate_dek`] to mint a fresh key.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Dek(bytes)
    }

    /// Borrow the raw key bytes. Crate-internal only — the wrapping and AEAD layers need it,
    /// but it must never be logged or written to disk.
    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// Redacted `Debug` so a DEK can never be accidentally printed into a log.
impl core::fmt::Debug for Dek {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Dek(<redacted>)")
    }
}

/// An encrypted secret value: the random nonce plus AEAD ciphertext-with-appended-tag. This
/// is the wire/at-rest form of a `blob` (`nonce || ciphertext || tag`). It
/// holds no secret material in the clear, so it derives `Serialize`/`Deserialize` for
/// storage and sync.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedValue {
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext with the 16-byte Poly1305 tag appended (AEAD combined mode).
    pub ciphertext: Vec<u8>,
}

/// Generate a fresh random 256-bit DEK from the OS CSPRNG.
pub fn generate_dek() -> Dek {
    Dek(random_array::<KEY_LEN>())
}

/// Encrypt `plaintext` under `dek` with a freshly generated random nonce, returning the
/// nonce and ciphertext+tag. A new nonce is generated on every call, so the same plaintext
/// encrypts to different ciphertext each time and a `(key, nonce)` pair is never reused.
pub fn encrypt_value(dek: &Dek, plaintext: &[u8]) -> EncryptedValue {
    let (nonce, ciphertext) = xchacha_encrypt(dek.as_bytes(), plaintext);
    EncryptedValue { nonce, ciphertext }
}

/// Decrypt an [`EncryptedValue`] under `dek`. Fails closed with [`CryptoError::DecryptionFailed`]
/// on any authentication failure — wrong key, tampered ciphertext, or a swapped nonce — and
/// never returns partial or unauthenticated plaintext.
pub fn decrypt_value(dek: &Dek, value: &EncryptedValue) -> Result<Vec<u8>, CryptoError> {
    xchacha_decrypt(dek.as_bytes(), &value.nonce, &value.ciphertext)
}

/// Low-level XChaCha20-Poly1305 encryption used by both value encryption and the identity
/// module (which encrypts the private-key seed under the Argon2id-derived unlock key). Not
/// public: the only value-level entry point is [`encrypt_value`], which enforces the
/// no-caller-nonce rule.
pub(crate) fn xchacha_encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> ([u8; NONCE_LEN], Vec<u8>) {
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let nonce_bytes = random_array::<NONCE_LEN>();
    let nonce = XNonce::from(nonce_bytes);
    // Encryption only fails if the plaintext is implausibly large (> ~256 GiB); for our use
    // (secret values, a 32-byte seed) it cannot fail in practice. We still avoid `unwrap` on
    // arbitrary caller input by treating any error as an internal invariant break.
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .expect("XChaCha20-Poly1305 encryption cannot fail for in-memory-sized plaintext");
    (nonce_bytes, ciphertext)
}

/// Low-level XChaCha20-Poly1305 decryption shared by value decryption and identity unlock.
/// Fails closed on any tag/authentication failure.
pub(crate) fn xchacha_decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let nonce = XNonce::from(*nonce);
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trips() {
        let dek = generate_dek();
        let plaintext = b"postgres://user:pw@host/db";
        let ct = encrypt_value(&dek, plaintext);
        let pt = decrypt_value(&dek, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let dek = generate_dek();
        let ct = encrypt_value(&dek, b"");
        assert_eq!(decrypt_value(&dek, &ct).unwrap(), b"");
    }

    #[test]
    fn fresh_nonce_each_call_gives_distinct_ciphertext() {
        let dek = generate_dek();
        let a = encrypt_value(&dek, b"same plaintext");
        let b = encrypt_value(&dek, b"same plaintext");
        // Randomized nonce => different nonce and different ciphertext for identical input.
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn tamper_ciphertext_bit_fails_closed() {
        let dek = generate_dek();
        let mut ct = encrypt_value(&dek, b"top secret");
        ct.ciphertext[0] ^= 0x01; // flip one bit
        let err = decrypt_value(&dek, &ct).unwrap_err();
        assert!(matches!(err, CryptoError::DecryptionFailed));
    }

    #[test]
    fn tamper_tag_bit_fails_closed() {
        let dek = generate_dek();
        let mut ct = encrypt_value(&dek, b"top secret");
        // Flip a bit in the trailing Poly1305 tag.
        let last = ct.ciphertext.len() - 1;
        ct.ciphertext[last] ^= 0x80;
        assert!(matches!(
            decrypt_value(&dek, &ct).unwrap_err(),
            CryptoError::DecryptionFailed
        ));
    }

    #[test]
    fn wrong_nonce_fails_closed() {
        let dek = generate_dek();
        let mut ct = encrypt_value(&dek, b"top secret");
        ct.nonce[0] ^= 0xFF; // substitute a different nonce
        assert!(matches!(
            decrypt_value(&dek, &ct).unwrap_err(),
            CryptoError::DecryptionFailed
        ));
    }

    #[test]
    fn wrong_key_fails_closed() {
        let dek = generate_dek();
        let other = generate_dek();
        let ct = encrypt_value(&dek, b"top secret");
        assert!(matches!(
            decrypt_value(&other, &ct).unwrap_err(),
            CryptoError::DecryptionFailed
        ));
    }

    #[test]
    fn dek_debug_is_redacted() {
        let dek = Dek::from_bytes([7u8; KEY_LEN]);
        assert_eq!(format!("{dek:?}"), "Dek(<redacted>)");
    }
}
