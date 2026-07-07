//! User identity: keypair generation and the portable, passphrase-encrypted private key.
//! A user has one long-term Ed25519 signing key and one X25519 wrapping key,
//! both derived from a single 32-byte seed. The seed is encrypted under the Argon2id-derived
//! unlock key and stored server-side as an opaque blob, so the identity is portable: unlock
//! with the passphrase on any machine and you regain both keys.
//!
//! ## Key derivation (design choice — read this before changing it)
//! One 32-byte random `seed` is generated with `OsRng`. From it:
//! - The **Ed25519** signing key is `SigningKey::from_bytes(seed)` — the seed *is* the
//!   Ed25519 secret scalar seed.
//! - The **X25519** secret is derived from a domain-separated hash:
//!   `Blake2b-256(seed || "wonton-x25519-v1")`, then loaded as a `crypto_box` secret key.
//!
//! Domain separation via the `"wonton-x25519-v1"` label means the two keys are
//! cryptographically independent (recovering one does not reveal the other) even though both
//! are recoverable from the single seed. This is the "may be derived from one seed" option,
//! made concrete. The `-v1` suffix reserves room to change the derivation later
//! without silently colliding with existing keys.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::aead::{xchacha_decrypt, xchacha_encrypt, NONCE_LEN};
use crate::kdf::{derive_unlock_key, Argon2Params};
use crate::rng::random_array;
use crate::CryptoError;

/// Length of the master identity seed (and of each public key), in bytes.
const SEED_LEN: usize = 32;

/// Domain-separation label mixed into the X25519 seed derivation. Changing this string
/// changes every derived X25519 key, so it is versioned.
const X25519_DOMAIN: &[u8] = b"wonton-x25519-v1";

/// The public half of an identity: the two public keys, safe to publish. Contains no secret
/// material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicIdentity {
    pub ed25519_pubkey: [u8; 32],
    pub x25519_pubkey: [u8; 32],
}

/// The portable, passphrase-encrypted private key. The `ciphertext` is the
/// 32-byte identity seed encrypted with XChaCha20-Poly1305 under the Argon2id-derived unlock
/// key. Holds only ciphertext and public KDF parameters, so it is safe to store on the blind
/// server and to serialize.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedPrivateKey {
    pub argon2_params: Argon2Params,
    pub nonce: [u8; NONCE_LEN],
    /// XChaCha20-Poly1305(unlock_key, nonce, seed) — 32-byte seed plus 16-byte tag.
    pub ciphertext: Vec<u8>,
}

/// An unlocked identity held in memory after a successful [`unlock`]. Holds the raw seed and
/// the derived X25519 seed; the Ed25519/X25519 key objects are reconstructed on demand. Both
/// seed buffers are wiped on drop (`ZeroizeOnDrop`) and never printed.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UnlockedIdentity {
    /// The public keys — not secret, so skipped by the zeroizer.
    #[zeroize(skip)]
    public: PublicIdentity,
    /// The master seed (== the Ed25519 secret-key seed).
    seed: [u8; SEED_LEN],
    /// The derived X25519 secret seed.
    x25519_seed: [u8; SEED_LEN],
}

impl core::fmt::Debug for UnlockedIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Public keys are safe to show; secret seeds never are.
        f.debug_struct("UnlockedIdentity")
            .field("public", &self.public)
            .field("seed", &"<redacted>")
            .field("x25519_seed", &"<redacted>")
            .finish()
    }
}

impl UnlockedIdentity {
    /// Build an unlocked identity from a raw master seed, deriving both keypairs.
    fn from_seed(seed: [u8; SEED_LEN]) -> Self {
        let x25519_seed = derive_x25519_seed(&seed);
        let public = public_from_seeds(&seed, &x25519_seed);
        UnlockedIdentity {
            public,
            seed,
            x25519_seed,
        }
    }

    /// The public identity (both public keys).
    pub fn public(&self) -> &PublicIdentity {
        &self.public
    }

    /// Reconstruct the Ed25519 signing key. Crate-internal: used by [`crate::sign`].
    pub(crate) fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }

    /// Reconstruct the X25519 secret key. Crate-internal: used by [`crate::unwrap_dek`].
    pub(crate) fn x25519_secret(&self) -> crypto_box::SecretKey {
        crypto_box::SecretKey::from_bytes(self.x25519_seed)
    }
}

/// Derive the X25519 secret seed from the master seed via a domain-separated BLAKE2b-256
/// hash (see module docs).
fn derive_x25519_seed(seed: &[u8; SEED_LEN]) -> [u8; SEED_LEN] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(seed);
    hasher.update(X25519_DOMAIN);
    let digest = hasher.finalize();
    let mut out = [0u8; SEED_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Compute both public keys from the master seed and its derived X25519 seed.
fn public_from_seeds(seed: &[u8; SEED_LEN], x25519_seed: &[u8; SEED_LEN]) -> PublicIdentity {
    let signing = SigningKey::from_bytes(seed);
    let ed25519_pubkey = signing.verifying_key().to_bytes();
    let x25519_secret = crypto_box::SecretKey::from_bytes(*x25519_seed);
    let x25519_pubkey = x25519_secret.public_key().to_bytes();
    PublicIdentity {
        ed25519_pubkey,
        x25519_pubkey,
    }
}

/// Generate a brand-new identity protected by `passphrase`.
///
/// Returns the [`PublicIdentity`] (to publish) and the [`WrappedPrivateKey`] (to store).
/// Uses fresh [`Argon2Params::recommended`] parameters and a fresh random seed and nonce.
///
/// The caller owns `passphrase` and should zeroize its own buffer afterward; this function
/// does not retain it.
pub fn generate_identity(passphrase: &[u8]) -> (PublicIdentity, WrappedPrivateKey) {
    let mut seed = random_array::<SEED_LEN>();
    let params = Argon2Params::recommended();

    // `recommended()` params are always valid, so derivation cannot fail here; the only
    // failure mode of `derive_unlock_key` is out-of-range parameters, which we control.
    let unlock_key = derive_unlock_key(passphrase, &params)
        .expect("recommended Argon2id parameters are always valid");

    let (nonce, ciphertext) = xchacha_encrypt(unlock_key.as_bytes(), &seed);
    let public = public_from_seeds(&seed, &derive_x25519_seed(&seed));

    seed.zeroize();

    let wrapped = WrappedPrivateKey {
        argon2_params: params,
        nonce,
        ciphertext,
    };
    (public, wrapped)
}

/// Unlock a [`WrappedPrivateKey`] with `passphrase`, recovering the [`UnlockedIdentity`].
///
/// Fails closed with [`CryptoError::DecryptionFailed`] on a wrong passphrase or tampered
/// ciphertext: Argon2id cannot itself distinguish a wrong passphrase, but the wrong derived
/// key fails the XChaCha20-Poly1305 auth-tag check, which is what rejects it.
pub fn unlock(
    wrapped: &WrappedPrivateKey,
    passphrase: &[u8],
) -> Result<UnlockedIdentity, CryptoError> {
    let unlock_key = derive_unlock_key(passphrase, &wrapped.argon2_params)?;

    let mut seed_bytes = xchacha_decrypt(unlock_key.as_bytes(), &wrapped.nonce, &wrapped.ciphertext)?;

    // A correctly-formed wrapped key always decrypts to exactly SEED_LEN bytes. If it does
    // not, the blob is corrupt/forged — fail closed rather than build a partial identity.
    if seed_bytes.len() != SEED_LEN {
        seed_bytes.zeroize();
        return Err(CryptoError::InvalidLength {
            what: "identity seed",
            expected: SEED_LEN,
            actual: seed_bytes.len(),
        });
    }

    let mut seed = [0u8; SEED_LEN];
    seed.copy_from_slice(&seed_bytes);
    seed_bytes.zeroize();

    let identity = UnlockedIdentity::from_seed(seed);
    seed.zeroize();
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &[u8] = b"a strong test passphrase";

    #[test]
    fn generate_then_unlock_round_trips_keys() {
        let (public, wrapped) = generate_identity(PASS);
        let unlocked = unlock(&wrapped, PASS).unwrap();
        // Public keys recovered on unlock match those published at generation.
        assert_eq!(unlocked.public(), &public);
    }

    #[test]
    fn unlock_is_deterministic_across_calls() {
        let (_public, wrapped) = generate_identity(PASS);
        let a = unlock(&wrapped, PASS).unwrap();
        let b = unlock(&wrapped, PASS).unwrap();
        assert_eq!(a.public(), b.public());
        // Signing keys reconstructed from the same seed are identical.
        assert_eq!(a.signing_key().to_bytes(), b.signing_key().to_bytes());
    }

    #[test]
    fn wrong_passphrase_fails_closed() {
        let (_public, wrapped) = generate_identity(PASS);
        let err = unlock(&wrapped, b"the wrong passphrase").unwrap_err();
        assert!(matches!(err, CryptoError::DecryptionFailed));
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let (_public, mut wrapped) = generate_identity(PASS);
        wrapped.ciphertext[0] ^= 0x01;
        assert!(matches!(
            unlock(&wrapped, PASS).unwrap_err(),
            CryptoError::DecryptionFailed
        ));
    }

    #[test]
    fn tampered_nonce_fails_closed() {
        let (_public, mut wrapped) = generate_identity(PASS);
        wrapped.nonce[0] ^= 0xFF;
        assert!(matches!(
            unlock(&wrapped, PASS).unwrap_err(),
            CryptoError::DecryptionFailed
        ));
    }

    #[test]
    fn ed25519_and_x25519_keys_are_independent() {
        let (public, _wrapped) = generate_identity(PASS);
        // The two public keys must not be equal (they are cryptographically distinct keys
        // over different curves, derived via domain separation).
        assert_ne!(public.ed25519_pubkey, public.x25519_pubkey);
    }

    #[test]
    fn distinct_identities_have_distinct_keys() {
        let (a, _) = generate_identity(PASS);
        let (b, _) = generate_identity(PASS);
        // Fresh random seeds => different keypairs even with the same passphrase.
        assert_ne!(a.ed25519_pubkey, b.ed25519_pubkey);
        assert_ne!(a.x25519_pubkey, b.x25519_pubkey);
    }

    #[test]
    fn debug_does_not_leak_seed() {
        let (_public, wrapped) = generate_identity(PASS);
        let unlocked = unlock(&wrapped, PASS).unwrap();
        let dbg = format!("{unlocked:?}");
        assert!(dbg.contains("<redacted>"));
        // The raw seed bytes must not appear in the debug output.
        assert!(!dbg.contains(&hex::encode(unlocked.seed)));
    }
}
