//! Asymmetric DEK wrapping via the X25519 `crypto_box` sealed box. A
//! sealed box is an *anonymous-sender* construction (libsodium `crypto_box_seal`): it
//! encrypts a DEK to a recipient's X25519 public key using an ephemeral sender keypair, so
//! anyone holding the recipient's public key can wrap a DEK for them, but only the recipient
//! (with the matching secret key) can unwrap it.
//!
//! This is how access control is expressed *in the cryptography*: granting user
//! U access to an environment means sealing that environment's DEK for U's public key. No
//! value re-encryption, O(1). Revocation requires rotating to a new DEK,
//! which is a higher-layer operation built on top of this primitive.

use crypto_box::{PublicKey, SecretKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::aead::{Dek, KEY_LEN};
use crate::identity::UnlockedIdentity;
use crate::CryptoError;

/// A DEK sealed for a recipient's X25519 public key. Opaque ciphertext — safe to store on
/// the blind server and to serialize. Internally: `ephemeral_pubkey (32) || XSalsa20-Poly1305
/// ciphertext+tag`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedDek(pub Vec<u8>);

/// Wrap `dek` for the recipient identified by `recipient_x25519_pubkey` using an anonymous
/// sealed box. Anyone can call this with a public key; only the holder of the matching secret
/// key can [`unwrap_dek`] it.
pub fn wrap_dek(dek: &Dek, recipient_x25519_pubkey: &[u8; 32]) -> SealedDek {
    let recipient = PublicKey::from_bytes(*recipient_x25519_pubkey);
    // Sealing generates a fresh ephemeral keypair internally via OsRng; it only fails for
    // implausibly large plaintext, which a 32-byte DEK never is.
    let sealed = recipient
        .seal(&mut OsRng, dek.as_bytes())
        .expect("sealing a 32-byte DEK cannot fail");
    SealedDek(sealed)
}

/// Unwrap a [`SealedDek`] with the recipient's unlocked identity (its X25519 secret key).
///
/// Fails closed with [`CryptoError::UnwrapFailed`] if the sealed box was tampered with or was
/// sealed for a *different* recipient's public key — the wrong secret key cannot open it.
/// This is the mechanism that denies a revoked or unauthorized user: with no
/// sealed DEK they can open, they get an error, never undecryptable-but-plausible bytes.
pub fn unwrap_dek(sealed: &SealedDek, recipient: &UnlockedIdentity) -> Result<Dek, CryptoError> {
    let secret: SecretKey = recipient.x25519_secret();
    let plaintext = secret
        .unseal(&sealed.0)
        .map_err(|_| CryptoError::UnwrapFailed)?;

    // A well-formed sealed DEK opens to exactly 32 key bytes. Anything else is malformed —
    // fail closed instead of constructing a truncated/oversized key.
    let bytes: [u8; KEY_LEN] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::UnwrapFailed)?;
    Ok(Dek::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::{decrypt_value, encrypt_value, generate_dek};
    use crate::identity::{generate_identity, unlock};

    fn identity(pass: &[u8]) -> UnlockedIdentity {
        let (_public, wrapped) = generate_identity(pass);
        unlock(&wrapped, pass).unwrap()
    }

    #[test]
    fn wrap_then_unwrap_round_trips() {
        let recipient = identity(b"recipient pass");
        let dek = generate_dek();

        let sealed = wrap_dek(&dek, &recipient.public().x25519_pubkey);
        let unwrapped = unwrap_dek(&sealed, &recipient).unwrap();

        assert_eq!(unwrapped.as_bytes(), dek.as_bytes());
    }

    #[test]
    fn dek_survives_full_envelope_round_trip() {
        // encrypt value -> wrap DEK for B -> unwrap with B -> decrypt (full envelope round trip).
        let bob = identity(b"bob pass");
        let dek = generate_dek();
        let ct = encrypt_value(&dek, b"DATABASE_URL=postgres://...");

        let sealed = wrap_dek(&dek, &bob.public().x25519_pubkey);
        let bob_dek = unwrap_dek(&sealed, &bob).unwrap();

        let pt = decrypt_value(&bob_dek, &ct).unwrap();
        assert_eq!(pt, b"DATABASE_URL=postgres://...");
    }

    #[test]
    fn wrapping_for_b_cannot_be_unwrapped_by_a() {
        let alice = identity(b"alice pass");
        let bob = identity(b"bob pass");
        let dek = generate_dek();

        // Wrap strictly for Bob.
        let sealed = wrap_dek(&dek, &bob.public().x25519_pubkey);

        // Alice must not be able to open it.
        let err = unwrap_dek(&sealed, &alice).unwrap_err();
        assert!(matches!(err, CryptoError::UnwrapFailed));

        // Bob still can.
        assert_eq!(
            unwrap_dek(&sealed, &bob).unwrap().as_bytes(),
            dek.as_bytes()
        );
    }

    #[test]
    fn tampered_sealed_box_fails_closed() {
        let recipient = identity(b"recipient pass");
        let dek = generate_dek();
        let mut sealed = wrap_dek(&dek, &recipient.public().x25519_pubkey);

        // Flip a byte in the ciphertext portion (past the 32-byte ephemeral pubkey prefix).
        let idx = sealed.0.len() - 1;
        sealed.0[idx] ^= 0x01;
        assert!(matches!(
            unwrap_dek(&sealed, &recipient).unwrap_err(),
            CryptoError::UnwrapFailed
        ));
    }

    #[test]
    fn truncated_sealed_box_fails_closed() {
        let recipient = identity(b"recipient pass");
        let dek = generate_dek();
        let sealed = wrap_dek(&dek, &recipient.public().x25519_pubkey);

        let truncated = SealedDek(sealed.0[..10].to_vec());
        assert!(matches!(
            unwrap_dek(&truncated, &recipient).unwrap_err(),
            CryptoError::UnwrapFailed
        ));
    }
}
