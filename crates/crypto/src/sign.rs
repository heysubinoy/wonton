//! Ed25519 signing over commit objects (PLAN.md §4.1/§6). Signing proves a commit was
//! authored by the holder of a given identity; verification on every history read is what
//! makes the commit DAG tamper-evident (PLAN.md §6, "verify each commit's signature").

use ed25519_dalek::{Signature, Signer, VerifyingKey};

use crate::identity::UnlockedIdentity;
use crate::CryptoError;

/// Ed25519 signature length in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// Sign `message` with the identity's Ed25519 key, returning the 64-byte signature.
pub fn sign(unlocked: &UnlockedIdentity, message: &[u8]) -> [u8; SIGNATURE_LEN] {
    let signing_key = unlocked.signing_key();
    let signature: Signature = signing_key.sign(message);
    signature.to_bytes()
}

/// Verify an Ed25519 `signature` over `message` against `pubkey`.
///
/// Returns `Err(CryptoError::SignatureInvalid)` — never a `bool` — so a caller cannot
/// accidentally ignore a failed verification by treating a `false` as success (PLAN.md
/// §12.3, fail closed). Uses `verify_strict`, which additionally rejects signatures made
/// under non-canonical or small-order public keys.
pub fn verify(
    pubkey: &[u8; 32],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), CryptoError> {
    let verifying_key =
        VerifyingKey::from_bytes(pubkey).map_err(|_| CryptoError::SignatureInvalid)?;
    let signature = Signature::from_bytes(signature);
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| CryptoError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{generate_identity, unlock};

    fn identity(pass: &[u8]) -> UnlockedIdentity {
        let (_public, wrapped) = generate_identity(pass);
        unlock(&wrapped, pass).unwrap()
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let id = identity(b"signer pass");
        let msg = b"tree_hash|parent|author|ts|message";
        let sig = sign(&id, msg);
        assert!(verify(&id.public().ed25519_pubkey, msg, &sig).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let id = identity(b"signer pass");
        let sig = sign(&id, b"original message");
        let err = verify(&id.public().ed25519_pubkey, b"different message", &sig).unwrap_err();
        assert!(matches!(err, CryptoError::SignatureInvalid));
    }

    #[test]
    fn verify_rejects_forged_signature() {
        let id = identity(b"signer pass");
        let msg = b"authentic message";
        let mut sig = sign(&id, msg);
        sig[0] ^= 0x01; // corrupt the signature
        assert!(matches!(
            verify(&id.public().ed25519_pubkey, msg, &sig).unwrap_err(),
            CryptoError::SignatureInvalid
        ));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let signer = identity(b"signer pass");
        let other = identity(b"other pass");
        let msg = b"message";
        let sig = sign(&signer, msg);
        // A valid signature, checked against the wrong public key, must fail.
        assert!(matches!(
            verify(&other.public().ed25519_pubkey, msg, &sig).unwrap_err(),
            CryptoError::SignatureInvalid
        ));
    }

    #[test]
    fn verify_rejects_garbage_pubkey() {
        let id = identity(b"signer pass");
        let msg = b"message";
        let sig = sign(&id, msg);
        // An all-ones "public key" is not a valid curve point; from_bytes/verify must reject.
        assert!(verify(&[0xFFu8; 32], msg, &sig).is_err());
    }
}
