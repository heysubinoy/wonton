use serde::{Deserialize, Serialize};

use crate::hash::Hash;
use crate::ObjectError;

/// One encrypted secret value: `nonce || ciphertext` where `ciphertext` already includes
/// the AEAD auth tag (combined mode). Encryption/decryption itself lives in `wonton-crypto`
/// — this crate only knows how to hash and (de)serialize the opaque bytes.
#[derive(Clone, Serialize, Deserialize)]
pub struct Blob {
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

impl Blob {
    pub fn new(nonce: [u8; 24], ciphertext: Vec<u8>) -> Self {
        Blob { nonce, ciphertext }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ObjectError> {
        serde_json::to_vec(self).map_err(ObjectError::Serialize)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ObjectError> {
        serde_json::from_slice(bytes).map_err(ObjectError::Deserialize)
    }

    pub fn hash(&self) -> Result<Hash, ObjectError> {
        Ok(Hash::of(&self.to_bytes()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_bytes() {
        let blob = Blob::new([7u8; 24], vec![1, 2, 3, 4]);
        let bytes = blob.to_bytes().unwrap();
        let back = Blob::from_bytes(&bytes).unwrap();
        assert_eq!(blob.hash().unwrap(), back.hash().unwrap());
    }

    #[test]
    fn hash_changes_if_ciphertext_flips_a_bit() {
        let a = Blob::new([0u8; 24], vec![0b0000_0001]);
        let b = Blob::new([0u8; 24], vec![0b0000_0000]);
        assert_ne!(a.hash().unwrap(), b.hash().unwrap());
    }
}
