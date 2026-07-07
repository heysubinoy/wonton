use std::fmt;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::ObjectError;

pub const HASH_LEN: usize = 32;

type Blake2b256 = Blake2b<U32>;

/// A BLAKE2b-256 content hash, hex-encoded for display/wire/storage.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash([u8; HASH_LEN]);

impl Hash {
    /// Hash arbitrary bytes with BLAKE2b-256. This is the sole hashing entry point for
    /// content addressing — never hash with anything else.
    pub fn of(bytes: &[u8]) -> Self {
        let mut hasher = Blake2b256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(&digest);
        Hash(out)
    }

    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, ObjectError> {
        let bytes = hex::decode(s).map_err(|_| ObjectError::InvalidHash(s.to_string()))?;
        let arr: [u8; HASH_LEN] = bytes
            .try_into()
            .map_err(|_| ObjectError::InvalidHash(s.to_string()))?;
        Ok(Hash(arr))
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", self.to_hex())
    }
}

impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Hash::from_hex(&s).map_err(DeError::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic() {
        assert_eq!(Hash::of(b"wonton"), Hash::of(b"wonton"));
    }

    #[test]
    fn hash_is_sensitive_to_input() {
        assert_ne!(Hash::of(b"wonton"), Hash::of(b"wontan"));
    }

    #[test]
    fn hex_round_trips() {
        let h = Hash::of(b"round trip me");
        assert_eq!(Hash::from_hex(&h.to_hex()).unwrap(), h);
    }

    #[test]
    fn from_hex_rejects_garbage() {
        assert!(Hash::from_hex("not hex").is_err());
        assert!(Hash::from_hex("deadbeef").is_err()); // too short
    }
}
