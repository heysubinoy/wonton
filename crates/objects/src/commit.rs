use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::hash::Hash;
use crate::ObjectError;

/// Everything an Ed25519 signature covers. Kept separate from `Commit` so callers (in
/// `wonton-vcs`, which holds the signing key via `wonton-crypto`) can serialize exactly
/// this and sign it, without this crate needing to know anything about signing keys.
#[derive(Clone, Serialize, Deserialize)]
pub struct CommitFields {
    pub tree_hash: Hash,
    /// 0 parents = root commit, 1 = normal, 2+ = merge commit.
    pub parent_hashes: Vec<Hash>,
    pub author_id: Uuid,
    /// Unix seconds, UTC.
    pub timestamp: i64,
    pub message: String,
}

impl CommitFields {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ObjectError> {
        serde_json::to_vec(self).map_err(ObjectError::Serialize)
    }
}

/// An immutable, content-addressed commit: signed fields plus the Ed25519 signature over
/// them. The commit's own hash covers the signature too, so tampering with either the
/// fields or the signature changes the address.
#[derive(Clone, Serialize, Deserialize)]
pub struct Commit {
    pub fields: CommitFields,
    /// Ed25519 signature (64 bytes) over `fields.signing_bytes()`.
    pub signature: Vec<u8>,
}

impl Commit {
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

    fn fields() -> CommitFields {
        CommitFields {
            tree_hash: Hash::of(b"tree"),
            parent_hashes: vec![],
            author_id: Uuid::nil(),
            timestamp: 1_700_000_000,
            message: "initial commit".to_string(),
        }
    }

    #[test]
    fn hash_covers_the_signature() {
        let a = Commit {
            fields: fields(),
            signature: vec![1; 64],
        };
        let b = Commit {
            fields: fields(),
            signature: vec![2; 64],
        };
        assert_ne!(a.hash().unwrap(), b.hash().unwrap());
    }

    #[test]
    fn round_trips_through_bytes() {
        let c = Commit {
            fields: fields(),
            signature: vec![9; 64],
        };
        let bytes = c.to_bytes().unwrap();
        let back = Commit::from_bytes(&bytes).unwrap();
        assert_eq!(c.hash().unwrap(), back.hash().unwrap());
    }
}
