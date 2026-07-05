use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::hash::Hash;
use crate::ObjectError;

/// A snapshot of `key_name -> blob_hash` for one commit. Key names are plaintext by design
/// (§16 decision, §5.2 of PLAN.md) — never put a secret value in a key name.
///
/// `BTreeMap` keeps entries in sorted order, which is what makes `hash()` deterministic
/// regardless of insertion order.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Tree {
    pub entries: BTreeMap<String, Hash>,
}

impl Tree {
    pub fn new() -> Self {
        Tree::default()
    }

    pub fn insert(&mut self, key: impl Into<String>, blob_hash: Hash) {
        self.entries.insert(key.into(), blob_hash);
    }

    pub fn remove(&mut self, key: &str) -> Option<Hash> {
        self.entries.remove(key)
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

    fn h(byte: u8) -> Hash {
        Hash::of(&[byte])
    }

    #[test]
    fn hash_is_independent_of_insertion_order() {
        let mut a = Tree::new();
        a.insert("B", h(2));
        a.insert("A", h(1));

        let mut b = Tree::new();
        b.insert("A", h(1));
        b.insert("B", h(2));

        assert_eq!(a.hash().unwrap(), b.hash().unwrap());
    }

    #[test]
    fn hash_changes_when_a_value_changes() {
        let mut a = Tree::new();
        a.insert("KEY", h(1));

        let mut b = Tree::new();
        b.insert("KEY", h(2));

        assert_ne!(a.hash().unwrap(), b.hash().unwrap());
    }
}
