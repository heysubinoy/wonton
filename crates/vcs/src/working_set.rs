//! The in-memory staging area a caller builds up before [`crate::commit`].
//!
//! A `WorkingSet` holds `key -> plaintext value`. It **deliberately never touches disk in
//! plaintext**: it is a pure in-memory struct. Persisting staged changes is a
//! later phase's concern (an *encrypted* staging cache), out of scope
//! for Phase 2.

use std::collections::BTreeMap;

/// An in-memory `key -> plaintext value` staging set. `BTreeMap` gives deterministic
/// iteration order, which keeps the tree built by [`crate::commit`] stable.
///
/// Values are plaintext and live only in memory. This type intentionally does not implement
/// on-disk persistence; a future phase's encrypted staging cache will handle
/// durability without ever writing plaintext.
#[derive(Clone, Debug, Default)]
pub struct WorkingSet {
    entries: BTreeMap<String, Vec<u8>>,
}

impl WorkingSet {
    /// A new, empty working set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Stage `key = value` (the plaintext to be encrypted at commit time). Returns the
    /// previously staged value for `key`, if any.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<Vec<u8>>) -> Option<Vec<u8>> {
        self.entries.insert(key.into(), value.into())
    }

    /// Remove `key` from the staged set, returning its value if it was present.
    pub fn unset(&mut self, key: &str) -> Option<Vec<u8>> {
        self.entries.remove(key)
    }

    /// Borrow the staged plaintext for `key`, if present.
    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.entries.get(key).map(Vec::as_slice)
    }

    /// True if `key` is staged.
    pub fn contains_key(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    /// Iterate staged `(key, value)` pairs in sorted key order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Vec<u8>)> {
        self.entries.iter()
    }

    /// Number of staged keys.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if nothing is staged.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_unset_round_trip() {
        let mut ws = WorkingSet::new();
        assert!(ws.is_empty());

        assert!(ws.set("DATABASE_URL", b"postgres://x".to_vec()).is_none());
        assert_eq!(ws.set("API_KEY", *b"abc").map(|_| ()), None);
        assert_eq!(ws.len(), 2);
        assert!(ws.contains_key("API_KEY"));
        assert_eq!(ws.get("DATABASE_URL"), Some(&b"postgres://x"[..]));

        // Re-setting returns the prior value.
        let prev = ws.set("API_KEY", b"def".to_vec());
        assert_eq!(prev, Some(b"abc".to_vec()));

        assert_eq!(ws.unset("API_KEY"), Some(b"def".to_vec()));
        assert!(!ws.contains_key("API_KEY"));
        assert!(ws.unset("API_KEY").is_none());
    }

    #[test]
    fn iter_is_sorted_by_key() {
        let mut ws = WorkingSet::new();
        ws.set("B", b"2".to_vec());
        ws.set("A", b"1".to_vec());
        ws.set("C", b"3".to_vec());
        let keys: Vec<&String> = ws.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec!["A", "B", "C"]);
    }
}
