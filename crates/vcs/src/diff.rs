//! Client-side, key-level diff: decrypt both trees locally and compare
//! at the key level → `Added` / `Removed` / `Changed`. **Never a byte diff of ciphertext.**

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use wonton_objects::{Hash, LocalObjectStore};

use crate::{decrypt_blob, load_tree_of_commit, ValueDecryptor, VcsError};

/// One key-level difference between two commits. Carries only the (plaintext) key name, which
/// is fine because key names are plaintext metadata by design.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffEntry {
    /// Present in `to`, absent in `from`.
    Added(String),
    /// Present in `from`, absent in `to`.
    Removed(String),
    /// Present in both, and the *decrypted plaintext* differs.
    Changed(String),
}

/// Diff two commits at the key level, returning the changes to get from `from` to `to`, in
/// sorted key order.
///
/// `from == None` means "diff against an empty tree", i.e. every key in `to` is `Added`.
///
/// Both commits are fetched and content-verified (via [`load_tree_of_commit`], which reuses
/// the same hash-verification as [`crate::log`]). Note this does **not** verify commit
/// *signatures* — the caller supplies no expected signer here; a caller that needs signature
/// guarantees for this history should run [`crate::log`] first.
///
/// ## The one correctness rule that matters
/// For a key present in both trees:
/// - **equal blob hashes ⇒ unchanged** (fast-path, skipped without decrypting): identical
///   ciphertext can only arise from the identical `(key, nonce, plaintext)` or an
///   astronomically unlikely nonce collision — safe to treat as unchanged.
/// - **unequal blob hashes ⇒ NOT necessarily changed.** Re-encrypting identical plaintext
///   produces a different blob every time (fresh random nonce), so we **decrypt both blobs
///   and compare the plaintext bytes**; only if they differ do we emit [`DiffEntry::Changed`].
///   Treating hash inequality alone as "changed" would wrongly flag values nobody touched.
pub fn diff(
    store: &LocalObjectStore,
    dec: &impl ValueDecryptor,
    from: Option<Hash>,
    to: Hash,
) -> Result<Vec<DiffEntry>, VcsError> {
    let from_tree = match from {
        Some(hash) => load_tree_of_commit(store, &hash)?,
        None => wonton_objects::Tree::new(),
    };
    let to_tree = load_tree_of_commit(store, &to)?;

    // Union of all key names across both trees, deduplicated and sorted (BTreeSet).
    let keys: BTreeSet<&String> = from_tree
        .entries
        .keys()
        .chain(to_tree.entries.keys())
        .collect();

    let mut entries = Vec::new();
    for key in keys {
        match (from_tree.entries.get(key), to_tree.entries.get(key)) {
            (None, Some(_)) => entries.push(DiffEntry::Added(key.clone())),
            (Some(_), None) => entries.push(DiffEntry::Removed(key.clone())),
            (Some(from_hash), Some(to_hash)) => {
                // Fast-path: identical ciphertext ⇒ definitely unchanged, skip decrypt.
                if from_hash == to_hash {
                    continue;
                }
                // Different blob hash is NOT proof of change: decrypt both and compare
                // plaintext ("Never a byte diff of ciphertext").
                let from_plain = decrypt_blob(store, dec, from_hash)?;
                let to_plain = decrypt_blob(store, dec, to_hash)?;
                if from_plain != to_plain {
                    entries.push(DiffEntry::Changed(key.clone()));
                }
            }
            // A key drawn from the union of both key sets is in at least one map.
            (None, None) => unreachable!("union key present in neither tree"),
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit::commit;
    use crate::testutil::{new_dek, new_identity, temp_store, tamper_object};
    use crate::{load_commit, WorkingSet};

    #[test]
    fn from_none_reports_everything_added() {
        let (_dir, store) = temp_store();
        let identity = new_identity(b"pass");
        let dek = new_dek();

        let mut ws = WorkingSet::new();
        ws.set("A", b"1".to_vec());
        ws.set("B", b"2".to_vec());
        let c1 = commit(&store, &dek, &identity, crate::author_id_from_identity(identity.public()),None, &ws, "c1").unwrap();

        let d = diff(&store, &dek, None, c1).unwrap();
        assert_eq!(
            d,
            vec![DiffEntry::Added("A".into()), DiffEntry::Added("B".into())]
        );
    }

    #[test]
    fn detects_added_removed_and_changed() {
        let (_dir, store) = temp_store();
        let identity = new_identity(b"pass");
        let dek = new_dek();

        // c1: A=apple, B=banana, R=removeme
        let mut ws = WorkingSet::new();
        ws.set("A", b"apple".to_vec());
        ws.set("B", b"banana".to_vec());
        ws.set("R", b"removeme".to_vec());
        let c1 = commit(&store, &dek, &identity, crate::author_id_from_identity(identity.public()),None, &ws, "c1").unwrap();

        // c2: A=apple (unchanged value, re-encrypted), B=blueberry (changed), C=cherry (added),
        //     R dropped (removed).
        let mut ws2 = WorkingSet::new();
        ws2.set("A", b"apple".to_vec());
        ws2.set("B", b"blueberry".to_vec());
        ws2.set("C", b"cherry".to_vec());
        let c2 = commit(&store, &dek, &identity, crate::author_id_from_identity(identity.public()),Some(c1), &ws2, "c2").unwrap();

        let d = diff(&store, &dek, Some(c1), c2).unwrap();
        // Sorted key order: A(unchanged→absent), B(changed), C(added), R(removed).
        assert_eq!(
            d,
            vec![
                DiffEntry::Changed("B".into()),
                DiffEntry::Added("C".into()),
                DiffEntry::Removed("R".into()),
            ]
        );
        // A must NOT appear (same plaintext, even though re-encrypted).
        assert!(!d.iter().any(|e| matches!(e, DiffEntry::Changed(k) if k == "A")));
    }

    /// The critical test (build spec): committing the *same* plaintext twice must produce NO
    /// `Changed` entry, even though the two commits' blob hashes for that key differ (fresh
    /// nonce each time). Asserts the differing-ciphertext precondition first so it can't pass
    /// vacuously.
    #[test]
    fn unchanged_value_recommitted_is_not_reported_as_changed() {
        let (_dir, store) = temp_store();
        let identity = new_identity(b"pass");
        let dek = new_dek();

        let mut ws = WorkingSet::new();
        ws.set("SECRET", b"do-not-touch".to_vec());
        let c1 = commit(&store, &dek, &identity, crate::author_id_from_identity(identity.public()),None, &ws, "c1").unwrap();

        // Re-stage the identical plaintext and commit again.
        let mut ws2 = WorkingSet::new();
        ws2.set("SECRET", b"do-not-touch".to_vec());
        let c2 = commit(&store, &dek, &identity, crate::author_id_from_identity(identity.public()),Some(c1), &ws2, "c2").unwrap();

        // Precondition: the two blob hashes for SECRET genuinely differ (distinct nonces), so
        // a hash-only diff *would* wrongly report a change.
        let t1 = load_commit(&store, &c1)
            .and_then(|_| crate::load_tree_of_commit(&store, &c1))
            .unwrap();
        let t2 = crate::load_tree_of_commit(&store, &c2).unwrap();
        let h1 = t1.entries.get("SECRET").unwrap();
        let h2 = t2.entries.get("SECRET").unwrap();
        assert_ne!(h1, h2, "test is vacuous: blob hashes should differ per nonce");

        // The plaintext-level diff must report nothing.
        let d = diff(&store, &dek, Some(c1), c2).unwrap();
        assert!(
            d.is_empty(),
            "recommitting identical plaintext must yield no diff, got {d:?}"
        );
    }

    #[test]
    fn tampered_blob_propagates_error_when_decrypted_for_a_changed_key() {
        let (_dir, store) = temp_store();
        let identity = new_identity(b"pass");
        let dek = new_dek();

        // Two commits with a genuinely different value for K, so diff must decrypt both blobs.
        let mut ws = WorkingSet::new();
        ws.set("K", b"v1".to_vec());
        let c1 = commit(&store, &dek, &identity, crate::author_id_from_identity(identity.public()),None, &ws, "c1").unwrap();
        ws.set("K", b"v2".to_vec());
        let c2 = commit(&store, &dek, &identity, crate::author_id_from_identity(identity.public()),Some(c1), &ws, "c2").unwrap();

        // Corrupt c2's blob for K on disk; the store's hash check on `get` must fire.
        let t2 = crate::load_tree_of_commit(&store, &c2).unwrap();
        let bad_blob = *t2.entries.get("K").unwrap();
        tamper_object(&store, &bad_blob, b"tampered ciphertext bytes");

        let err = diff(&store, &dek, Some(c1), c2).unwrap_err();
        assert!(matches!(
            err,
            VcsError::Object(wonton_objects::ObjectError::HashMismatch { .. })
        ));
    }

    #[test]
    fn wrong_dek_fails_closed_on_changed_key() {
        let (_dir, store) = temp_store();
        let identity = new_identity(b"pass");
        let dek = new_dek();

        let mut ws = WorkingSet::new();
        ws.set("K", b"v1".to_vec());
        let c1 = commit(&store, &dek, &identity, crate::author_id_from_identity(identity.public()),None, &ws, "c1").unwrap();
        ws.set("K", b"v2".to_vec());
        let c2 = commit(&store, &dek, &identity, crate::author_id_from_identity(identity.public()),Some(c1), &ws, "c2").unwrap();

        // A different DEK cannot authenticate the blobs → decryption fails closed.
        let wrong = new_dek();
        let err = diff(&store, &wrong, Some(c1), c2).unwrap_err();
        assert!(matches!(
            err,
            VcsError::Crypto(wonton_crypto::CryptoError::DecryptionFailed)
        ));
    }
}
