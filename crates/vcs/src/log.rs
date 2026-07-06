//! Verified history walk (PLAN.md §6, "Log / history"): walk the parent chain from a tip,
//! verifying each commit's content hash and Ed25519 signature, and report tampering loudly by
//! aborting the walk. A bad commit is **never** skipped (PLAN.md §6/§12.3).

use wonton_objects::{Commit, Hash, LocalObjectStore};

use crate::{load_commit, verify_commit_signature, VcsError};

/// A commit that passed [`log`]'s full verification (content hash + signature), paired with
/// the hash it was fetched by.
#[derive(Clone)]
pub struct VerifiedCommit {
    pub hash: Hash,
    pub commit: Commit,
}

// Manual `Debug` because `wonton_objects::Commit` does not implement `Debug`. A commit holds
// no plaintext (only ciphertext hashes and plaintext metadata), so surfacing its fields is
// safe and makes test assertions (`unwrap_err`, etc.) ergonomic.
impl core::fmt::Debug for VerifiedCommit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifiedCommit")
            .field("hash", &self.hash)
            .field("tree_hash", &self.commit.fields.tree_hash)
            .field("parent_hashes", &self.commit.fields.parent_hashes)
            .field("author_id", &self.commit.fields.author_id)
            .field("timestamp", &self.commit.fields.timestamp)
            .field("message", &self.commit.fields.message)
            .finish()
    }
}

/// Walk the mainline (first-parent) chain from `tip` back to the root, verifying every commit,
/// and return the verified commits **tip-first** (index 0 is `tip`, the last element is the
/// root). Mirrors `git log --first-parent`: a merge commit itself is included in the walk, but
/// its second-and-later parents' exclusive history is not additionally traversed.
///
/// For each commit, in order:
/// 1. Fetch it via the store (which re-verifies the content hash — an
///    [`wonton_objects::ObjectError::HashMismatch`] here means on-disk tampering and
///    propagates as an error) and re-check `commit.hash()` as defense in depth ([`load_commit`]).
/// 2. Verify the Ed25519 signature over `fields.signing_bytes()` against `signer_pubkey`. A
///    failure aborts the walk with an error — the commit is never accepted or skipped.
/// 3. Continue via `parent_hashes[0]` (the mainline parent, whether this is a 1-parent commit or
///    a 2+-parent merge commit); stop when `parent_hashes` is empty (root reached).
///
/// **Phase-2 constraint still in force (temporary — see crate docs / PROGRESS.md §8):**
/// `signer_pubkey` is a single expected signer for the whole history (single-identity local use).
/// Multi-author signer resolution via a user registry is a Phase 3/4 concern.
///
/// **Phase 5b change:** earlier phases rejected any 2+-parent commit outright
/// ([`VcsError::MultiParentCommit`]), since merge commits could not yet exist. Now that
/// [`crate::merge::commit_merge`] produces them, `log` must not permanently break on a branch
/// that has ever been merged — it follows the first parent through a merge commit instead of
/// erroring. Finding the *other* side's history (or the merge base) is
/// [`crate::merge::merge_base`]'s job, which deliberately uses a different, all-parents
/// traversal.
pub fn log(
    store: &LocalObjectStore,
    tip: Hash,
    signer_pubkey: &[u8; 32],
) -> Result<Vec<VerifiedCommit>, VcsError> {
    let mut history = Vec::new();
    let mut cursor = Some(tip);

    while let Some(hash) = cursor {
        let commit = load_commit(store, &hash)?;
        verify_commit_signature(&commit, &hash, signer_pubkey)?;

        // Mainline hop: first parent, whether this is a normal commit or a merge commit. Empty
        // `parent_hashes` (a root commit) ends the walk.
        cursor = commit.fields.parent_hashes.first().copied();

        history.push(VerifiedCommit { hash, commit });
    }

    Ok(history)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit::commit;
    use crate::testutil::{new_dek, new_identity, temp_store, tamper_object};
    use crate::WorkingSet;
    use wonton_objects::{Commit, CommitFields, Tree};
    use wonton_crypto::sign;

    #[test]
    fn walks_and_verifies_a_three_commit_chain_tip_first() {
        let (_dir, store) = temp_store();
        let identity = new_identity(b"pass");
        let dek = new_dek();
        let pubkey = identity.public().ed25519_pubkey;

        let mut ws = WorkingSet::new();
        ws.set("K", b"one".to_vec());
        let c1 = commit(&store, &dek, &identity, crate::author_id_from_identity(identity.public()),None, &ws, "c1").unwrap();
        ws.set("K", b"two".to_vec());
        let c2 = commit(&store, &dek, &identity, crate::author_id_from_identity(identity.public()),Some(c1), &ws, "c2").unwrap();
        ws.set("K", b"three".to_vec());
        let c3 = commit(&store, &dek, &identity, crate::author_id_from_identity(identity.public()),Some(c2), &ws, "c3").unwrap();

        let history = log(&store, c3, &pubkey).unwrap();
        let hashes: Vec<Hash> = history.iter().map(|v| v.hash).collect();
        assert_eq!(hashes, vec![c3, c2, c1]); // tip-first
        let messages: Vec<&str> = history.iter().map(|v| v.commit.fields.message.as_str()).collect();
        assert_eq!(messages, vec!["c3", "c2", "c1"]);
    }

    #[test]
    fn single_root_commit_walks_to_length_one() {
        let (_dir, store) = temp_store();
        let identity = new_identity(b"pass");
        let dek = new_dek();
        let c1 = commit(&store, &dek, &identity, crate::author_id_from_identity(identity.public()),None, &WorkingSet::new(), "root").unwrap();
        let history = log(&store, c1, &identity.public().ed25519_pubkey).unwrap();
        assert_eq!(history.len(), 1);
        assert!(history[0].commit.fields.parent_hashes.is_empty());
    }

    #[test]
    fn on_disk_commit_tampering_fails_closed() {
        let (_dir, store) = temp_store();
        let identity = new_identity(b"pass");
        let dek = new_dek();
        let c1 = commit(&store, &dek, &identity, crate::author_id_from_identity(identity.public()),None, &WorkingSet::new(), "root").unwrap();

        // Overwrite the stored commit bytes in place (hostile/corrupted disk). The store's
        // own hash re-verification on `get` must catch it.
        tamper_object(&store, &c1, b"garbage bytes not matching the hash");

        let err = log(&store, c1, &identity.public().ed25519_pubkey).unwrap_err();
        assert!(matches!(err, VcsError::Object(wonton_objects::ObjectError::HashMismatch { .. })));
    }

    #[test]
    fn corrupted_signature_fails_with_signature_error() {
        let (_dir, store) = temp_store();
        let identity = new_identity(b"pass");
        let dek = new_dek();
        let c1 = commit(&store, &dek, &identity, crate::author_id_from_identity(identity.public()),None, &WorkingSet::new(), "root").unwrap();

        // Read the commit, flip a signature byte, and re-store it at its *recomputed* hash so
        // the content-hash check passes and we actually reach signature verification.
        let bytes = store.get(&c1).unwrap().unwrap();
        let mut c = Commit::from_bytes(&bytes).unwrap();
        c.signature[0] ^= 0x01;
        let new_bytes = c.to_bytes().unwrap();
        let new_hash = Hash::of(&new_bytes);
        store.put(&new_hash, &new_bytes).unwrap();

        let err = log(&store, new_hash, &identity.public().ed25519_pubkey).unwrap_err();
        assert!(matches!(
            err,
            VcsError::Crypto(wonton_crypto::CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn wrong_signer_pubkey_fails_closed() {
        let (_dir, store) = temp_store();
        let signer = new_identity(b"signer pass");
        let other = new_identity(b"other pass");
        let dek = new_dek();
        let c1 = commit(
            &store,
            &dek,
            &signer,
            crate::author_id_from_identity(signer.public()),
            None,
            &WorkingSet::new(),
            "root",
        )
        .unwrap();

        // A genuine, untampered commit verified against the wrong pubkey must fail.
        let err = log(&store, c1, &other.public().ed25519_pubkey).unwrap_err();
        assert!(matches!(
            err,
            VcsError::Crypto(wonton_crypto::CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn malformed_signature_length_fails_closed() {
        let (_dir, store) = temp_store();
        let identity = new_identity(b"pass");
        let dek = new_dek();
        let c1 = commit(&store, &dek, &identity, crate::author_id_from_identity(identity.public()),None, &WorkingSet::new(), "root").unwrap();

        // Truncate the signature to an invalid length and re-store at the recomputed hash.
        let bytes = store.get(&c1).unwrap().unwrap();
        let mut c = Commit::from_bytes(&bytes).unwrap();
        c.signature.truncate(10);
        let new_bytes = c.to_bytes().unwrap();
        let new_hash = Hash::of(&new_bytes);
        store.put(&new_hash, &new_bytes).unwrap();

        let err = log(&store, new_hash, &identity.public().ed25519_pubkey).unwrap_err();
        assert!(matches!(err, VcsError::BadSignatureLength { actual: 10, .. }));
    }

    /// Phase 5b behavior change: a 2+-parent (merge) commit is no longer rejected. `log` includes
    /// it in the walk and continues via its *first* parent (the mainline), and must NOT error and
    /// must NOT additionally walk the merged-in side's exclusive history.
    #[test]
    fn multi_parent_commit_is_included_and_walk_follows_first_parent() {
        let (_dir, store) = temp_store();
        let identity = new_identity(b"pass");
        let dek = new_dek();
        let author = crate::author_id_from_identity(identity.public());

        // Mainline: root -> child.
        let root = commit(&store, &dek, &identity, author, None, &WorkingSet::new(), "root").unwrap();
        let child = commit(&store, &dek, &identity, author, Some(root), &WorkingSet::new(), "child").unwrap();

        // An independent side branch ("theirs") that only a merge commit's SECOND parent reaches.
        let side = commit(&store, &dek, &identity, author, None, &WorkingSet::new(), "side").unwrap();

        // Hand-build a signed merge commit with two parents (commit() only makes 0/1-parent
        // commits) and store it: parents = [mainline child, side].
        let empty_tree = Tree::new();
        let tree_bytes = empty_tree.to_bytes().unwrap();
        let tree_hash = Hash::of(&tree_bytes);
        store.put(&tree_hash, &tree_bytes).unwrap();
        let fields = CommitFields {
            tree_hash,
            parent_hashes: vec![child, side],
            author_id: author,
            timestamp: 1_700_000_100,
            message: "merge".to_string(),
        };
        let signature = sign(&identity, &fields.signing_bytes().unwrap());
        let merge = Commit { fields, signature: signature.to_vec() };
        let merge_bytes = merge.to_bytes().unwrap();
        let merge_hash = Hash::of(&merge_bytes);
        store.put(&merge_hash, &merge_bytes).unwrap();

        // Must not error, must include the merge commit, must follow parent[0] (mainline) only.
        let history = log(&store, merge_hash, &identity.public().ed25519_pubkey).unwrap();
        let hashes: Vec<Hash> = history.iter().map(|v| v.hash).collect();
        assert_eq!(hashes, vec![merge_hash, child, root]);
        assert!(
            !hashes.contains(&side),
            "must not additionally walk the merged-in side's exclusive history"
        );
    }

    #[test]
    fn missing_commit_reports_not_found() {
        let (_dir, store) = temp_store();
        let identity = new_identity(b"pass");
        let never_stored = Hash::of(b"nope");
        let err = log(&store, never_stored, &identity.public().ed25519_pubkey).unwrap_err();
        assert!(matches!(err, VcsError::CommitNotFound(_)));
    }
}
