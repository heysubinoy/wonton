//! Verified history walk: walk the parent chain from a tip,
//! verifying each commit's content hash and Ed25519 signature, and report tampering loudly by
//! aborting the walk. A bad commit is **never** skipped.

use std::collections::BTreeSet;

use uuid::Uuid;
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
/// `resolve_signer(author_id)` is called once per commit to look up the Ed25519 pubkey that
/// commit's signature must verify against — a genuinely multi-author history (e.g. one shared
/// with several users) resolves each commit against its *own* author, not one fixed signer for
/// the whole walk (see the crate docs' "Multi-author `log`" note). If the resolver returns
/// `None` for a commit's author, the walk fails closed with [`VcsError::UnknownSigner`] rather
/// than skipping verification — an unresolvable signer is never treated as implicitly valid.
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
    resolve_signer: impl Fn(Uuid) -> Option<[u8; 32]>,
) -> Result<Vec<VerifiedCommit>, VcsError> {
    let mut history = Vec::new();
    let mut cursor = Some(tip);

    while let Some(hash) = cursor {
        let commit = load_commit(store, &hash)?;
        let signer_pubkey = resolve_signer(commit.fields.author_id)
            .ok_or(VcsError::UnknownSigner(commit.fields.author_id))?;
        verify_commit_signature(&commit, &hash, &signer_pubkey)?;

        // Mainline hop: first parent, whether this is a normal commit or a merge commit. Empty
        // `parent_hashes` (a root commit) ends the walk.
        cursor = commit.fields.parent_hashes.first().copied();

        history.push(VerifiedCommit { hash, commit });
    }

    Ok(history)
}

/// Walk the same mainline (first-parent) chain [`log`] would, collecting the distinct set of
/// `author_id`s that appear in it — **without** verifying any signature. Content hashes are
/// still re-checked (via [`load_commit`]), so a tampered/corrupted commit is still rejected; only
/// the *signature* check is deferred. This exists so a caller (typically the CLI) can resolve
/// exactly the set of authors' public keys it will need — e.g. from a server's user directory —
/// before running the real, fully-verifying [`log`] walk with a resolver built from that set.
pub fn mainline_author_ids(store: &LocalObjectStore, tip: Hash) -> Result<BTreeSet<Uuid>, VcsError> {
    let mut authors = BTreeSet::new();
    let mut cursor = Some(tip);

    while let Some(hash) = cursor {
        let commit = load_commit(store, &hash)?;
        authors.insert(commit.fields.author_id);
        cursor = commit.fields.parent_hashes.first().copied();
    }

    Ok(authors)
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

        let history = log(&store, c3, |_| Some(pubkey)).unwrap();
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
        let history = log(&store, c1, |_| Some(identity.public().ed25519_pubkey)).unwrap();
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

        let err = log(&store, c1, |_| Some(identity.public().ed25519_pubkey)).unwrap_err();
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

        let err = log(&store, new_hash, |_| Some(identity.public().ed25519_pubkey)).unwrap_err();
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
        let err = log(&store, c1, |_| Some(other.public().ed25519_pubkey)).unwrap_err();
        assert!(matches!(
            err,
            VcsError::Crypto(wonton_crypto::CryptoError::SignatureInvalid)
        ));
    }

    /// The bug this resolver-based design fixes (found via manual end-to-end testing,
    /// 2026-07-06): a history genuinely authored by two different identities must verify
    /// correctly for a reader who has *both* authors' public keys, resolving each commit
    /// against its own `author_id` rather than one fixed signer for the whole walk.
    #[test]
    fn multi_author_history_verifies_when_each_commit_resolves_to_its_own_author() {
        let (_dir, store) = temp_store();
        let alice = new_identity(b"alice pass");
        let bob = new_identity(b"bob pass");
        let dek = new_dek();
        let alice_id = crate::author_id_from_identity(alice.public());
        let bob_id = crate::author_id_from_identity(bob.public());

        let mut ws = WorkingSet::new();
        ws.set("K", b"one".to_vec());
        let c1 = commit(&store, &dek, &alice, alice_id, None, &ws, "alice's commit").unwrap();
        ws.set("K", b"two".to_vec());
        let c2 = commit(&store, &dek, &bob, bob_id, Some(c1), &ws, "bob's commit").unwrap();

        let alice_pub = alice.public().ed25519_pubkey;
        let bob_pub = bob.public().ed25519_pubkey;
        let history = log(&store, c2, move |author_id| {
            if author_id == alice_id {
                Some(alice_pub)
            } else if author_id == bob_id {
                Some(bob_pub)
            } else {
                None
            }
        })
        .unwrap();

        let hashes: Vec<Hash> = history.iter().map(|v| v.hash).collect();
        assert_eq!(hashes, vec![c2, c1]);
    }

    /// A resolver that has no key at all for a commit's author must fail the walk closed
    /// ([`VcsError::UnknownSigner`]) rather than silently accepting or skipping that commit.
    #[test]
    fn unresolvable_signer_fails_closed() {
        let (_dir, store) = temp_store();
        let identity = new_identity(b"pass");
        let dek = new_dek();
        let author_id = crate::author_id_from_identity(identity.public());
        let c1 = commit(&store, &dek, &identity, author_id, None, &WorkingSet::new(), "root").unwrap();

        let err = log(&store, c1, |_: Uuid| None).unwrap_err();
        assert!(matches!(err, VcsError::UnknownSigner(id) if id == author_id));
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

        let err = log(&store, new_hash, |_| Some(identity.public().ed25519_pubkey)).unwrap_err();
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
        let history = log(&store, merge_hash, |_| Some(identity.public().ed25519_pubkey)).unwrap();
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
        let err = log(&store, never_stored, |_| Some(identity.public().ed25519_pubkey)).unwrap_err();
        assert!(matches!(err, VcsError::CommitNotFound(_)));
    }

    #[test]
    fn mainline_author_ids_collects_every_distinct_author_without_verifying_signatures() {
        let (_dir, store) = temp_store();
        let alice = new_identity(b"alice pass");
        let bob = new_identity(b"bob pass");
        let dek = new_dek();
        let alice_id = crate::author_id_from_identity(alice.public());
        let bob_id = crate::author_id_from_identity(bob.public());

        let mut ws = WorkingSet::new();
        ws.set("K", b"one".to_vec());
        let c1 = commit(&store, &dek, &alice, alice_id, None, &ws, "alice's commit").unwrap();
        ws.set("K", b"two".to_vec());
        let c2 = commit(&store, &dek, &bob, bob_id, Some(c1), &ws, "bob's commit").unwrap();
        ws.set("K", b"three".to_vec());
        let c3 = commit(&store, &dek, &alice, alice_id, Some(c2), &ws, "alice again").unwrap();

        let authors = mainline_author_ids(&store, c3).unwrap();
        assert_eq!(authors, [alice_id, bob_id].into_iter().collect());
    }
}
