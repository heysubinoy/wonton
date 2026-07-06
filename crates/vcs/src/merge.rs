//! Three-way client-side merge (PLAN.md §6, "Merge"; PROGRESS.md §3.8). Entirely offline and
//! client-side, like the rest of this crate: the server never sees plaintext, a merge base, or a
//! conflict — it only ever sees the final signed merge commit's ciphertext objects.
//!
//! ## Why this is a separate module from `commit`/`log`
//! - [`merge_base`] needs a genuinely different graph walk from [`crate::log`]'s mainline-only
//!   walk: it must consider *every* parent of a merge commit, not just the first, to find the
//!   nearest commit reachable from both sides.
//! - [`commit_merge`] produces a 2-parent commit. [`crate::commit::commit`] stays 0-or-1-parent
//!   and its public signature is unchanged — this module reuses its internal blob/tree/sign
//!   logic via [`crate::commit::build_and_sign`] rather than widening it.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

use uuid::Uuid;
use wonton_objects::{Hash, LocalObjectStore};

use crate::commit::build_and_sign;
use crate::{load_commit, CommitSigner, ValueEncryptor, VcsError, WorkingSet};

/// The full set of ancestor hashes reachable from `start` by following **every** entry in each
/// commit's `parent_hashes` (unlike [`crate::log`]'s first-parent-only walk) — `start` itself is
/// included. Used by [`merge_base`], which needs to know "everything `a` (or `b`) can reach",
/// not just its mainline.
fn all_ancestors(store: &LocalObjectStore, start: Hash) -> Result<HashSet<Hash>, VcsError> {
    let mut seen = HashSet::new();
    let mut queue = VecDeque::from([start]);
    while let Some(hash) = queue.pop_front() {
        if !seen.insert(hash) {
            continue;
        }
        let commit = load_commit(store, &hash)?;
        for parent in &commit.fields.parent_hashes {
            queue.push_back(*parent);
        }
    }
    Ok(seen)
}

/// Nearest common ancestor of `a` and `b`, considering every parent at each step (not just the
/// first) — a genuinely different traversal from [`crate::log`]'s mainline-only walk, since a
/// merge base search must be able to find a common ancestor reachable only via a merge commit's
/// second parent.
///
/// Implementation: collect the full ancestor set of `a`, then breadth-first from `b` (nearest
/// first) and return the first hash already in that set. `None` means the histories are disjoint
/// (no common ancestor); the caller then treats the merge base as an empty tree, which
/// [`three_way_merge`] already handles correctly (every key on both sides counts as "added",
/// since an empty base can never equal either side).
pub fn merge_base(store: &LocalObjectStore, a: Hash, b: Hash) -> Result<Option<Hash>, VcsError> {
    let ancestors_of_a = all_ancestors(store, a)?;

    let mut seen = HashSet::new();
    let mut queue = VecDeque::from([b]);
    while let Some(hash) = queue.pop_front() {
        if !seen.insert(hash) {
            continue;
        }
        if ancestors_of_a.contains(&hash) {
            return Ok(Some(hash));
        }
        let commit = load_commit(store, &hash)?;
        for parent in &commit.fields.parent_hashes {
            queue.push_back(*parent);
        }
    }
    Ok(None)
}

/// One key's three-way resolution outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeEntry {
    /// No conflict: the merged result for this key. `None` means the merge deletes the key.
    Resolved(Option<Vec<u8>>),
    /// Both sides changed this key (relative to `base`) to different values — a human (or a
    /// caller acting on their behalf) must pick `ours`, `theirs`, or supply a new value. `None`
    /// on a side means that side deleted the key.
    Conflict {
        ours: Option<Vec<u8>>,
        theirs: Option<Vec<u8>>,
    },
}

/// The one rule that covers add/change/remove uniformly for every key in the union of `base`,
/// `ours`, and `theirs` (PLAN.md §6, generalized):
/// - unchanged on our side (`ours == base`, including "absent in both") → take theirs, whatever
///   it is (an addition, a change, or a deletion).
/// - unchanged on their side (`theirs == base`) → take ours.
/// - both sides differ from `base`:
///   - `ours == theirs` → no conflict, both independently arrived at the same result (covers
///     "both added the same value" and "both changed to the same value"; "both deleted" is
///     already caught by the first two branches, since a deletion equals `base` on neither side
///     only when base itself wasn't absent — either way it can't reach this branch spuriously).
///   - otherwise → [`MergeEntry::Conflict`] (differing adds, differing changes, and "one side
///     deletes, the other modifies", since a deletion is `None` and can never equal a modified
///     `Some`).
///
/// Written as one match per key rather than special-casing add/change/remove separately — the
/// rule above already covers all of them uniformly.
pub fn three_way_merge(
    base: &BTreeMap<String, Vec<u8>>,
    ours: &BTreeMap<String, Vec<u8>>,
    theirs: &BTreeMap<String, Vec<u8>>,
) -> BTreeMap<String, MergeEntry> {
    let keys: BTreeSet<&String> = base.keys().chain(ours.keys()).chain(theirs.keys()).collect();

    let mut out = BTreeMap::new();
    for key in keys {
        let b = base.get(key);
        let o = ours.get(key);
        let t = theirs.get(key);

        let entry = if o == b {
            MergeEntry::Resolved(t.cloned())
        } else if t == b || o == t {
            MergeEntry::Resolved(o.cloned())
        } else {
            MergeEntry::Conflict {
                ours: o.cloned(),
                theirs: t.cloned(),
            }
        };
        out.insert(key.clone(), entry);
    }
    out
}

/// Build and store a 2-parent merge commit from an already-fully-resolved [`WorkingSet`] (every
/// [`MergeEntry::Conflict`] must already be settled by the caller before this is called — this
/// function has no notion of "conflict", only a final plaintext result). Separate from
/// [`crate::commit::commit`] (which stays 0-or-1-parent, unchanged, zero risk to its existing call
/// sites) rather than widening its `parent: Option<Hash>` to a `Vec<Hash>` everywhere.
pub fn commit_merge(
    store: &LocalObjectStore,
    enc: &impl ValueEncryptor,
    signer: &impl CommitSigner,
    author_id: Uuid,
    parents: [Hash; 2],
    working_set: &WorkingSet,
    message: impl Into<String>,
) -> Result<Hash, VcsError> {
    build_and_sign(
        store,
        enc,
        signer,
        author_id,
        vec![parents[0], parents[1]],
        working_set,
        message,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit::commit;
    use crate::testutil::{new_dek, new_identity, temp_store};

    fn author(identity: &wonton_crypto::UnlockedIdentity) -> Uuid {
        crate::author_id_from_identity(identity.public())
    }

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, Vec<u8>> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.as_bytes().to_vec()))
            .collect()
    }

    // ---- merge_base --------------------------------------------------------------------------

    #[test]
    fn merge_base_finds_the_common_ancestor_through_a_merge_commit() {
        let (_dir, store) = temp_store();
        let identity = new_identity(b"pass");
        let dek = new_dek();
        let a = author(&identity);

        let root = commit(&store, &dek, &identity, a, None, &WorkingSet::new(), "root").unwrap();
        // Two branches diverge from root.
        let ours = commit(&store, &dek, &identity, a, Some(root), &WorkingSet::new(), "ours").unwrap();
        let theirs = commit(&store, &dek, &identity, a, Some(root), &WorkingSet::new(), "theirs").unwrap();

        let base = merge_base(&store, ours, theirs).unwrap();
        assert_eq!(base, Some(root));
    }

    #[test]
    fn merge_base_considers_every_parent_not_just_first() {
        let (_dir, store) = temp_store();
        let identity = new_identity(b"pass");
        let dek = new_dek();
        let a = author(&identity);

        // `side` only becomes reachable from `ours` via a merge commit's SECOND parent.
        let root = commit(&store, &dek, &identity, a, None, &WorkingSet::new(), "root").unwrap();
        let side = commit(&store, &dek, &identity, a, Some(root), &WorkingSet::new(), "side").unwrap();
        let mainline = commit(&store, &dek, &identity, a, Some(root), &WorkingSet::new(), "mainline").unwrap();
        let ours = commit_merge(&store, &dek, &identity, a, [mainline, side], &WorkingSet::new(), "merge side in").unwrap();

        // `theirs` branches off of `side` directly — only reachable from `ours` via its 2nd parent.
        let theirs = commit(&store, &dek, &identity, a, Some(side), &WorkingSet::new(), "theirs").unwrap();

        let base = merge_base(&store, ours, theirs).unwrap();
        assert_eq!(base, Some(side), "must find `side` via the merge commit's second parent");
    }

    #[test]
    fn merge_base_is_none_for_disjoint_histories() {
        let (_dir, store) = temp_store();
        let identity = new_identity(b"pass");
        let dek = new_dek();
        let a = author(&identity);

        let x = commit(&store, &dek, &identity, a, None, &WorkingSet::new(), "x").unwrap();
        let y = commit(&store, &dek, &identity, a, None, &WorkingSet::new(), "y").unwrap();

        assert_eq!(merge_base(&store, x, y).unwrap(), None);
    }

    // ---- three_way_merge -----------------------------------------------------------------------

    #[test]
    fn only_ours_changed_takes_ours() {
        let base = map(&[("K", "base")]);
        let ours = map(&[("K", "ours-value")]);
        let theirs = map(&[("K", "base")]);
        let out = three_way_merge(&base, &ours, &theirs);
        assert_eq!(out.get("K"), Some(&MergeEntry::Resolved(Some(b"ours-value".to_vec()))));
    }

    #[test]
    fn only_theirs_changed_takes_theirs() {
        let base = map(&[("K", "base")]);
        let ours = map(&[("K", "base")]);
        let theirs = map(&[("K", "theirs-value")]);
        let out = three_way_merge(&base, &ours, &theirs);
        assert_eq!(out.get("K"), Some(&MergeEntry::Resolved(Some(b"theirs-value".to_vec()))));
    }

    #[test]
    fn both_changed_to_the_same_value_is_not_a_conflict() {
        let base = map(&[("K", "base")]);
        let ours = map(&[("K", "same")]);
        let theirs = map(&[("K", "same")]);
        let out = three_way_merge(&base, &ours, &theirs);
        assert_eq!(out.get("K"), Some(&MergeEntry::Resolved(Some(b"same".to_vec()))));
    }

    #[test]
    fn both_changed_to_different_values_is_a_conflict() {
        let base = map(&[("K", "base")]);
        let ours = map(&[("K", "ours-value")]);
        let theirs = map(&[("K", "theirs-value")]);
        let out = three_way_merge(&base, &ours, &theirs);
        assert_eq!(
            out.get("K"),
            Some(&MergeEntry::Conflict {
                ours: Some(b"ours-value".to_vec()),
                theirs: Some(b"theirs-value".to_vec()),
            })
        );
    }

    #[test]
    fn one_side_deletes_other_modifies_is_a_conflict() {
        let base = map(&[("K", "base")]);
        let ours: BTreeMap<String, Vec<u8>> = BTreeMap::new(); // ours deletes K
        let theirs = map(&[("K", "theirs-value")]);
        let out = three_way_merge(&base, &ours, &theirs);
        assert_eq!(
            out.get("K"),
            Some(&MergeEntry::Conflict {
                ours: None,
                theirs: Some(b"theirs-value".to_vec()),
            })
        );
    }

    #[test]
    fn one_side_deletes_other_unchanged_resolves_to_deletion() {
        let base = map(&[("K", "base")]);
        let ours: BTreeMap<String, Vec<u8>> = BTreeMap::new(); // ours deletes K
        let theirs = map(&[("K", "base")]); // theirs unchanged
        let out = three_way_merge(&base, &ours, &theirs);
        assert_eq!(out.get("K"), Some(&MergeEntry::Resolved(None)));
    }

    #[test]
    fn both_add_same_new_key_same_value_is_not_a_conflict() {
        let base: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let ours = map(&[("NEW", "v")]);
        let theirs = map(&[("NEW", "v")]);
        let out = three_way_merge(&base, &ours, &theirs);
        assert_eq!(out.get("NEW"), Some(&MergeEntry::Resolved(Some(b"v".to_vec()))));
    }

    #[test]
    fn both_add_same_new_key_different_values_is_a_conflict() {
        let base: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let ours = map(&[("NEW", "ours-value")]);
        let theirs = map(&[("NEW", "theirs-value")]);
        let out = three_way_merge(&base, &ours, &theirs);
        assert_eq!(
            out.get("NEW"),
            Some(&MergeEntry::Conflict {
                ours: Some(b"ours-value".to_vec()),
                theirs: Some(b"theirs-value".to_vec()),
            })
        );
    }

    #[test]
    fn unrelated_key_changes_on_both_sides_both_auto_merge_without_conflict() {
        let base = map(&[("A", "a0"), ("B", "b0")]);
        let ours = map(&[("A", "a1"), ("B", "b0")]);
        let theirs = map(&[("A", "a0"), ("B", "b1")]);
        let out = three_way_merge(&base, &ours, &theirs);
        assert_eq!(out.get("A"), Some(&MergeEntry::Resolved(Some(b"a1".to_vec()))));
        assert_eq!(out.get("B"), Some(&MergeEntry::Resolved(Some(b"b1".to_vec()))));
    }

    #[test]
    fn disjoint_histories_treat_base_as_empty_so_every_key_is_added() {
        // No merge_base at all (base is the empty map) -> both sides' values are "added".
        let base: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let ours = map(&[("OURS_ONLY", "x")]);
        let theirs = map(&[("THEIRS_ONLY", "y")]);
        let out = three_way_merge(&base, &ours, &theirs);
        assert_eq!(out.get("OURS_ONLY"), Some(&MergeEntry::Resolved(Some(b"x".to_vec()))));
        assert_eq!(out.get("THEIRS_ONLY"), Some(&MergeEntry::Resolved(Some(b"y".to_vec()))));
    }

    // ---- commit_merge --------------------------------------------------------------------------

    #[test]
    fn commit_merge_produces_a_two_parent_commit_that_log_can_walk() {
        let (_dir, store) = temp_store();
        let identity = new_identity(b"pass");
        let dek = new_dek();
        let a = author(&identity);

        let root = commit(&store, &dek, &identity, a, None, &WorkingSet::new(), "root").unwrap();
        let ours = commit(&store, &dek, &identity, a, Some(root), &WorkingSet::new(), "ours").unwrap();
        let theirs = commit(&store, &dek, &identity, a, Some(root), &WorkingSet::new(), "theirs").unwrap();

        let mut ws = WorkingSet::new();
        ws.set("K", b"merged".to_vec());
        let merge_hash = commit_merge(&store, &dek, &identity, a, [ours, theirs], &ws, "merge").unwrap();

        let merged_commit = load_commit(&store, &merge_hash).unwrap();
        assert_eq!(merged_commit.fields.parent_hashes, vec![ours, theirs]);

        // `log`'s mainline-follow fix (Phase 5b) must walk straight through without erroring.
        let history = crate::log(&store, merge_hash, |_| Some(identity.public().ed25519_pubkey)).unwrap();
        let hashes: Vec<Hash> = history.iter().map(|v| v.hash).collect();
        assert_eq!(hashes, vec![merge_hash, ours, root]);
    }
}
