//! `pull` — fetch missing history for a branch's remote tip, verify every object, store it
//! locally, and report whether the result is a clean fast-forward or a divergence that a human
//! must reconcile. This crate never auto-clobbers a divergence.
//!
//! ## Integrity boundary (read this)
//! `pull` guarantees **content-hash integrity**: every object it stores was fetched via
//! [`SyncClient::fetch_object`], which verifies `Hash::of(bytes) == requested_hash`, and is then
//! re-verified by `LocalObjectStore::put`. It does **not** verify commit *signatures* /
//! authorship — that requires `wonton-crypto`, which this crate deliberately cannot depend on.
//! Signature verification of the pulled history is a separate, already-built concern
//! (`wonton_vcs::log`) that the CLI orchestration layer must run *after* a pull completes. Do
//! not mistake a successful `pull` for a fully-verified history.
//!
//! ## Divergence detection is a simplification
//! `pull` decides fast-forward-vs-diverged with a **first-parent-only** walk and treats a
//! commit with 2+ parents as an error ([`SyncError::MultiParentCommit`]), matching
//! `wonton_vcs::log`. It does not compute a real merge-base / LCA (that arrives with the
//! Phase 5 three-way merge). Its only job is to detect "cannot fast-forward, a merge step is
//! needed" without clobbering local work.

use wonton_objects::{Commit, Hash, LocalObjectStore, Tree};

use crate::client::SyncClient;
use crate::error::SyncError;

/// The result of a [`pull`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PullOutcome {
    /// Nothing to do: the branch is absent remotely, or the remote tip already equals
    /// `local_tip`.
    UpToDate,
    /// The remote tip is a descendant of `local_tip` (or `local_tip` was `None`, a full clone).
    /// All newly-discovered objects have been fetched, verified, and stored; the caller may now
    /// advance its ref to `new_tip`.
    FastForward { new_tip: Hash },
    /// `local_tip` is not on the remote tip's first-parent history, so this cannot be a
    /// fast-forward. Newly-discovered remote objects were still fetched and stored (they are
    /// harmless content-addressed bytes), but the caller must merge (Phase 5) rather than
    /// advance the ref.
    Diverged { local_tip: Hash, remote_tip: Hash },
}

/// Pull `branch` of `(repo, env)` into `store`, given the caller's current `local_tip` (its
/// ref value for this branch, or `None` if it has none / this is a clone).
///
/// See the module docs for the integrity boundary and the divergence-detection simplification.
pub async fn pull(
    client: &SyncClient,
    store: &LocalObjectStore,
    repo: &str,
    env: &str,
    branch: &str,
    local_tip: Option<Hash>,
) -> Result<PullOutcome, SyncError> {
    let refs = client.get_refs(repo, env).await?;
    let remote_tip = match refs.get(branch) {
        Some(hex) => Hash::from_hex(hex)?,
        // The branch does not exist remotely: there is nothing to pull. Whether or not the
        // caller has a local tip, the result is "nothing to fetch" — report UpToDate.
        None => return Ok(PullOutcome::UpToDate),
    };

    // Already there — don't fetch anything.
    if local_tip == Some(remote_tip) {
        return Ok(PullOutcome::UpToDate);
    }

    // How the backward first-parent walk from `remote_tip` terminated.
    enum Stop {
        /// Reached `local_tip` — it is an ancestor of `remote_tip` (clean fast-forward).
        Local,
        /// Reached a commit already in the local store (dedup boundary), which is NOT
        /// `local_tip`. Whether this is a fast-forward depends on a local ancestry check.
        Known(Hash),
        /// Reached a root commit (0 parents) without meeting `local_tip`.
        Root,
    }

    let mut current = remote_tip;
    let stop = loop {
        if local_tip == Some(current) {
            break Stop::Local;
        }
        // Stop the network walk as soon as we reach something we already have: content-
        // addressed objects are transitively complete, so we already hold everything below it.
        if store.contains(&current) {
            break Stop::Known(current);
        }
        // Fetch + verify + store this commit and everything it references, then follow its
        // (single) parent.
        let commit = fetch_and_store_commit(client, store, &current).await?;
        let parents = &commit.fields.parent_hashes;
        if parents.len() >= 2 {
            return Err(SyncError::MultiParentCommit(current.to_hex()));
        }
        match parents.first() {
            Some(parent) => current = *parent,
            None => break Stop::Root,
        }
    };

    Ok(match stop {
        Stop::Local => PullOutcome::FastForward {
            new_tip: remote_tip,
        },
        Stop::Root => match local_tip {
            // Full clone: nothing local to protect, so walking to the root is a fast-forward.
            None => PullOutcome::FastForward {
                new_tip: remote_tip,
            },
            // We walked remote's whole first-parent history and never met local_tip: diverged.
            Some(local_tip) => PullOutcome::Diverged {
                local_tip,
                remote_tip,
            },
        },
        Stop::Known(boundary) => match local_tip {
            None => PullOutcome::FastForward {
                new_tip: remote_tip,
            },
            // We stopped at an object we already had. It is a fast-forward iff local_tip is on
            // that boundary's own (already-local) first-parent history. This local-only check
            // keeps the "stop at what we already have" network optimization while still
            // deciding fast-forward-vs-diverged correctly.
            Some(local_tip) => {
                if local_first_parent_reaches(store, boundary, &local_tip)? {
                    PullOutcome::FastForward {
                        new_tip: remote_tip,
                    }
                } else {
                    PullOutcome::Diverged {
                        local_tip,
                        remote_tip,
                    }
                }
            }
        },
    })
}

/// Fetch a commit (verifying its hash), store it, then fetch+store its tree and every blob the
/// tree references (skipping ones already present). Returns the deserialized commit so the
/// caller can follow its parent link.
async fn fetch_and_store_commit(
    client: &SyncClient,
    store: &LocalObjectStore,
    hash: &Hash,
) -> Result<Commit, SyncError> {
    let bytes = client.fetch_object(hash).await?;
    store.put(hash, &bytes)?;
    let commit = Commit::from_bytes(&bytes)?;

    let tree = fetch_and_store_tree(client, store, &commit.fields.tree_hash).await?;
    for blob_hash in tree.entries.values() {
        if !store.contains(blob_hash) {
            let blob_bytes = client.fetch_object(blob_hash).await?;
            store.put(blob_hash, &blob_bytes)?;
        }
    }
    Ok(commit)
}

/// Fetch+store a tree if absent (or read it back if already present), returning it deserialized.
async fn fetch_and_store_tree(
    client: &SyncClient,
    store: &LocalObjectStore,
    hash: &Hash,
) -> Result<Tree, SyncError> {
    if let Some(bytes) = store.get(hash)? {
        return Ok(Tree::from_bytes(&bytes)?);
    }
    let bytes = client.fetch_object(hash).await?;
    store.put(hash, &bytes)?;
    Ok(Tree::from_bytes(&bytes)?)
}

/// First-parent walk **in the local store** from `from`, returning whether `target` is reached.
/// Used to classify a dedup-boundary stop as fast-forward or diverged without any network I/O.
/// Errors on a merge commit (consistent with the pull walk) or a missing object.
fn local_first_parent_reaches(
    store: &LocalObjectStore,
    from: Hash,
    target: &Hash,
) -> Result<bool, SyncError> {
    let mut current = from;
    loop {
        if current == *target {
            return Ok(true);
        }
        let bytes = match store.get(&current)? {
            Some(b) => b,
            None => return Ok(false),
        };
        let commit = Commit::from_bytes(&bytes)?;
        if commit.fields.parent_hashes.len() >= 2 {
            return Err(SyncError::MultiParentCommit(current.to_hex()));
        }
        match commit.fields.parent_hashes.first() {
            Some(parent) => current = *parent,
            None => return Ok(false),
        }
    }
}
