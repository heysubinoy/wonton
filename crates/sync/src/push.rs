//! `push` — upload a caller-selected set of local objects, then compare-and-swap the branch
//! ref from `old_hash` to `new_hash` (PLAN.md §9).
//!
//! Which objects to upload is the *caller's* decision (e.g. the set discovered by walking local
//! history since the last known remote tip — orchestration that belongs to the CLI, not here).
//! `push` just reads each from the store, declares its kind, and uploads it, then moves the ref.

use wonton_objects::{Commit, Hash, LocalObjectStore, Tree};

use crate::client::SyncClient;
use crate::error::SyncError;

/// Upload `object_hashes` (read from `store`) and then CAS-move `branch` of `(repo, env)` from
/// `old_hash` to `new_hash`.
///
/// - Uploads are idempotent server-side, so re-pushing an object the server already has is
///   harmless. This crate does **not** check existence first (there is no bulk-exists endpoint;
///   see PROGRESS.md open items for the possible future optimization) — it simply re-uploads.
/// - A lost CAS is surfaced as [`SyncError::Conflict`] carrying the ref's actual current value,
///   so the caller can pull-then-merge-then-retry (Phase 5). `push` never resolves the conflict
///   or clobbers the ref itself.
// The 8-argument signature is fixed by the Phase 3 sync spec (repo/env/branch coordinates +
// object set + CAS old/new tips); grouping them into a struct would only obscure a stable,
// deliberately-explicit public API.
#[allow(clippy::too_many_arguments)]
pub async fn push(
    client: &SyncClient,
    store: &LocalObjectStore,
    repo: &str,
    env: &str,
    branch: &str,
    object_hashes: &[Hash],
    old_hash: Option<Hash>,
    new_hash: Hash,
) -> Result<(), SyncError> {
    for hash in object_hashes {
        let bytes = store
            .get(hash)?
            .ok_or_else(|| SyncError::LocalObjectMissing(hash.to_hex()))?;
        let kind = sniff_kind(&bytes);
        client.upload_object(hash, kind, &bytes).await?;
    }
    client
        .move_ref(repo, env, branch, old_hash.as_ref(), &new_hash)
        .await
}

/// Client-side object-kind detection. The wire format (a JSON-serialized `Blob`/`Tree`/`Commit`)
/// does not self-describe its kind, but the server's upload route requires the caller to declare
/// one. We sniff it by attempting the most-specific deserializations first: a `Commit` (has
/// `fields` + `signature`), then a `Tree` (has `entries`), else fall back to `"blob"`. The three
/// shapes have disjoint required fields, so this is unambiguous — a pragmatic heuristic, not a
/// self-describing format (noted in PROGRESS.md open items).
fn sniff_kind(bytes: &[u8]) -> &'static str {
    if Commit::from_bytes(bytes).is_ok() {
        "commit"
    } else if Tree::from_bytes(bytes).is_ok() {
        "tree"
    } else {
        "blob"
    }
}
