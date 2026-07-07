//! The one error type for `wonton-sync`.
//!
//! HTTP status codes from the server are mapped to distinct variants
//! so a caller can react precisely: retry after login on [`SyncError::Unauthorized`], ask for a
//! grant on [`SyncError::Forbidden`], reconcile a race on [`SyncError::Conflict`], etc. The
//! catch-all [`SyncError::ServerError`] preserves the raw status + parsed `{"error": ...}`
//! message for anything unmapped.

use reqwest::StatusCode;
use wonton_objects::ObjectError;
use wonton_shared::RefConflict;

/// Everything that can go wrong talking to a `wonton-server`.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// 401 — missing, invalid, or expired bearer token.
    #[error("unauthorized (401): missing, invalid, or expired token")]
    Unauthorized,

    /// 403 — the token is valid but the caller's role is insufficient for this route.
    #[error("forbidden (403): insufficient role for this operation")]
    Forbidden,

    /// 404 — the addressed object / ref / environment does not exist. Carries the server message.
    #[error("not found (404): {0}")]
    NotFound(String),

    /// 400 — the server rejected the request (e.g. a hash/content mismatch on upload, or a
    /// ref move to an object it has never seen). Carries the server message.
    #[error("bad request (400): {0}")]
    BadRequest(String),

    /// 409 — a compare-and-swap ref move lost the race; `current` is the ref's actual value
    /// (or `None` if it does not exist). Only produced by the ref-move route. The caller should
    /// pull, merge (Phase 5), and retry — this crate never auto-clobbers.
    #[error("ref move conflict (409): remote tip is now {:?}", .0.current)]
    Conflict(RefConflict),

    /// A pulled object's bytes did not hash to the value they were fetched by. This
    /// aborts the sync and flags a possibly-hostile (or buggy) server — the mismatch is
    /// never silently accepted. This is *content-hash* integrity only; authorship/signature
    /// verification of pulled commits is a separate concern (`wonton_vcs::log`).
    #[error(
        "content-hash mismatch fetching object: requested {requested}, \
         server returned bytes hashing to {actual} — aborting, possibly hostile server"
    )]
    IntegrityMismatch { requested: String, actual: String },

    /// `push` was asked to upload an object that isn't in the local store. This is a caller
    /// bug (the object should have been committed locally first), not a server condition.
    #[error("local object {0} not present in store (commit it locally before pushing)")]
    LocalObjectMissing(String),

    /// `pull`'s first-parent walk reached a commit with 2+ parents (a merge). Multi-parent
    /// traversal is a Phase 5 concern (mirrors `wonton_vcs::log`'s restriction); refuse rather
    /// than silently pick a line.
    #[error(
        "multi-parent (merge) commit {0} encountered during pull walk; \
         merge-graph traversal is a Phase 5 concern"
    )]
    MultiParentCommit(String),

    /// A transport-level failure (DNS, connection, timeout, body read, JSON decode of a
    /// success body, ...).
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),

    /// An object-layer failure: (de)serializing a commit/tree, a bad hex hash, or a
    /// `LocalObjectStore` read/write (including its own on-disk hash re-verification).
    #[error(transparent)]
    Object(#[from] ObjectError),

    /// Any other non-success status, with the raw code and the parsed server message.
    #[error("server error ({0}): {1}")]
    ServerError(StatusCode, String),
}

impl SyncError {
    /// Whether this is a generic HTTP 409 (`ApiError::Conflict`, e.g. "store already exists" /
    /// "environment already exists") as opposed to the ref-move-specific
    /// [`SyncError::Conflict`] variant, which carries structured CAS data instead of a plain
    /// message. Lets a caller treat "already exists" as an idempotent no-op without matching on
    /// `reqwest::StatusCode` directly.
    pub fn is_already_exists(&self) -> bool {
        matches!(self, SyncError::ServerError(status, _) if status.as_u16() == 409)
    }
}
