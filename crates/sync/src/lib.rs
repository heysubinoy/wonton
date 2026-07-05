//! # wonton-sync
//!
//! The client half of Wonton's sync protocol (PLAN.md §9): a typed REST client for the blind
//! `wonton-server`, plus [`pull`] / [`push`] built on top of it.
//!
//! ## What this crate is (and is not) responsible for
//! `wonton-sync` **moves opaque bytes**. It deliberately does **not** depend on `wonton-crypto`
//! (the documented dependency-direction rule: "sync moves opaque bytes only") and never
//! decrypts a value, unwraps a DEK, or verifies an authorship signature. It *does* deserialize
//! `Commit`/`Tree` objects to walk the DAG — that is plaintext structural metadata (hashes,
//! parent links, key names), none of which is secret (PLAN.md §3 "accepted leakage").
//!
//! ### Integrity: content-hash, not authorship
//! The integrity guarantee here is exactly PLAN.md §9's "every pulled object is verified before
//! use": [`SyncClient::fetch_object`] checks `Hash::of(bytes) == requested_hash` before
//! returning, and [`pull`] additionally re-verifies via `LocalObjectStore::put`. A mismatch
//! aborts and reports a possibly-hostile server. This is **content-hash integrity** — every
//! object is exactly what its hash claims. It is **not** authorship verification: checking each
//! commit's Ed25519 signature requires `wonton-crypto` and is a separate, already-built concern
//! (`wonton_vcs::log`) that the CLI orchestration layer runs after a pull. Do not mistake this
//! crate for doing complete verification alone.
//!
//! ## Surface
//! - [`SyncClient`] — one method per server route, mapping status codes to [`SyncError`].
//! - [`pull`] / [`PullOutcome`] — fetch + verify + store missing history; report fast-forward
//!   vs. diverged (first-parent-only; not a full merge-base computation — Phase 5).
//! - [`push`] — upload objects, then CAS-move the ref; surface a 409 as [`SyncError::Conflict`].

mod client;
mod error;
mod pull;
mod push;

pub use client::SyncClient;
pub use error::SyncError;
pub use pull::{pull, PullOutcome};
pub use push::push;
