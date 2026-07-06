//! # wonton-vcs
//!
//! The client-side git-like layer of Wonton (PLAN.md §6), Phase 2 scope: local commit
//! creation, verified history (`log`), and client-side key-level `diff`. Everything here
//! runs on the client *after* decryption — the blind server (PLAN.md §2/§7) never sees any
//! of it. There is deliberately **no ref/branch/config management yet** (that is Phase 4)
//! and **no server/sync** (Phase 3): this crate's API operates directly on commit [`Hash`]es
//! the caller already holds (e.g. "the previous tip", if any).
//!
//! ## What this crate guarantees
//! - **Fail closed on every read (PLAN.md §12.3).** Every object fetched from the store is
//!   hash-verified (the store does this on `get`; [`log`]/[`diff`] re-check the commit hash
//!   as defense in depth). [`log`] additionally verifies each commit's Ed25519 signature
//!   against the caller-supplied signer key and aborts the whole walk on the first failure —
//!   a bad commit is never skipped.
//! - **Never a byte-diff of ciphertext (PLAN.md §6).** [`diff`] treats equal blob hashes as
//!   "definitely unchanged" (a safe fast-path) but never treats *unequal* blob hashes as
//!   proof of change: re-encrypting identical plaintext yields a different blob every time
//!   (fresh random nonce), so [`diff`] decrypts both sides and compares plaintext before
//!   ever reporting a key as `Changed`.
//!
//! ## Phase-2 simplifications (temporary — see PROGRESS.md §8)
//! - **Placeholder author id.** `wonton-crypto` identities have no `Uuid`; Phase 2 has no
//!   user registry (that is Phase 3+). [`author_id_from_identity`] derives a *deterministic*
//!   UUIDv5 from the Ed25519 public key so the same identity always commits under the same
//!   id. Phase 3/4 replaces this with a real, server-assigned registered user id — the
//!   commit format does not change, only the source of the `Uuid`.
//! - **Single-signer `log`.** [`log`] takes one expected signer pubkey and verifies every
//!   commit in the history against it. Multi-author signer resolution via a user registry is
//!   a Phase 3/4 concern.
//! - **First-parent-only walk.** [`log`] follows `parent_hashes[0]` only and *errors* on any
//!   commit with 2+ parents ([`VcsError::MultiParentCommit`]) rather than silently picking a
//!   line. Full merge-graph traversal is a Phase 5 concern (merges do not exist yet).

mod commit;
mod diff;
mod log;
mod working_set;

#[cfg(test)]
mod testutil;

use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;
use wonton_crypto::{decrypt_value, encrypt_value, verify, CryptoError, Dek, EncryptedValue, PublicIdentity};
use wonton_objects::{Blob, Commit, Hash, LocalObjectStore, ObjectError, Tree};

pub use commit::commit;
pub use diff::{diff, DiffEntry};
pub use log::{log, VerifiedCommit};
pub use working_set::WorkingSet;

/// Encrypts a single plaintext value into an [`EncryptedValue`] with a fresh nonce. [`commit`]
/// is generic over this trait rather than taking a raw [`Dek`] directly, so a caller that must
/// never hold a raw DEK in its own process (e.g. the CLI, which only talks to `wonton-agent`)
/// can supply a per-value, agent-backed adapter instead. Implemented for [`Dek`] itself so every
/// existing offline caller (and every test in this crate) is unaffected.
///
/// Fallible (unlike the underlying local `encrypt_value`, which cannot fail): an agent-backed
/// implementation can fail closed on things a raw `Dek` never could — the agent being locked,
/// unreachable, or not holding a cached DEK for the requested context.
pub trait ValueEncryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedValue, VcsError>;
}

/// Decrypts a single [`EncryptedValue`], failing closed on a bad key/nonce/auth tag (or, for an
/// agent-backed implementation, a locked/unreachable agent). [`diff`] is generic over this trait
/// for the same reason [`commit`] is generic over [`ValueEncryptor`] — see its docs.
pub trait ValueDecryptor {
    fn decrypt(&self, value: &EncryptedValue) -> Result<Vec<u8>, VcsError>;
}

impl ValueEncryptor for Dek {
    fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedValue, VcsError> {
        Ok(encrypt_value(self, plaintext))
    }
}

impl ValueDecryptor for Dek {
    fn decrypt(&self, value: &EncryptedValue) -> Result<Vec<u8>, VcsError> {
        Ok(decrypt_value(self, value)?)
    }
}

/// Errors from every fallible path in this crate. Wraps the underlying [`ObjectError`] and
/// [`CryptoError`] (so a corrupted/tampered object on disk or a failed decrypt/verify
/// propagates as a clean `Err`, never a panic — PLAN.md §12.3) and adds VCS-specific cases.
#[derive(Debug, thiserror::Error)]
pub enum VcsError {
    /// An underlying object-store / (de)serialization failure. Notably, a
    /// [`ObjectError::HashMismatch`] surfaced here means on-disk tampering or corruption of a
    /// stored object and must be treated as hostile (PLAN.md §12.3), not swallowed.
    #[error(transparent)]
    Object(#[from] ObjectError),

    /// An underlying cryptographic failure: a failed value decryption
    /// ([`CryptoError::DecryptionFailed`]) or a failed commit-signature verification
    /// ([`CryptoError::SignatureInvalid`]). Either aborts the operation.
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    /// A commit hash was walked/requested but no object exists for it in the store.
    #[error("commit not found in store: {0}")]
    CommitNotFound(String),

    /// A commit referenced a tree hash that is absent from the store.
    #[error("tree not found in store: {0}")]
    TreeNotFound(String),

    /// A tree referenced a blob hash that is absent from the store.
    #[error("blob not found in store: {0}")]
    BlobNotFound(String),

    /// Defense-in-depth check failed: a fetched commit's recomputed hash did not equal the
    /// hash it was fetched by. The store already checks this on `get`; re-checking here makes
    /// this crate's integrity guarantee self-contained. Indicates tampering/corruption.
    #[error("commit hash mismatch: fetched by {expected}, recomputed {actual}")]
    HashMismatch { expected: String, actual: String },

    /// A stored commit's signature field was not exactly 64 bytes, so it cannot be a valid
    /// Ed25519 signature. Treated as a verification failure (fail closed), never a panic on
    /// the `try_into` (per the length-bridging note in the build spec).
    #[error("commit {hash} has a malformed signature: expected 64 bytes, got {actual}")]
    BadSignatureLength { hash: String, actual: usize },

    /// [`log`]'s first-parent walk reached a commit with 2+ parents (a merge commit). Phase 2
    /// deliberately refuses to silently pick a parent; full merge-graph traversal is Phase 5.
    #[error(
        "multi-parent (merge) commit {0} encountered during first-parent log walk; \
         merge-graph traversal is a Phase 5 concern"
    )]
    MultiParentCommit(String),
}

/// Derive the Phase-2 **placeholder** author id for an identity.
///
/// `wonton-crypto`'s [`PublicIdentity`] carries no `Uuid`, and Phase 2 has no user registry,
/// so we derive a *deterministic* UUIDv5 (no RNG) from the Ed25519 public key. The same
/// identity therefore always commits under the same id, and this can be swapped for a real
/// server-assigned registered user id in Phase 3/4 without changing the on-disk commit
/// format. **This is a temporary placeholder, not a permanent design decision.**
pub fn author_id_from_identity(public: &PublicIdentity) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_OID, &public.ed25519_pubkey)
}

/// Current wall-clock time as unix seconds (PLAN.md commit schema: `timestamp: i64`). Uses
/// `std::time` only (no `chrono`/`time` crate, per the build spec). A clock set before the
/// unix epoch yields `0` rather than erroring — the timestamp is descriptive metadata, not a
/// security boundary.
pub(crate) fn current_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Fetch a commit by hash and verify its content integrity (but **not** its signature — see
/// [`verify_commit_signature`] for that). Shared by [`log`] and [`diff`] so the fetch +
/// hash-recompute logic lives in exactly one place.
///
/// - `store.get` already re-verifies `hash == BLAKE2b(bytes)` and returns
///   [`ObjectError::HashMismatch`] on on-disk tampering — that propagates as an error here.
/// - We *additionally* recompute `commit.hash()` and compare (defense in depth), so this
///   crate's guarantee does not silently rely on the store's behavior.
pub(crate) fn load_commit(store: &LocalObjectStore, hash: &Hash) -> Result<Commit, VcsError> {
    let bytes = store
        .get(hash)?
        .ok_or_else(|| VcsError::CommitNotFound(hash.to_hex()))?;
    let commit = Commit::from_bytes(&bytes)?;
    let recomputed = commit.hash()?;
    if recomputed != *hash {
        return Err(VcsError::HashMismatch {
            expected: hash.to_hex(),
            actual: recomputed.to_hex(),
        });
    }
    Ok(commit)
}

/// Verify a commit's Ed25519 signature over `fields.signing_bytes()` against `signer_pubkey`.
///
/// Fails closed: a wrong-length signature becomes [`VcsError::BadSignatureLength`] (never a
/// panic on `try_into`), and a cryptographic verification failure becomes
/// [`CryptoError::SignatureInvalid`] wrapped in [`VcsError::Crypto`]. Callers must treat any
/// `Err` as fatal and never continue past a bad commit (PLAN.md §6/§12.3).
pub(crate) fn verify_commit_signature(
    commit: &Commit,
    commit_hash: &Hash,
    signer_pubkey: &[u8; 32],
) -> Result<(), VcsError> {
    let signature: [u8; 64] =
        commit
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| VcsError::BadSignatureLength {
                hash: commit_hash.to_hex(),
                actual: commit.signature.len(),
            })?;
    let message = commit.fields.signing_bytes()?;
    verify(signer_pubkey, &message, &signature)?;
    Ok(())
}

/// Fetch and deserialize the [`Tree`] pointed to by a (content-verified) commit.
pub(crate) fn load_tree_of_commit(
    store: &LocalObjectStore,
    commit_hash: &Hash,
) -> Result<Tree, VcsError> {
    let commit = load_commit(store, commit_hash)?;
    let tree_hash = commit.fields.tree_hash;
    let bytes = store
        .get(&tree_hash)?
        .ok_or_else(|| VcsError::TreeNotFound(tree_hash.to_hex()))?;
    Ok(Tree::from_bytes(&bytes)?)
}

/// Fetch a blob by hash and decrypt it via `dec`, bridging `wonton-objects`'s [`Blob`]
/// (nonce + ciphertext) to `wonton-crypto`'s structurally-identical [`EncryptedValue`]. Fails
/// closed on a missing blob, on-disk tampering (`store.get` re-verifies the hash), or an AEAD
/// authentication failure.
pub(crate) fn decrypt_blob(
    store: &LocalObjectStore,
    dec: &impl ValueDecryptor,
    blob_hash: &Hash,
) -> Result<Vec<u8>, VcsError> {
    let bytes = store
        .get(blob_hash)?
        .ok_or_else(|| VcsError::BlobNotFound(blob_hash.to_hex()))?;
    let blob = Blob::from_bytes(&bytes)?;
    let value = EncryptedValue {
        nonce: blob.nonce,
        ciphertext: blob.ciphertext,
    };
    dec.decrypt(&value)
}
