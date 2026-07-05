//! Content-addressed object model for Wonton (§5.2/§6 of PLAN.md): blob/tree/commit
//! structs, BLAKE2b-256 hashing, and a local on-disk object store. This crate never
//! decrypts anything and never holds key material — it only knows how to hash, serialize,
//! and store/retrieve opaque bytes plus their plaintext metadata (key names, timestamps,
//! parent links).

mod blob;
mod commit;
mod hash;
mod store;
mod tree;

pub use blob::Blob;
pub use commit::{Commit, CommitFields};
pub use hash::{Hash, HASH_LEN};
pub use store::LocalObjectStore;
pub use tree::Tree;

#[derive(Debug, thiserror::Error)]
pub enum ObjectError {
    #[error("invalid hash: {0}")]
    InvalidHash(String),
    #[error("hash mismatch: expected {expected}, computed {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("failed to serialize object: {0}")]
    Serialize(serde_json::Error),
    #[error("failed to deserialize object: {0}")]
    Deserialize(serde_json::Error),
    #[error("io error: {0}")]
    Io(std::io::Error),
}
