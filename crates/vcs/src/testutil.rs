//! Shared test-only helpers (compiled only under `#[cfg(test)]`). Kept in one place so the
//! `commit` / `log` / `diff` test modules don't each re-derive a temp store, an identity, and
//! the store's on-disk path layout.

use std::fs;
use std::path::PathBuf;

use wonton_crypto::{generate_dek, generate_identity, unlock, Dek, UnlockedIdentity};
use wonton_objects::{Hash, LocalObjectStore};

/// A self-cleaning temporary directory (avoids a `tempfile` dev-dependency, mirroring the
/// pattern already used in `wonton-objects`'s store tests). Held alive by the test; dropping
/// it removes the backing store.
pub(crate) struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Create a unique temp dir plus a `LocalObjectStore` rooted in it. The `TempDir` is returned
/// so the caller can keep it alive for the test's duration (dropping it deletes the store).
pub(crate) fn temp_store() -> (TempDir, LocalObjectStore) {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "wonton-vcs-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    fs::create_dir_all(&p).unwrap();
    let store = LocalObjectStore::open(p.clone()).unwrap();
    (TempDir(p), store)
}

/// Generate and unlock a fresh identity under `passphrase`.
pub(crate) fn new_identity(passphrase: &[u8]) -> UnlockedIdentity {
    let (_public, wrapped) = generate_identity(passphrase);
    unlock(&wrapped, passphrase).unwrap()
}

/// A fresh random DEK.
pub(crate) fn new_dek() -> Dek {
    generate_dek()
}

/// Overwrite a stored object's bytes in place, simulating a hostile/corrupted disk. Reuses
/// the store's git-style `<root>/<hex[0..2]>/<hex[2..]>` layout. The written bytes will no
/// longer match `hash`, so the store's re-verification on `get` must reject them.
pub(crate) fn tamper_object(store: &LocalObjectStore, hash: &Hash, bytes: &[u8]) {
    let hex = hash.to_hex();
    let path = store.root().join(&hex[0..2]).join(&hex[2..]);
    fs::write(path, bytes).unwrap();
}
