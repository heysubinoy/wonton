use std::fs;
use std::path::{Path, PathBuf};

use crate::hash::Hash;
use crate::ObjectError;

/// A local, content-addressed object store: files are laid out git-style
/// (`<root>/<first-2-hex-chars>/<remaining-62-hex-chars>`) so no directory ever holds an
/// unreasonable number of entries. Every `put` verifies the caller's claimed hash matches
/// the bytes (mirrors the server-side rule in §7: reject a push whose hash doesn't match
/// its content) and every `get` re-verifies on the way out — a corrupted or tampered file
/// on disk must be detected, never silently returned (§12.3, fail closed).
pub struct LocalObjectStore {
    root: PathBuf,
}

impl LocalObjectStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, ObjectError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(ObjectError::Io)?;
        Ok(LocalObjectStore { root })
    }

    fn path_for(&self, hash: &Hash) -> PathBuf {
        let hex = hash.to_hex();
        self.root.join(&hex[0..2]).join(&hex[2..])
    }

    /// Store `bytes` under `hash`. Fails if `hash != BLAKE2b-256(bytes)` — callers must
    /// hash before calling, this just double-checks so a bug upstream can't silently
    /// corrupt the store.
    pub fn put(&self, hash: &Hash, bytes: &[u8]) -> Result<(), ObjectError> {
        let computed = Hash::of(bytes);
        if computed != *hash {
            return Err(ObjectError::HashMismatch {
                expected: hash.to_hex(),
                actual: computed.to_hex(),
            });
        }
        let path = self.path_for(hash);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(ObjectError::Io)?;
        }
        fs::write(path, bytes).map_err(ObjectError::Io)
    }

    /// Fetch bytes for `hash`, re-verifying the hash on the way out. A mismatch here means
    /// on-disk corruption or tampering and is reported, never silently served.
    pub fn get(&self, hash: &Hash) -> Result<Option<Vec<u8>>, ObjectError> {
        let path = self.path_for(hash);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(ObjectError::Io(e)),
        };
        let computed = Hash::of(&bytes);
        if computed != *hash {
            return Err(ObjectError::HashMismatch {
                expected: hash.to_hex(),
                actual: computed.to_hex(),
            });
        }
        Ok(Some(bytes))
    }

    pub fn contains(&self, hash: &Hash) -> bool {
        self.path_for(hash).exists()
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_stored_object() {
        let dir = tempdir();
        let store = LocalObjectStore::open(dir.path()).unwrap();
        let bytes = b"hello wonton".to_vec();
        let hash = Hash::of(&bytes);

        store.put(&hash, &bytes).unwrap();
        let fetched = store.get(&hash).unwrap().unwrap();
        assert_eq!(fetched, bytes);
        assert!(store.contains(&hash));
    }

    #[test]
    fn missing_object_returns_none() {
        let dir = tempdir();
        let store = LocalObjectStore::open(dir.path()).unwrap();
        let hash = Hash::of(b"never stored");
        assert!(store.get(&hash).unwrap().is_none());
    }

    #[test]
    fn put_rejects_mismatched_hash() {
        let dir = tempdir();
        let store = LocalObjectStore::open(dir.path()).unwrap();
        let wrong_hash = Hash::of(b"not the real content");
        let err = store.put(&wrong_hash, b"real content").unwrap_err();
        assert!(matches!(err, ObjectError::HashMismatch { .. }));
    }

    #[test]
    fn get_detects_on_disk_tampering() {
        let dir = tempdir();
        let store = LocalObjectStore::open(dir.path()).unwrap();
        let bytes = b"original content".to_vec();
        let hash = Hash::of(&bytes);
        store.put(&hash, &bytes).unwrap();

        // Simulate a hostile/corrupted filesystem by overwriting the stored bytes in place.
        let path = store.path_for(&hash);
        std::fs::write(&path, b"tampered content").unwrap();

        let err = store.get(&hash).unwrap_err();
        assert!(matches!(err, ObjectError::HashMismatch { .. }));
    }

    /// Minimal temp-dir helper so this crate doesn't need a `tempfile` dev-dependency for
    /// four tests.
    struct TempDir(PathBuf);
    impl TempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn tempdir() -> TempDir {
        let mut p = std::env::temp_dir();
        let unique = format!(
            "wonton-objects-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        );
        p.push(unique);
        fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}
