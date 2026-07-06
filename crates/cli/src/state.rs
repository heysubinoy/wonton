//! Local VCS state (PROGRESS.md §3.6): the per-context branch pointer, last-known ref tips, and
//! staging area — plus resolution of the on-disk object store directory.
//!
//! ## `state.toml` (`<data_local_dir>/wonton/state.toml`)
//! A single TOML file mirroring [`crate::config::Config`]'s load/save pattern. It holds **only
//! non-secret metadata**: plaintext key names (plaintext by design, PLAN.md §16) and content
//! hashes (which address ciphertext blobs in the object store). No plaintext secret value and no
//! ciphertext bytes are ever stored inline here, satisfying the no-plaintext-on-disk invariant
//! (PLAN.md §14).
//!
//! ## Object store (`<data_local_dir>/wonton/objects/`)
//! One shared [`wonton_objects::LocalObjectStore`] across every context/branch — a single flat,
//! content-addressed namespace like git's, safe because blobs are ciphertext and objects are
//! content-addressed (no cross-environment collision risk).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use directories::BaseDirs;
use serde::{Deserialize, Serialize};
use wonton_objects::Hash;

/// Errors loading or saving local VCS state. Mirrors [`crate::config::ConfigError`].
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// Could not determine the XDG data-local directory (no home directory).
    #[error("could not determine a data directory (no home directory)")]
    NoDataDir,
    /// Filesystem I/O failure reading/writing the state file.
    #[error("state i/o error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The on-disk state file was not valid TOML.
    #[error("state file at {path} is not valid TOML: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    /// Failed to serialize the state to TOML (should not happen for our own types).
    #[error("failed to serialize state: {0}")]
    Serialize(#[from] toml::ser::Error),
}

/// The whole local VCS state: per-context branch/tips/staging, keyed by `Context.name`.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalState {
    #[serde(default)]
    pub contexts: BTreeMap<String, ContextState>,
}

/// One context's local VCS state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextState {
    /// The current branch. Defaults to `"main"` on first `use`/`switch`.
    #[serde(default = "default_branch")]
    pub branch: String,
    /// The DEK version currently cached in the agent for this context — the version of the
    /// wrapped-DEK entry `use` unwrapped. `0` means "never granted / unknown". `share` reads it to
    /// know which version it is granting a copy of; `key rotate` bumps it after a successful
    /// rotation. `#[serde(default)]` so old `state.toml` files without this field still load as 0.
    ///
    /// **Field order matters:** this scalar must precede the `tips`/`staged` tables — the `toml`
    /// serializer rejects a scalar emitted after a table.
    #[serde(default)]
    pub dek_version: u32,
    /// Branch name -> last-known commit hash (local cache of the server ref; `pull` refreshes it,
    /// `push` advances it on success).
    #[serde(default)]
    pub tips: BTreeMap<String, Hash>,
    /// Pending changes not yet committed: key name -> staged entry.
    #[serde(default)]
    pub staged: BTreeMap<String, StagedEntry>,
}

fn default_branch() -> String {
    "main".to_string()
}

impl Default for ContextState {
    fn default() -> Self {
        ContextState {
            branch: default_branch(),
            dek_version: 0,
            tips: BTreeMap::new(),
            staged: BTreeMap::new(),
        }
    }
}

/// A pending staged change for one key. Adjacently tagged so both variants serialize as uniform
/// TOML tables (`{ op = "set", hash = "..." }` / `{ op = "unset" }`) — avoiding the mixed
/// string-vs-table value problem TOML has when an externally-tagged enum yields a bare string for
/// a unit variant next to a table for a newtype variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", content = "hash", rename_all = "lowercase")]
pub enum StagedEntry {
    /// `wonton set KEY=value`: the value is already agent-encrypted and `put` into the object
    /// store; this is that blob's hash.
    Set(Hash),
    /// `wonton unset KEY`: a staged deletion (tombstone).
    Unset,
}

impl LocalState {
    /// Load from an explicit path (used by tests). A missing file yields an empty default.
    pub fn load_from(path: &Path) -> Result<LocalState, StateError> {
        match std::fs::read_to_string(path) {
            Ok(contents) => toml::from_str(&contents).map_err(|source| StateError::Parse {
                path: path.to_path_buf(),
                source,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(LocalState::default()),
            Err(source) => Err(StateError::Io {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    /// Save to an explicit path. Writes to a sibling temp file and renames over the target, so a
    /// crash mid-write cannot corrupt existing state. Creates parent directories as needed.
    pub fn save_to(&self, path: &Path) -> Result<(), StateError> {
        let toml = toml::to_string_pretty(self)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| StateError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let tmp = path.with_extension(format!("toml.tmp.{}", std::process::id()));
        std::fs::write(&tmp, toml.as_bytes()).map_err(|source| StateError::Io {
            path: tmp.clone(),
            source,
        })?;
        std::fs::rename(&tmp, path).map_err(|source| StateError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    }

    /// Borrow a context's state, or `None` if it has none yet.
    pub fn context(&self, name: &str) -> Option<&ContextState> {
        self.contexts.get(name)
    }

    /// Mutably borrow a context's state, inserting a default (`branch = "main"`, empty) if absent.
    pub fn context_mut(&mut self, name: &str) -> &mut ContextState {
        self.contexts.entry(name.to_string()).or_default()
    }
}

/// The default state file path: `<data_local_dir>/wonton/state.toml`. Creates the `wonton`
/// directory if missing, mirroring [`crate::agent::default_socket_path`]'s convention.
pub fn default_state_path() -> anyhow::Result<PathBuf> {
    let dir = wonton_data_dir()?;
    Ok(dir.join("state.toml"))
}

/// The object-store directory co-located with `state_path`: `<state_dir>/objects/`. In production
/// `state_path` is `<data_local_dir>/wonton/state.toml`, so this resolves to
/// `<data_local_dir>/wonton/objects/` (the intended default); deriving it from `state_path` rather
/// than a separate default means a test that injects a temp `state_path` automatically gets an
/// isolated object store next to it. `LocalObjectStore::open` creates it if missing.
pub fn object_store_dir_for(state_path: &Path) -> PathBuf {
    state_path
        .parent()
        .map(|p| p.join("objects"))
        .unwrap_or_else(|| PathBuf::from("objects"))
}

/// Open (creating if needed) the shared local object store at `dir`.
pub fn open_object_store(dir: &Path) -> anyhow::Result<wonton_objects::LocalObjectStore> {
    Ok(wonton_objects::LocalObjectStore::open(dir)?)
}

/// `<data_local_dir>/wonton`, created if missing.
fn wonton_data_dir() -> anyhow::Result<PathBuf> {
    let base = BaseDirs::new().ok_or(StateError::NoDataDir)?;
    let dir = base.data_local_dir().join("wonton");
    std::fs::create_dir_all(&dir).map_err(|source| StateError::Io {
        path: dir.clone(),
        source,
    })?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hash(seed: &[u8]) -> Hash {
        Hash::of(seed)
    }

    #[test]
    fn state_round_trips_through_save_and_load() {
        let dir = std::env::temp_dir().join(format!("wonton-state-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("state.toml");

        let mut state = LocalState::default();
        let cs = state.context_mut("acme-dev");
        cs.branch = "main".to_string();
        cs.tips.insert("main".to_string(), sample_hash(b"tip"));
        cs.staged.insert("API_KEY".to_string(), StagedEntry::Set(sample_hash(b"blob")));
        cs.staged.insert("OLD_KEY".to_string(), StagedEntry::Unset);
        state.save_to(&path).unwrap();

        let loaded = LocalState::load_from(&path).unwrap();
        assert_eq!(loaded, state);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_state_file_loads_as_empty_default() {
        let path = std::env::temp_dir().join("wonton-nonexistent-state-xyz.toml");
        let _ = std::fs::remove_file(&path);
        let loaded = LocalState::load_from(&path).unwrap();
        assert_eq!(loaded, LocalState::default());
    }

    #[test]
    fn context_mut_defaults_branch_to_main() {
        let mut state = LocalState::default();
        assert_eq!(state.context_mut("new-ctx").branch, "main");
    }

    #[test]
    fn staged_entry_set_and_unset_round_trip_through_toml() {
        // A map with both variants must round-trip (the adjacently-tagged representation keeps
        // both as uniform TOML tables).
        let mut state = LocalState::default();
        let cs = state.context_mut("c");
        cs.staged.insert("SET".to_string(), StagedEntry::Set(sample_hash(b"h")));
        cs.staged.insert("UNSET".to_string(), StagedEntry::Unset);

        let toml = toml::to_string_pretty(&state).unwrap();
        let back: LocalState = toml::from_str(&toml).unwrap();
        assert_eq!(back, state);
        assert_eq!(
            back.context("c").unwrap().staged.get("SET"),
            Some(&StagedEntry::Set(sample_hash(b"h")))
        );
        assert_eq!(
            back.context("c").unwrap().staged.get("UNSET"),
            Some(&StagedEntry::Unset)
        );
    }
}
