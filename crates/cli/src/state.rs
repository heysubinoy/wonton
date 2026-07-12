//! Local VCS state: per-branch last-known tip and staging area, keyed by `org/store/branch` —
//! plus resolution of the on-disk object store directory.
//!
//! ## `state.toml` (`<data_local_dir>/wonton/state.toml`)
//! A single TOML file mirroring [`crate::config::Config`]'s load/save pattern. It holds **only
//! non-secret metadata**: plaintext key names (plaintext by design) and content
//! hashes (which address ciphertext blobs in the object store). No plaintext secret value and no
//! ciphertext bytes are ever stored inline here, satisfying the no-plaintext-on-disk invariant.
//!
//! A branch is now the top-level DEK/ACL unit (it replaces what used to be called an
//! "environment" — see `crate::config`'s module docs), so each entry here has exactly ONE tip,
//! not a `branch -> tip` map: there's nothing left to map over. This cache is global/per-machine
//! (shared across every directory bound to the same `org/store/branch`, harmless since objects
//! and tips are content-addressed ciphertext) — the *current* branch for a given directory lives
//! in that directory's `.wonton.local` file instead (`crate::config`), not here.
//!
//! ## Object store (`<data_local_dir>/wonton/objects/`)
//! One shared [`wonton_objects::LocalObjectStore`] across every branch — a single flat,
//! content-addressed namespace like git's, safe because blobs are ciphertext and objects are
//! content-addressed (no cross-branch collision risk).

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

/// The whole local VCS state: per-branch tip/staging, keyed by `"org/store/branch"`.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalState {
    #[serde(default)]
    pub branches: BTreeMap<String, BranchState>,
}

/// One branch's local VCS state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BranchState {
    /// The DEK version currently cached in the agent for this branch — the version of the
    /// wrapped-DEK entry last unwrapped (or self-granted at `init`/`branch -b` time). `0` means
    /// "never granted server-side yet" — `push`'s first-time-provisioning preamble checks this.
    /// `share` reads it to know which version it is granting a copy of; `key rotate` bumps it
    /// after a successful rotation.
    ///
    /// **Field order matters:** this scalar must precede the `staged` table — the `toml`
    /// serializer rejects a scalar emitted after a table.
    #[serde(default)]
    pub dek_version: u32,
    /// Last-known commit hash for this branch (local cache of the server ref; `pull` refreshes
    /// it, `push` advances it on success). `None` if never pulled/committed.
    #[serde(default)]
    pub tip: Option<Hash>,
    /// If this branch was created via `wonton branch -b <name> --from <source>`, the source
    /// branch's full key (`"org/store/branch"`) and the hash of the commit that seeded this
    /// branch's first commit (its root). `merge` uses this as the cross-DEK merge base — see
    /// `commands::merge`'s module doc for why a cryptographic `merge_base` walk can't cross a
    /// DEK boundary, but a recorded fork root can stand in for one.
    #[serde(default)]
    pub forked_from: Option<ForkedFrom>,
    /// Pending changes not yet committed: key name -> staged entry.
    #[serde(default)]
    pub staged: BTreeMap<String, StagedEntry>,
    /// A `wonton merge` paused on unresolved conflicts, resumed via `wonton merge --continue`.
    /// `None` when no merge is in progress. Holds only content hashes and key/branch names —
    /// never plaintext (reuses the exact hash-only mechanism `StagedEntry` already uses, instead
    /// of a plaintext-conflict-file approach, which would violate the no-plaintext-on-disk rule).
    #[serde(default)]
    pub merge: Option<MergeState>,
}

/// Where a branch was forked from, recorded once at `wonton branch -b --from` time. See
/// [`BranchState::forked_from`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkedFrom {
    /// The source branch's full key (`"org/store/branch"`).
    pub branch: String,
    /// This branch's own root commit (its first commit, seeded from the source's values at fork
    /// time, encrypted under this branch's own DEK) — the merge base for reconciling with the
    /// source branch later.
    pub root: Hash,
}

/// A merge paused mid-resolution: the two tips + their (possibly absent) common ancestor, and
/// whatever conflicts have/haven't yet been resolved. Every field is a content hash, key name, or
/// branch key — never plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeState {
    /// The full key (`"org/store/branch"`) of the branch being merged in ("theirs") — may be a
    /// different DEK than the current branch's; see `commands::merge`.
    pub branch: String,
    pub ours_tip: Hash,
    pub theirs_tip: Hash,
    /// The merge-base commit, or `None` for disjoint histories (the merge then proceeds against
    /// an empty base tree). For a `--from`-forked pair this is the forked branch's own root
    /// (`ForkedFrom::root`), decryptable under whichever side's DEK actually encrypted it.
    #[serde(default)]
    pub base: Option<Hash>,
    /// Key -> resolved entry for every conflicting key that has been settled so far (via the
    /// interactive prompt). See [`ResolvedEntry`] for why this isn't a plain `Option<Hash>`.
    #[serde(default)]
    pub resolved: BTreeMap<String, ResolvedEntry>,
    /// Key -> the still-conflicting (ours, theirs) blob hashes, not yet resolved.
    #[serde(default)]
    pub conflicts: BTreeMap<String, ConflictHashes>,
}

/// One key's resolved outcome in a paused/resumed merge. Mirrors [`StagedEntry`]'s adjacent
/// tagging, and for the same underlying reason: a plain `Option<Hash>` map value would work for
/// the `Set` case, but `toml_edit`'s inline-table serializer silently *drops* a `None` map value
/// on serialize instead of preserving it (verified empirically against `toml_edit` 0.22's
/// `SerializeInlineTable::serialize_value`, which treats the value's `Error::unsupported_none()`
/// as "just omit this entry"). That would make a resolved-to-deletion key indistinguishable from
/// "never resolved" after a save/load round trip, silently corrupting a paused merge's state. An
/// explicit tombstone variant round-trips exactly like `StagedEntry` already does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", content = "hash", rename_all = "lowercase")]
pub enum ResolvedEntry {
    /// Resolved to this blob hash (already agent-encrypted, already in the local object store —
    /// either an existing side's blob reused as-is, or a freshly-encrypted manual entry).
    Set(Hash),
    /// Resolved to a deletion: the key will be absent from the merge commit's tree.
    Delete,
}

/// The still-conflicting blob hashes for one key. `None` on a side means that side deleted the
/// key (the classic "one side deletes, the other modifies" conflict). Unlike [`ResolvedEntry`]
/// above, `Option<Hash>` is fine here: these are plain struct fields, not map values, so a `None`
/// field is simply omitted from the serialized table (the same precedent as
/// `Identity::session_token`), never silently dropped from a collection the way a map value would
/// be.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictHashes {
    #[serde(default)]
    pub ours: Option<Hash>,
    #[serde(default)]
    pub theirs: Option<Hash>,
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

    /// Borrow a branch's state, or `None` if it has none yet.
    pub fn branch(&self, key: &str) -> Option<&BranchState> {
        self.branches.get(key)
    }

    /// Mutably borrow a branch's state, inserting a default (no tip, empty) if absent.
    pub fn branch_mut(&mut self, key: &str) -> &mut BranchState {
        self.branches.entry(key.to_string()).or_default()
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
        let bs = state.branch_mut("acme/backend/main");
        bs.tip = Some(sample_hash(b"tip"));
        bs.staged.insert("API_KEY".to_string(), StagedEntry::Set(sample_hash(b"blob")));
        bs.staged.insert("OLD_KEY".to_string(), StagedEntry::Unset);
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
    fn branch_mut_defaults_to_no_tip() {
        let mut state = LocalState::default();
        assert_eq!(state.branch_mut("acme/backend/new").tip, None);
    }

    #[test]
    fn staged_entry_set_and_unset_round_trip_through_toml() {
        // A map with both variants must round-trip (the adjacently-tagged representation keeps
        // both as uniform TOML tables).
        let mut state = LocalState::default();
        let bs = state.branch_mut("acme/backend/dev");
        bs.staged.insert("SET".to_string(), StagedEntry::Set(sample_hash(b"h")));
        bs.staged.insert("UNSET".to_string(), StagedEntry::Unset);

        let toml = toml::to_string_pretty(&state).unwrap();
        let back: LocalState = toml::from_str(&toml).unwrap();
        assert_eq!(back, state);
        assert_eq!(
            back.branch("acme/backend/dev").unwrap().staged.get("SET"),
            Some(&StagedEntry::Set(sample_hash(b"h")))
        );
        assert_eq!(
            back.branch("acme/backend/dev").unwrap().staged.get("UNSET"),
            Some(&StagedEntry::Unset)
        );
    }

    /// The field-ordering constraint this file's doc comments already warn about: `merge` (an
    /// `Option` of a table-shaped type) must not break the TOML serializer when placed after the
    /// existing `staged` table. Also covers the `None`/empty-map cases explicitly.
    #[test]
    fn branch_state_round_trips_with_no_merge_in_progress() {
        let mut state = LocalState::default();
        state.branch_mut("acme/backend/dev").tip = Some(sample_hash(b"tip"));

        let toml = toml::to_string_pretty(&state).unwrap();
        assert!(
            !toml.contains("[branches.\"acme/backend/dev\".merge]"),
            "an absent merge must not appear at all, got:\n{toml}"
        );
        let back: LocalState = toml::from_str(&toml).unwrap();
        assert_eq!(back, state);
        assert_eq!(back.branch("acme/backend/dev").unwrap().merge, None);
    }

    /// A fully populated `MergeState` — including a resolved deletion (`ResolvedEntry::Delete`)
    /// and a delete-vs-modify conflict (`ConflictHashes { ours: None, .. }`) — round-trips through
    /// TOML exactly, and the serialized file holds only hex hashes / key names / branch keys,
    /// never plaintext.
    #[test]
    fn merge_state_round_trips_through_toml_including_none_and_tombstone_cases() {
        let dir = std::env::temp_dir().join(format!("wonton-state-merge-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("state.toml");

        let mut resolved = BTreeMap::new();
        resolved.insert("SET_KEY".to_string(), ResolvedEntry::Set(sample_hash(b"resolved-blob")));
        resolved.insert("DELETED_KEY".to_string(), ResolvedEntry::Delete);

        let mut conflicts = BTreeMap::new();
        conflicts.insert(
            "STILL_CONFLICTING".to_string(),
            ConflictHashes {
                ours: Some(sample_hash(b"ours-blob")),
                theirs: Some(sample_hash(b"theirs-blob")),
            },
        );
        conflicts.insert(
            "DELETE_VS_MODIFY".to_string(),
            ConflictHashes {
                ours: None,
                theirs: Some(sample_hash(b"theirs-blob-2")),
            },
        );

        let mut state = LocalState::default();
        let bs = state.branch_mut("acme/backend/main");
        bs.tip = Some(sample_hash(b"ours-tip"));
        bs.merge = Some(MergeState {
            branch: "acme/backend/feature".to_string(),
            ours_tip: sample_hash(b"ours-tip"),
            theirs_tip: sample_hash(b"theirs-tip"),
            base: Some(sample_hash(b"base-tip")),
            resolved,
            conflicts,
        });
        state.save_to(&path).unwrap();

        let loaded = LocalState::load_from(&path).unwrap();
        assert_eq!(loaded, state);

        let merge = loaded.branch("acme/backend/main").unwrap().merge.as_ref().unwrap();
        assert_eq!(merge.branch, "acme/backend/feature");
        assert_eq!(merge.resolved.get("DELETED_KEY"), Some(&ResolvedEntry::Delete));
        assert_eq!(
            merge.conflicts.get("DELETE_VS_MODIFY"),
            Some(&ConflictHashes { ours: None, theirs: Some(sample_hash(b"theirs-blob-2")) })
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
