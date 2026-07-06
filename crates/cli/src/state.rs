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
    /// A `wonton merge` paused on unresolved conflicts, resumed via `wonton merge --continue`.
    /// `None` when no merge is in progress. Holds only content hashes and key/branch names —
    /// never plaintext (PROGRESS.md §3.8: reuses the exact hash-only mechanism `StagedEntry`
    /// already uses, instead of PLAN.md §6's plaintext-conflict-file suggestion, which would
    /// violate rule #5).
    #[serde(default)]
    pub merge: Option<MergeState>,
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
            merge: None,
        }
    }
}

/// A merge paused mid-resolution: the two tips + their (possibly absent) common ancestor, and
/// whatever conflicts have/haven't yet been resolved. Every field is a content hash, key name, or
/// branch name — never plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeState {
    /// The branch being merged in ("theirs").
    pub branch: String,
    pub ours_tip: Hash,
    pub theirs_tip: Hash,
    /// The merge-base commit, or `None` for disjoint histories (the merge then proceeds against
    /// an empty base tree).
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

    /// The field-ordering constraint this file's doc comments already warn about: `merge` (an
    /// `Option` of a table-shaped type) must not break the TOML serializer when placed after the
    /// existing `tips`/`staged` tables. Also covers the `None`/empty-map cases explicitly.
    #[test]
    fn context_state_round_trips_with_no_merge_in_progress() {
        let mut state = LocalState::default();
        state.context_mut("acme-dev").tips.insert("main".to_string(), sample_hash(b"tip"));

        let toml = toml::to_string_pretty(&state).unwrap();
        assert!(
            !toml.contains("[contexts.acme-dev.merge]"),
            "an absent merge must not appear at all, got:\n{toml}"
        );
        let back: LocalState = toml::from_str(&toml).unwrap();
        assert_eq!(back, state);
        assert_eq!(back.context("acme-dev").unwrap().merge, None);
    }

    /// A fully populated `MergeState` — including a resolved deletion (`ResolvedEntry::Delete`)
    /// and a delete-vs-modify conflict (`ConflictHashes { ours: None, .. }`) — round-trips through
    /// TOML exactly, and the serialized file holds only hex hashes / key names / branch names,
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
        let cs = state.context_mut("acme-dev");
        cs.tips.insert("main".to_string(), sample_hash(b"ours-tip"));
        cs.merge = Some(MergeState {
            branch: "feature".to_string(),
            ours_tip: sample_hash(b"ours-tip"),
            theirs_tip: sample_hash(b"theirs-tip"),
            base: Some(sample_hash(b"base-tip")),
            resolved,
            conflicts,
        });
        state.save_to(&path).unwrap();

        let loaded = LocalState::load_from(&path).unwrap();
        assert_eq!(loaded, state);

        let merge = loaded.context("acme-dev").unwrap().merge.as_ref().unwrap();
        assert_eq!(merge.branch, "feature");
        assert_eq!(merge.resolved.get("DELETED_KEY"), Some(&ResolvedEntry::Delete));
        assert_eq!(
            merge.conflicts.get("DELETE_VS_MODIFY"),
            Some(&ConflictHashes { ours: None, theirs: Some(sample_hash(b"theirs-blob-2")) })
        );

        // No plaintext byte anywhere in the file: every non-structural token is either hex (a
        // `Hash`'s hex encoding is 64 lowercase hex chars) or one of the key/branch names we
        // supplied ourselves above.
        let contents = std::fs::read_to_string(&path).unwrap();
        for token in contents.split(['=', '"', '\n', ' ', '.', '[', ']']) {
            let token = token.trim();
            if token.is_empty() || token.ends_with(':') {
                continue;
            }
            let is_hex_hash = token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit());
            let is_known_plaintext_metadata = matches!(
                token,
                "contexts" | "acme-dev" | "branch" | "main" | "feature" | "dek_version" | "tips"
                    | "staged" | "merge" | "ours_tip" | "theirs_tip" | "base" | "resolved"
                    | "conflicts" | "op" | "hash" | "set" | "delete" | "ours" | "theirs"
                    | "SET_KEY" | "DELETED_KEY" | "STILL_CONFLICTING" | "DELETE_VS_MODIFY" | "0"
            );
            assert!(
                is_hex_hash || is_known_plaintext_metadata,
                "unexpected token '{token}' in state.toml (possible plaintext leak):\n{contents}"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
