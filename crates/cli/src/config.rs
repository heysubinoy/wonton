//! Local CLI state: known identities (`~/.config/wonton/config.toml`) plus project discovery
//! via `wonton.toml` / `.wonton.local`.
//!
//! ## Config file (`~/.config/wonton/config.toml`)
//! A single TOML file holding the user's known [`Identity`]s. It caches the *ciphertext* wrapped
//! private key and Argon2id parameters (safe to store, like an OpenSSH encrypted private key
//! file) and a short-lived session bearer token, so most commands avoid a network round-trip. It
//! never stores the passphrase or any plaintext secret.
//!
//! ## `wonton.toml` — committed, minimal, the single source of truth for *where*
//! A project directory is bound to a store by a `wonton.toml` file at its root, meant to be
//! checked into git alongside the project:
//! ```toml
//! server = "https://wonton.example.com"
//! store = "acme/backend"     # "org/store"
//! ```
//! It intentionally does **not** name a branch — see `.wonton.local` below. Discovered by
//! walking upward from the cwd, exactly like git finds `.git`. Read fresh on every invocation:
//! there is **no shell-hook `cd` integration** (explicitly out of scope for v1) — the pragmatic
//! v1 behavior, matching how tools like `.nvmrc` are re-read per invocation rather than via a
//! resident shell hook.
//!
//! ## `.wonton.local` — uncommitted, per-directory, the current branch (git's `HEAD`)
//! A sibling file, next to `wonton.toml`, holding just `branch = "<name>"`. This is *not*
//! committed (should be gitignored) — it's the actual `.git/HEAD` equivalent: which branch
//! *this particular clone* is looking at. Two clones of the same `org/store` on one machine can
//! be on different branches simultaneously, exactly like two independent git clones. `wonton
//! branch <name>` rewrites it; `wonton pull`/`push`/etc. read it fresh every time, so hand-editing
//! it and running `wonton pull` pulls whatever branch is now named there.

use std::path::{Path, PathBuf};

use directories::BaseDirs;
use serde::{Deserialize, Serialize};

/// Errors loading or saving local CLI state.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Could not determine the XDG config directory (no home directory).
    #[error("could not determine a config directory (no home directory)")]
    NoConfigDir,
    /// Filesystem I/O failure reading/writing the config file.
    #[error("config i/o error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The on-disk config file was not valid TOML.
    #[error("config file at {path} is not valid TOML: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    /// Failed to serialize the config to TOML (should not happen for our own types).
    #[error("failed to serialize config: {0}")]
    Serialize(#[from] toml::ser::Error),
}

/// The whole local config: every identity ever logged in on this machine, plus optional
/// machine-wide defaults.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Fallback server URL used when a command needs one and none is given explicitly (currently
    /// just `login`, for a username that isn't already a known identity). Set via `wonton config
    /// set-server <url>`. A project's own `wonton.toml` always wins over this once one exists —
    /// this is only ever a bootstrapping convenience for commands with no project context yet.
    #[serde(default)]
    pub default_server: Option<String>,
    #[serde(default)]
    pub identities: Vec<Identity>,
}

/// A known identity: a local nickname bound to a server-facing username on one server, plus the
/// public keys and the *ciphertext* material needed to re-login on a warm or restarted agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// Local nickname. Defaults to `username` in this v1.
    pub name: String,
    /// Server-facing login handle.
    pub username: String,
    pub server_url: String,
    /// Server-assigned user id (from register / login_complete). Keys the wrapped-DEK map.
    pub user_id: String,
    pub ed25519_pubkey_b64: String,
    pub x25519_pubkey_b64: String,
    /// base64 of `nonce(24) || ciphertext` — the wrapped-privkey wire blob (see the module docs
    /// on the framing convention). Cached ciphertext, safe at rest; useless without the
    /// passphrase.
    pub wrapped_privkey_b64: String,
    pub argon2_salt_b64: String,
    pub argon2_m_cost_kib: u32,
    pub argon2_t_cost: u32,
    pub argon2_p_cost: u32,
    /// Cached session bearer token, so most commands skip re-authenticating every invocation.
    #[serde(default)]
    pub session_token: Option<String>,
    /// Unix-seconds expiry of `session_token`.
    #[serde(default)]
    pub session_expires_at: Option<i64>,
}

impl Config {
    /// Load from the default path (`~/.config/wonton/config.toml`). A missing file is not an
    /// error — it yields an empty default config.
    #[allow(dead_code)]
    pub fn load() -> Result<Config, ConfigError> {
        Self::load_from(&default_config_path()?)
    }

    /// Load from an explicit path (used by tests). A missing file yields an empty default.
    pub fn load_from(path: &Path) -> Result<Config, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(contents) => toml::from_str(&contents).map_err(|source| ConfigError::Parse {
                path: path.to_path_buf(),
                source,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(source) => Err(ConfigError::Io {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    /// Save to the default path. See [`Config::load`] on why this is the convenience wrapper.
    #[allow(dead_code)]
    pub fn save(&self) -> Result<(), ConfigError> {
        self.save_to(&default_config_path()?)
    }

    /// Save to an explicit path (used by tests). Writes to a sibling temp file and renames over
    /// the target, so a crash mid-write cannot corrupt an existing config. Creates parent
    /// directories as needed.
    pub fn save_to(&self, path: &Path) -> Result<(), ConfigError> {
        let toml = toml::to_string_pretty(self)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| ConfigError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        // A unique-enough temp name in the same directory (same filesystem => atomic rename).
        let tmp = path.with_extension(format!("toml.tmp.{}", std::process::id()));
        std::fs::write(&tmp, toml.as_bytes()).map_err(|source| ConfigError::Io {
            path: tmp.clone(),
            source,
        })?;
        std::fs::rename(&tmp, path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    }

    /// Find an identity by its local `name`.
    pub fn find_identity(&self, name: &str) -> Option<&Identity> {
        self.identities.iter().find(|i| i.name == name)
    }

    /// Insert `identity`, replacing any existing one with the same `name`.
    pub fn upsert_identity(&mut self, identity: Identity) {
        match self.identities.iter_mut().find(|i| i.name == identity.name) {
            Some(existing) => *existing = identity,
            None => self.identities.push(identity),
        }
    }
}

/// The default config file path: `<config_dir>/wonton/config.toml`.
pub fn default_config_path() -> Result<PathBuf, ConfigError> {
    let base = BaseDirs::new().ok_or(ConfigError::NoConfigDir)?;
    Ok(base.config_dir().join("wonton").join("config.toml"))
}

// ---- `wonton.toml` project discovery --------------------------------------------------

/// The parsed shape of a `wonton.toml` file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct WontonToml {
    pub server: String,
    /// `"org/store"`.
    pub store: String,
}

/// A resolved project: the directory `wonton.toml` was found in, plus its parsed fields split
/// into `org`/`store`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub dir: PathBuf,
    pub server: String,
    pub org: String,
    pub store: String,
}

fn parse_wonton_toml(contents: &str) -> Option<WontonToml> {
    toml::from_str(contents).ok()
}

/// Walk upward from `start` (like git finding `.git`) looking for a `wonton.toml` file. A
/// `store` field not of the form `"org/store"` (exactly one `/`), or a file that's unreadable /
/// malformed TOML, is skipped (treated as absent) rather than erroring — same policy as `.git`
/// discovery ignoring things that aren't really a `.git` dir.
pub fn find_project(start: &Path) -> Option<Project> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        let marker = d.join("wonton.toml");
        if marker.is_file() {
            if let Ok(contents) = std::fs::read_to_string(&marker) {
                if let Some(w) = parse_wonton_toml(&contents) {
                    if let Some((org, store)) = w.store.split_once('/') {
                        if !org.is_empty() && !store.is_empty() && !store.contains('/') {
                            return Some(Project {
                                dir: d.to_path_buf(),
                                server: w.server,
                                org: org.to_string(),
                                store: store.to_string(),
                            });
                        }
                    }
                }
            }
        }
        dir = d.parent();
    }
    None
}

/// Read a `wonton.toml` file directly (no upward walk, no org/store split). Returns `None` if
/// unreadable or malformed. Used by `init`'s overwrite guard.
pub fn read_wonton_toml(path: &Path) -> Option<WontonToml> {
    std::fs::read_to_string(path).ok().and_then(|c| parse_wonton_toml(&c))
}

/// Write `wonton.toml` at `path` (`server` + `store = "org/store"`).
pub fn write_wonton_toml(path: &Path, server: &str, org: &str, store: &str) -> std::io::Result<()> {
    std::fs::write(path, format!("server = \"{server}\"\nstore = \"{org}/{store}\"\n"))
}

// ---- `.wonton.local` per-directory branch pointer --------------------------------------

#[derive(Deserialize, Serialize)]
struct LocalMarker {
    branch: String,
}

/// Read the current branch from `.wonton.local` next to `wonton.toml` in `project_dir`. `None`
/// if absent, unreadable, or malformed.
pub fn read_local_branch(project_dir: &Path) -> Option<String> {
    let contents = std::fs::read_to_string(project_dir.join(".wonton.local")).ok()?;
    toml::from_str::<LocalMarker>(&contents).ok().map(|m| m.branch)
}

/// Write `.wonton.local`'s `branch` field in `project_dir`. Not gitignore-aware itself — callers
/// (`init`/`branch -b`) print a reminder to gitignore it.
pub fn write_local_branch(project_dir: &Path, branch: &str) -> std::io::Result<()> {
    std::fs::write(project_dir.join(".wonton.local"), format!("branch = \"{branch}\"\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_identity(name: &str) -> Identity {
        Identity {
            name: name.to_string(),
            username: name.to_string(),
            server_url: "http://localhost:9999".to_string(),
            user_id: "uid-123".to_string(),
            ed25519_pubkey_b64: "ed".to_string(),
            x25519_pubkey_b64: "x".to_string(),
            wrapped_privkey_b64: "wrapped".to_string(),
            argon2_salt_b64: "salt".to_string(),
            argon2_m_cost_kib: 19456,
            argon2_t_cost: 2,
            argon2_p_cost: 1,
            session_token: Some("tok".to_string()),
            session_expires_at: Some(123),
        }
    }

    #[test]
    fn config_round_trips_through_save_and_load() {
        let dir = std::env::temp_dir().join(format!("wonton-cfg-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("config.toml");

        let mut config = Config::default();
        config.upsert_identity(sample_identity("alice"));
        config.save_to(&path).unwrap();

        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(loaded, config);
        assert_eq!(loaded.find_identity("alice"), Some(&sample_identity("alice")));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_config_file_loads_as_empty_default() {
        let path = std::env::temp_dir().join("wonton-nonexistent-config-xyz.toml");
        let _ = std::fs::remove_file(&path);
        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(loaded, Config::default());
    }

    #[test]
    fn default_server_round_trips_through_save_and_load() {
        let dir = std::env::temp_dir().join(format!("wonton-cfg-defserver-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("config.toml");

        assert_eq!(Config::load_from(&path).unwrap().default_server, None);

        let mut config = Config::load_from(&path).unwrap();
        config.default_server = Some("https://wonton.example.com".to_string());
        config.save_to(&path).unwrap();

        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(loaded.default_server, Some("https://wonton.example.com".to_string()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn upsert_replaces_by_name() {
        let mut config = Config::default();
        config.upsert_identity(sample_identity("alice"));
        let mut updated = sample_identity("alice");
        updated.user_id = "uid-999".to_string();
        config.upsert_identity(updated);
        assert_eq!(config.identities.len(), 1);
        assert_eq!(config.find_identity("alice").unwrap().user_id, "uid-999");
    }

    #[test]
    fn wonton_toml_is_found_walking_up_from_a_deeper_cwd() {
        let root = std::env::temp_dir().join(format!("wonton-project-test-{}", std::process::id()));
        let deep = root.join("a").join("b").join("c");
        std::fs::create_dir_all(&deep).unwrap();
        write_wonton_toml(&root.join("wonton.toml"), "https://wonton.example.com", "acme", "backend").unwrap();

        let found = find_project(&deep).unwrap();
        assert_eq!(found.dir, root);
        assert_eq!(found.org, "acme");
        assert_eq!(found.store, "backend");
        assert_eq!(found.server, "https://wonton.example.com");

        let found_at_root = find_project(&root).unwrap();
        assert_eq!(found_at_root.dir, root);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn no_wonton_toml_anywhere_resolves_to_none() {
        let empty = std::env::temp_dir().join(format!("wonton-project-empty-{}", std::process::id()));
        std::fs::create_dir_all(&empty).unwrap();
        assert_eq!(find_project(&empty), None);
        let _ = std::fs::remove_dir_all(&empty);
    }

    #[test]
    fn local_branch_round_trips_and_defaults_to_absent() {
        let root = std::env::temp_dir().join(format!("wonton-local-branch-test-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();

        assert_eq!(read_local_branch(&root), None);
        write_local_branch(&root, "feature-x").unwrap();
        assert_eq!(read_local_branch(&root), Some("feature-x".to_string()));

        // Hand-editing it (simulating a user directly editing the file) takes effect immediately
        // — read_local_branch always reads fresh, no caching.
        write_local_branch(&root, "main").unwrap();
        assert_eq!(read_local_branch(&root), Some("main".to_string()));

        let _ = std::fs::remove_dir_all(&root);
    }
}
