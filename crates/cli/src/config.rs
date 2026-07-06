//! Local CLI state (PLAN.md §8.1) — the kubeconfig-style config file plus `.wonton` marker
//! discovery.
//!
//! ## Config file (`~/.config/wonton/config.toml`)
//! A single TOML file (kubeconfig-style) holding the user's known [`Identity`]s and
//! [`Context`]s and which context is current. It caches the *ciphertext* wrapped private key
//! and Argon2id parameters (safe to store, like an OpenSSH encrypted private key file — see
//! PLAN.md §12.4/§8.1) and a short-lived session bearer token, so most commands avoid a network
//! round-trip. It never stores the passphrase or any plaintext secret.
//!
//! ## `.wonton` marker
//! A project directory can be bound to a context by a `.wonton` TOML file (`context = "<name>"`).
//! It is discovered by walking upward from the cwd, exactly like git finds `.git`. This is read
//! fresh on every invocation: there is **no shell-hook `cd` integration** (explicitly out of
//! scope for v1) — the pragmatic v1 behavior, matching how tools like `.nvmrc` are re-read per
//! invocation rather than via a resident shell hook.
//!
//! ## Context resolution order (for any command needing "the current context")
//! 1. An explicit CLI flag (not yet added — a later task's commands will).
//! 2. The `.wonton` marker, if present in the cwd or any ancestor.
//! 3. `config.current_context`.
//! 4. Otherwise an error telling the user to `wonton use` or `wonton link`.

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

/// The whole local config: known identities, known contexts, and the current selection.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub identities: Vec<Identity>,
    #[serde(default)]
    pub contexts: Vec<Context>,
    #[serde(default)]
    pub current_context: Option<String>,
}

/// A known identity: a local nickname bound to a server-facing username on one server, plus the
/// public keys and the *ciphertext* material needed to re-login on a warm or restarted agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// Local nickname (referenced by `Context.identity`). Defaults to `username` in this v1.
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

/// A named context: the `store/environment` tuple plus which identity reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Context {
    pub name: String,
    pub store: String,
    pub environment: String,
    /// References an [`Identity::name`].
    pub identity: String,
}

impl Config {
    /// Load from the default path (`~/.config/wonton/config.toml`). A missing file is not an
    /// error — it yields an empty default config.
    ///
    /// The command layer resolves the path once and uses [`Config::load_from`]/[`Config::save_to`]
    /// directly (so tests can inject a temp path); this default-path convenience wrapper is part
    /// of the public API for callers that don't need that injection point.
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

    /// Find a context by name.
    pub fn find_context(&self, name: &str) -> Option<&Context> {
        self.contexts.iter().find(|c| c.name == name)
    }

    /// Insert `identity`, replacing any existing one with the same `name`.
    pub fn upsert_identity(&mut self, identity: Identity) {
        match self.identities.iter_mut().find(|i| i.name == identity.name) {
            Some(existing) => *existing = identity,
            None => self.identities.push(identity),
        }
    }

    /// Insert `context`, replacing any existing one with the same `name`.
    pub fn upsert_context(&mut self, context: Context) {
        match self.contexts.iter_mut().find(|c| c.name == context.name) {
            Some(existing) => *existing = context,
            None => self.contexts.push(context),
        }
    }
}

/// The default config file path: `<config_dir>/wonton/config.toml`.
pub fn default_config_path() -> Result<PathBuf, ConfigError> {
    let base = BaseDirs::new().ok_or(ConfigError::NoConfigDir)?;
    Ok(base.config_dir().join("wonton").join("config.toml"))
}

// ---- `.wonton` marker discovery -------------------------------------------------------

/// Parse a `.wonton` marker's TOML for its single `context` field.
fn parse_marker(contents: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct Marker {
        context: String,
    }
    toml::from_str::<Marker>(contents).ok().map(|m| m.context)
}

/// Walk upward from `start` (like git finding `.git`) looking for a `.wonton` file; return the
/// context name it names, if any. Unreadable or malformed markers are skipped (treated as
/// absent) rather than erroring.
pub fn find_wonton_context(start: &Path) -> Option<String> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        let marker = d.join(".wonton");
        if marker.is_file() {
            if let Ok(contents) = std::fs::read_to_string(&marker) {
                if let Some(ctx) = parse_marker(&contents) {
                    return Some(ctx);
                }
            }
        }
        dir = d.parent();
    }
    None
}

/// Read the context named by a `.wonton` marker file directly (no upward walk). Returns `None`
/// if the file is unreadable or malformed. Used by `link` to detect an existing marker.
pub fn read_marker_file(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok().and_then(|c| parse_marker(&c))
}

/// Resolve the current context *name* per the resolution order in the module docs (excluding
/// the not-yet-implemented explicit CLI flag): `.wonton` marker in an ancestor of `cwd`, else
/// `config.current_context`, else an error.
pub fn resolve_context_name(config: &Config, cwd: &Path) -> anyhow::Result<String> {
    if let Some(ctx) = find_wonton_context(cwd) {
        return Ok(ctx);
    }
    if let Some(ctx) = &config.current_context {
        return Ok(ctx.clone());
    }
    anyhow::bail!("no current context; run `wonton use <context>` or `wonton link <context>` first")
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

    fn sample_context(name: &str, identity: &str) -> Context {
        Context {
            name: name.to_string(),
            store: "acme".to_string(),
            environment: "dev".to_string(),
            identity: identity.to_string(),
        }
    }

    #[test]
    fn config_round_trips_through_save_and_load() {
        let dir = std::env::temp_dir().join(format!("wonton-cfg-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("config.toml");

        let mut config = Config::default();
        config.upsert_identity(sample_identity("alice"));
        config.upsert_context(sample_context("acme-dev", "alice"));
        config.current_context = Some("acme-dev".to_string());
        config.save_to(&path).unwrap();

        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(loaded, config);
        assert_eq!(loaded.find_identity("alice"), Some(&sample_identity("alice")));
        assert_eq!(
            loaded.find_context("acme-dev"),
            Some(&sample_context("acme-dev", "alice"))
        );

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
    fn wonton_marker_is_found_walking_up_from_a_deeper_cwd() {
        let root = std::env::temp_dir().join(format!("wonton-marker-test-{}", std::process::id()));
        let deep = root.join("a").join("b").join("c");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(root.join(".wonton"), "context = \"my-ctx\"\n").unwrap();

        assert_eq!(find_wonton_context(&deep), Some("my-ctx".to_string()));
        assert_eq!(find_wonton_context(&root), Some("my-ctx".to_string()));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn resolution_order_prefers_marker_over_current_context() {
        let root = std::env::temp_dir().join(format!("wonton-res-test-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(".wonton"), "context = \"from-marker\"\n").unwrap();

        let mut config = Config {
            current_context: Some("from-config".to_string()),
            ..Default::default()
        };
        assert_eq!(resolve_context_name(&config, &root).unwrap(), "from-marker");

        // With no marker, falls back to current_context.
        let empty = std::env::temp_dir().join(format!("wonton-res-empty-{}", std::process::id()));
        std::fs::create_dir_all(&empty).unwrap();
        assert_eq!(resolve_context_name(&config, &empty).unwrap(), "from-config");

        // With neither, it errors.
        config.current_context = None;
        assert!(resolve_context_name(&config, &empty).is_err());

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&empty);
    }
}
