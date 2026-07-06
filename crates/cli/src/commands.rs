//! The identity / context-switching commands (PLAN.md §8): `login`, `context add|list`,
//! `context` (show), `use`, and `link`.
//!
//! Each command's *logic* is a free function taking explicit `config_path` / `socket_path` /
//! `cwd` arguments (rather than resolving the real defaults itself), so integration tests can
//! drive it against a temp config, an in-process agent daemon over a temp socket, and a real
//! `wonton-server`. The thin `main.rs` handlers resolve the real defaults and call these.
//!
//! ## Wrapped-privkey wire framing (the convention this task owns — keep it consistent)
//! The server treats the wrapped private key as one opaque blob. Both register and login here
//! frame it as **`base64(nonce(24) || ciphertext)`**, with the Argon2id params carried
//! separately. The agent reconstructs a `wonton_crypto::WrappedPrivateKey` from that same
//! framing internally, so the CLI never re-derives it in two places — register builds the blob,
//! login forwards whatever the server hands back unchanged.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use anyhow::{anyhow, bail, Context as _};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use uuid::Uuid;
use wonton_crypto::{generate_identity, EncryptedValue};
use wonton_objects::{Blob, Commit, Hash, LocalObjectStore, Tree};
use wonton_shared::{
    Argon2ParamsDto, GrantKeyRequest, LoginCompleteRequest, LoginStartRequest, MemberRequest,
    ObjectUploadRequest, RegisterRequest, Role, RotateRequest,
};
use wonton_sync::{PullOutcome, SyncClient, SyncError};
use wonton_vcs::{DiffEntry, ValueDecryptor, ValueEncryptor, WorkingSet};

use crate::agent::cipher::AgentCipher;
use crate::agent::client as agent;
use crate::agent::protocol::Argon2ParamsWire;
use crate::config::{self, Config, Context, Identity};
use crate::state::{object_store_dir_for, open_object_store, LocalState, StagedEntry};

/// `wonton login <username>`. Registers on first use of a username, unlocks the agent, completes
/// a challenge-response login, and caches the session token + wrapped-key material in the config.
///
/// `passphrase` is consumed (moved into the agent login call and dropped there); it is never
/// cached. `server_url` may be omitted if the identity already exists in config with a stored
/// server URL.
pub async fn login(
    config_path: &Path,
    socket_path: &Path,
    server_url: Option<String>,
    username: &str,
    passphrase: String,
) -> anyhow::Result<()> {
    let mut config = Config::load_from(config_path)?;

    // Local nickname == username in this v1 (no separate `--name` flag).
    let name = username;
    let existing = config.find_identity(name).cloned();
    let server_url = server_url
        .or_else(|| existing.as_ref().map(|i| i.server_url.clone()))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "--server <url> is required the first time you log in as '{username}'"
            )
        })?;

    let client = SyncClient::new(&server_url);

    // Step 2: resolve the wrapped-privkey blob + Argon2 params + a challenge nonce. A 404 from
    // login_start means the username is unknown -> first-time registration.
    let (wrapped_privkey_b64, params_dto, challenge_nonce) = match client
        .login_start(&LoginStartRequest {
            username: username.to_string(),
        })
        .await
    {
        Ok(start) => (start.wrapped_privkey, start.argon2_params, start.challenge_nonce),
        Err(SyncError::NotFound(_)) => {
            // First-time registration: generate a fresh identity locally and frame the blob.
            let (public, wrapped) = generate_identity(passphrase.as_bytes());
            let blob = [wrapped.nonce.as_slice(), wrapped.ciphertext.as_slice()].concat();
            let wrapped_b64 = STANDARD.encode(&blob);
            let params_dto = Argon2ParamsDto {
                salt: STANDARD.encode(wrapped.argon2_params.salt),
                m_cost_kib: wrapped.argon2_params.m_cost_kib,
                t_cost: wrapped.argon2_params.t_cost,
                p_cost: wrapped.argon2_params.p_cost,
            };
            client
                .register(&RegisterRequest {
                    username: username.to_string(),
                    ed25519_pubkey: STANDARD.encode(public.ed25519_pubkey),
                    x25519_pubkey: STANDARD.encode(public.x25519_pubkey),
                    wrapped_privkey: wrapped_b64.clone(),
                    argon2_params: params_dto.clone(),
                })
                .await
                .context("registration failed")?;
            // login_complete still needs a signed challenge; fetch one now that the user exists.
            let start = client
                .login_start(&LoginStartRequest {
                    username: username.to_string(),
                })
                .await
                .context("login_start after register failed")?;
            (wrapped_b64, params_dto, start.challenge_nonce)
        }
        Err(e) => return Err(e).context("login_start failed"),
    };

    // Step 3: hand the wrapped key + passphrase to the agent to unlock (passphrase moved in).
    let params_wire = Argon2ParamsWire {
        salt_b64: params_dto.salt.clone(),
        m_cost_kib: params_dto.m_cost_kib,
        t_cost: params_dto.t_cost,
        p_cost: params_dto.p_cost,
    };
    agent::login(
        socket_path,
        wrapped_privkey_b64.clone(),
        params_wire,
        passphrase,
    )
    .await
    .context("agent unlock failed (wrong passphrase?)")?;

    // Step 4: have the agent sign the challenge nonce. `challenge_nonce` is already base64 of the
    // raw nonce bytes, which is exactly the base64 message the agent's `sign` expects.
    let signature_b64 = agent::sign(socket_path, challenge_nonce.clone())
        .await
        .context("agent failed to sign the login challenge")?;

    // Step 5: complete the login and cache the session + key material.
    let complete = client
        .login_complete(&LoginCompleteRequest {
            username: username.to_string(),
            challenge_nonce,
            signature: signature_b64,
        })
        .await
        .context("login_complete failed")?;

    // Public keys come from the agent (authoritative for both the register and existing-user
    // paths — login_start doesn't return them).
    let pubkeys = agent::public_identity(socket_path)
        .await
        .context("could not read the agent's public identity")?;

    let server_display = server_url.clone();
    config.upsert_identity(Identity {
        name: name.to_string(),
        username: username.to_string(),
        server_url,
        user_id: complete.user_id,
        ed25519_pubkey_b64: pubkeys.ed25519_pubkey_b64,
        x25519_pubkey_b64: pubkeys.x25519_pubkey_b64,
        wrapped_privkey_b64,
        argon2_salt_b64: params_dto.salt,
        argon2_m_cost_kib: params_dto.m_cost_kib,
        argon2_t_cost: params_dto.t_cost,
        argon2_p_cost: params_dto.p_cost,
        session_token: Some(complete.token),
        session_expires_at: Some(complete.expires_at),
    });
    config.save_to(config_path)?;

    println!("Logged in as '{name}' (username '{username}') on {server_display}.");
    Ok(())
}

/// `wonton context add <name> --store --env --identity`. Validates the identity exists, then
/// appends/updates the context. No network or agent interaction.
pub fn context_add(
    config_path: &Path,
    name: &str,
    store: &str,
    environment: &str,
    identity: &str,
) -> anyhow::Result<()> {
    let mut config = Config::load_from(config_path)?;
    if config.find_identity(identity).is_none() {
        bail!("no identity named '{identity}'; run `wonton login <username>` first");
    }
    config.upsert_context(Context {
        name: name.to_string(),
        store: store.to_string(),
        environment: environment.to_string(),
        identity: identity.to_string(),
    });
    config.save_to(config_path)?;
    println!("Context '{name}' added ({store}@{environment}, identity '{identity}').");
    Ok(())
}

/// `wonton context list`. Prints every configured context, marking the current one.
pub fn context_list(config_path: &Path) -> anyhow::Result<()> {
    let config = Config::load_from(config_path)?;
    if config.contexts.is_empty() {
        println!("No contexts configured. Add one with `wonton context add`.");
        return Ok(());
    }
    for c in &config.contexts {
        let current = config.current_context.as_deref() == Some(c.name.as_str());
        let marker = if current { "*" } else { " " };
        println!(
            "{marker} {} -> {}@{} (identity: {})",
            c.name, c.store, c.environment, c.identity
        );
    }
    Ok(())
}

/// `wonton context` (no subcommand). Resolves and prints the current context and whether the
/// agent currently holds a cached DEK for it. Does not auto-start the agent.
pub async fn context_show(config_path: &Path, socket_path: &Path, cwd: &Path) -> anyhow::Result<()> {
    let config = Config::load_from(config_path)?;
    let name = config::resolve_context_name(&config, cwd)?;
    let ctx = config
        .find_context(&name)
        .ok_or_else(|| anyhow::anyhow!("current context '{name}' is not in the config"))?;

    // Best-effort: if the agent isn't running, report "no" rather than erroring.
    let cached = match agent::status(socket_path).await {
        Ok(status) => status.cached_contexts.contains(&ctx.name),
        Err(_) => false,
    };

    println!("Context: {}", ctx.name);
    println!("  store:       {}", ctx.store);
    println!("  environment: {}", ctx.environment);
    println!("  identity:    {}", ctx.identity);
    println!("  DEK cached:  {}", if cached { "yes" } else { "no" });
    Ok(())
}

/// `wonton use <name>`. Switches the current context, unwrapping the environment's DEK into the
/// agent the first time (cheap on subsequent uses once cached). This is the Phase 4 exit
/// criterion: "switching context unwraps the right DEK".
pub async fn use_context(
    config_path: &Path,
    state_path: &Path,
    socket_path: &Path,
    name: &str,
) -> anyhow::Result<()> {
    let mut config = Config::load_from(config_path)?;
    let ctx = config
        .find_context(name)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no context named '{name}'; add one with `wonton context add`"))?;
    let identity = config
        .find_identity(&ctx.identity)
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "context '{name}' references unknown identity '{}'",
                ctx.identity
            )
        })?;

    // Step 2: the agent must be unlocked for this identity.
    let status = agent::status(socket_path).await.map_err(|_| {
        anyhow::anyhow!(
            "agent is not running; run `wonton login {}` first",
            identity.username
        )
    })?;
    if !status.unlocked {
        bail!("agent is locked; run `wonton login {}` first", identity.username);
    }
    // Guard against a different identity being resident (its unwrap would just fail closed, but a
    // clear message is friendlier).
    if let Ok(keys) = agent::public_identity(socket_path).await {
        if keys.x25519_pubkey_b64 != identity.x25519_pubkey_b64 {
            bail!(
                "the agent is unlocked for a different identity; run `wonton login {}` first",
                identity.username
            );
        }
    }

    // Step 3: already cached -> cheap switch, no network.
    if status.cached_contexts.contains(&ctx.name) {
        config.current_context = Some(ctx.name.clone());
        config.save_to(config_path)?;
        println!(
            "Switched to context '{}' ({}@{}) [already cached].",
            ctx.name, ctx.store, ctx.environment
        );
        return Ok(());
    }

    // Step 4: fetch the wrapped-DEK map and find this identity's entry.
    let mut client = SyncClient::new(&identity.server_url);
    if let Some(token) = &identity.session_token {
        client.set_token(token);
    }
    let keys = match client.list_keys(&ctx.store, &ctx.environment).await {
        Ok(k) => k,
        // A non-member gets 403 before ever seeing the map — same user-facing meaning.
        Err(SyncError::Forbidden) => {
            bail!("you don't have access to {}@{}", ctx.store, ctx.environment)
        }
        Err(SyncError::Unauthorized) => bail!(
            "your session for '{}' has expired; run `wonton login {}` again",
            identity.name,
            identity.username
        ),
        Err(e) => return Err(e).context("could not fetch the environment's wrapped-DEK map"),
    };

    let entry = keys
        .get(&identity.user_id)
        .and_then(|entries| entries.iter().max_by_key(|e| e.dek_version))
        .ok_or_else(|| anyhow::anyhow!("you don't have access to {}@{}", ctx.store, ctx.environment))?;

    // `sealed_box` is already base64 on the wire; forward it straight to the agent, which
    // unwraps it with the resident X25519 secret and caches the DEK under the context name.
    let dek_version = entry.dek_version;
    agent::unwrap_dek(socket_path, ctx.name.clone(), entry.sealed_box.clone())
        .await
        .context("agent could not unwrap the DEK for this environment")?;

    // Persist the version we just unwrapped so `share`/`rotate` know what version this context's
    // cached DEK is (they can't ask the agent — the raw DEK never leaves it).
    let mut state = LocalState::load_from(state_path)?;
    state.context_mut(&ctx.name).dek_version = dek_version;
    state.save_to(state_path)?;

    // Step 5: record the selection.
    config.current_context = Some(ctx.name.clone());
    config.save_to(config_path)?;
    println!(
        "Switched to context '{}' ({}@{}); DEK unwrapped into the agent.",
        ctx.name, ctx.store, ctx.environment
    );
    Ok(())
}

/// `wonton link <name>`. Binds the current directory to a context by writing a `.wonton` marker.
/// Idempotent for the same context; refuses to overwrite a marker naming a *different* one.
pub fn link(config_path: &Path, cwd: &Path, name: &str) -> anyhow::Result<()> {
    let config = Config::load_from(config_path)?;
    if config.find_context(name).is_none() {
        bail!("no context named '{name}'; add one with `wonton context add` first");
    }
    let marker = cwd.join(".wonton");
    if marker.exists() {
        match config::read_marker_file(&marker) {
            Some(existing) if existing == name => {
                println!(".wonton already links this directory to '{name}'.");
                return Ok(());
            }
            Some(existing) => bail!(
                ".wonton already exists here linking to '{existing}'; refusing to overwrite it \
                 (remove it first to relink)"
            ),
            None => bail!(
                "a .wonton file already exists here but is unreadable/malformed; refusing to \
                 overwrite it"
            ),
        }
    }
    std::fs::write(&marker, format!("context = \"{name}\"\n"))
        .with_context(|| format!("writing {}", marker.display()))?;
    println!("Linked this directory to context '{name}' (wrote .wonton).");
    Ok(())
}

// =====================================================================================
// Phase 4c: the VCS porcelain (switch/status/set/unset/commit/log/diff/pull/push/run/export)
//
// Every command below operates on a caller-resolved *current context* (`main.rs` resolves the
// name via `config::resolve_context_name` and passes it as `ctx_name`; there is no `--context`
// flag in v1). None of them ever holds a raw `Dek` or `UnlockedIdentity`: all encrypt/decrypt/
// sign goes through the agent socket via [`AgentCipher`]. `state.toml` holds only key names and
// content hashes — never plaintext or ciphertext bytes.
// =====================================================================================

/// The output format for `wonton export`. Only dotenv is supported in v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Dotenv,
}

impl ExportFormat {
    /// Parse the `--format` flag. Errors clearly on an unsupported value.
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "dotenv" | "env" => Ok(ExportFormat::Dotenv),
            other => bail!("unsupported export format '{other}'; only 'dotenv' is supported"),
        }
    }
}

/// Resolve a context + its identity from config, requiring the agent to be unlocked for that
/// identity and holding a cached DEK for the context. Mirrors `use_context`'s guard style so the
/// failure message always points the user at `wonton use`.
async fn ready_context(
    config: &Config,
    socket_path: &Path,
    ctx_name: &str,
) -> anyhow::Result<(Context, Identity)> {
    let ctx = config
        .find_context(ctx_name)
        .cloned()
        .ok_or_else(|| anyhow!("no context named '{ctx_name}'; add one with `wonton context add`"))?;
    let identity = config
        .find_identity(&ctx.identity)
        .cloned()
        .ok_or_else(|| anyhow!("context '{ctx_name}' references unknown identity '{}'", ctx.identity))?;

    let status = agent::status(socket_path)
        .await
        .map_err(|_| anyhow!("agent is not running; run `wonton use {ctx_name}` first"))?;
    if !status.unlocked || !status.cached_contexts.contains(&ctx.name) {
        bail!("no DEK cached for context '{ctx_name}'; run `wonton use {ctx_name}` first");
    }
    Ok((ctx, identity))
}

/// `wonton switch <branch>` — purely local: set the current context's branch. No DEK unwrap, no
/// network. This is the Phase-4 exit criterion "switching branch needs no unwrap".
pub fn switch(state_path: &Path, ctx_name: &str, branch: &str) -> anyhow::Result<()> {
    let mut state = LocalState::load_from(state_path)?;
    state.context_mut(ctx_name).branch = branch.to_string();
    state.save_to(state_path)?;
    println!("Switched context '{ctx_name}' to branch '{branch}'.");
    Ok(())
}

/// `wonton status` — print context, branch, DEK-cached status, and the staged working-tree diff.
pub async fn status(
    config_path: &Path,
    state_path: &Path,
    socket_path: &Path,
    ctx_name: &str,
) -> anyhow::Result<()> {
    let config = Config::load_from(config_path)?;
    let ctx = config
        .find_context(ctx_name)
        .ok_or_else(|| anyhow!("no context named '{ctx_name}'"))?;
    let state = LocalState::load_from(state_path)?;
    let cs = state.context(ctx_name).cloned().unwrap_or_default();
    let branch = cs.branch.clone();

    // Best-effort DEK-cached check (report "no" if the agent isn't running).
    let cached = match agent::status(socket_path).await {
        Ok(s) => s.cached_contexts.contains(&ctx.name),
        Err(_) => false,
    };

    println!("Context: {ctx_name}");
    println!("  store:       {}", ctx.store);
    println!("  environment: {}", ctx.environment);
    println!("  branch:      {branch}");
    println!("  DEK cached:  {}", if cached { "yes" } else { "no" });

    // Staged diff markers, computed WITHOUT decrypting (just key-name presence in the tip tree).
    let store = open_object_store(&object_store_dir_for(state_path))?;
    let tip = cs.tips.get(&branch).copied();
    let tip_tree = tip.map(|h| tree_of_commit(&store, h)).transpose().unwrap_or(None).unwrap_or_default();
    if cs.staged.is_empty() {
        println!("  staged:      (nothing staged)");
    } else {
        println!("  staged:");
        for (key, entry) in &cs.staged {
            let marker = match entry {
                StagedEntry::Set(_) if tip_tree.entries.contains_key(key) => '~',
                StagedEntry::Set(_) => '+',
                StagedEntry::Unset => '-',
            };
            println!("    {marker}{key}");
        }
    }
    Ok(())
}

/// `wonton set KEY=VALUE ...` — agent-encrypt each value, store the blob locally, stage it.
pub async fn set(
    config_path: &Path,
    state_path: &Path,
    socket_path: &Path,
    ctx_name: &str,
    pairs: Vec<(String, String)>,
) -> anyhow::Result<()> {
    let config = Config::load_from(config_path)?;
    let (ctx, _identity) = ready_context(&config, socket_path, ctx_name).await?;
    let store = open_object_store(&object_store_dir_for(state_path))?;
    let cipher = AgentCipher::new(socket_path, ctx.name.clone());

    let mut state = LocalState::load_from(state_path)?;
    let cs = state.context_mut(&ctx.name);
    let count = pairs.len();
    for (key, value) in pairs {
        let encrypted = cipher.encrypt(value.as_bytes())?;
        let blob = Blob::new(encrypted.nonce, encrypted.ciphertext);
        let blob_bytes = blob.to_bytes()?;
        let blob_hash = Hash::of(&blob_bytes);
        store.put(&blob_hash, &blob_bytes)?;
        cs.staged.insert(key, StagedEntry::Set(blob_hash));
    }
    state.save_to(state_path)?;
    println!("Staged {count} value(s) in context '{ctx_name}'.");
    Ok(())
}

/// `wonton unset KEY ...` — stage a tombstone for each key. Purely local (no agent/crypto).
pub fn unset(
    config_path: &Path,
    state_path: &Path,
    ctx_name: &str,
    keys: Vec<String>,
) -> anyhow::Result<()> {
    // Validate the context exists for a friendly error; no crypto/network needed.
    let config = Config::load_from(config_path)?;
    if config.find_context(ctx_name).is_none() {
        bail!("no context named '{ctx_name}'; add one with `wonton context add`");
    }
    let mut state = LocalState::load_from(state_path)?;
    let cs = state.context_mut(ctx_name);
    let count = keys.len();
    for key in keys {
        cs.staged.insert(key, StagedEntry::Unset);
    }
    state.save_to(state_path)?;
    println!("Staged deletion of {count} key(s) in context '{ctx_name}'.");
    Ok(())
}

/// `wonton commit -m <message>` — build the effective working set from the current tip plus the
/// staged overlay, sign a new commit via the agent, advance the tip, and clear staging.
pub async fn commit(
    config_path: &Path,
    state_path: &Path,
    socket_path: &Path,
    ctx_name: &str,
    message: String,
) -> anyhow::Result<()> {
    let config = Config::load_from(config_path)?;
    let (ctx, identity) = ready_context(&config, socket_path, ctx_name).await?;
    let store = open_object_store(&object_store_dir_for(state_path))?;
    let cipher = AgentCipher::new(socket_path, ctx.name.clone());

    let mut state = LocalState::load_from(state_path)?;
    let cs = state.context_mut(&ctx.name);
    let branch = cs.branch.clone();
    let parent = cs.tips.get(&branch).copied();
    let staged = cs.staged.clone();
    if staged.is_empty() {
        bail!("nothing staged; use `wonton set KEY=value` (or `wonton unset KEY`) first");
    }

    let working_set = effective_working_set(&store, &cipher, parent, &staged)?;
    let author_id = Uuid::parse_str(&identity.user_id)
        .with_context(|| format!("identity user_id '{}' is not a valid UUID", identity.user_id))?;

    let new_hash = wonton_vcs::commit(&store, &cipher, &cipher, author_id, parent, &working_set, message)?;

    let cs = state.context_mut(&ctx.name);
    cs.staged.clear();
    cs.tips.insert(branch.clone(), new_hash);
    state.save_to(state_path)?;
    println!(
        "Committed {} to branch '{branch}' ({}@{}).",
        new_hash.to_hex(),
        ctx.store,
        ctx.environment
    );
    Ok(())
}

/// `wonton log` — verified first-parent history from the current tip. No cipher needed
/// (signature-only verification against this identity's own pubkey).
pub fn log(config_path: &Path, state_path: &Path, ctx_name: &str) -> anyhow::Result<()> {
    let config = Config::load_from(config_path)?;
    let ctx = config
        .find_context(ctx_name)
        .ok_or_else(|| anyhow!("no context named '{ctx_name}'"))?;
    let identity = config
        .find_identity(&ctx.identity)
        .ok_or_else(|| anyhow!("context '{ctx_name}' references unknown identity '{}'", ctx.identity))?;

    let state = LocalState::load_from(state_path)?;
    let cs = state.context(ctx_name).cloned().unwrap_or_default();
    let branch = cs.branch.clone();
    let tip = match cs.tips.get(&branch).copied() {
        Some(t) => t,
        None => {
            println!("No commits on branch '{branch}' yet.");
            return Ok(());
        }
    };

    let pubkey = decode_ed25519_pubkey(&identity.ed25519_pubkey_b64)?;
    let store = open_object_store(&object_store_dir_for(state_path))?;
    let history = wonton_vcs::log(&store, tip, &pubkey)?;
    for vc in &history {
        println!("commit {}", vc.hash.to_hex());
        println!("  author:  {}", vc.commit.fields.author_id);
        println!("  date:    {}", vc.commit.fields.timestamp);
        println!("  message: {}", vc.commit.fields.message);
        println!();
    }
    Ok(())
}

/// `wonton diff [a] [b]` — key-level diff (returns entries for `main.rs` to print).
///
/// - both given: diff commit `a` against commit `b`;
/// - one given: diff the empty tree against that commit;
/// - none given: diff the current tip's parent against the current tip.
pub async fn diff(
    config_path: &Path,
    state_path: &Path,
    socket_path: &Path,
    ctx_name: &str,
    a: Option<String>,
    b: Option<String>,
) -> anyhow::Result<Vec<DiffEntry>> {
    let config = Config::load_from(config_path)?;
    let (ctx, _identity) = ready_context(&config, socket_path, ctx_name).await?;
    let state = LocalState::load_from(state_path)?;
    let cs = state.context(ctx_name).cloned().unwrap_or_default();
    let branch = cs.branch.clone();
    let store = open_object_store(&object_store_dir_for(state_path))?;
    let cipher = AgentCipher::new(socket_path, ctx.name.clone());

    let (from_hash, to_hash) = match (a, b) {
        (Some(a), Some(b)) => (Some(parse_commit_hash(&a)?), parse_commit_hash(&b)?),
        // A single positional argument is the `to` commit; diff it against the empty tree.
        (Some(a), None) => (None, parse_commit_hash(&a)?),
        (None, _) => {
            let tip = cs
                .tips
                .get(&branch)
                .copied()
                .ok_or_else(|| anyhow!("no commits on branch '{branch}' to diff"))?;
            (commit_first_parent(&store, tip)?, tip)
        }
    };

    Ok(wonton_vcs::diff(&store, &cipher, from_hash, to_hash)?)
}

/// `wonton pull` — fast-forward the current branch from the server, refreshing the local tip.
pub async fn pull(config_path: &Path, state_path: &Path, ctx_name: &str) -> anyhow::Result<()> {
    let config = Config::load_from(config_path)?;
    let (ctx, identity) = context_and_identity(&config, ctx_name)?;
    let mut state = LocalState::load_from(state_path)?;
    let cs = state.context(ctx_name).cloned().unwrap_or_default();
    let branch = cs.branch.clone();
    let local_tip = cs.tips.get(&branch).copied();

    let store = open_object_store(&object_store_dir_for(state_path))?;
    let client = authed_client(&identity);

    let outcome = wonton_sync::pull(&client, &store, &ctx.store, &ctx.environment, &branch, local_tip).await?;
    match outcome {
        PullOutcome::UpToDate => println!("Already up to date on branch '{branch}'."),
        PullOutcome::FastForward { new_tip } => {
            state.context_mut(ctx_name).tips.insert(branch.clone(), new_tip);
            state.save_to(state_path)?;
            println!("Fast-forwarded '{branch}' to {}.", new_tip.to_hex());
        }
        PullOutcome::Diverged { local_tip, remote_tip } => {
            println!(
                "Diverged: local {} vs remote {}. A merge (Phase 5) is required; local state left unchanged.",
                local_tip.to_hex(),
                remote_tip.to_hex()
            );
        }
    }
    Ok(())
}

/// `wonton push` — upload local objects then CAS-move the branch ref.
///
/// **Known v1 limitation** (pragmatic object-set walk): we read the remote's current hash for the
/// branch as `old_hash`, then walk the local commit chain back from the tip collecting every
/// commit/tree/blob until we reach `old_hash` (or a root, or an object the local store lacks). We
/// do not diff against the full remote object set, so on a diverged history this may re-upload
/// objects the server already has — harmless (uploads are idempotent), but not minimal.
pub async fn push(config_path: &Path, state_path: &Path, ctx_name: &str) -> anyhow::Result<()> {
    let config = Config::load_from(config_path)?;
    let (ctx, identity) = context_and_identity(&config, ctx_name)?;
    let state = LocalState::load_from(state_path)?;
    let cs = state.context(ctx_name).cloned().unwrap_or_default();
    let branch = cs.branch.clone();
    let local_tip = cs
        .tips
        .get(&branch)
        .copied()
        .ok_or_else(|| anyhow!("nothing to push; no local commits on branch '{branch}'"))?;

    let store = open_object_store(&object_store_dir_for(state_path))?;
    let client = authed_client(&identity);

    let refs = client.get_refs(&ctx.store, &ctx.environment).await?;
    let old_hash = match refs.get(&branch) {
        Some(hex) => Some(Hash::from_hex(hex)?),
        None => None,
    };
    if old_hash == Some(local_tip) {
        println!("Already up to date; nothing to push.");
        return Ok(());
    }

    let object_hashes = collect_objects_to_push(&store, local_tip, old_hash)?;
    match wonton_sync::push(
        &client,
        &store,
        &ctx.store,
        &ctx.environment,
        &branch,
        &object_hashes,
        old_hash,
        local_tip,
    )
    .await
    {
        Ok(()) => {
            println!("Pushed branch '{branch}' -> {}.", local_tip.to_hex());
            Ok(())
        }
        Err(SyncError::Conflict(c)) => bail!(
            "someone else pushed first (remote '{branch}' is now {}); run `wonton pull` then retry",
            c.current.as_deref().unwrap_or("<absent>")
        ),
        Err(e) => Err(e).context("push failed"),
    }
}

/// `wonton run -- <cmd> [args...]` — decrypt the effective working tree into env vars, spawn the
/// child with them injected (stdio inherited), and return the child's exit code for `main.rs` to
/// propagate. **Never writes any decrypted value to disk.**
pub async fn run(
    config_path: &Path,
    state_path: &Path,
    socket_path: &Path,
    ctx_name: &str,
    cmd: Vec<String>,
) -> anyhow::Result<i32> {
    if cmd.is_empty() {
        bail!("no command given; usage: `wonton run -- <cmd> [args...]`");
    }
    let config = Config::load_from(config_path)?;
    let (ctx, _identity) = ready_context(&config, socket_path, ctx_name).await?;
    let store = open_object_store(&object_store_dir_for(state_path))?;
    let cipher = AgentCipher::new(socket_path, ctx.name.clone());

    let state = LocalState::load_from(state_path)?;
    let cs = state.context(ctx_name).cloned().unwrap_or_default();
    let tip = cs.tips.get(&cs.branch).copied();
    let working_set = effective_working_set(&store, &cipher, tip, &cs.staged)?;

    let mut command = std::process::Command::new(&cmd[0]);
    command.args(&cmd[1..]);
    for (key, value) in working_set.iter() {
        let value = std::str::from_utf8(value).map_err(|_| {
            anyhow!("value for '{key}' is not valid UTF-8; `wonton run` can only inject UTF-8 env vars")
        })?;
        command.env(key, value);
    }
    let status = command
        .status()
        .with_context(|| format!("failed to spawn '{}'", cmd[0]))?;
    Ok(status.code().unwrap_or(1))
}

/// `wonton export --format dotenv <path>` — decrypt the effective working tree and write it to a
/// file the user names. **Prints an explicit plaintext warning to stderr before writing.** Only
/// ever runs on direct request, never as a side effect of another command.
pub async fn export(
    config_path: &Path,
    state_path: &Path,
    socket_path: &Path,
    ctx_name: &str,
    format: ExportFormat,
    path: &Path,
) -> anyhow::Result<()> {
    let config = Config::load_from(config_path)?;
    let (ctx, _identity) = ready_context(&config, socket_path, ctx_name).await?;
    let store = open_object_store(&object_store_dir_for(state_path))?;
    let cipher = AgentCipher::new(socket_path, ctx.name.clone());

    let state = LocalState::load_from(state_path)?;
    let cs = state.context(ctx_name).cloned().unwrap_or_default();
    let tip = cs.tips.get(&cs.branch).copied();
    let working_set = effective_working_set(&store, &cipher, tip, &cs.staged)?;

    let contents = match format {
        ExportFormat::Dotenv => render_dotenv(&working_set)?,
    };

    eprintln!(
        "wonton: writing {} decrypted secret(s) to {} in plaintext — handle with care",
        working_set.len(),
        path.display()
    );
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    println!("Exported {} secret(s) to {}.", working_set.len(), path.display());
    Ok(())
}

// =====================================================================================
// Phase 5a: sharing, revocation, and DEK rotation (PLAN.md §4.4/§8.3).
//
// `share` is O(1) — it wraps a COPY of the already-cached DEK for a new recipient, no value
// re-encryption. `revoke` and `key rotate` both run `perform_rotation`: a fresh DEK is generated
// in the agent, the committed history is re-encrypted under it, the new DEK is re-wrapped for
// every *remaining* member, and everything is applied in one atomic server-side rotate batch. A
// revoked user, holding only the retired DEK, can no longer decrypt anything committed afterward.
// =====================================================================================

/// `wonton share <user> --env <ctx> [--role ...]` — grant `target_username` access to the
/// context's environment by wrapping a copy of the currently-cached DEK for their X25519 public
/// key. O(1): no value re-encryption, no rotation (PLAN.md §4.4).
pub async fn share(
    config_path: &Path,
    state_path: &Path,
    socket_path: &Path,
    ctx_name: &str,
    target_username: &str,
    role: Role,
) -> anyhow::Result<()> {
    let config = Config::load_from(config_path)?;
    // Needs its own cached DEK (via `wonton use`) to wrap a copy for the target.
    let (ctx, identity) = ready_context(&config, socket_path, ctx_name).await?;
    let client = authed_client(&identity);

    // Resolve the target's public keys (any valid actor may look a user up).
    let target = client.get_user(target_username).await.map_err(|e| match e {
        SyncError::NotFound(_) => anyhow!("no such user '{target_username}'"),
        other => anyhow!("could not look up user '{target_username}': {other}"),
    })?;

    // The version currently cached in the agent for this context is the version we grant under.
    let state = LocalState::load_from(state_path)?;
    let dek_version = state.context(ctx_name).map(|cs| cs.dek_version).unwrap_or(0);
    if dek_version == 0 {
        bail!("no known DEK version for context '{ctx_name}'; run `wonton use {ctx_name}` again");
    }

    // Best-effort membership upsert (server-side `ON CONFLICT DO UPDATE`, always safe to call —
    // a no-op if the target already holds this role or higher isn't distinguished here).
    client
        .add_member(
            &ctx.store,
            &ctx.environment,
            &MemberRequest {
                user_id: target.user_id.clone(),
                role,
            },
        )
        .await
        .context("could not add the target as a member of the environment")?;

    // Wrap a copy of the cached DEK for the target — the raw DEK never leaves the agent.
    let sealed_box =
        agent::wrap_dek_for_recipient(socket_path, ctx.name.clone(), target.x25519_pubkey.clone())
            .await
            .context("agent could not wrap the DEK for the target")?;

    client
        .grant_key(
            &ctx.store,
            &ctx.environment,
            &GrantKeyRequest {
                user_id: target.user_id.clone(),
                dek_version,
                sealed_box,
            },
        )
        .await
        .context("could not upload the wrapped-DEK grant")?;

    println!(
        "Shared {}@{} with '{target_username}' as {} (DEK v{dek_version}).",
        ctx.store,
        ctx.environment,
        role_label(role)
    );
    Ok(())
}

/// `wonton revoke <user> --env <ctx>` — remove the target's membership, then rotate the DEK.
/// Revocation *is* rotation (PLAN.md §4.4): the target may have cached the old DEK, so the only
/// way to actually deny them is to move to a new one they don't hold.
pub async fn revoke(
    config_path: &Path,
    state_path: &Path,
    socket_path: &Path,
    ctx_name: &str,
    target_username: &str,
) -> anyhow::Result<()> {
    let config = Config::load_from(config_path)?;
    let (ctx, identity) = ready_context(&config, socket_path, ctx_name).await?;
    let client = authed_client(&identity);

    let target = client.get_user(target_username).await.map_err(|e| match e {
        SyncError::NotFound(_) => anyhow!("no such user '{target_username}'"),
        other => anyhow!("could not look up user '{target_username}': {other}"),
    })?;

    client
        .remove_member(&ctx.store, &ctx.environment, &target.user_id)
        .await
        .context("could not remove the target's membership")?;
    println!(
        "Removed '{target_username}' from {}@{}; rotating the DEK...",
        ctx.store, ctx.environment
    );

    perform_rotation(state_path, socket_path, &ctx, &identity).await
}

/// `wonton key rotate --env <ctx>` — rotate the environment's DEK with no membership change
/// (re-encrypt history under a fresh DEK and re-wrap for the current members).
pub async fn rotate(
    config_path: &Path,
    state_path: &Path,
    socket_path: &Path,
    ctx_name: &str,
) -> anyhow::Result<()> {
    let config = Config::load_from(config_path)?;
    let (ctx, identity) = ready_context(&config, socket_path, ctx_name).await?;
    perform_rotation(state_path, socket_path, &ctx, &identity).await
}

/// The shared 8-step rotation both `revoke` and `key rotate` run (PROGRESS.md §3.7). Assumes the
/// caller already resolved + guarded the context (old DEK cached under `ctx.name`).
///
/// Known edge case (not specially handled): if `revoke` removed the last *other* member, the
/// member list may contain only the rotator (or, if the rotator revoked themselves, be empty).
/// The rotation still proceeds; an env with zero members afterward is unusual but not this
/// phase's problem to prevent — the code simply doesn't crash on it.
async fn perform_rotation(
    state_path: &Path,
    socket_path: &Path,
    ctx: &Context,
    identity: &Identity,
) -> anyhow::Result<()> {
    let client = authed_client(identity);
    let store = open_object_store(&object_store_dir_for(state_path))?;

    // 2. The members to re-wrap for (reflects any just-applied `remove_member`).
    let members = client
        .list_members(&ctx.store, &ctx.environment)
        .await
        .context("could not list environment members")?;

    // 3. The next DEK version.
    let details = client
        .get_env_details(&ctx.store, &ctx.environment)
        .await
        .context("could not read the environment's current DEK version")?;
    let new_version = details.active_dek_version + 1;

    // 4. Stage a fresh DEK in the agent under a temp context (distinct from `ctx.name`, whose DEK
    //    is still the OLD one we need to decrypt the current history with).
    let temp_ctx = format!("{}::rotate::{new_version}", ctx.name);
    agent::generate_dek(socket_path, temp_ctx.clone())
        .await
        .context("agent could not generate a new DEK")?;

    // 5. Re-encrypt the CURRENT TIP's committed tree (no staged overlay) under the new DEK. The
    //    new commit's parent is the old tip; sign via either cipher (signing ignores context).
    let mut state = LocalState::load_from(state_path)?;
    let cs = state.context(&ctx.name).cloned().unwrap_or_default();
    let branch = cs.branch.clone();
    let old_tip = cs.tips.get(&branch).copied();

    let old_cipher = AgentCipher::new(socket_path, ctx.name.clone());
    let new_cipher = AgentCipher::new(socket_path, temp_ctx.clone());
    let working_set = effective_working_set(&store, &old_cipher, old_tip, &BTreeMap::new())?;

    let author_id = Uuid::parse_str(&identity.user_id)
        .with_context(|| format!("identity user_id '{}' is not a valid UUID", identity.user_id))?;
    let new_hash = wonton_vcs::commit(
        &store,
        &new_cipher,
        &old_cipher,
        author_id,
        old_tip,
        &working_set,
        "key rotation",
    )?;

    // 6. Wrap the new DEK for every remaining member; remember our own sealed box for the hot-swap.
    let mut wrapped_deks = Vec::with_capacity(members.len());
    let mut own_sealed: Option<String> = None;
    for member in &members {
        let sealed =
            agent::wrap_dek_for_recipient(socket_path, temp_ctx.clone(), member.x25519_pubkey.clone())
                .await
                .with_context(|| {
                    format!("could not wrap the new DEK for member {}", member.user_id)
                })?;
        if member.user_id == identity.user_id {
            own_sealed = Some(sealed.clone());
        }
        wrapped_deks.push(GrantKeyRequest {
            user_id: member.user_id.clone(),
            dek_version: new_version,
            sealed_box: sealed,
        });
    }

    // 7. Collect the re-encrypted object batch (new commit back to the old tip) and apply the
    //    rotation atomically server-side (objects + new wrapped-DEK map + version bump).
    let object_hashes = collect_objects_to_push(&store, new_hash, old_tip)?;
    let objects = objects_for_upload(&store, &object_hashes)?;
    client
        .rotate(
            &ctx.store,
            &ctx.environment,
            &RotateRequest {
                new_dek_version: new_version,
                objects,
                wrapped_deks,
            },
        )
        .await
        .context("rotation batch was rejected by the server")?;

    // 8. Advance the local tip, hot-swap the agent's `ctx.name`-cached DEK to the new one (so the
    //    caller keeps working under the new DEK), and persist the new version.
    if let Some(sealed) = own_sealed {
        agent::unwrap_dek(socket_path, ctx.name.clone(), sealed)
            .await
            .context("could not hot-swap the rotated DEK into the agent")?;
    }
    let cs = state.context_mut(&ctx.name);
    cs.tips.insert(branch.clone(), new_hash);
    cs.dek_version = new_version;
    state.save_to(state_path)?;

    println!(
        "Rotated {}@{} to DEK v{new_version}; re-encrypted history at {} for {} member(s).",
        ctx.store,
        ctx.environment,
        new_hash.to_hex(),
        members.len()
    );
    Ok(())
}

// ---- shared helpers for the VCS porcelain --------------------------------------------------

/// Resolve a context + identity from config without any agent/network check (for pull/push, which
/// move opaque objects and need no cached DEK).
fn context_and_identity(config: &Config, ctx_name: &str) -> anyhow::Result<(Context, Identity)> {
    let ctx = config
        .find_context(ctx_name)
        .cloned()
        .ok_or_else(|| anyhow!("no context named '{ctx_name}'; add one with `wonton context add`"))?;
    let identity = config
        .find_identity(&ctx.identity)
        .cloned()
        .ok_or_else(|| anyhow!("context '{ctx_name}' references unknown identity '{}'", ctx.identity))?;
    Ok((ctx, identity))
}

/// A `SyncClient` for an identity's server, carrying its cached session token.
fn authed_client(identity: &Identity) -> SyncClient {
    let mut client = SyncClient::new(&identity.server_url);
    if let Some(token) = &identity.session_token {
        client.set_token(token);
    }
    client
}

/// Decode a base64 Ed25519 public key into 32 bytes, failing closed on a bad length.
fn decode_ed25519_pubkey(b64: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = STANDARD
        .decode(b64)
        .context("stored ed25519 pubkey is not valid base64")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("stored ed25519 pubkey is not 32 bytes"))
}

/// Parse a hex commit hash argument.
fn parse_commit_hash(s: &str) -> anyhow::Result<Hash> {
    Hash::from_hex(s).map_err(|_| anyhow!("'{s}' is not a valid commit hash"))
}

/// Load and deserialize the [`Tree`] a commit points at (reading `wonton_objects` directly, since
/// `wonton-vcs`'s equivalent helper is crate-private).
fn tree_of_commit(store: &LocalObjectStore, commit_hash: Hash) -> anyhow::Result<Tree> {
    let bytes = store
        .get(&commit_hash)?
        .ok_or_else(|| anyhow!("commit {} is not in the local store; run `wonton pull` first", commit_hash.to_hex()))?;
    let commit = Commit::from_bytes(&bytes)?;
    let tree_bytes = store
        .get(&commit.fields.tree_hash)?
        .ok_or_else(|| anyhow!("tree {} missing from the local store", commit.fields.tree_hash.to_hex()))?;
    Ok(Tree::from_bytes(&tree_bytes)?)
}

/// The (single) first parent of a commit, or `None` for a root commit.
fn commit_first_parent(store: &LocalObjectStore, commit_hash: Hash) -> anyhow::Result<Option<Hash>> {
    let bytes = store
        .get(&commit_hash)?
        .ok_or_else(|| anyhow!("commit {} is not in the local store", commit_hash.to_hex()))?;
    let commit = Commit::from_bytes(&bytes)?;
    match commit.fields.parent_hashes.as_slice() {
        [] => Ok(None),
        [p] => Ok(Some(*p)),
        _ => bail!("commit {} is a merge commit; diffing merges is a Phase 5 concern", commit_hash.to_hex()),
    }
}

/// Decrypt one already-stored ciphertext blob via the agent.
fn decrypt_blob(
    store: &LocalObjectStore,
    cipher: &AgentCipher,
    blob_hash: &Hash,
) -> anyhow::Result<Vec<u8>> {
    let bytes = store
        .get(blob_hash)?
        .ok_or_else(|| anyhow!("blob {} missing from the local store", blob_hash.to_hex()))?;
    let blob = Blob::from_bytes(&bytes)?;
    let value = EncryptedValue {
        nonce: blob.nonce,
        ciphertext: blob.ciphertext,
    };
    Ok(cipher.decrypt(&value)?)
}

/// Build the effective decrypted [`WorkingSet`] = the tip tree decrypted, with `staged` overlaid
/// (`Set` → replace/add the decrypted staged blob, `Unset` → drop the key). Used by `commit`,
/// `run`, and `export`. Every value is decrypted through the agent; nothing is written to disk.
fn effective_working_set(
    store: &LocalObjectStore,
    cipher: &AgentCipher,
    tip: Option<Hash>,
    staged: &BTreeMap<String, StagedEntry>,
) -> anyhow::Result<WorkingSet> {
    let mut working_set = WorkingSet::new();

    if let Some(tip) = tip {
        let tree = tree_of_commit(store, tip)?;
        for (key, blob_hash) in &tree.entries {
            let plaintext = decrypt_blob(store, cipher, blob_hash)?;
            working_set.set(key.clone(), plaintext);
        }
    }

    for (key, entry) in staged {
        match entry {
            StagedEntry::Set(blob_hash) => {
                let plaintext = decrypt_blob(store, cipher, blob_hash)?;
                working_set.set(key.clone(), plaintext);
            }
            StagedEntry::Unset => {
                working_set.unset(key);
            }
        }
    }
    Ok(working_set)
}

/// Collect every local commit/tree/blob hash reachable from `tip` by a first-parent walk, stopping
/// at `stop` (the remote's current tip), a root, or an object the local store lacks. See
/// [`push`]'s doc comment for the known-limitation caveat.
fn collect_objects_to_push(
    store: &LocalObjectStore,
    tip: Hash,
    stop: Option<Hash>,
) -> anyhow::Result<Vec<Hash>> {
    let mut hashes = Vec::new();
    let mut seen = HashSet::new();
    let mut cursor = Some(tip);

    while let Some(current) = cursor {
        if Some(current) == stop {
            break;
        }
        let bytes = match store.get(&current)? {
            Some(b) => b,
            // Not in the local store: it's already on the server (older history) — stop walking.
            None => break,
        };
        if seen.insert(current) {
            hashes.push(current);
        }
        let commit = Commit::from_bytes(&bytes)?;

        // The commit's tree and every blob it references.
        let tree_hash = commit.fields.tree_hash;
        if store.contains(&tree_hash) && seen.insert(tree_hash) {
            hashes.push(tree_hash);
            if let Some(tree_bytes) = store.get(&tree_hash)? {
                let tree = Tree::from_bytes(&tree_bytes)?;
                for blob_hash in tree.entries.values() {
                    if store.contains(blob_hash) && seen.insert(*blob_hash) {
                        hashes.push(*blob_hash);
                    }
                }
            }
        }

        cursor = match commit.fields.parent_hashes.as_slice() {
            [] => None,
            [p] => Some(*p),
            _ => bail!("commit {} is a merge commit; pushing merges is a Phase 5 concern", current.to_hex()),
        };
    }
    Ok(hashes)
}

/// Build the [`ObjectUploadRequest`] batch for a rotation from a list of local object hashes,
/// reading each object's bytes from the store and sniffing its kind. Used by `perform_rotation`
/// (the `rotate` route takes an explicit object batch rather than reusing `wonton_sync::push`,
/// which moves a ref instead of applying a wrapped-DEK map).
fn objects_for_upload(
    store: &LocalObjectStore,
    hashes: &[Hash],
) -> anyhow::Result<Vec<ObjectUploadRequest>> {
    let mut out = Vec::with_capacity(hashes.len());
    for h in hashes {
        let bytes = store
            .get(h)?
            .ok_or_else(|| anyhow!("object {} missing from the local store", h.to_hex()))?;
        out.push(ObjectUploadRequest {
            hash: h.to_hex(),
            kind: sniff_kind(&bytes).to_string(),
            body: STANDARD.encode(&bytes),
        });
    }
    Ok(out)
}

/// Determine an object's kind by structural sniffing (`Commit`, then `Tree`, else `blob`) — the
/// same disjoint-required-fields heuristic `wonton_sync::push` uses (the wire format doesn't
/// self-describe its kind).
fn sniff_kind(bytes: &[u8]) -> &'static str {
    if Commit::from_bytes(bytes).is_ok() {
        "commit"
    } else if Tree::from_bytes(bytes).is_ok() {
        "tree"
    } else {
        "blob"
    }
}

/// The stored/wire string for a [`Role`], for user-facing confirmation messages.
fn role_label(role: Role) -> &'static str {
    match role {
        Role::Admin => "admin",
        Role::Writer => "writer",
        Role::Reader => "reader",
    }
}

/// Render a [`WorkingSet`] as dotenv (`KEY=value` per line). Values containing whitespace / `=` /
/// quotes / newlines are double-quoted with `\`-escaping. A non-UTF-8 value is a hard error.
fn render_dotenv(working_set: &WorkingSet) -> anyhow::Result<String> {
    let mut out = String::new();
    for (key, value) in working_set.iter() {
        let value = std::str::from_utf8(value)
            .map_err(|_| anyhow!("value for '{key}' is not valid UTF-8; cannot export as dotenv"))?;
        let needs_quotes = value
            .chars()
            .any(|c| c.is_whitespace() || c == '=' || c == '"' || c == '\'' || c == '#');
        if needs_quotes {
            let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
            out.push_str(&format!("{key}=\"{escaped}\"\n"));
        } else {
            out.push_str(&format!("{key}={value}\n"));
        }
    }
    Ok(out)
}
