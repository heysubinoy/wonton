//! The identity / context-switching commands: `login`, `context add|list`,
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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, Write};
use std::path::Path;

use anyhow::{anyhow, bail, Context as _};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use uuid::Uuid;
use wonton_crypto::{generate_identity, EncryptedValue};
use wonton_objects::{Blob, Commit, Hash, LocalObjectStore, Tree, HASH_LEN};
use wonton_shared::{
    Argon2ParamsDto, CreateEnvRequest, CreateStoreRequest, GrantKeyRequest, LoginCompleteRequest,
    LoginStartRequest, MemberRequest, ObjectUploadRequest, RegisterRequest, Role, RotateRequest,
};
use wonton_sync::{PullOutcome, SyncClient, SyncError};
use wonton_vcs::{DiffEntry, MergeEntry, ValueDecryptor, ValueEncryptor, WorkingSet};

use crate::agent::cipher::AgentCipher;
use crate::agent::client as agent;
use crate::agent::protocol::Argon2ParamsWire;
use crate::config::{self, Config, Context, Identity};
use crate::state::{
    object_store_dir_for, open_object_store, ConflictHashes, LocalState, MergeState,
    ResolvedEntry, StagedEntry,
};

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
            eprintln!(
                "wonton: registering a new identity for '{username}'. There is no passphrase \
                 recovery — if you forget it, this identity's data is unrecoverable and you'll \
                 need to re-provision a new one. Store it somewhere safe."
            );
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

/// `wonton whoami` — show which locally-logged-in identity/identities are cached, without
/// needing a resolvable context (unlike `wonton context`, which requires one). Useful right
/// after `login`, before any `context add` has happened, and for quickly checking which server
/// an identity points at without digging into `config.toml`.
pub fn whoami(config_path: &Path) -> anyhow::Result<()> {
    let config = Config::load_from(config_path)?;
    let mut out = std::io::stdout();
    whoami_report(&config, &mut out)?;
    Ok(())
}

/// The actual reporting logic behind [`whoami`], writing to an injectable `impl Write` so tests
/// can assert on the exact content rather than just "did it not crash". `pub(crate)` (not
/// private) so `tests.rs`'s integration tests — which need the real server/agent fixtures that
/// already live there — can call it directly instead of duplicating that fixture setup in a
/// same-file test module.
pub(crate) fn whoami_report(config: &Config, out: &mut impl Write) -> anyhow::Result<()> {
    match config.identities.as_slice() {
        [] => writeln!(out, "Not logged in. Run `wonton login <username> --server <url>` first.")?,
        [only] => {
            writeln!(out, "{} (username '{}') on {}", only.name, only.username, only.server_url)?;
            writeln!(out, "  user id: {}", only.user_id)?;
        }
        many => {
            writeln!(out, "Logged-in identities:")?;
            for identity in many {
                writeln!(
                    out,
                    "  {} (username '{}') on {}",
                    identity.name, identity.username, identity.server_url
                )?;
            }
            writeln!(
                out,
                "\nMore than one identity is cached — pass --identity where a command needs one \
                 to disambiguate."
            )?;
        }
    }
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
// Provisioning: create a store/environment. Any authenticated identity can create a store
// (stores have no membership of their own); creating an environment additionally bootstraps and
// self-grants its first DEK, since only a client holding key material can do that — the server
// can never generate or wrap a DEK on anyone's behalf.
// =====================================================================================

/// Resolve which identity a provisioning command should act as: the caller-supplied `--identity`
/// if given, else the sole cached identity if there's exactly one, else a clear error naming the
/// choices (0 identities: log in first; 2+: ambiguous, must disambiguate).
fn resolve_identity_name<'a>(config: &'a Config, given: Option<&'a str>) -> anyhow::Result<&'a str> {
    if let Some(name) = given {
        return Ok(name);
    }
    match config.identities.as_slice() {
        [] => bail!("no identity logged in; run `wonton login <username> --server <url>` first"),
        [only] => Ok(only.name.as_str()),
        many => {
            let names: Vec<&str> = many.iter().map(|i| i.name.as_str()).collect();
            bail!("multiple identities are logged in ({}); pass --identity to disambiguate", names.join(", "))
        }
    }
}

/// `wonton store create <name> [--identity <identity>]` — create a new store on the server.
/// `--identity` is only required if more than one identity is logged in locally. Idempotent:
/// a store that already exists is treated as success, not an error (`mkdir -p` style), so a
/// repeated onboarding flow can safely re-run this.
pub async fn store_create(
    config_path: &Path,
    identity_name: Option<&str>,
    name: &str,
) -> anyhow::Result<()> {
    let config = Config::load_from(config_path)?;
    let identity_name = resolve_identity_name(&config, identity_name)?;
    let identity = config.find_identity(identity_name).ok_or_else(|| {
        anyhow!("no identity named '{identity_name}'; run `wonton login {identity_name}` first")
    })?;
    let client = authed_client(identity);
    match client.create_store(&CreateStoreRequest { name: name.to_string() }).await {
        Ok(_) => println!("Created store '{name}'."),
        Err(e) if e.is_already_exists() => println!("Store '{name}' already exists; nothing to do."),
        Err(e) => return Err(e).with_context(|| format!("could not create store '{name}'")),
    }
    Ok(())
}

/// `wonton env create <store> <env> [--identity <identity>]` — create a new environment within
/// `store` (the caller becomes its first admin member, same as the server already does for
/// `POST /stores/{{store}}/envs`), then immediately bootstrap the environment's first DEK:
/// generate it in the agent, wrap it for the caller's own X25519 public key, and self-grant it
/// at version 1. No context needs to exist yet for this — a scratch label stages the DEK in the
/// agent just long enough to wrap it. `--identity` is only required if more than one identity is
/// logged in locally.
///
/// Idempotent, but only in the sense that re-running it is safe: if the environment already
/// exists, this is a no-op that does **not** attempt the DEK bootstrap (self-granting into an
/// environment you didn't just create would be wrong — you either already have access, or you
/// need an admin to `wonton share` you in).
pub async fn env_create(
    config_path: &Path,
    socket_path: &Path,
    identity_name: Option<&str>,
    store: &str,
    env: &str,
) -> anyhow::Result<()> {
    let config = Config::load_from(config_path)?;
    let identity_name = resolve_identity_name(&config, identity_name)?;
    let identity = config.find_identity(identity_name).ok_or_else(|| {
        anyhow!("no identity named '{identity_name}'; run `wonton login {identity_name}` first")
    })?;
    let client = authed_client(identity);

    match client.create_env(store, &CreateEnvRequest { name: env.to_string() }).await {
        Ok(_) => {}
        Err(e) if e.is_already_exists() => {
            println!(
                "Environment '{store}@{env}' already exists; skipping creation and DEK bootstrap."
            );
            println!(
                "If you don't already have access, ask an admin to run `wonton share <you> \
                 --context <context>`."
            );
            return Ok(());
        }
        Err(e) => return Err(e).with_context(|| format!("could not create environment '{store}@{env}'")),
    }

    let temp_ctx = format!("{store}-{env}::init");
    agent::generate_dek(socket_path, temp_ctx.clone())
        .await
        .context("agent could not generate the environment's first DEK (are you logged in?)")?;
    let sealed = agent::wrap_dek_for_recipient(socket_path, temp_ctx, identity.x25519_pubkey_b64.clone())
        .await
        .context("agent could not wrap the DEK for self-grant")?;
    client
        .grant_key(
            store,
            env,
            &GrantKeyRequest {
                user_id: identity.user_id.clone(),
                dek_version: 1,
                sealed_box: sealed,
            },
        )
        .await
        .context("could not self-grant the environment's first DEK")?;

    println!("Created environment '{store}@{env}' and granted yourself DEK v1.");
    println!(
        "Next: wonton context add <name> --store {store} --env {env} --identity {identity_name}"
    );
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
pub fn switch(state_path: &Path, ctx_name: &str, branch: &str, create: bool) -> anyhow::Result<()> {
    let mut state = LocalState::load_from(state_path)?;
    let cs = state.context(ctx_name).cloned().unwrap_or_default();
    let known = cs.branch == branch || cs.tips.contains_key(branch);
    if !known && !create {
        bail!(
            "no local record of branch '{branch}' in context '{ctx_name}'; pass --create if \
             you're starting a brand new branch, or if you're about to `wonton pull` a branch \
             that exists on the remote but you haven't fetched yet"
        );
    }
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

/// `wonton log` — verified first-parent history from the current tip. Resolves each commit's
/// expected signer by its own `author_id` rather than assuming the local caller's own identity
/// authored the whole history: a history shared with (or received from) another user contains
/// commits authored by *their* identity too, and those must verify against *their* pubkey, not
/// ours (found by manual end-to-end testing). Author pubkeys are resolved via
/// the server's global user directory (`get_user_by_id`), not just current env membership, so a
/// since-revoked member's past commits remain verifiable.
pub async fn log(config_path: &Path, state_path: &Path, ctx_name: &str) -> anyhow::Result<()> {
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

    let store = open_object_store(&object_store_dir_for(state_path))?;
    let author_ids = wonton_vcs::mainline_author_ids(&store, tip)?;
    let client = authed_client(identity);
    let mut signers: HashMap<Uuid, [u8; 32]> = HashMap::new();
    for author_id in author_ids {
        let info = client
            .get_user_by_id(&author_id.to_string())
            .await
            .with_context(|| format!("could not resolve public key for commit author {author_id}"))?;
        signers.insert(author_id, decode_ed25519_pubkey(&info.ed25519_pubkey)?);
    }

    let history = wonton_vcs::log(&store, tip, |author_id| signers.get(&author_id).copied())?;
    for vc in &history {
        println!("commit {} ({})", short_hash(&vc.hash), vc.hash.to_hex());
        println!("  author:  {}", vc.commit.fields.author_id);
        println!("  date:    {}", vc.commit.fields.timestamp);
        println!("  message: {}", vc.commit.fields.message);
        println!();
    }
    Ok(())
}

/// Abbreviate a hash to its first 12 hex characters (48 bits) for scannable display — `diff` and
/// every other command that accepts a commit hash also accepts any unambiguous prefix, so this
/// is always enough to paste back in, and the full hash is still printed alongside it in `log`.
fn short_hash(hash: &Hash) -> String {
    hash.to_hex()[..12].to_string()
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
        (Some(a), Some(b)) => (Some(parse_commit_hash(&store, &a)?), parse_commit_hash(&store, &b)?),
        // A single positional argument is the `to` commit; diff it against the empty tree.
        (Some(a), None) => (None, parse_commit_hash(&store, &a)?),
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

/// Decrypt an entire commit's tree into a plaintext `key -> value` map. `tip = None` yields an
/// empty map (used for a merge base of `None`, i.e. disjoint histories).
fn tree_to_plaintext_map(
    store: &LocalObjectStore,
    cipher: &AgentCipher,
    tip: Option<Hash>,
) -> anyhow::Result<BTreeMap<String, Vec<u8>>> {
    let mut map = BTreeMap::new();
    if let Some(tip) = tip {
        let tree = tree_of_commit(store, tip)?;
        for (key, blob_hash) in &tree.entries {
            map.insert(key.clone(), decrypt_blob(store, cipher, blob_hash)?);
        }
    }
    Ok(map)
}

/// Agent-encrypt `plaintext` and store it as a new blob, returning its hash. The manual-entry
/// conflict-resolution path uses this — identical to what `set()` does for `wonton set`, never
/// writing the plaintext to disk itself.
fn encrypt_and_store(store: &LocalObjectStore, cipher: &AgentCipher, plaintext: &[u8]) -> anyhow::Result<Hash> {
    let encrypted = cipher.encrypt(plaintext)?;
    let blob = Blob::new(encrypted.nonce, encrypted.ciphertext);
    let blob_bytes = blob.to_bytes()?;
    let blob_hash = Hash::of(&blob_bytes);
    store.put(&blob_hash, &blob_bytes)?;
    Ok(blob_hash)
}

/// Render a value for the interactive conflict prompt: `<deleted>` for an absent side, the UTF-8
/// text if valid, else a byte-count placeholder (never guess/mangle non-UTF-8 bytes into text).
fn display_conflict_value(value: Option<&[u8]>) -> String {
    match value {
        None => "<deleted>".to_string(),
        Some(bytes) => match std::str::from_utf8(bytes) {
            Ok(s) => s.to_string(),
            Err(_) => format!("<binary, {} bytes>", bytes.len()),
        },
    }
}

/// One conflict's resolution, as chosen at the interactive prompt.
enum PromptOutcome {
    Ours,
    Theirs,
    Manual(String),
    /// Stop resolving now (explicit `s`, or EOF on a non-interactive/closed stdin).
    Skip,
}

/// Prompt for a single conflicting key's resolution via `reader`/`writer` (injectable so this is
/// testable without real stdin/stdout). Re-prompts on an unrecognized line;
/// EOF at any point is treated as `Skip` (a closed/non-interactive stdin must never hang or panic).
fn prompt_conflict_resolution(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    key: &str,
    ours: Option<&[u8]>,
    theirs: Option<&[u8]>,
) -> anyhow::Result<PromptOutcome> {
    writeln!(writer, "Conflict on '{key}':")?;
    writeln!(writer, "  ours:   {}", display_conflict_value(ours))?;
    writeln!(writer, "  theirs: {}", display_conflict_value(theirs))?;
    loop {
        write!(writer, "[o]urs / [t]heirs / [m]anual / [s]kip> ")?;
        writer.flush()?;
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(PromptOutcome::Skip); // EOF
        }
        match line.trim() {
            "o" | "ours" => return Ok(PromptOutcome::Ours),
            "t" | "theirs" => return Ok(PromptOutcome::Theirs),
            "s" | "skip" => return Ok(PromptOutcome::Skip),
            "m" | "manual" => {
                write!(writer, "Enter value for '{key}': ")?;
                writer.flush()?;
                let mut value = String::new();
                if reader.read_line(&mut value)? == 0 {
                    return Ok(PromptOutcome::Skip); // EOF while typing the value
                }
                let value = value.strip_suffix('\n').unwrap_or(&value);
                let value = value.strip_suffix('\r').unwrap_or(value);
                return Ok(PromptOutcome::Manual(value.to_string()));
            }
            _ => {
                writeln!(writer, "Please enter o, t, m, or s.")?;
            }
        }
    }
}

/// Run the interactive one-key-at-a-time conflict prompt over `conflicts`, moving each resolved
/// key into `resolved`. Calls `persist` after **every single resolution** so an interrupted
/// `--continue` loses at most the one answer in flight. Stops — leaving that
/// key and every key after it in `conflicts` — on `Skip`.
fn resolve_conflicts_interactively(
    store: &LocalObjectStore,
    cipher: &AgentCipher,
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    conflicts: &mut BTreeMap<String, ConflictHashes>,
    resolved: &mut BTreeMap<String, ResolvedEntry>,
    mut persist: impl FnMut(&BTreeMap<String, ConflictHashes>, &BTreeMap<String, ResolvedEntry>) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let keys: Vec<String> = conflicts.keys().cloned().collect();
    for key in keys {
        let hashes = conflicts.get(&key).expect("key came from conflicts.keys()").clone();
        let ours_plain = hashes.ours.as_ref().map(|h| decrypt_blob(store, cipher, h)).transpose()?;
        let theirs_plain = hashes.theirs.as_ref().map(|h| decrypt_blob(store, cipher, h)).transpose()?;

        let outcome = prompt_conflict_resolution(reader, writer, &key, ours_plain.as_deref(), theirs_plain.as_deref())?;
        let resolved_entry = match outcome {
            PromptOutcome::Skip => break,
            PromptOutcome::Ours => match hashes.ours {
                Some(h) => ResolvedEntry::Set(h),
                None => ResolvedEntry::Delete,
            },
            PromptOutcome::Theirs => match hashes.theirs {
                Some(h) => ResolvedEntry::Set(h),
                None => ResolvedEntry::Delete,
            },
            PromptOutcome::Manual(value) => ResolvedEntry::Set(encrypt_and_store(store, cipher, value.as_bytes())?),
        };
        conflicts.remove(&key);
        resolved.insert(key, resolved_entry);
        persist(conflicts, resolved)?;
    }
    Ok(())
}

/// Finalize a merge: fold every already-settled conflict (`resolved`, decrypting each blob hash
/// back to plaintext — `commit_merge` takes a plaintext `WorkingSet`, not hashes) into the
/// non-conflicting `resolved_plaintext` map, build the final `WorkingSet`, and produce the
/// 2-parent merge commit. Prints an added/changed/removed summary relative to `ours_map`.
#[allow(clippy::too_many_arguments)]
fn finalize_merge_commit(
    store: &LocalObjectStore,
    cipher: &AgentCipher,
    author_id: Uuid,
    ours_tip: Hash,
    theirs_tip: Hash,
    ours_map: &BTreeMap<String, Vec<u8>>,
    mut resolved_plaintext: BTreeMap<String, Option<Vec<u8>>>,
    resolved_conflicts: &BTreeMap<String, ResolvedEntry>,
    branch: &str,
) -> anyhow::Result<Hash> {
    for (key, entry) in resolved_conflicts {
        let value = match entry {
            ResolvedEntry::Set(hash) => Some(decrypt_blob(store, cipher, hash)?),
            ResolvedEntry::Delete => None,
        };
        resolved_plaintext.insert(key.clone(), value);
    }

    let mut working_set = WorkingSet::new();
    let (mut added, mut changed, mut removed) = (0usize, 0usize, 0usize);
    for (key, value) in &resolved_plaintext {
        match (ours_map.get(key), value) {
            (None, Some(v)) => {
                working_set.set(key.clone(), v.clone());
                added += 1;
            }
            (Some(old), Some(new)) => {
                working_set.set(key.clone(), new.clone());
                if old != new {
                    changed += 1;
                }
            }
            (Some(_), None) => removed += 1,
            (None, None) => {}
        }
    }

    let message = format!("Merge branch '{branch}'");
    let hash = wonton_vcs::commit_merge(store, cipher, cipher, author_id, [ours_tip, theirs_tip], &working_set, message)?;
    println!(
        "Merged '{branch}': {added} added, {changed} changed, {removed} removed -> {}.",
        hash.to_hex()
    );
    Ok(hash)
}

/// `wonton merge <branch>` — three-way merge `branch` into the current branch.
/// Entirely offline/client-side: the server never sees plaintext, a merge base, or a conflict.
pub async fn merge(
    config_path: &Path,
    state_path: &Path,
    socket_path: &Path,
    ctx_name: &str,
    branch: &str,
) -> anyhow::Result<()> {
    let config = Config::load_from(config_path)?;
    let (ctx, identity) = ready_context(&config, socket_path, ctx_name).await?;
    let store = open_object_store(&object_store_dir_for(state_path))?;
    let cipher = AgentCipher::new(socket_path, ctx.name.clone());
    let author_id = Uuid::parse_str(&identity.user_id)
        .with_context(|| format!("identity user_id '{}' is not a valid UUID", identity.user_id))?;

    let mut state = LocalState::load_from(state_path)?;
    let cs = state.context_mut(&ctx.name);
    if cs.merge.is_some() {
        bail!("a merge is already in progress; resolve it and run `wonton merge --continue`");
    }
    let current_branch = cs.branch.clone();
    let ours_tip = cs
        .tips
        .get(&current_branch)
        .copied()
        .ok_or_else(|| anyhow!("branch '{current_branch}' has no commits yet; nothing to merge into"))?;
    let theirs_tip = cs.tips.get(branch).copied().ok_or_else(|| {
        anyhow!("unknown branch '{branch}'; `pull`/`switch` to make it known locally first")
    })?;

    if ours_tip == theirs_tip {
        println!("Branch '{branch}' is already merged into '{current_branch}'.");
        return Ok(());
    }

    let base = wonton_vcs::merge_base(&store, ours_tip, theirs_tip)?;
    let ours_tree = tree_of_commit(&store, ours_tip)?;
    let theirs_tree = tree_of_commit(&store, theirs_tip)?;

    let base_map = tree_to_plaintext_map(&store, &cipher, base)?;
    let ours_map = tree_to_plaintext_map(&store, &cipher, Some(ours_tip))?;
    let theirs_map = tree_to_plaintext_map(&store, &cipher, Some(theirs_tip))?;

    let merged = wonton_vcs::three_way_merge(&base_map, &ours_map, &theirs_map);

    let mut resolved_plaintext: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();
    let mut conflicts: BTreeMap<String, ConflictHashes> = BTreeMap::new();
    for (key, entry) in merged {
        match entry {
            MergeEntry::Resolved(value) => {
                resolved_plaintext.insert(key, value);
            }
            MergeEntry::Conflict { .. } => {
                conflicts.insert(
                    key.clone(),
                    ConflictHashes {
                        ours: ours_tree.entries.get(&key).copied(),
                        theirs: theirs_tree.entries.get(&key).copied(),
                    },
                );
            }
        }
    }

    if conflicts.is_empty() {
        let hash = finalize_merge_commit(
            &store,
            &cipher,
            author_id,
            ours_tip,
            theirs_tip,
            &ours_map,
            resolved_plaintext,
            &BTreeMap::new(),
            branch,
        )?;
        let cs = state.context_mut(&ctx.name);
        cs.tips.insert(current_branch, hash);
        state.save_to(state_path)?;
        return Ok(());
    }

    // Conflicts exist: persist the initial (fully unresolved) state up front, so even an
    // immediate `s`kip on the very first key leaves a resumable `--continue` state on disk.
    let mut resolved: BTreeMap<String, ResolvedEntry> = BTreeMap::new();
    let cs = state.context_mut(&ctx.name);
    cs.merge = Some(MergeState {
        branch: branch.to_string(),
        ours_tip,
        theirs_tip,
        base,
        resolved: resolved.clone(),
        conflicts: conflicts.clone(),
    });
    state.save_to(state_path)?;

    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut stdout = std::io::stdout();
    resolve_conflicts_interactively(&store, &cipher, &mut reader, &mut stdout, &mut conflicts, &mut resolved, |c, r| {
        let mut state = LocalState::load_from(state_path)?;
        let cs = state.context_mut(&ctx.name);
        cs.merge = Some(MergeState {
            branch: branch.to_string(),
            ours_tip,
            theirs_tip,
            base,
            resolved: r.clone(),
            conflicts: c.clone(),
        });
        Ok(state.save_to(state_path)?)
    })?;

    if conflicts.is_empty() {
        let hash = finalize_merge_commit(
            &store,
            &cipher,
            author_id,
            ours_tip,
            theirs_tip,
            &ours_map,
            resolved_plaintext,
            &resolved,
            branch,
        )?;
        let mut state = LocalState::load_from(state_path)?;
        let cs = state.context_mut(&ctx.name);
        cs.tips.insert(current_branch, hash);
        cs.merge = None;
        state.save_to(state_path)?;
    } else {
        println!(
            "Merge paused: {} conflict(s) remain. Resolve them and run `wonton merge --continue`.",
            conflicts.len()
        );
    }
    Ok(())
}

/// `wonton merge --continue` — resume a merge paused by `merge` on unresolved conflicts.
pub async fn merge_continue(
    config_path: &Path,
    state_path: &Path,
    socket_path: &Path,
    ctx_name: &str,
) -> anyhow::Result<()> {
    let config = Config::load_from(config_path)?;
    let (ctx, identity) = ready_context(&config, socket_path, ctx_name).await?;
    let store = open_object_store(&object_store_dir_for(state_path))?;
    let cipher = AgentCipher::new(socket_path, ctx.name.clone());
    let author_id = Uuid::parse_str(&identity.user_id)
        .with_context(|| format!("identity user_id '{}' is not a valid UUID", identity.user_id))?;

    let state = LocalState::load_from(state_path)?;
    let cs = state.context(&ctx.name).cloned().unwrap_or_default();
    let mut merge_state = cs
        .merge
        .clone()
        .ok_or_else(|| anyhow!("no merge in progress; run `wonton merge <branch>` first"))?;

    let branch_name = merge_state.branch.clone();
    let ours_tip = merge_state.ours_tip;
    let theirs_tip = merge_state.theirs_tip;
    let base = merge_state.base;

    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut stdout = std::io::stdout();
    resolve_conflicts_interactively(
        &store,
        &cipher,
        &mut reader,
        &mut stdout,
        &mut merge_state.conflicts,
        &mut merge_state.resolved,
        |c, r| {
            let mut state = LocalState::load_from(state_path)?;
            let cs = state.context_mut(&ctx.name);
            cs.merge = Some(MergeState {
                branch: branch_name.clone(),
                ours_tip,
                theirs_tip,
                base,
                resolved: r.clone(),
                conflicts: c.clone(),
            });
            Ok(state.save_to(state_path)?)
        },
    )?;

    if merge_state.conflicts.is_empty() {
        let base_map = tree_to_plaintext_map(&store, &cipher, base)?;
        let ours_map = tree_to_plaintext_map(&store, &cipher, Some(ours_tip))?;
        let theirs_map = tree_to_plaintext_map(&store, &cipher, Some(theirs_tip))?;
        let merged = wonton_vcs::three_way_merge(&base_map, &ours_map, &theirs_map);
        let mut resolved_plaintext: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();
        for (key, entry) in merged {
            if let MergeEntry::Resolved(value) = entry {
                resolved_plaintext.insert(key, value);
            }
        }

        let hash = finalize_merge_commit(
            &store,
            &cipher,
            author_id,
            ours_tip,
            theirs_tip,
            &ours_map,
            resolved_plaintext,
            &merge_state.resolved,
            &branch_name,
        )?;

        let mut state = LocalState::load_from(state_path)?;
        let cs = state.context_mut(&ctx.name);
        let current_branch = cs.branch.clone();
        cs.tips.insert(current_branch, hash);
        cs.merge = None;
        state.save_to(state_path)?;
    } else {
        // Already persisted incrementally by `resolve_conflicts_interactively`'s `persist` closure.
        println!(
            "Merge paused: {} conflict(s) remain. Resolve them and run `wonton merge --continue`.",
            merge_state.conflicts.len()
        );
    }
    Ok(())
}

/// `wonton merge --abort` — discard a paused merge entirely. Safe by construction: a paused
/// merge has never produced a commit (that only happens once every conflict is resolved and
/// `merge`/`merge --continue` finalizes it), so there is nothing to unwind except the persisted
/// `MergeState` itself. The branch tip and all prior history are untouched.
pub async fn merge_abort(state_path: &Path, ctx_name: &str) -> anyhow::Result<()> {
    let mut state = LocalState::load_from(state_path)?;
    let cs = state.context(ctx_name).cloned().unwrap_or_default();
    let merge_state = cs
        .merge
        .ok_or_else(|| anyhow!("no merge in progress; nothing to abort"))?;
    state.context_mut(ctx_name).merge = None;
    state.save_to(state_path)?;
    println!(
        "Aborted the merge of '{}' ({} unresolved conflict(s) discarded).",
        merge_state.branch,
        merge_state.conflicts.len()
    );
    Ok(())
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
// Phase 5a: sharing, revocation, and DEK rotation.
//
// `share` is O(1) — it wraps a COPY of the already-cached DEK for a new recipient, no value
// re-encryption. `revoke` and `key rotate` both run `perform_rotation`: a fresh DEK is generated
// in the agent, the committed history is re-encrypted under it, the new DEK is re-wrapped for
// every *remaining* member, and everything is applied in one atomic server-side rotate batch. A
// revoked user, holding only the retired DEK, can no longer decrypt anything committed afterward.
// =====================================================================================

/// `wonton share <user> --env <ctx> [--role ...]` — grant `target_username` access to the
/// context's environment by wrapping a copy of the currently-cached DEK for their X25519 public
/// key. O(1): no value re-encryption, no rotation.
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
/// Revocation *is* rotation: the target may have cached the old DEK, so the only
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

/// The shared 8-step rotation both `revoke` and `key rotate` run. Assumes the
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

/// Parse a commit hash argument, accepting either the full 64-char hex hash or an unambiguous
/// prefix of it (git-style abbreviation). A prefix is resolved against `store`, then filtered to
/// hashes that are actually `Commit` objects (a prefix that happens to also match a tree/blob is
/// not a valid commit reference). Fails closed on no match or on ambiguity, listing candidates
/// rather than silently picking one.
fn parse_commit_hash(store: &LocalObjectStore, s: &str) -> anyhow::Result<Hash> {
    if s.len() == HASH_LEN * 2 {
        return Hash::from_hex(s).map_err(|_| anyhow!("'{s}' is not a valid commit hash"));
    }
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("'{s}' is not a valid commit hash or hash prefix");
    }
    let candidates = store.resolve_prefix(s)?;
    let commit_matches: Vec<Hash> = candidates
        .into_iter()
        .filter(|h| {
            store
                .get(h)
                .ok()
                .flatten()
                .is_some_and(|bytes| Commit::from_bytes(&bytes).is_ok())
        })
        .collect();
    match commit_matches.as_slice() {
        [] => bail!("no commit matches hash prefix '{s}'"),
        [only] => Ok(*only),
        many => {
            let list: Vec<String> = many.iter().map(|h| h.to_hex()).collect();
            bail!(
                "hash prefix '{s}' is ambiguous ({} matching commits): {}",
                many.len(),
                list.join(", ")
            )
        }
    }
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

/// Collect every local commit/tree/blob hash reachable from `tip`, stopping a given path at
/// `stop` (the remote's current tip), a root, an object the local store lacks, or a
/// previously-visited hash. Walks **every** parent of a merge commit (Phase 5b), not just the
/// first — unlike `log`'s mainline-only walk, `push` must upload objects reachable via a merge
/// commit's second parent too (e.g. a side branch merged in but never separately pushed on this
/// ref). Uploading is idempotent server-side, so visiting a shared ancestor from two paths and
/// (thanks to `seen`) collecting it only once is an optimization, not a correctness requirement.
fn collect_objects_to_push(
    store: &LocalObjectStore,
    tip: Hash,
    stop: Option<Hash>,
) -> anyhow::Result<Vec<Hash>> {
    let mut hashes = Vec::new();
    let mut seen = HashSet::new();
    let mut worklist = vec![tip];

    while let Some(current) = worklist.pop() {
        if Some(current) == stop || !seen.insert(current) {
            continue;
        }
        let bytes = match store.get(&current)? {
            Some(b) => b,
            // Not in the local store: it's already on the server (older history) — stop walking.
            None => continue,
        };
        hashes.push(current);
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

        worklist.extend(commit.fields.parent_hashes.iter().copied());
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

#[cfg(test)]
mod merge_prompt_tests {
    use std::io::Cursor;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use wonton_crypto::{generate_dek, generate_identity, wrap_dek};

    use super::*;
    use crate::agent::daemon;
    use crate::agent::protocol::Argon2ParamsWire;

    // ---- prompt_conflict_resolution (pure, no store/cipher needed) ---------------------------

    #[test]
    fn ours_and_theirs_are_parsed() {
        let mut out = Vec::new();
        let outcome =
            prompt_conflict_resolution(&mut Cursor::new(b"o\n".to_vec()), &mut out, "K", Some(b"a"), Some(b"b"))
                .unwrap();
        assert!(matches!(outcome, PromptOutcome::Ours));

        let mut out = Vec::new();
        let outcome =
            prompt_conflict_resolution(&mut Cursor::new(b"t\n".to_vec()), &mut out, "K", Some(b"a"), Some(b"b"))
                .unwrap();
        assert!(matches!(outcome, PromptOutcome::Theirs));
    }

    #[test]
    fn skip_and_eof_both_yield_skip() {
        let mut out = Vec::new();
        let outcome =
            prompt_conflict_resolution(&mut Cursor::new(b"s\n".to_vec()), &mut out, "K", Some(b"a"), Some(b"b"))
                .unwrap();
        assert!(matches!(outcome, PromptOutcome::Skip));

        let mut out = Vec::new();
        let outcome =
            prompt_conflict_resolution(&mut Cursor::new(Vec::new()), &mut out, "K", Some(b"a"), Some(b"b")).unwrap();
        assert!(matches!(outcome, PromptOutcome::Skip), "EOF on a non-interactive stdin must not hang or panic");
    }

    #[test]
    fn manual_entry_reads_the_typed_value() {
        let mut out = Vec::new();
        let outcome = prompt_conflict_resolution(
            &mut Cursor::new(b"m\nmanual-value\n".to_vec()),
            &mut out,
            "K",
            Some(b"a"),
            Some(b"b"),
        )
        .unwrap();
        match outcome {
            PromptOutcome::Manual(v) => assert_eq!(v, "manual-value"),
            _ => panic!("expected Manual"),
        }
    }

    #[test]
    fn unrecognized_input_reprompts_then_accepts_a_valid_choice() {
        let mut out = Vec::new();
        let outcome = prompt_conflict_resolution(
            &mut Cursor::new(b"nonsense\no\n".to_vec()),
            &mut out,
            "K",
            Some(b"a"),
            Some(b"b"),
        )
        .unwrap();
        assert!(matches!(outcome, PromptOutcome::Ours));
        let printed = String::from_utf8(out).unwrap();
        assert!(printed.contains("Please enter"), "must nudge the user on garbage input, got:\n{printed}");
    }

    #[test]
    fn deleted_sides_render_distinctly_from_binary_or_utf8() {
        assert_eq!(display_conflict_value(None), "<deleted>");
        assert_eq!(display_conflict_value(Some(b"hello")), "hello");
        assert!(display_conflict_value(Some(&[0xff, 0xfe, 0x00])).starts_with("<binary"));
    }

    // ---- resolve_conflicts_interactively (needs a real store + agent-cached DEK) --------------

    fn unique_path(tag: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!(
            "wonton-merge-resolve-test-{tag}-{}-{n}-{nanos}",
            std::process::id()
        ))
    }

    async fn agent_with_dek_and_store(context: &str) -> (PathBuf, LocalObjectStore) {
        let sock = unique_path("sock").with_extension("sock");
        let listener = daemon::bind_listener(&sock).await.expect("bind agent socket");
        tokio::spawn(daemon::serve(listener, daemon::new_state()));

        let passphrase = b"pw-merge-resolve";
        let (public, wrapped) = generate_identity(passphrase);
        let blob = [wrapped.nonce.as_slice(), wrapped.ciphertext.as_slice()].concat();
        let params = Argon2ParamsWire {
            salt_b64: STANDARD.encode(wrapped.argon2_params.salt),
            m_cost_kib: wrapped.argon2_params.m_cost_kib,
            t_cost: wrapped.argon2_params.t_cost,
            p_cost: wrapped.argon2_params.p_cost,
        };
        agent::login(&sock, STANDARD.encode(&blob), params, String::from_utf8_lossy(passphrase).into_owned())
            .await
            .expect("agent login");

        let dek = generate_dek();
        let sealed = wrap_dek(&dek, &public.x25519_pubkey);
        agent::unwrap_dek(&sock, context.to_string(), STANDARD.encode(&sealed.0))
            .await
            .expect("agent unwrap dek");

        let store = open_object_store(&unique_path("objects")).expect("open object store");
        (sock, store)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stops_on_skip_and_persists_after_every_resolution_not_before() {
        let (sock, store) = agent_with_dek_and_store("ctx").await;
        let cipher = AgentCipher::new(sock, "ctx");

        let ours_a = encrypt_and_store(&store, &cipher, b"ours-a").unwrap();
        let theirs_a = encrypt_and_store(&store, &cipher, b"theirs-a").unwrap();
        let ours_b = encrypt_and_store(&store, &cipher, b"ours-b").unwrap();
        let theirs_b = encrypt_and_store(&store, &cipher, b"theirs-b").unwrap();

        let mut conflicts = BTreeMap::new();
        conflicts.insert("A".to_string(), ConflictHashes { ours: Some(ours_a), theirs: Some(theirs_a) });
        conflicts.insert("B".to_string(), ConflictHashes { ours: Some(ours_b), theirs: Some(theirs_b) });
        let mut resolved = BTreeMap::new();

        // "A" resolved via ours; "B" is skipped, stopping the loop.
        let mut reader = Cursor::new(b"o\ns\n".to_vec());
        let mut writer = Vec::new();
        let mut persist_calls = 0u32;
        resolve_conflicts_interactively(&store, &cipher, &mut reader, &mut writer, &mut conflicts, &mut resolved, |_c, _r| {
            persist_calls += 1;
            Ok(())
        })
        .unwrap();

        assert_eq!(persist_calls, 1, "persist must run exactly once, right after A resolves");
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved.get("A"), Some(&ResolvedEntry::Set(ours_a)));
        assert_eq!(conflicts.len(), 1, "B must remain unresolved after a skip");
        assert!(conflicts.contains_key("B"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn manual_and_delete_vs_modify_resolutions_work() {
        let (sock, store) = agent_with_dek_and_store("ctx").await;
        let cipher = AgentCipher::new(sock, "ctx");

        let theirs_hash = encrypt_and_store(&store, &cipher, b"theirs-value").unwrap();

        let mut conflicts = BTreeMap::new();
        // "DELETED": ours deleted it (None), theirs modified it.
        conflicts.insert("DELETED".to_string(), ConflictHashes { ours: None, theirs: Some(theirs_hash) });
        let mut resolved = BTreeMap::new();

        // Resolve "DELETED" manually to a brand-new value.
        let mut reader = Cursor::new(b"m\nmanual-resolution\n".to_vec());
        let mut writer = Vec::new();
        resolve_conflicts_interactively(&store, &cipher, &mut reader, &mut writer, &mut conflicts, &mut resolved, |_c, _r| Ok(()))
            .unwrap();

        assert!(conflicts.is_empty());
        match resolved.get("DELETED") {
            Some(ResolvedEntry::Set(hash)) => {
                let plaintext = decrypt_blob(&store, &cipher, hash).unwrap();
                assert_eq!(plaintext, b"manual-resolution");
            }
            other => panic!("expected a manually-resolved Set entry, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn theirs_choice_on_a_deleted_side_resolves_to_delete() {
        let (sock, store) = agent_with_dek_and_store("ctx").await;
        let cipher = AgentCipher::new(sock, "ctx");

        let ours_hash = encrypt_and_store(&store, &cipher, b"ours-value").unwrap();
        let mut conflicts = BTreeMap::new();
        // ours modified it, theirs deleted it (None) — choosing "theirs" must resolve to Delete.
        conflicts.insert("KEY".to_string(), ConflictHashes { ours: Some(ours_hash), theirs: None });
        let mut resolved = BTreeMap::new();

        let mut reader = Cursor::new(b"t\n".to_vec());
        let mut writer = Vec::new();
        resolve_conflicts_interactively(&store, &cipher, &mut reader, &mut writer, &mut conflicts, &mut resolved, |_c, _r| Ok(()))
            .unwrap();

        assert_eq!(resolved.get("KEY"), Some(&ResolvedEntry::Delete));
    }
}
