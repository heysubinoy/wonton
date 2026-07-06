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

use std::path::Path;

use anyhow::{bail, Context as _};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use wonton_crypto::generate_identity;
use wonton_shared::{
    Argon2ParamsDto, LoginCompleteRequest, LoginStartRequest, RegisterRequest,
};
use wonton_sync::{SyncClient, SyncError};

use crate::agent::client as agent;
use crate::agent::protocol::Argon2ParamsWire;
use crate::config::{self, Config, Context, Identity};

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
pub async fn use_context(config_path: &Path, socket_path: &Path, name: &str) -> anyhow::Result<()> {
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
    agent::unwrap_dek(socket_path, ctx.name.clone(), entry.sealed_box.clone())
        .await
        .context("agent could not unwrap the DEK for this environment")?;

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
