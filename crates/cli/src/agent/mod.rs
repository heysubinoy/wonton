//! `wonton-agent` — the ssh-agent-style key agent.
//!
//! `wonton login` unlocks a user's identity ONCE per session into this long-lived daemon; every
//! later command borrows the unlocked capability without re-prompting for a passphrase and —
//! critically — **without any raw secret key material ever leaving the agent process.** The
//! agent performs operations (sign a message, unwrap/cache a DEK, encrypt/decrypt a value under
//! a cached DEK) and returns only non-secret results (a signature, a plaintext value). It never
//! hands back the identity seed or a raw `Dek`. This is what makes keeping secrets off disk and
//! key material confined and zeroized tractable: raw key material stays in one place.
//!
//! Submodules: [`protocol`] (the shared wire types), [`daemon`] (the resident process), and
//! [`client`] (connect / auto-start / typed request wrappers).

// The client exposes one typed wrapper per protocol operation. Several are not yet called by
// the built `status`/`lock` subcommands — they are the API the future `login`/`use`/etc.
// commands (a later task) will use. Allow dead code on the whole module rather than peppering
// each forward-looking wrapper with an attribute.
#[allow(dead_code)]
pub mod client;
pub mod cipher;
pub mod daemon;
pub mod protocol;

use std::path::PathBuf;

use anyhow::Context;
use clap::Subcommand;
use directories::BaseDirs;

/// The agent socket file name inside the runtime/data directory.
const SOCKET_NAME: &str = "wonton-agent.sock";

/// `wonton agent <...>` — internal-use subcommands for the key daemon. Hidden from the top-level
/// help: end users interact with the agent implicitly via `login`/`use`/etc. (a later task).
#[derive(Debug, Subcommand)]
pub enum AgentCommand {
    /// Run the agent daemon in the foreground (normally auto-started as a detached child).
    Start,
    /// Report whether the agent is reachable and, if so, whether it is unlocked.
    Status,
    /// Wipe the agent's in-memory state (identity + cached DEKs), like `ssh-add -D`.
    Lock,
}

/// Resolve the agent socket path. Prefers the XDG runtime directory (`XDG_RUNTIME_DIR` on Linux)
/// when available — it is the correct home for ephemeral, per-user, per-session sockets — and
/// otherwise falls back to the data-local directory joined with a `wonton` subdirectory, created
/// if missing.
pub fn default_socket_path() -> anyhow::Result<PathBuf> {
    let base = BaseDirs::new().context("could not determine a home directory for the socket")?;
    let dir = if let Some(runtime_dir) = base.runtime_dir() {
        runtime_dir.to_path_buf()
    } else {
        let dir = base.data_local_dir().join("wonton");
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating agent directory {}", dir.display()))?;
        dir
    };
    Ok(dir.join(SOCKET_NAME))
}

/// Execute a `wonton agent <...>` subcommand.
pub async fn run(command: AgentCommand) -> anyhow::Result<()> {
    match command {
        AgentCommand::Start => daemon::run().await,
        AgentCommand::Status => run_status().await,
        AgentCommand::Lock => run_lock().await,
    }
}

async fn run_status() -> anyhow::Result<()> {
    let path = default_socket_path()?;
    match client::status(&path).await {
        Ok(status) => {
            if status.unlocked {
                if status.cached_contexts.is_empty() {
                    println!("agent running: unlocked, no cached contexts");
                } else {
                    println!(
                        "agent running: unlocked, cached contexts: {}",
                        status.cached_contexts.join(", ")
                    );
                }
            } else {
                println!("agent running: locked");
            }
            Ok(())
        }
        Err(client::ClientError::Unreachable) => {
            println!("agent not running");
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

async fn run_lock() -> anyhow::Result<()> {
    let path = default_socket_path()?;
    match client::lock(&path).await {
        Ok(()) => {
            println!("agent locked");
            Ok(())
        }
        Err(client::ClientError::Unreachable) => {
            println!("no agent running");
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests;
