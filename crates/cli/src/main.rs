//! `wonton` — the CLI porcelain and crypto engine.
//!
//! This binary hosts the identity / context-switching commands (`login`, `context`, `use`,
//! `link`) built on top of the ssh-agent-style key daemon (the hidden `agent` subcommand group).

mod agent;
mod commands;
mod config;
mod state;

#[cfg(test)]
mod tests;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "wonton",
    bin_name = "wonton",
    version,
    about = "Wonton — an end-to-end encrypted, git-like secrets manager"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Unlock an identity into the agent, registering it on first use.
    Login {
        /// The server-facing username to log in as (also the local identity nickname).
        username: String,
        /// The server URL. Required the first time a username is used; reused from config after.
        #[arg(long)]
        server: Option<String>,
    },
    /// Manage and inspect contexts. With no subcommand, shows the current context.
    Context {
        #[command(subcommand)]
        command: Option<ContextCommand>,
    },
    /// Switch to a context, unwrapping its environment DEK into the agent.
    Use {
        /// The context name (see `wonton context list`).
        name: String,
    },
    /// Bind the current directory to a context by writing a `.wonton` marker.
    Link {
        /// The context name to link.
        name: String,
    },
    /// Provision a new store on the server.
    Store {
        #[command(subcommand)]
        command: StoreCommand,
    },
    /// Provision a new environment within a store, self-granting its first DEK.
    Env {
        #[command(subcommand)]
        command: EnvCommand,
    },
    /// Switch the current context to a different branch (purely local; no unwrap).
    Switch {
        /// The branch to switch to.
        branch: String,
        /// Allow switching to a branch with no local history yet — either to start a brand
        /// new branch, or because you're about to `wonton pull` one that exists remotely.
        #[arg(long)]
        create: bool,
    },
    /// Show the current context, branch, DEK-cache status, and staged changes.
    Status,
    /// Stage one or more `KEY=VALUE` secrets in the current context.
    Set {
        /// `KEY=VALUE` pairs to stage.
        #[arg(required = true)]
        pairs: Vec<String>,
    },
    /// Stage deletion of one or more keys in the current context.
    Unset {
        /// Key names to unset.
        #[arg(required = true)]
        keys: Vec<String>,
    },
    /// Commit the staged changes in the current context.
    Commit {
        #[arg(short, long)]
        message: String,
    },
    /// Show the verified commit history of the current branch.
    Log,
    /// Diff two commits (or the last commit's change if no args are given).
    Diff {
        /// The "from" commit hash (or the only commit, diffed against the empty tree).
        a: Option<String>,
        /// The "to" commit hash.
        b: Option<String>,
    },
    /// Fetch and fast-forward the current branch from the server.
    Pull,
    /// Upload local commits and move the branch ref on the server.
    Push,
    /// Three-way merge a branch into the current branch, resume a paused merge with
    /// `--continue`, or discard one with `--abort`. Exactly one of `branch` / `--continue` /
    /// `--abort` must be given.
    Merge {
        /// The branch to merge into the current branch.
        branch: Option<String>,
        /// Resume a merge paused earlier on unresolved conflicts.
        #[arg(long = "continue")]
        resume: bool,
        /// Discard a paused merge entirely (no commit was ever made, so there's nothing else to
        /// unwind).
        #[arg(long)]
        abort: bool,
    },
    /// Run a command with the current context's secrets injected as env vars (never on disk).
    Run {
        /// The command and its arguments (everything after `--`).
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
    },
    /// Export the current context's secrets to a file (plaintext — prints a warning).
    Export {
        /// Output format (only `dotenv` is supported in v1).
        #[arg(long)]
        format: String,
        /// The file to write.
        path: PathBuf,
    },
    /// Grant a user access to a context's environment (wraps the DEK for them; O(1)).
    Share {
        /// The username to share with.
        user: String,

        /// The context to share (a context name, per `wonton context list` — not the server-side
        /// environment name).
        #[arg(long)]
        context: String,
        /// The role to grant.
        #[arg(long, default_value = "reader")]
        role: String,
    },
    /// Revoke a user's access to a context's environment (removes them and rotates the DEK).
    Revoke {
        /// The username to revoke.
        user: String,
        /// The context to revoke access to (a context name, not the server-side environment
        /// name).
        #[arg(long)]
        context: String,
    },
    /// Data-key management for a context's environment.
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    /// Key agent daemon management (internal use).
    #[command(subcommand, hide = true)]
    Agent(agent::AgentCommand),
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    /// Rotate the environment's DEK, re-encrypting history and re-wrapping for members.
    Rotate {
        /// The context whose environment DEK to rotate (a context name, not the server-side
        /// environment name).
        #[arg(long)]
        context: String,
    },
}

#[derive(Debug, Subcommand)]
enum ContextCommand {
    /// Add (or update) a context.
    Add {
        /// The context name.
        name: String,
        #[arg(long)]
        store: String,
        #[arg(long = "env")]
        environment: String,
        /// The local identity name this context reads with.
        #[arg(long)]
        identity: String,
    },
    /// List all configured contexts.
    List,
}

#[derive(Debug, Subcommand)]
enum StoreCommand {
    /// Create a new store on the server.
    Create {
        /// The store's name.
        name: String,
        /// The local identity to create it as. Only needed if more than one identity is
        /// logged in locally.
        #[arg(long)]
        identity: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum EnvCommand {
    /// Create a new environment within a store and self-grant its first DEK.
    Create {
        /// The store the environment belongs to.
        store: String,
        /// The environment's name.
        name: String,
        /// The local identity to create it as. Only needed if more than one identity is
        /// logged in locally.
        #[arg(long)]
        identity: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Login { username, server } => {
            let config_path = config::default_config_path()?;
            let socket = agent::client::ensure_running().await?;
            let passphrase = rpassword::prompt_password("Passphrase: ")?;
            commands::login(&config_path, &socket, server, &username, passphrase).await
        }
        Command::Context { command } => match command {
            Some(ContextCommand::Add {
                name,
                store,
                environment,
                identity,
            }) => {
                let config_path = config::default_config_path()?;
                commands::context_add(&config_path, &name, &store, &environment, &identity)
            }
            Some(ContextCommand::List) => {
                let config_path = config::default_config_path()?;
                commands::context_list(&config_path)
            }
            None => {
                let config_path = config::default_config_path()?;
                // Don't auto-start the agent just to report cache status.
                let socket = agent::default_socket_path()?;
                let cwd = current_dir()?;
                commands::context_show(&config_path, &socket, &cwd).await
            }
        },
        Command::Use { name } => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let socket = agent::client::ensure_running().await?;
            commands::use_context(&config_path, &state_path, &socket, &name).await
        }
        Command::Link { name } => {
            let config_path = config::default_config_path()?;
            let cwd = current_dir()?;
            commands::link(&config_path, &cwd, &name)
        }
        Command::Store { command } => match command {
            StoreCommand::Create { name, identity } => {
                let config_path = config::default_config_path()?;
                commands::store_create(&config_path, identity.as_deref(), &name).await
            }
        },
        Command::Env { command } => match command {
            EnvCommand::Create { store, name, identity } => {
                let config_path = config::default_config_path()?;
                let socket = agent::client::ensure_running().await?;
                commands::env_create(&config_path, &socket, identity.as_deref(), &store, &name).await
            }
        },
        Command::Switch { branch, create } => {
            let state_path = state::default_state_path()?;
            let ctx = resolve_ctx()?;
            commands::switch(&state_path, &ctx, &branch, create)
        }
        Command::Status => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let socket = agent::default_socket_path()?;
            let ctx = resolve_ctx()?;
            commands::status(&config_path, &state_path, &socket, &ctx).await
        }
        Command::Set { pairs } => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let parsed = parse_pairs(&pairs)?;
            let socket = agent::client::ensure_running().await?;
            let ctx = resolve_ctx()?;
            commands::set(&config_path, &state_path, &socket, &ctx, parsed).await
        }
        Command::Unset { keys } => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let ctx = resolve_ctx()?;
            commands::unset(&config_path, &state_path, &ctx, keys)
        }
        Command::Commit { message } => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let socket = agent::client::ensure_running().await?;
            let ctx = resolve_ctx()?;
            commands::commit(&config_path, &state_path, &socket, &ctx, message).await
        }
        Command::Log => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let ctx = resolve_ctx()?;
            commands::log(&config_path, &state_path, &ctx).await
        }
        Command::Diff { a, b } => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let socket = agent::client::ensure_running().await?;
            let ctx = resolve_ctx()?;
            let entries = commands::diff(&config_path, &state_path, &socket, &ctx, a, b).await?;
            if entries.is_empty() {
                println!("No changes.");
            }
            for entry in entries {
                match entry {
                    wonton_vcs::DiffEntry::Added(k) => println!("+ {k}"),
                    wonton_vcs::DiffEntry::Removed(k) => println!("- {k}"),
                    wonton_vcs::DiffEntry::Changed(k) => println!("~ {k}"),
                }
            }
            Ok(())
        }
        Command::Pull => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let ctx = resolve_ctx()?;
            commands::pull(&config_path, &state_path, &ctx).await
        }
        Command::Push => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let ctx = resolve_ctx()?;
            commands::push(&config_path, &state_path, &ctx).await
        }
        Command::Run { cmd } => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let socket = agent::client::ensure_running().await?;
            let ctx = resolve_ctx()?;
            let code = commands::run(&config_path, &state_path, &socket, &ctx, cmd).await?;
            std::process::exit(code);
        }
        Command::Export { format, path } => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let socket = agent::client::ensure_running().await?;
            let ctx = resolve_ctx()?;
            let format = commands::ExportFormat::parse(&format)?;
            commands::export(&config_path, &state_path, &socket, &ctx, format, &path).await
        }
        Command::Merge { branch, resume, abort } => {
            let state_path = state::default_state_path()?;
            let ctx = resolve_ctx()?;
            match (branch, resume, abort) {
                (None, false, true) => commands::merge_abort(&state_path, &ctx).await,
                (Some(_), _, true) | (_, true, true) => {
                    anyhow::bail!("pass exactly one of a branch name, `--continue`, or `--abort`")
                }
                (Some(_), true, false) => anyhow::bail!("pass either a branch name or `--continue`, not both"),
                (Some(branch), false, false) => {
                    let config_path = config::default_config_path()?;
                    let socket = agent::client::ensure_running().await?;
                    commands::merge(&config_path, &state_path, &socket, &ctx, &branch).await
                }
                (None, true, false) => {
                    let config_path = config::default_config_path()?;
                    let socket = agent::client::ensure_running().await?;
                    commands::merge_continue(&config_path, &state_path, &socket, &ctx).await
                }
                (None, false, false) => {
                    anyhow::bail!("usage: `wonton merge <branch>`, `wonton merge --continue`, or `wonton merge --abort`")
                }
            }
        }
        Command::Share { user, context, role } => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let socket = agent::client::ensure_running().await?;
            let role = parse_role(&role)?;
            commands::share(&config_path, &state_path, &socket, &context, &user, role).await
        }
        Command::Revoke { user, context } => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let socket = agent::client::ensure_running().await?;
            commands::revoke(&config_path, &state_path, &socket, &context, &user).await
        }
        Command::Key { command } => match command {
            KeyCommand::Rotate { context } => {
                let config_path = config::default_config_path()?;
                let state_path = state::default_state_path()?;
                let socket = agent::client::ensure_running().await?;
                commands::rotate(&config_path, &state_path, &socket, &context).await
            }
        },
        Command::Agent(command) => agent::run(command).await,
    }
}

/// Parse the `--role` flag for `wonton share` into a [`wonton_shared::Role`]. Mirrors the
/// lowercase serde representation the wire type uses.
fn parse_role(s: &str) -> anyhow::Result<wonton_shared::Role> {
    match s.to_ascii_lowercase().as_str() {
        "admin" => Ok(wonton_shared::Role::Admin),
        "writer" => Ok(wonton_shared::Role::Writer),
        "reader" => Ok(wonton_shared::Role::Reader),
        other => anyhow::bail!("invalid role '{other}'; expected reader, writer, or admin"),
    }
}

fn current_dir() -> anyhow::Result<PathBuf> {
    std::env::current_dir().map_err(|e| anyhow::anyhow!("cannot determine current directory: {e}"))
}

/// Resolve the current context name for the VCS porcelain commands, via the `.wonton` marker (in
/// the cwd or an ancestor) or `config.current_context`. All these commands operate on "the current
/// context"; there is no `--context` flag in v1.
fn resolve_ctx() -> anyhow::Result<String> {
    let config_path = config::default_config_path()?;
    let config = config::Config::load_from(&config_path)?;
    let cwd = current_dir()?;
    config::resolve_context_name(&config, &cwd)
}

/// Parse `KEY=VALUE` positional arguments into pairs, erroring clearly on a missing `=`.
fn parse_pairs(pairs: &[String]) -> anyhow::Result<Vec<(String, String)>> {
    pairs
        .iter()
        .map(|pair| {
            let (key, value) = pair
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("'{pair}' is not a KEY=VALUE pair (missing '=')"))?;
            if key.is_empty() {
                anyhow::bail!("'{pair}' has an empty key");
            }
            Ok((key.to_string(), value.to_string()))
        })
        .collect()
}
