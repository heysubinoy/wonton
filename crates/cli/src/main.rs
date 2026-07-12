//! `wonton` — the CLI porcelain and crypto engine.
//!
//! This binary hosts the identity/workspace commands (`login`, `init`, `clone`, `branch`) built
//! on top of the ssh-agent-style key daemon (the hidden `agent` subcommand group).

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
    /// Show which identity/identities are logged in locally, and which server each points at.
    Whoami,
    /// Forget a cached identity's key material locally. Defaults to the sole/current identity if
    /// more than one is cached. The account still exists server-side.
    Logout {
        /// The local identity nickname to forget. Only needed if more than one is cached.
        name: Option<String>,
    },
    /// Manage machine-wide defaults in the global config (`~/.config/wonton/config.toml`).
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Bootstrap a new project in the current directory — fully local, zero network calls.
    /// Server contact is deferred to the first `wonton push`.
    Init {
        /// The org to bind to. Defaults to your own username.
        org: Option<String>,
        /// The store (repo) name. Defaults to the current directory's name.
        store: Option<String>,
        /// The starting branch. Defaults to "main".
        branch: Option<String>,
        /// The local identity to act as. Only needed if more than one identity is logged in.
        #[arg(long)]
        identity: Option<String>,
    },
    /// Join an existing org/store into the current directory (for a directory that isn't a git
    /// checkout already carrying a `wonton.toml`).
    Clone {
        org: String,
        store: String,
        /// The branch to start on. Defaults to "main".
        branch: Option<String>,
        #[arg(long)]
        identity: Option<String>,
    },
    /// List, switch, or create branches. `wonton branch` alone lists; `wonton branch <name>`
    /// switches; `wonton branch -b <name> [--from <source>]` creates one.
    Branch {
        /// Switch to this branch.
        name: Option<String>,
        /// Create a new branch with this name instead of switching to an existing one.
        #[arg(short = 'b')]
        create: Option<String>,
        /// When creating (`-b`), seed the new branch from this existing branch's current values.
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        identity: Option<String>,
    },
    /// Provision a store (repo) within an org on the server — advanced/manual path; the golden
    /// path (`init`/`branch -b`) defers this to the first `push`.
    Store {
        #[command(subcommand)]
        command: StoreCommand,
    },
    /// Show the current workspace, branch, DEK-cache status, and staged changes.
    Status,
    /// Stage one or more `KEY=VALUE` secrets on the current branch.
    Set {
        /// `KEY=VALUE` pairs to stage.
        #[arg(required = true)]
        pairs: Vec<String>,
    },
    /// Stage deletion of one or more keys on the current branch.
    Unset {
        /// Key names to unset.
        #[arg(required = true)]
        keys: Vec<String>,
    },
    /// Commit the staged changes on the current branch.
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
    /// Upload local commits and move the branch ref on the server. The first push on a branch
    /// also provisions it server-side (org/store/branch + DEK self-grant).
    Push,
    /// Three-way merge another branch into the current branch, resume a paused merge with
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
    /// Run a command with the current branch's secrets injected as env vars (never on disk).
    Run {
        /// The command and its arguments (everything after `--`).
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
    },
    /// Print the current branch's secrets to stdout as `KEY=VALUE` — nothing touches disk.
    View {
        /// List key names only, without values.
        #[arg(long)]
        keys_only: bool,
    },
    /// Export the current branch's secrets to a file (plaintext — prints a warning).
    Export {
        /// Output format (only `dotenv` is supported in v1).
        #[arg(long)]
        format: String,
        /// The file to write.
        path: PathBuf,
    },
    /// Grant a user access to a branch (wraps the DEK for them; O(1)). Also auto-joins them to
    /// the org server-side.
    Share {
        /// The username to share with.
        user: String,
        /// The branch to share. Defaults to the current directory's branch.
        #[arg(long)]
        branch: Option<String>,
        /// The role to grant.
        #[arg(long, default_value = "reader")]
        role: String,
    },
    /// Revoke a user's access to a branch (removes them and rotates the DEK).
    Revoke {
        /// The username to revoke.
        user: String,
        /// The branch to revoke access to. Defaults to the current directory's branch.
        #[arg(long)]
        branch: Option<String>,
    },
    /// Data-key management for a branch.
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
    /// Rotate a branch's DEK, re-encrypting history and re-wrapping for members.
    Rotate {
        /// The branch to rotate. Defaults to the current directory's branch.
        #[arg(long)]
        branch: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Set (or update) the default server URL, used by `login` when `--server` is omitted and
    /// the username isn't already a known identity.
    SetServer {
        url: String,
    },
    /// Show the current default server, if any.
    Show,
}

#[derive(Debug, Subcommand)]
enum StoreCommand {
    /// Create a store (repo) within an org on the server, creating the org first if needed.
    Create {
        /// The org the store belongs to.
        org: String,
        /// The store's name.
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
            let passphrase = match std::env::var("WONTON_PASSPHRASE") {
                Ok(p) => {
                    eprintln!(
                        "wonton: reading passphrase from WONTON_PASSPHRASE — for automation \
                         only; the interactive prompt (omit the env var) is safer for everyday use."
                    );
                    p
                }
                Err(_) => rpassword::prompt_password("Passphrase: ")?,
            };
            commands::login(&config_path, &socket, server, &username, passphrase).await
        }
        Command::Whoami => {
            let config_path = config::default_config_path()?;
            commands::whoami(&config_path)
        }
        Command::Logout { name } => {
            let config_path = config::default_config_path()?;
            let socket = agent::default_socket_path()?;
            commands::logout(&config_path, &socket, name.as_deref()).await
        }
        Command::Config { command } => {
            let config_path = config::default_config_path()?;
            match command {
                ConfigCommand::SetServer { url } => commands::config_set_server(&config_path, &url),
                ConfigCommand::Show => commands::config_show(&config_path),
            }
        }
        Command::Init { org, store, branch, identity } => {
            let config_path = config::default_config_path()?;
            let socket = agent::client::ensure_running().await?;
            let cwd = current_dir()?;
            commands::init(&config_path, &socket, &cwd, org, store, branch, identity.as_deref()).await
        }
        Command::Clone { org, store, branch, identity } => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let socket = agent::client::ensure_running().await?;
            let cwd = current_dir()?;
            commands::clone(&config_path, &state_path, &socket, &cwd, &org, &store, branch.as_deref(), identity.as_deref()).await
        }
        Command::Branch { name, create, from, identity } => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let cwd = current_dir()?;
            match (name, create) {
                (None, None) => commands::branch_list(&config_path, &state_path, &cwd).await,
                (Some(n), None) => {
                    let socket = agent::client::ensure_running().await?;
                    commands::branch_switch(&config_path, &state_path, &socket, &cwd, &n).await
                }
                (None, Some(n)) => {
                    let socket = agent::client::ensure_running().await?;
                    commands::branch_create(&config_path, &state_path, &socket, &cwd, &n, from.as_deref(), identity.as_deref()).await
                }
                (Some(_), Some(_)) => {
                    anyhow::bail!("pass either a branch name to switch to, or -b <name> to create one, not both")
                }
            }
        }
        Command::Store { command } => match command {
            StoreCommand::Create { org, name, identity } => {
                let config_path = config::default_config_path()?;
                commands::store_create(&config_path, identity.as_deref(), &org, &name).await
            }
        },
        Command::Status => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let socket = agent::default_socket_path()?;
            let cwd = current_dir()?;
            commands::status(&config_path, &state_path, &socket, &cwd).await
        }
        Command::Set { pairs } => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let parsed = parse_pairs(&pairs)?;
            let socket = agent::client::ensure_running().await?;
            let cwd = current_dir()?;
            commands::set(&config_path, &state_path, &socket, &cwd, parsed).await
        }
        Command::Unset { keys } => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let cwd = current_dir()?;
            commands::unset(&config_path, &state_path, &cwd, keys)
        }
        Command::Commit { message } => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let socket = agent::client::ensure_running().await?;
            let cwd = current_dir()?;
            commands::commit(&config_path, &state_path, &socket, &cwd, message).await
        }
        Command::Log => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let cwd = current_dir()?;
            commands::log(&config_path, &state_path, &cwd).await
        }
        Command::Diff { a, b } => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let socket = agent::client::ensure_running().await?;
            let cwd = current_dir()?;
            let entries = commands::diff(&config_path, &state_path, &socket, &cwd, a, b).await?;
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
            let cwd = current_dir()?;
            commands::pull(&config_path, &state_path, &cwd).await
        }
        Command::Push => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let socket = agent::client::ensure_running().await?;
            let cwd = current_dir()?;
            commands::push(&config_path, &state_path, &socket, &cwd).await
        }
        Command::Run { cmd } => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let socket = agent::client::ensure_running().await?;
            let cwd = current_dir()?;
            let code = commands::run(&config_path, &state_path, &socket, &cwd, cmd).await?;
            std::process::exit(code);
        }
        Command::View { keys_only } => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let socket = agent::client::ensure_running().await?;
            let cwd = current_dir()?;
            let entries = commands::view(&config_path, &state_path, &socket, &cwd).await?;
            if entries.is_empty() {
                println!("No secrets.");
            }
            for (k, value) in entries {
                if keys_only {
                    println!("{k}");
                } else {
                    match std::str::from_utf8(&value) {
                        Ok(v) => println!("{k}={v}"),
                        Err(_) => println!("{k}=<binary value, {} bytes>", value.len()),
                    }
                }
            }
            Ok(())
        }
        Command::Export { format, path } => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let socket = agent::client::ensure_running().await?;
            let cwd = current_dir()?;
            let format = commands::ExportFormat::parse(&format)?;
            commands::export(&config_path, &state_path, &socket, &cwd, format, &path).await
        }
        Command::Merge { branch, resume, abort } => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let cwd = current_dir()?;
            match (branch, resume, abort) {
                (None, false, true) => commands::merge_abort(&config_path, &state_path, &cwd).await,
                (Some(_), _, true) | (_, true, true) => {
                    anyhow::bail!("pass exactly one of a branch name, `--continue`, or `--abort`")
                }
                (Some(_), true, false) => anyhow::bail!("pass either a branch name or `--continue`, not both"),
                (Some(branch), false, false) => {
                    let socket = agent::client::ensure_running().await?;
                    commands::merge(&config_path, &state_path, &socket, &cwd, &branch).await
                }
                (None, true, false) => {
                    let socket = agent::client::ensure_running().await?;
                    commands::merge_continue(&config_path, &state_path, &socket, &cwd).await
                }
                (None, false, false) => {
                    anyhow::bail!("usage: `wonton merge <branch>`, `wonton merge --continue`, or `wonton merge --abort`")
                }
            }
        }
        Command::Share { user, branch, role } => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let socket = agent::client::ensure_running().await?;
            let cwd = current_dir()?;
            let role = parse_role(&role)?;
            commands::share(&config_path, &state_path, &socket, &cwd, branch.as_deref(), &user, role).await
        }
        Command::Revoke { user, branch } => {
            let config_path = config::default_config_path()?;
            let state_path = state::default_state_path()?;
            let socket = agent::client::ensure_running().await?;
            let cwd = current_dir()?;
            commands::revoke(&config_path, &state_path, &socket, &cwd, branch.as_deref(), &user).await
        }
        Command::Key { command } => match command {
            KeyCommand::Rotate { branch } => {
                let config_path = config::default_config_path()?;
                let state_path = state::default_state_path()?;
                let socket = agent::client::ensure_running().await?;
                let cwd = current_dir()?;
                commands::rotate(&config_path, &state_path, &socket, &cwd, branch.as_deref()).await
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
