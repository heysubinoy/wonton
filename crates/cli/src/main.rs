//! `wonton` — the CLI porcelain and crypto engine (PLAN.md §8).
//!
//! This binary hosts the identity / context-switching commands (`login`, `context`, `use`,
//! `link`) built on top of the ssh-agent-style key daemon (the hidden `agent` subcommand group,
//! PLAN.md §8.2). The remaining verbs (`switch`/`status`/`set`/`unset`/`commit`/`log`/`diff`/
//! `pull`/`push`/`run`/`export`) are a later task.

mod agent;
mod commands;
mod config;

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
    /// Key agent daemon management (internal use).
    #[command(subcommand, hide = true)]
    Agent(agent::AgentCommand),
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
            let socket = agent::client::ensure_running().await?;
            commands::use_context(&config_path, &socket, &name).await
        }
        Command::Link { name } => {
            let config_path = config::default_config_path()?;
            let cwd = current_dir()?;
            commands::link(&config_path, &cwd, &name)
        }
        Command::Agent(command) => agent::run(command).await,
    }
}

fn current_dir() -> anyhow::Result<PathBuf> {
    std::env::current_dir().map_err(|e| anyhow::anyhow!("cannot determine current directory: {e}"))
}
