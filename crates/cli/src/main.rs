//! `wonton` — the CLI porcelain and crypto engine (PLAN.md §8).
//!
//! This task builds only the `agent` subcommand group (the ssh-agent-style key daemon,
//! PLAN.md §8.2) plus the clap skeleton hosting it. The user-facing commands
//! (`login`/`use`/`switch`/`set`/`commit`/`run`/...) are a later task that will build on top of
//! the agent implemented here.

mod agent;

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
    /// Key agent daemon management (internal use).
    #[command(subcommand, hide = true)]
    Agent(agent::AgentCommand),
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
        Command::Agent(command) => agent::run(command).await,
    }
}
