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
    about = "Wonton — an end-to-end encrypted, git-like secrets manager",
    long_about = "Wonton — an end-to-end encrypted, git-like secrets manager.\n\n\
        The server only ever stores ciphertext and public keys; every value is encrypted and \
        decrypted on your machine. Projects are organized like GitHub: an org owns stores \
        (repos), and every branch within a store is its own encryption/access-control boundary \
        with its own key, just like `git checkout -b` but for secrets.",
    after_help = "EXAMPLES:\n    \
        wonton login alice --server https://wonton.example.com\n    \
        wonton init                        # bootstrap a project here, fully local\n    \
        wonton set DATABASE_URL=postgres://prod-db/acme\n    \
        wonton commit -m \"seed prod secrets\"\n    \
        wonton push                        # first push provisions it on the server\n    \
        wonton run -- ./start-server       # inject secrets into a subprocess\n    \
        eval \"$(wonton export --format shell)\"  # load secrets into THIS shell\n    \
        wonton share bob --role reader     # bob must have logged in once already\n    \
        wonton branch -b feature --from main\n\n\
        Run `wonton <command> --help` for full details on any command."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Unlock an identity into the local key agent, registering it on first use.
    ///
    /// The first time a username is used anywhere, this registers a brand-new identity on the
    /// given server (an Ed25519 signing key + an X25519 key for receiving shared DEKs), protects
    /// its private key with your passphrase (Argon2id), and logs in. There is NO passphrase
    /// recovery — if you forget it, that identity's data is gone for good.
    ///
    /// On every later login for the same username, `--server` can be omitted (the server is
    /// remembered) and this just re-authenticates via a signed challenge — your passphrase never
    /// leaves this machine, let alone crosses the network.
    ///
    /// The agent only ever holds ONE identity's key material unlocked at a time, so this also
    /// becomes the new "current" identity for any command that needs `--identity` to disambiguate
    /// (see `wonton whoami`). Set `WONTON_PASSPHRASE` to skip the interactive prompt (for
    /// scripts/CI only — it is less safe than typing it).
    Login {
        /// The server-facing username to log in as (also the local identity nickname).
        username: String,
        /// The server URL. Required the first time this username is used anywhere on this
        /// machine; after that it's remembered. Falls back to `wonton config set-server`'s
        /// default if omitted and never set.
        #[arg(long)]
        server: Option<String>,
    },
    /// Show which identity/identities are logged in locally, and which server each points at.
    ///
    /// With more than one identity cached, the one marked "(current)" is what commands default
    /// to when `--identity` is omitted — it's whichever identity `login` unlocked most recently.
    Whoami,
    /// Forget a cached identity's key material from this machine.
    ///
    /// This is local only — the account still exists on the server and can be logged back into
    /// with the same passphrase at any time. Defaults to the sole cached identity, or the current
    /// one if more than one is cached (same resolution `--identity` uses elsewhere); ambiguous
    /// otherwise. If the identity being forgotten is the one currently resident in the agent,
    /// this also locks the agent so its key material stops working for the rest of the session.
    Logout {
        /// The local identity nickname to forget. Only needed if more than one is cached.
        name: Option<String>,
    },
    /// Manage machine-wide defaults in the global config (`~/.config/wonton/config.toml`).
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Bootstrap a new project in the current directory.
    ///
    /// Fully local — zero network calls, so this always succeeds instantly and never fails due
    /// to a name collision with anyone else. It writes `wonton.toml` (committed: server + org/
    /// store) and `.wonton.local` (gitignored: the current branch) and generates a fresh DEK for
    /// the starting branch inside the local key agent. Server contact — creating the org/store/
    /// branch for real, and self-granting the DEK — is deferred to your first `wonton push`.
    ///
    /// Requires being logged in already (`wonton login`), since a DEK has to be generated for
    /// someone's identity.
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
    /// Bind the current directory to an existing org/store you already have access to.
    ///
    /// Use this for a directory that isn't a git checkout already carrying a `wonton.toml` — for
    /// example an empty directory someone shared a store with you into. Confirms the org/store/
    /// branch actually exists first (a hard failure, no markers written, if it doesn't — a typo
    /// will never start working no matter how long you wait), then writes the same markers
    /// `init` would and immediately tries to unwrap the branch's DEK and pull its history, so you
    /// find out right away if you're not shared in *yet* (a soft warning, since that might
    /// resolve itself shortly) rather than on the next unrelated command.
    Clone {
        /// The org, or `org/store` as a single argument.
        org: String,
        /// The store (repo) name. Omit if `org` was given as `org/store`.
        store: Option<String>,
        /// The branch to start on. Defaults to "main".
        branch: Option<String>,
        /// The local identity to act as. Only needed if more than one identity is logged in.
        #[arg(long)]
        identity: Option<String>,
    },
    /// List, switch to, or create branches.
    ///
    /// `wonton branch` alone lists every branch you have local history for AND every branch the
    /// server says you can access (like `git branch -a`), marking the current one. `wonton branch
    /// <name>` switches to an existing branch, unwrapping its DEK and auto-pulling its history if
    /// this is the first time you're touching it here. `wonton branch -b <name> [--from <src>]`
    /// creates a brand-new branch with its OWN DEK — a real encryption boundary, not just a label
    /// — optionally seeded with `<src>`'s current values so you have something to start editing.
    /// Both switching and creating are purely local except for the network calls `-b --from`
    /// needs to read the source branch's current values.
    Branch {
        /// Switch to this existing branch.
        name: Option<String>,
        /// Create a new branch with its own DEK, instead of switching to an existing one.
        #[arg(short = 'b', value_name = "NAME")]
        create: Option<String>,
        /// When creating with `-b`, seed the new branch's values from this existing branch.
        #[arg(short = 'f', long)]
        from: Option<String>,
        /// The local identity to act as. Only needed if more than one identity is logged in.
        #[arg(long)]
        identity: Option<String>,
    },
    /// Provision a store (repo) within an org on the server directly.
    ///
    /// Advanced/manual path — the golden path (`init`, or `branch -b` for a new branch) defers
    /// all of this to your first `push` instead, so you normally never need to run this yourself.
    /// Idempotent: an org/store that already exists is treated as success, not an error.
    Store {
        #[command(subcommand)]
        command: StoreCommand,
    },
    /// Show the current workspace, branch, DEK-cache status, ahead/behind, and staged changes.
    ///
    /// Reads `wonton.toml`/`.wonton.local` fresh, so it always reflects reality even if you
    /// hand-edited `.wonton.local` or another clone pushed since you last looked.
    Status,
    /// Stage one or more `KEY=VALUE` secrets on the current branch.
    ///
    /// Purely local — nothing is encrypted-and-sent until `wonton commit`, and nothing reaches
    /// the server until `wonton push`. Re-setting an already-staged key overwrites it.
    Set {
        /// `KEY=VALUE` pairs to stage, e.g. `DATABASE_URL=postgres://... API_KEY=sk-live-...`.
        #[arg(required = true, value_name = "KEY=VALUE")]
        pairs: Vec<String>,
    },
    /// Stage deletion of one or more keys on the current branch.
    ///
    /// Purely local, like `set` — takes effect on the next `wonton commit`.
    Unset {
        /// Key names to unset.
        #[arg(required = true)]
        keys: Vec<String>,
    },
    /// Commit the staged changes on the current branch.
    ///
    /// Encrypts every staged value under the branch's DEK, writes a signed commit object, and
    /// advances the local tip. Still local-only — run `wonton push` to upload it.
    Commit {
        /// The commit message.
        #[arg(short, long)]
        message: String,
    },
    /// Show the verified commit history of the current branch (like `git log`).
    ///
    /// Every commit's signature is checked against its author's public key before being shown,
    /// so a tampered or replayed history object is caught here rather than trusted silently.
    Log,
    /// Diff two commits, or show the last commit's change if no args are given (like `git show`).
    Diff {
        /// The "from" commit hash (abbreviated hashes are accepted, like git). If omitted, uses
        /// the current branch's tip's own diff against its first parent (or the empty tree for
        /// a root commit).
        a: Option<String>,
        /// The "to" commit hash. Requires `a` to also be given.
        b: Option<String>,
    },
    /// Fetch and fast-forward the current branch from the server (like `git pull --ff-only`).
    ///
    /// Fails clearly if the local and remote histories have diverged rather than silently
    /// picking a side — use `wonton merge` for that case.
    Pull,
    /// Upload local commits and move the branch ref on the server (like `git push`).
    ///
    /// The FIRST push on a brand-new branch also provisions it server-side — creating the org/
    /// store/branch if needed and self-granting the DEK — since `init`/`branch -b` deliberately
    /// make zero network calls. Two independently-`init`ed directories racing to provision the
    /// same org/store/branch name fail loudly here (their DEKs are cryptographically
    /// irreconcilable) rather than corrupting anything.
    Push,
    /// Three-way merge another branch into the current one, or manage a paused merge.
    ///
    /// Exactly one of a branch name, `--continue`, or `--abort` must be given. Merging across two
    /// branches with different DEKs (the normal case, since every branch has its own key) is
    /// handled transparently — conflicting keys pause the merge for you to resolve interactively,
    /// after which `--continue` picks up where you left off. `--abort` discards a paused merge
    /// entirely; nothing was ever committed, so there's nothing else to undo.
    Merge {
        /// The branch to merge into the current branch.
        branch: Option<String>,
        /// Resume a merge paused earlier on unresolved conflicts.
        #[arg(long = "continue")]
        resume: bool,
        /// Discard a paused merge entirely.
        #[arg(long)]
        abort: bool,
    },
    /// Run a command with the current branch's secrets injected as env vars.
    ///
    /// Secrets exist only in the child process's environment for its lifetime — never written to
    /// disk. This is the safest way to use secrets in a one-shot command or long-running server
    /// process. Note a subprocess can never modify ITS PARENT shell's environment (a Unix
    /// limitation, not a wonton one) — if you want secrets loaded into the shell you're typing
    /// in, use `eval "$(wonton export --format shell)"` instead.
    Run {
        /// The command and its arguments — everything after `--`, e.g. `wonton run -- ./start`.
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
    },
    /// Print the current branch's decrypted secrets to stdout as `KEY=VALUE`.
    ///
    /// The look-before-you-`export`/`run` command: nothing touches disk (unlike `export`) and no
    /// subprocess is spawned just to see what you have (unlike `run`). Includes both committed
    /// and any currently-staged values.
    View {
        /// List key names only, without values — safer for screen-sharing.
        #[arg(long)]
        keys_only: bool,
    },
    /// Export the current branch's secrets to a file, or print them for `eval`/`source`.
    #[command(long_about = "Export the current branch's secrets to a file, or print them for \
        `eval`/`source`.\n\n\
        Two formats:\n\n  \
        dotenv (default) — `KEY=VALUE` lines. With no path, writes `.env` in the current \
        directory. A given path that names a directory (an existing one, or `.`/`./`) gets \
        `.env` appended rather than failing to write to a directory.\n\n  \
        shell — `export KEY='VALUE'` statements. With no path, prints to STDOUT instead of \
        writing a file, specifically so `eval \"$(wonton export --format shell)\"` loads \
        secrets into the CURRENT shell — the one thing `wonton run` structurally cannot do, \
        since a child process can never mutate its parent's environment. Given a path, writes \
        `.env.sh` there instead (for `source`-ing later).\n\n\
        Always prints an explicit plaintext warning to stderr first (never stdout, so it can't \
        corrupt an `eval`/`source` pipeline) — this is the one command that deliberately puts \
        secrets in a form that outlives the wonton process, so it never runs silently.")]
    Export {
        /// Output format: `dotenv` or `shell`.
        #[arg(long, default_value = "dotenv")]
        format: String,
        /// The file (or directory) to write. Omit to use the format's own default (a `.env` file
        /// for dotenv; stdout, for `eval`/`source`, for shell).
        path: Option<PathBuf>,
    },
    /// Grant a user access to a branch by wrapping a copy of its DEK for them (O(1)).
    ///
    /// No value re-encryption happens — sharing is instant regardless of history size. Also
    /// auto-joins the target to this branch's org server-side, so there's no separate "invite to
    /// org" step. The target user must have logged in at least once already (sharing looks up
    /// their public key by username), otherwise this fails clearly rather than silently no-op-ing.
    Share {
        /// The username to share with.
        user: String,
        /// The branch to share. Defaults to the current directory's branch.
        #[arg(long)]
        branch: Option<String>,
        /// The access level to grant: reader, writer, or admin.
        #[arg(long, default_value = "reader")]
        role: String,
    },
    /// Revoke a user's access to a branch.
    ///
    /// Removes them from the branch's membership AND rotates the DEK — their cached copy of the
    /// old key stops decrypting anything committed afterward. This re-encrypts history and
    /// re-wraps the new DEK for every remaining member, so it's not O(1) like `share`.
    Revoke {
        /// The username to revoke.
        user: String,
        /// The branch to revoke access to. Defaults to the current directory's branch.
        #[arg(long)]
        branch: Option<String>,
    },
    /// Data-key (DEK) management for a branch.
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    /// Key agent daemon management (internal use — the agent starts itself automatically).
    #[command(subcommand, hide = true)]
    Agent(agent::AgentCommand),
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    /// Rotate a branch's DEK: generate a fresh key, re-encrypt its history under it, and
    /// re-wrap it for every current member — in one atomic server-side batch.
    ///
    /// Use this if you suspect a member's key material may have leaked without them actually
    /// leaving the branch (`wonton revoke` already rotates automatically when someone leaves).
    Rotate {
        /// The branch to rotate. Defaults to the current directory's branch.
        #[arg(long)]
        branch: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Set (or update) the default server URL used when a command needs one and none is given
    /// explicitly — currently just `login`, for a username that isn't already a known identity.
    ///
    /// Purely a bootstrapping convenience: once you're logged in anywhere, that identity's server
    /// is remembered on its own, and a project's own `wonton.toml` always wins once one exists.
    SetServer {
        /// The server URL, e.g. `https://wonton.example.com`.
        url: String,
    },
    /// Show the current default server, if any.
    Show,
}

#[derive(Debug, Subcommand)]
enum StoreCommand {
    /// Create a store (repo) within an org on the server, creating the org first if needed.
    ///
    /// The creator becomes the org's owner if the org is newly created. Idempotent: an org/store
    /// that already exists is treated as success (like `mkdir -p`), not an error — safe to run
    /// more than once or from more than one machine without coordinating first.
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
            let (org, store, branch) = commands::parse_clone_target(org, store, branch)?;
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
            let entries = commands::log(&config_path, &state_path, &cwd).await?;
            if entries.is_empty() {
                println!("No commits yet.");
            }
            for entry in entries {
                println!("commit {} ({})", commands::short_hash(&entry.hash), entry.hash.to_hex());
                println!("  author:  {} <{}>", entry.author_username, entry.author_id);
                println!("  date:    {}", entry.timestamp);
                println!("  message: {}", entry.message);
                println!();
            }
            Ok(())
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
            if let Some(contents) =
                commands::export(&config_path, &state_path, &socket, &cwd, format, path.as_deref()).await?
            {
                print!("{contents}");
            }
            Ok(())
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
