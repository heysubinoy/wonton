//! End-to-end tests for the identity / context commands. Each test drives the
//! command *logic* in `crate::commands` directly (not the compiled binary) against BOTH a real
//! `wonton-server` (bound to an ephemeral port over a temp-file SQLite DB, mirroring
//! `wonton-sync`'s integration tests) and a real in-process agent daemon (over a temp socket,
//! mirroring `crate::agent::tests`), using a temp config path so nothing touches the real
//! `~/.config/wonton`.
//!
//! `.wonton` marker discovery and config save/load round-trips are covered by unit tests in
//! `crate::config`; these tests focus on the networked flows (`login`, `use`) plus `link`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use wonton_crypto::{generate_dek, wrap_dek, EncryptedValue};
use wonton_objects::{Blob, Commit, Hash, Tree};
use wonton_shared::{CreateEnvRequest, CreateStoreRequest, GrantKeyRequest, Role};
use wonton_sync::SyncClient;
use wonton_vcs::ValueDecryptor;

use crate::agent::cipher::AgentCipher;
use crate::agent::{client as agent, daemon};
use crate::commands;
use crate::config::Config;
use crate::state::{object_store_dir_for, open_object_store, LocalState, ResolvedEntry};

/// A unique temp path per call (parallel-safe): pid + atomic counter + nanosecond timestamp.
fn unique(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!(
        "wonton-cli-test-{tag}-{}-{n}-{nanos}",
        std::process::id()
    ))
}

/// Start a real `wonton-server` over a fresh temp-file DB; return its base URL. The router owns
/// the pool, so we keep no separate handle.
async fn start_server() -> String {
    let db = unique("db");
    let url = format!("sqlite://{}", db.display());
    let pool = wonton_server::connect(&url).await.expect("connect + migrate");
    let router = wonton_server::build_router(pool);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("http://{addr}")
}

/// Bind + spawn an in-process agent daemon; return its socket path.
async fn spawn_agent() -> PathBuf {
    let path = unique("agent").with_extension("sock");
    let listener = daemon::bind_listener(&path).await.expect("bind agent socket");
    tokio::spawn(daemon::serve(listener, daemon::new_state()));
    path
}

fn temp_config_path() -> PathBuf {
    unique("cfg").join("config.toml")
}

fn temp_state_path() -> PathBuf {
    unique("state").join("state.toml")
}

/// Grant `user_id` a freshly-generated DEK (version 1) for `store`/`env`, returning nothing —
/// the DEK stays server-side (sealed) and is unwrapped into the agent by `use`. Mirrors what a
/// real `wonton share` will do in a later phase.
async fn grant_dek(base: &str, token: &str, store: &str, env: &str, user_id: &str, x25519_b64: &str) {
    let mut client = SyncClient::new(base);
    client.set_token(token);
    let dek = generate_dek();
    let x: [u8; 32] = STANDARD.decode(x25519_b64).unwrap().as_slice().try_into().unwrap();
    let sealed = wrap_dek(&dek, &x);
    client
        .grant_key(
            store,
            env,
            &GrantKeyRequest {
                user_id: user_id.to_string(),
                dek_version: 1,
                sealed_box: STANDARD.encode(&sealed.0),
            },
        )
        .await
        .unwrap();
}

/// Everything a Phase-4c command needs: a real server, an in-process agent with the context's DEK
/// unwrapped, and temp config/state paths (the object store is co-located with `state_path`).
struct Fixture {
    base: String,
    config_path: PathBuf,
    state_path: PathBuf,
    socket: PathBuf,
    user_id: String,
}

/// Log `user` in against `base`, provision `acme`/`dev`, grant + `use` the DEK, and return a
/// ready-to-drive [`Fixture`]. Reuses `base`/`socket` if provided (so two "machines" can share one
/// server), otherwise starts fresh ones.
async fn ready_fixture(
    user: &str,
    base: Option<String>,
    provision: bool,
) -> Fixture {
    let base = match base {
        Some(b) => b,
        None => start_server().await,
    };
    let socket = spawn_agent().await;
    let config_path = temp_config_path();
    let state_path = temp_state_path();

    commands::login(&config_path, &socket, Some(base.clone()), user, format!("pw-{user}"))
        .await
        .unwrap();
    let id = Config::load_from(&config_path)
        .unwrap()
        .find_identity(user)
        .unwrap()
        .clone();

    if provision {
        let mut client = SyncClient::new(&base);
        client.set_token(id.session_token.clone().unwrap());
        client
            .create_store(&CreateStoreRequest { name: "acme".into() })
            .await
            .unwrap();
        client
            .create_env("acme", &CreateEnvRequest { name: "dev".into() })
            .await
            .unwrap();
        grant_dek(
            &base,
            id.session_token.as_ref().unwrap(),
            "acme",
            "dev",
            &id.user_id,
            &id.x25519_pubkey_b64,
        )
        .await;
    }

    commands::context_add(&config_path, "acme-dev", "acme", "dev", user).unwrap();
    commands::use_context(&config_path, &state_path, &socket, "acme-dev")
        .await
        .unwrap();

    Fixture {
        base,
        config_path,
        state_path,
        socket,
        user_id: id.user_id,
    }
}

/// The full self-service bootstrap flow, using ONLY real CLI commands (no raw `SyncClient`
/// bypass like `ready_fixture` uses): register/login, `store create`, `env create` (which
/// self-grants DEK v1), `context add`, `use`, and finally `set`/`commit`/`run` to prove the
/// freshly-created environment is genuinely usable end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn store_and_env_create_bootstrap_a_freshly_usable_environment() {
    let base = start_server().await;
    let machine = login_only("bootstrapper", &base).await;

    commands::store_create(&machine.config_path, Some("bootstrapper"), "widgets")
        .await
        .expect("store create");
    commands::env_create(
        &machine.config_path,
        &machine.socket,
        Some("bootstrapper"),
        "widgets",
        "prod",
    )
    .await
    .expect("env create should create the env and self-grant DEK v1");

    commands::context_add(&machine.config_path, "widgets-prod", "widgets", "prod", "bootstrapper")
        .unwrap();
    commands::use_context(&machine.config_path, &machine.state_path, &machine.socket, "widgets-prod")
        .await
        .expect("use should find the self-granted DEK via list_keys, no separate share needed");

    commands::set(
        &machine.config_path,
        &machine.state_path,
        &machine.socket,
        "widgets-prod",
        vec![("WIDGET_KEY".into(), "sk-widget-123".into())],
    )
    .await
    .unwrap();
    commands::commit(
        &machine.config_path,
        &machine.state_path,
        &machine.socket,
        "widgets-prod",
        "first commit in a freshly bootstrapped env".into(),
    )
    .await
    .unwrap();

    let out = unique("bootstrapout");
    let out_str = out.to_string_lossy().to_string();
    let code = commands::run(
        &machine.config_path,
        &machine.state_path,
        &machine.socket,
        "widgets-prod",
        vec!["sh".into(), "-c".into(), format!("printf '%s' \"$WIDGET_KEY\" > {out_str}")],
    )
    .await
    .unwrap();
    assert_eq!(code, 0);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "sk-widget-123");
    let _ = std::fs::remove_file(&out);
}

/// A second store creation with the same name must surface the server's 409 clearly, not panic
/// or silently succeed. Also exercises `--identity` being omitted entirely: with exactly one
/// identity logged in, it must be inferred without error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn store_create_reports_a_duplicate_name_clearly() {
    let base = start_server().await;
    let machine = login_only("dupstore", &base).await;
    commands::store_create(&machine.config_path, None, "acme").await.unwrap();
    let err = commands::store_create(&machine.config_path, None, "acme")
        .await
        .unwrap_err();
    assert!(err.to_string().to_lowercase().contains("acme"), "got: {err}");
}

/// With more than one identity cached in the same config, omitting `--identity` must be a clear
/// error naming the ambiguity rather than silently picking one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn store_create_without_identity_errors_clearly_when_ambiguous() {
    let base = start_server().await;
    let socket = spawn_agent().await;
    let config_path = temp_config_path();
    commands::login(&config_path, &socket, Some(base.clone()), "multi-a", "pw-a".into())
        .await
        .unwrap();
    commands::login(&config_path, &socket, Some(base), "multi-b", "pw-b".into())
        .await
        .unwrap();

    let err = commands::store_create(&config_path, None, "acme").await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("multi-a") && msg.contains("multi-b"), "got: {msg}");
}

/// `switch` is purely local: no server, no agent, and it persists the branch.
#[tokio::test]
async fn switch_is_local_and_persists() {
    let state_path = temp_state_path();
    commands::switch(&state_path, "acme-dev", "feature", true).unwrap();
    let state = crate::state::LocalState::load_from(&state_path).unwrap();
    assert_eq!(state.context("acme-dev").unwrap().branch, "feature");
}

/// A typo'd branch name must be a clear error, not a silently-created empty branch — `--create`
/// is required to switch to one with no local history yet.
#[tokio::test]
async fn switch_without_create_rejects_an_unknown_branch() {
    let state_path = temp_state_path();
    let err = commands::switch(&state_path, "acme-dev", "mian", false).unwrap_err();
    assert!(err.to_string().contains("--create"), "got: {err}");
    let state = crate::state::LocalState::load_from(&state_path).unwrap();
    assert!(
        state.context("acme-dev").is_none(),
        "a rejected switch must not create or mutate any context state"
    );
}

/// Switching back to a branch already recorded in `tips` (or the branch already selected) must
/// not require `--create` — this is the common case (going back and forth between branches you
/// already have local history on).
#[tokio::test]
async fn switch_without_create_allows_an_already_known_branch() {
    let state_path = temp_state_path();
    // A fresh context defaults to "main" -- switching to the branch you're already on needs no
    // --create even before anything has ever been committed.
    commands::switch(&state_path, "acme-dev", "main", false)
        .expect("switching to the already-selected default branch needs no --create");

    // Seed "feature" directly into tips (as a `pull` or a merge-base fork would), simulating a
    // branch we already have local history for -- switching to it needs no --create either.
    fork_branch(&state_path, "acme-dev", "feature", Hash::of(b"root"));
    commands::switch(&state_path, "acme-dev", "feature", false)
        .expect("switching to a branch already present in tips needs no --create");
}

/// `set` stages an encrypted blob; `status` runs; `unset` overwrites it with a tombstone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_status_and_unset_manage_the_staging_area() {
    let fx = ready_fixture("erin", None, true).await;

    commands::set(
        &fx.config_path,
        &fx.state_path,
        &fx.socket,
        "acme-dev",
        vec![("API_KEY".into(), "sk-live-123".into())],
    )
    .await
    .unwrap();

    let state = crate::state::LocalState::load_from(&fx.state_path).unwrap();
    let staged = &state.context("acme-dev").unwrap().staged;
    assert!(matches!(
        staged.get("API_KEY"),
        Some(crate::state::StagedEntry::Set(_))
    ));

    // status must run without error against the staged tree.
    commands::status(&fx.config_path, &fx.state_path, &fx.socket, "acme-dev")
        .await
        .unwrap();

    // `unset` replaces the staged Set with an Unset tombstone.
    commands::unset(&fx.config_path, &fx.state_path, "acme-dev", vec!["API_KEY".into()]).unwrap();
    let state = crate::state::LocalState::load_from(&fx.state_path).unwrap();
    assert_eq!(
        state.context("acme-dev").unwrap().staged.get("API_KEY"),
        Some(&crate::state::StagedEntry::Unset)
    );
}

/// `commit` clears staging, advances the tip, and `log` shows the commit with the REAL
/// server-assigned `author_id` (`Uuid::parse_str(user_id)`), not the old placeholder derivation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_advances_tip_and_log_shows_real_author_id() {
    let fx = ready_fixture("frank", None, true).await;

    commands::set(
        &fx.config_path,
        &fx.state_path,
        &fx.socket,
        "acme-dev",
        vec![("DATABASE_URL".into(), "postgres://x".into())],
    )
    .await
    .unwrap();
    commands::commit(&fx.config_path, &fx.state_path, &fx.socket, "acme-dev", "initial".into())
        .await
        .unwrap();

    let state = crate::state::LocalState::load_from(&fx.state_path).unwrap();
    let cs = state.context("acme-dev").unwrap();
    assert!(cs.staged.is_empty(), "staging must be cleared after commit");
    let tip = *cs.tips.get("main").expect("tip advanced");

    // Read the commit back and check its author_id is the parsed real user_id.
    let store = crate::state::open_object_store(
        &crate::state::object_store_dir_for(&fx.state_path),
    )
    .unwrap();
    let bytes = store.get(&tip).unwrap().unwrap();
    let commit = wonton_objects::Commit::from_bytes(&bytes).unwrap();
    assert_eq!(
        commit.fields.author_id,
        uuid::Uuid::parse_str(&fx.user_id).unwrap()
    );
    assert_eq!(commit.fields.message, "initial");

    // `log` runs and verifies the signature against the identity's own pubkey.
    commands::log(&fx.config_path, &fx.state_path, "acme-dev").await.unwrap();
}

/// `diff` between two real commits reports the right Added/Changed keys, and re-committing an
/// identical value must NOT report `Changed` (mirrors `wonton-vcs`'s critical test).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn diff_reports_added_and_changed_but_not_unchanged() {
    let fx = ready_fixture("grace", None, true).await;

    // c1: A=apple, B=banana
    commands::set(
        &fx.config_path,
        &fx.state_path,
        &fx.socket,
        "acme-dev",
        vec![("A".into(), "apple".into()), ("B".into(), "banana".into())],
    )
    .await
    .unwrap();
    commands::commit(&fx.config_path, &fx.state_path, &fx.socket, "acme-dev", "c1".into())
        .await
        .unwrap();
    let c1 = *crate::state::LocalState::load_from(&fx.state_path)
        .unwrap()
        .context("acme-dev")
        .unwrap()
        .tips
        .get("main")
        .unwrap();

    // c2: A=apple (same value, re-encrypted), B=blueberry (changed), C=cherry (added)
    commands::set(
        &fx.config_path,
        &fx.state_path,
        &fx.socket,
        "acme-dev",
        vec![
            ("A".into(), "apple".into()),
            ("B".into(), "blueberry".into()),
            ("C".into(), "cherry".into()),
        ],
    )
    .await
    .unwrap();
    commands::commit(&fx.config_path, &fx.state_path, &fx.socket, "acme-dev", "c2".into())
        .await
        .unwrap();
    let c2 = *crate::state::LocalState::load_from(&fx.state_path)
        .unwrap()
        .context("acme-dev")
        .unwrap()
        .tips
        .get("main")
        .unwrap();

    let entries = commands::diff(
        &fx.config_path,
        &fx.state_path,
        &fx.socket,
        "acme-dev",
        Some(c1.to_hex()),
        Some(c2.to_hex()),
    )
    .await
    .unwrap();

    use wonton_vcs::DiffEntry;
    assert_eq!(
        entries,
        vec![DiffEntry::Changed("B".into()), DiffEntry::Added("C".into())]
    );
    assert!(
        !entries.iter().any(|e| matches!(e, DiffEntry::Changed(k) if k == "A")),
        "re-committing the same value must not show Changed"
    );
}

/// `run` injects the effective secrets as env vars into a child process (never touching disk) and
/// propagates its exit code.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_injects_secrets_as_env_vars() {
    let fx = ready_fixture("heidi", None, true).await;

    commands::set(
        &fx.config_path,
        &fx.state_path,
        &fx.socket,
        "acme-dev",
        vec![("MY_SECRET".into(), "hunter2".into())],
    )
    .await
    .unwrap();
    commands::commit(&fx.config_path, &fx.state_path, &fx.socket, "acme-dev", "c1".into())
        .await
        .unwrap();

    let out = unique("runout");
    let out_str = out.to_string_lossy().to_string();
    let code = commands::run(
        &fx.config_path,
        &fx.state_path,
        &fx.socket,
        "acme-dev",
        vec![
            "sh".into(),
            "-c".into(),
            format!("printf '%s' \"$MY_SECRET\" > {out_str}"),
        ],
    )
    .await
    .unwrap();
    assert_eq!(code, 0);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "hunter2");
    let _ = std::fs::remove_file(&out);
}

/// `export --format dotenv` writes a file whose parsed content matches the committed + staged
/// values. (The plaintext warning is emitted to stderr; we assert the file's correctness.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn export_writes_dotenv_matching_the_working_tree() {
    let fx = ready_fixture("ivan", None, true).await;

    commands::set(
        &fx.config_path,
        &fx.state_path,
        &fx.socket,
        "acme-dev",
        vec![("TOKEN".into(), "abc123".into())],
    )
    .await
    .unwrap();
    commands::commit(&fx.config_path, &fx.state_path, &fx.socket, "acme-dev", "c1".into())
        .await
        .unwrap();
    // Stage an additional value on top of the committed one; export uses tip + staged overlay.
    commands::set(
        &fx.config_path,
        &fx.state_path,
        &fx.socket,
        "acme-dev",
        vec![("EXTRA".into(), "with space".into())],
    )
    .await
    .unwrap();

    let out = unique("dotenv");
    commands::export(
        &fx.config_path,
        &fx.state_path,
        &fx.socket,
        "acme-dev",
        commands::ExportFormat::Dotenv,
        &out,
    )
    .await
    .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap();
    assert!(contents.contains("TOKEN=abc123\n"), "got: {contents}");
    assert!(contents.contains("EXTRA=\"with space\"\n"), "got: {contents}");
    let _ = std::fs::remove_file(&out);
}

/// End-to-end: machine A commits + pushes; a second machine (fresh config/state/store + fresh
/// agent) logs in as the same user, `use`s the DEK, pulls, and sees the same tip and the same
/// decrypted value.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_then_fresh_machine_pull_sees_the_same_secrets() {
    // Machine A: provision + grant + commit + push.
    let a = ready_fixture("judy", None, true).await;
    commands::set(
        &a.config_path,
        &a.state_path,
        &a.socket,
        "acme-dev",
        vec![("SHARED".into(), "top-secret".into())],
    )
    .await
    .unwrap();
    commands::commit(&a.config_path, &a.state_path, &a.socket, "acme-dev", "seed".into())
        .await
        .unwrap();
    commands::push(&a.config_path, &a.state_path, "acme-dev").await.unwrap();
    let a_tip = *crate::state::LocalState::load_from(&a.state_path)
        .unwrap()
        .context("acme-dev")
        .unwrap()
        .tips
        .get("main")
        .unwrap();

    // Machine B: same user + server, but fresh socket/config/state (⇒ fresh object store).
    let b = ready_fixture("judy", Some(a.base.clone()), false).await;
    commands::pull(&b.config_path, &b.state_path, "acme-dev").await.unwrap();

    let b_tip = *crate::state::LocalState::load_from(&b.state_path)
        .unwrap()
        .context("acme-dev")
        .unwrap()
        .tips
        .get("main")
        .unwrap();
    assert_eq!(a_tip, b_tip, "machine B should have fast-forwarded to A's tip");

    // Machine B can `log` (verify) and decrypt the value via `run`.
    commands::log(&b.config_path, &b.state_path, "acme-dev").await.unwrap();
    let out = unique("bpull");
    let out_str = out.to_string_lossy().to_string();
    let code = commands::run(
        &b.config_path,
        &b.state_path,
        &b.socket,
        "acme-dev",
        vec!["sh".into(), "-c".into(), format!("printf '%s' \"$SHARED\" > {out_str}")],
    )
    .await
    .unwrap();
    assert_eq!(code, 0);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "top-secret");
    let _ = std::fs::remove_file(&out);
}

/// A first-time `login` on a brand-new username registers, unlocks the agent, and ends with a
/// valid cached session token + user_id in config.
#[tokio::test]
async fn login_registers_new_user_and_caches_session() {
    let base = start_server().await;
    let socket = spawn_agent().await;
    let config_path = temp_config_path();

    commands::login(&config_path, &socket, Some(base.clone()), "alice", "pw-alice".into())
        .await
        .expect("first login should register + succeed");

    let config = Config::load_from(&config_path).unwrap();
    let id = config.find_identity("alice").expect("identity persisted");
    assert_eq!(id.username, "alice");
    assert_eq!(id.server_url, base);
    assert!(!id.user_id.is_empty(), "user_id should be populated");
    assert!(id.session_token.is_some(), "session token should be cached");
    assert!(id.session_expires_at.unwrap() > 0);
    assert!(!id.wrapped_privkey_b64.is_empty());

    let status = agent::status(&socket).await.unwrap();
    assert!(status.unlocked, "agent should be unlocked after login");
}

/// `login` on an already-registered username does NOT re-register (no duplicate-username 409)
/// and still ends up with a valid token. Also exercises omitting `--server` on a repeat login
/// (the stored server URL is reused).
#[tokio::test]
async fn login_existing_user_does_not_reregister() {
    let base = start_server().await;
    let socket = spawn_agent().await;
    let config_path = temp_config_path();

    commands::login(&config_path, &socket, Some(base.clone()), "bob", "pw-bob".into())
        .await
        .expect("initial login registers bob");

    // Lock, then log in again WITHOUT --server (reused from config). Must take the existing-user
    // path (login_start succeeds), not attempt a second register (which would 409).
    agent::lock(&socket).await.unwrap();
    commands::login(&config_path, &socket, None, "bob", "pw-bob".into())
        .await
        .expect("second login on an existing user should succeed without re-registering");

    let config = Config::load_from(&config_path).unwrap();
    let id = config.find_identity("bob").unwrap();
    assert_eq!(id.server_url, base, "server URL reused from config");
    assert!(id.session_token.is_some());
    let status = agent::status(&socket).await.unwrap();
    assert!(status.unlocked);
}

/// Provision a store + env, grant the logged-in identity a real wrapped DEK, then `context add`
/// + `use`: `use` succeeds and the agent's status afterward shows the context cached.
#[tokio::test]
async fn context_add_and_use_unwraps_the_dek() {
    let base = start_server().await;
    let socket = spawn_agent().await;
    let config_path = temp_config_path();

    let state_path = temp_state_path();
    commands::login(&config_path, &socket, Some(base.clone()), "carol", "pw-carol".into())
        .await
        .unwrap();
    let id = Config::load_from(&config_path)
        .unwrap()
        .find_identity("carol")
        .unwrap()
        .clone();

    // As carol (admin of the env she creates), provision and grant herself a DEK — mirroring what
    // a real `wonton share` would do in a later phase.
    let mut client = SyncClient::new(&base);
    client.set_token(id.session_token.clone().unwrap());
    client
        .create_store(&CreateStoreRequest { name: "acme".into() })
        .await
        .unwrap();
    client
        .create_env("acme", &CreateEnvRequest { name: "dev".into() })
        .await
        .unwrap();

    let dek = generate_dek();
    let x_bytes = STANDARD.decode(&id.x25519_pubkey_b64).unwrap();
    let x25519: [u8; 32] = x_bytes.as_slice().try_into().unwrap();
    let sealed = wrap_dek(&dek, &x25519);
    client
        .grant_key(
            "acme",
            "dev",
            &GrantKeyRequest {
                user_id: id.user_id.clone(),
                dek_version: 1,
                sealed_box: STANDARD.encode(&sealed.0),
            },
        )
        .await
        .unwrap();

    commands::context_add(&config_path, "acme-dev", "acme", "dev", "carol").unwrap();
    commands::use_context(&config_path, &state_path, &socket, "acme-dev")
        .await
        .expect("use should unwrap the granted DEK");

    let status = agent::status(&socket).await.unwrap();
    assert!(
        status.cached_contexts.contains(&"acme-dev".to_string()),
        "agent should have cached the context's DEK, got {:?}",
        status.cached_contexts
    );
    let config = Config::load_from(&config_path).unwrap();
    assert_eq!(config.current_context.as_deref(), Some("acme-dev"));
    // `use` persisted the granted DEK version (1) into state.toml for `share`/`rotate` to read.
    let state = crate::state::LocalState::load_from(&state_path).unwrap();
    assert_eq!(state.context("acme-dev").unwrap().dek_version, 1);

    // Re-using an already-cached context is cheap and still succeeds.
    commands::use_context(&config_path, &state_path, &socket, "acme-dev")
        .await
        .expect("re-use of a cached context should succeed");
}

/// `use` on a context where no wrapped-DEK entry exists for the identity fails with a clear
/// "you don't have access" error (not a crash / generic 404). Here the user is a member (admin of
/// the env she created) so `list_keys` succeeds, but no DEK was ever granted to her.
#[tokio::test]
async fn use_without_a_granted_dek_reports_no_access() {
    let base = start_server().await;
    let socket = spawn_agent().await;
    let config_path = temp_config_path();

    let state_path = temp_state_path();
    commands::login(&config_path, &socket, Some(base.clone()), "dave", "pw-dave".into())
        .await
        .unwrap();
    let id = Config::load_from(&config_path)
        .unwrap()
        .find_identity("dave")
        .unwrap()
        .clone();

    let mut client = SyncClient::new(&base);
    client.set_token(id.session_token.clone().unwrap());
    client
        .create_store(&CreateStoreRequest { name: "acme".into() })
        .await
        .unwrap();
    client
        .create_env("acme", &CreateEnvRequest { name: "prod".into() })
        .await
        .unwrap();
    // NOTE: no grant_key — dave has no wrapped DEK for prod.

    commands::context_add(&config_path, "acme-prod", "acme", "prod", "dave").unwrap();
    let err = commands::use_context(&config_path, &state_path, &socket, "acme-prod")
        .await
        .expect_err("use must fail with no granted DEK");
    assert!(
        err.to_string().contains("don't have access"),
        "expected an access error, got: {err}"
    );

    // The context was NOT selected on failure.
    let config = Config::load_from(&config_path).unwrap();
    assert_eq!(config.current_context, None);
}

/// `context add` refuses to reference an identity that isn't in the config.
#[tokio::test]
async fn context_add_rejects_unknown_identity() {
    let config_path = temp_config_path();
    let err = commands::context_add(&config_path, "ctx", "acme", "dev", "ghost")
        .expect_err("unknown identity should be rejected");
    assert!(err.to_string().contains("no identity named 'ghost'"), "got: {err}");
}

/// `link` writes a `.wonton` marker, is idempotent for the same context, and refuses to clobber a
/// marker naming a different context.
#[tokio::test]
async fn link_writes_marker_and_refuses_to_clobber_a_different_context() {
    let config_path = temp_config_path();
    // Seed two contexts (they need an identity to exist first).
    let mut config = Config::default();
    config.upsert_identity(crate::config::Identity {
        name: "u".into(),
        username: "u".into(),
        server_url: "http://x".into(),
        user_id: "uid".into(),
        ed25519_pubkey_b64: "e".into(),
        x25519_pubkey_b64: "x".into(),
        wrapped_privkey_b64: "w".into(),
        argon2_salt_b64: "s".into(),
        argon2_m_cost_kib: 19456,
        argon2_t_cost: 2,
        argon2_p_cost: 1,
        session_token: None,
        session_expires_at: None,
    });
    config.upsert_context(crate::config::Context {
        name: "one".into(),
        store: "acme".into(),
        environment: "dev".into(),
        identity: "u".into(),
    });
    config.upsert_context(crate::config::Context {
        name: "two".into(),
        store: "acme".into(),
        environment: "prod".into(),
        identity: "u".into(),
    });
    config.save_to(&config_path).unwrap();

    let dir = unique("linkdir");
    std::fs::create_dir_all(&dir).unwrap();

    commands::link(&config_path, &dir, "one").expect("first link writes the marker");
    assert_eq!(
        crate::config::find_wonton_context(&dir),
        Some("one".to_string())
    );

    // Idempotent for the same context.
    commands::link(&config_path, &dir, "one").expect("relinking the same context is fine");

    // Refuses a different context.
    let err = commands::link(&config_path, &dir, "two").expect_err("must not clobber");
    assert!(err.to_string().contains("refusing to overwrite"), "got: {err}");

    let _ = std::fs::remove_dir_all(&dir);
}

// ---- Phase 5a: share / revoke / key rotate -----------------------------------------------

/// A logged-in-but-unprovisioned "machine": fresh agent/config/state, the user is registered but
/// no store/env/context is set up yet. Used for a share *target* (who has no DEK until shared).
struct Machine {
    config_path: PathBuf,
    state_path: PathBuf,
    socket: PathBuf,
}

async fn login_only(user: &str, base: &str) -> Machine {
    let socket = spawn_agent().await;
    let config_path = temp_config_path();
    let state_path = temp_state_path();
    commands::login(&config_path, &socket, Some(base.to_string()), user, format!("pw-{user}"))
        .await
        .unwrap();
    Machine {
        config_path,
        state_path,
        socket,
    }
}

/// Count the object files under `state_path`'s co-located object store (git-style fanout dirs).
fn count_objects(state_path: &std::path::Path) -> usize {
    fn walk(p: &std::path::Path) -> usize {
        let mut n = 0;
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                let path = e.path();
                if path.is_dir() {
                    n += walk(&path);
                } else {
                    n += 1;
                }
            }
        }
        n
    }
    walk(&object_store_dir_for(state_path))
}

/// The blob hash a committed tree maps `key` to (for asserting a value's ciphertext changed after
/// rotation without decrypting it).
fn blob_hash_for_key(state_path: &std::path::Path, tip: Hash, key: &str) -> Hash {
    let store = open_object_store(&object_store_dir_for(state_path)).unwrap();
    let commit = Commit::from_bytes(&store.get(&tip).unwrap().unwrap()).unwrap();
    let tree = Tree::from_bytes(&store.get(&commit.fields.tree_hash).unwrap().unwrap()).unwrap();
    *tree.entries.get(key).unwrap()
}

fn tip_of(state_path: &std::path::Path) -> Hash {
    *LocalState::load_from(state_path)
        .unwrap()
        .context("acme-dev")
        .unwrap()
        .tips
        .get("main")
        .unwrap()
}

/// `share` grants a second user access with NO re-encryption (O(1)): the object count is
/// unchanged, and the target can then `use` + `pull` + read the same secret the sharer committed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn share_grants_access_without_re_encryption() {
    let owner = ready_fixture("p5owner", None, true).await;
    commands::set(
        &owner.config_path,
        &owner.state_path,
        &owner.socket,
        "acme-dev",
        vec![("SECRET".into(), "sk-shared".into())],
    )
    .await
    .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, "acme-dev", "seed".into())
        .await
        .unwrap();
    commands::push(&owner.config_path, &owner.state_path, "acme-dev").await.unwrap();

    let bob = login_only("p5bob", &owner.base).await;

    // O(1): share must not create any objects (no re-encryption).
    let before = count_objects(&owner.state_path);
    commands::share(
        &owner.config_path,
        &owner.state_path,
        &owner.socket,
        "acme-dev",
        "p5bob",
        Role::Reader,
    )
    .await
    .expect("share should grant access");
    let after = count_objects(&owner.state_path);
    assert_eq!(before, after, "share must not re-encrypt / create objects");

    // Bob can now use the context, pull, and read the same secret.
    commands::context_add(&bob.config_path, "acme-dev", "acme", "dev", "p5bob").unwrap();
    commands::use_context(&bob.config_path, &bob.state_path, &bob.socket, "acme-dev")
        .await
        .expect("bob can use the shared context");
    commands::pull(&bob.config_path, &bob.state_path, "acme-dev").await.unwrap();

    let out = unique("shareout");
    let out_str = out.to_string_lossy().to_string();
    let code = commands::run(
        &bob.config_path,
        &bob.state_path,
        &bob.socket,
        "acme-dev",
        vec!["sh".into(), "-c".into(), format!("printf '%s' \"$SECRET\" > {out_str}")],
    )
    .await
    .unwrap();
    assert_eq!(code, 0);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "sk-shared");
    let _ = std::fs::remove_file(&out);
}

/// The bug found by manual end-to-end testing (2026-07-06): `log` used to verify every commit
/// against the *local caller's own* pubkey, so a second identity reading a history it did not
/// entirely author itself would fail signature verification on every commit it didn't write —
/// not because anything was tampered, but because its own key obviously can't verify someone
/// else's signature. After sharing, Bob's `log` over a history genuinely authored by BOTH Alice
/// and Bob (each committing in turn) must succeed, resolving each commit against its own author.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn log_verifies_a_history_with_more_than_one_real_author() {
    let alice = ready_fixture("p5xalice", None, true).await;
    commands::set(
        &alice.config_path,
        &alice.state_path,
        &alice.socket,
        "acme-dev",
        vec![("K".into(), "alice-value".into())],
    )
    .await
    .unwrap();
    commands::commit(&alice.config_path, &alice.state_path, &alice.socket, "acme-dev", "alice's commit".into())
        .await
        .unwrap();
    commands::push(&alice.config_path, &alice.state_path, "acme-dev").await.unwrap();

    let bob = login_only("p5xbob", &alice.base).await;
    commands::share(
        &alice.config_path,
        &alice.state_path,
        &alice.socket,
        "acme-dev",
        "p5xbob",
        Role::Writer,
    )
    .await
    .unwrap();
    commands::context_add(&bob.config_path, "acme-dev", "acme", "dev", "p5xbob").unwrap();
    commands::use_context(&bob.config_path, &bob.state_path, &bob.socket, "acme-dev")
        .await
        .unwrap();
    commands::pull(&bob.config_path, &bob.state_path, "acme-dev").await.unwrap();

    // Bob commits too, so the history now has two genuinely distinct real authors.
    commands::set(
        &bob.config_path,
        &bob.state_path,
        &bob.socket,
        "acme-dev",
        vec![("K2".into(), "bob-value".into())],
    )
    .await
    .unwrap();
    commands::commit(&bob.config_path, &bob.state_path, &bob.socket, "acme-dev", "bob's commit".into())
        .await
        .unwrap();

    // Both Alice and Bob must be able to verify the full two-author history via `log`.
    commands::log(&bob.config_path, &bob.state_path, "acme-dev").await.unwrap();
    commands::push(&bob.config_path, &bob.state_path, "acme-dev").await.unwrap();
    commands::pull(&alice.config_path, &alice.state_path, "acme-dev").await.unwrap();
    commands::log(&alice.config_path, &alice.state_path, "acme-dev").await.unwrap();
}

/// The Phase-5 exit criterion: after `revoke` + the fresh commit that follows, the revoked user's
/// STALE cached DEK can no longer decrypt a value committed after the revocation (AEAD auth
/// failure, fail-closed — never garbage).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoke_denies_the_revoked_users_stale_dek() {
    let owner = ready_fixture("p5rowner", None, true).await;
    commands::set(
        &owner.config_path,
        &owner.state_path,
        &owner.socket,
        "acme-dev",
        vec![("OLD".into(), "old-value".into())],
    )
    .await
    .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, "acme-dev", "v1".into())
        .await
        .unwrap();

    // Mallory is shared in (gets DEK v1) and caches it via `use`.
    let mallory = login_only("p5mallory", &owner.base).await;
    commands::share(
        &owner.config_path,
        &owner.state_path,
        &owner.socket,
        "acme-dev",
        "p5mallory",
        Role::Reader,
    )
    .await
    .unwrap();
    commands::context_add(&mallory.config_path, "acme-dev", "acme", "dev", "p5mallory").unwrap();
    commands::use_context(&mallory.config_path, &mallory.state_path, &mallory.socket, "acme-dev")
        .await
        .expect("mallory caches DEK v1");

    // Owner revokes Mallory (removes membership + rotates to v2; owner hot-swaps to v2).
    commands::revoke(
        &owner.config_path,
        &owner.state_path,
        &owner.socket,
        "acme-dev",
        "p5mallory",
    )
    .await
    .expect("revoke + rotate");
    let state = LocalState::load_from(&owner.state_path).unwrap();
    assert_eq!(state.context("acme-dev").unwrap().dek_version, 2, "owner is on v2 after rotation");

    // Owner commits a NEW secret under the v2 DEK.
    commands::set(
        &owner.config_path,
        &owner.state_path,
        &owner.socket,
        "acme-dev",
        vec![("NEW".into(), "post-revocation-secret".into())],
    )
    .await
    .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, "acme-dev", "v2-secret".into())
        .await
        .unwrap();

    // Grab the NEW blob (encrypted under v2) from the owner's store.
    let tip = tip_of(&owner.state_path);
    let blob_hash = blob_hash_for_key(&owner.state_path, tip, "NEW");
    let store = open_object_store(&object_store_dir_for(&owner.state_path)).unwrap();
    let blob = Blob::from_bytes(&store.get(&blob_hash).unwrap().unwrap()).unwrap();
    let value = EncryptedValue {
        nonce: blob.nonce,
        ciphertext: blob.ciphertext,
    };

    // Mallory's agent still holds the STALE v1 DEK under "acme-dev"; it must fail to open the
    // v2-encrypted value — fail closed, not a crash and not garbage.
    let mallory_cipher = AgentCipher::new(mallory.socket.clone(), "acme-dev");
    let result = tokio::task::spawn_blocking(move || mallory_cipher.decrypt(&value))
        .await
        .unwrap();
    assert!(result.is_err(), "revoked user's stale DEK must not decrypt post-rotation ciphertext");
}

/// `key rotate` alone (no membership change): advances the tip, changes an existing key's blob
/// hash (re-encrypted under a fresh DEK), and a remaining member can still log + decrypt after.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn key_rotate_alone_advances_tip_and_reencrypts() {
    let owner = ready_fixture("p5kowner", None, true).await;
    commands::set(
        &owner.config_path,
        &owner.state_path,
        &owner.socket,
        "acme-dev",
        vec![("KEY".into(), "the-value".into())],
    )
    .await
    .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, "acme-dev", "v1".into())
        .await
        .unwrap();

    let tip1 = tip_of(&owner.state_path);
    let h1 = blob_hash_for_key(&owner.state_path, tip1, "KEY");

    commands::rotate(&owner.config_path, &owner.state_path, &owner.socket, "acme-dev")
        .await
        .expect("key rotate");

    let state = LocalState::load_from(&owner.state_path).unwrap();
    assert_eq!(state.context("acme-dev").unwrap().dek_version, 2, "version advanced to 2");
    let tip2 = tip_of(&owner.state_path);
    assert_ne!(tip1, tip2, "rotation must advance the tip");
    let h2 = blob_hash_for_key(&owner.state_path, tip2, "KEY");
    assert_ne!(h1, h2, "the same plaintext under a fresh DEK+nonce must yield a different blob");

    // A remaining member (the owner) can still verify history and decrypt under the new DEK.
    commands::log(&owner.config_path, &owner.state_path, "acme-dev").await.unwrap();
    let out = unique("rotateout");
    let out_str = out.to_string_lossy().to_string();
    let code = commands::run(
        &owner.config_path,
        &owner.state_path,
        &owner.socket,
        "acme-dev",
        vec!["sh".into(), "-c".into(), format!("printf '%s' \"$KEY\" > {out_str}")],
    )
    .await
    .unwrap();
    assert_eq!(code, 0);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "the-value");
    let _ = std::fs::remove_file(&out);
}

// ---- Phase 5b: three-way merge ------------------------------------------------------------

/// Fork a new local branch named `branch` off `at` (the commit both histories will share as
/// their merge base) within `ctx_name`. There's no `checkout -b` porcelain command (v1 only has
/// `switch` to an already-known branch), so this directly seeds `state.toml`'s `tips`
/// map the same way `pull` would after fetching a peer's branch.
fn fork_branch(state_path: &std::path::Path, ctx_name: &str, branch: &str, at: Hash) {
    let mut state = LocalState::load_from(state_path).unwrap();
    state.context_mut(ctx_name).tips.insert(branch.to_string(), at);
    state.save_to(state_path).unwrap();
}

/// Read one env var's value out of the current working tree via `wonton run`, for asserting the
/// merged result without touching the object store's internals.
async fn read_via_run(f: &Fixture, key: &str) -> String {
    let out = unique(&format!("mergeread-{key}"));
    let out_str = out.to_string_lossy().to_string();
    let code = commands::run(
        &f.config_path,
        &f.state_path,
        &f.socket,
        "acme-dev",
        vec!["sh".into(), "-c".into(), format!("printf '%s' \"${key}\" > {out_str}")],
    )
    .await
    .unwrap();
    assert_eq!(code, 0);
    let value = std::fs::read_to_string(&out).unwrap();
    let _ = std::fs::remove_file(&out);
    value
}

/// Two branches that each add a different, non-overlapping key auto-merge with zero conflicts,
/// producing a real 2-parent commit that `wonton log` walks through without erroring.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn merge_with_no_conflicts_produces_a_two_parent_commit() {
    let owner = ready_fixture("p5bmerge1", None, true).await;
    commands::set(&owner.config_path, &owner.state_path, &owner.socket, "acme-dev", vec![("ROOT".into(), "root-value".into())])
        .await
        .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, "acme-dev", "root".into())
        .await
        .unwrap();
    let root_tip = tip_of(&owner.state_path);

    fork_branch(&owner.state_path, "acme-dev", "feature", root_tip);
    commands::switch(&owner.state_path, "acme-dev", "feature", false).unwrap();
    commands::set(&owner.config_path, &owner.state_path, &owner.socket, "acme-dev", vec![("FEATURE_KEY".into(), "feature-value".into())])
        .await
        .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, "acme-dev", "feature commit".into())
        .await
        .unwrap();

    commands::switch(&owner.state_path, "acme-dev", "main", false).unwrap();
    commands::set(&owner.config_path, &owner.state_path, &owner.socket, "acme-dev", vec![("MAIN_KEY".into(), "main-value".into())])
        .await
        .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, "acme-dev", "main commit".into())
        .await
        .unwrap();
    let main_tip_before = tip_of(&owner.state_path);

    commands::merge(&owner.config_path, &owner.state_path, &owner.socket, "acme-dev", "feature")
        .await
        .expect("no conflicts, must merge cleanly");

    let merged_tip = tip_of(&owner.state_path);
    assert_ne!(merged_tip, main_tip_before);

    let store = open_object_store(&object_store_dir_for(&owner.state_path)).unwrap();
    let commit = Commit::from_bytes(&store.get(&merged_tip).unwrap().unwrap()).unwrap();
    assert_eq!(commit.fields.parent_hashes.len(), 2, "a merge commit must have exactly 2 parents");
    assert!(commit.fields.parent_hashes.contains(&main_tip_before));

    // `wonton log`'s Phase 5b mainline-follow fix must walk past the merge commit without error.
    commands::log(&owner.config_path, &owner.state_path, "acme-dev").await.unwrap();

    assert_eq!(read_via_run(&owner, "ROOT").await, "root-value");
    assert_eq!(read_via_run(&owner, "MAIN_KEY").await, "main-value");
    assert_eq!(read_via_run(&owner, "FEATURE_KEY").await, "feature-value");

    let state = LocalState::load_from(&owner.state_path).unwrap();
    assert!(state.context("acme-dev").unwrap().merge.is_none(), "no merge state persisted for a clean merge");
}

/// A same-key divergent edit on both branches conflicts. Since the test process's stdin is
/// non-interactive (immediate EOF), `merge` pauses on it exactly like a skipped prompt would,
/// persisting only content hashes (never plaintext) into `state.toml`. Manually completing the
/// resolution (as the interactive loop itself would) and calling `merge --continue` must then
/// finalize the 2-parent commit and clear the paused state.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn merge_conflict_pauses_with_hash_only_state_then_continue_resolves() {
    let owner = ready_fixture("p5bmerge2", None, true).await;
    commands::set(&owner.config_path, &owner.state_path, &owner.socket, "acme-dev", vec![("KEY".into(), "base-value".into())])
        .await
        .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, "acme-dev", "root".into())
        .await
        .unwrap();
    let root_tip = tip_of(&owner.state_path);

    fork_branch(&owner.state_path, "acme-dev", "feature", root_tip);
    commands::switch(&owner.state_path, "acme-dev", "feature", false).unwrap();
    commands::set(&owner.config_path, &owner.state_path, &owner.socket, "acme-dev", vec![("KEY".into(), "feature-value".into())])
        .await
        .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, "acme-dev", "feature edit".into())
        .await
        .unwrap();

    commands::switch(&owner.state_path, "acme-dev", "main", false).unwrap();
    commands::set(&owner.config_path, &owner.state_path, &owner.socket, "acme-dev", vec![("KEY".into(), "main-value".into())])
        .await
        .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, "acme-dev", "main edit".into())
        .await
        .unwrap();

    commands::merge(&owner.config_path, &owner.state_path, &owner.socket, "acme-dev", "feature")
        .await
        .expect("merge itself succeeds even though it pauses on an unresolved conflict");

    let state = LocalState::load_from(&owner.state_path).unwrap();
    let merge_state = state
        .context("acme-dev")
        .unwrap()
        .merge
        .clone()
        .expect("a paused merge must be persisted");
    assert_eq!(merge_state.branch, "feature");
    assert_eq!(merge_state.conflicts.len(), 1);
    assert!(merge_state.conflicts.contains_key("KEY"));
    assert!(merge_state.resolved.is_empty());

    // Only hex hashes / structural TOML keys may appear — never the plaintext values.
    let raw = std::fs::read_to_string(&owner.state_path).unwrap();
    assert!(!raw.contains("base-value"));
    assert!(!raw.contains("feature-value"));
    assert!(!raw.contains("main-value"));

    // Resolve "KEY" to "ours" (main-value) exactly as a completed interactive prompt would,
    // by editing the persisted hashes directly, then finish via `--continue`.
    {
        let mut state = LocalState::load_from(&owner.state_path).unwrap();
        let cs = state.context_mut("acme-dev");
        let mut merge_state = cs.merge.clone().unwrap();
        let conflict = merge_state.conflicts.remove("KEY").unwrap();
        merge_state.resolved.insert("KEY".to_string(), ResolvedEntry::Set(conflict.ours.unwrap()));
        cs.merge = Some(merge_state);
        state.save_to(&owner.state_path).unwrap();
    }

    commands::merge_continue(&owner.config_path, &owner.state_path, &owner.socket, "acme-dev")
        .await
        .expect("continue finalizes once every conflict is resolved");

    let state = LocalState::load_from(&owner.state_path).unwrap();
    assert!(state.context("acme-dev").unwrap().merge.is_none(), "merge state must be cleared after finalizing");

    let merged_tip = tip_of(&owner.state_path);
    let store = open_object_store(&object_store_dir_for(&owner.state_path)).unwrap();
    let commit = Commit::from_bytes(&store.get(&merged_tip).unwrap().unwrap()).unwrap();
    assert_eq!(commit.fields.parent_hashes.len(), 2);
    commands::log(&owner.config_path, &owner.state_path, "acme-dev").await.unwrap();

    assert_eq!(read_via_run(&owner, "KEY").await, "main-value", "resolved to ours (main-value)");
}

/// `merge --continue` with nothing paused is a clear user error, not a silent no-op.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn merge_continue_without_a_paused_merge_errors() {
    let owner = ready_fixture("p5bmerge3", None, true).await;
    let err = commands::merge_continue(&owner.config_path, &owner.state_path, &owner.socket, "acme-dev")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no merge in progress"), "got: {err}");
}

/// Merging an unknown/never-fetched branch name is a clear user error, not a silent no-op.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn merge_unknown_branch_errors() {
    let owner = ready_fixture("p5bmerge4", None, true).await;
    commands::set(&owner.config_path, &owner.state_path, &owner.socket, "acme-dev", vec![("K".into(), "v".into())])
        .await
        .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, "acme-dev", "root".into())
        .await
        .unwrap();

    let err = commands::merge(&owner.config_path, &owner.state_path, &owner.socket, "acme-dev", "nonexistent")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("unknown branch"), "got: {err}");
}

// ---- no-plaintext-on-disk ------------------------------------------------------------------

/// Recursively collects every regular file under `root` (missing dirs yield an empty list).
fn all_files(root: &std::path::Path) -> Vec<PathBuf> {
    fn walk(p: &std::path::Path, out: &mut Vec<PathBuf>) {
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                let path = e.path();
                if path.is_dir() {
                    walk(&path, out);
                } else {
                    out.push(path);
                }
            }
        }
    }
    let mut files = Vec::new();
    walk(root, &mut files);
    files
}

/// The no-plaintext-on-disk rule: plaintext secrets must never touch disk except through the two
/// named exits (`wonton run`'s child-process environment and `wonton export`'s named file). This drives
/// a full `set` -> `commit` -> `run` cycle (the same cycle `share_grants_access_without_re_encryption`
/// above uses to actually read a secret back) and then scans every file under both the state
/// directory (object store + `state.toml`, including any paused-merge state) and the config
/// directory (`config.toml`, cached wrapped keys) for the literal plaintext bytes, asserting they
/// never appear — only ciphertext/hashes may.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_plaintext_secret_touches_disk_outside_the_named_export_exit() {
    let fx = ready_fixture("nopt", None, true).await;
    let plaintext = "sk-super-secret-plaintext-marker-9f3a";

    commands::set(
        &fx.config_path,
        &fx.state_path,
        &fx.socket,
        "acme-dev",
        vec![("SECRET".into(), plaintext.into())],
    )
    .await
    .unwrap();
    commands::commit(&fx.config_path, &fx.state_path, &fx.socket, "acme-dev", "seed".into())
        .await
        .unwrap();

    // `run` must inject the plaintext only into the child process's environment, never to disk.
    let code = commands::run(
        &fx.config_path,
        &fx.state_path,
        &fx.socket,
        "acme-dev",
        vec!["true".into()],
    )
    .await
    .unwrap();
    assert_eq!(code, 0);

    let needle = plaintext.as_bytes();
    for dir in [
        fx.state_path.parent().expect("state_path has a parent dir"),
        fx.config_path.parent().expect("config_path has a parent dir"),
    ] {
        for file in all_files(dir) {
            let bytes = std::fs::read(&file).unwrap();
            assert!(
                bytes.windows(needle.len()).all(|w| w != needle),
                "plaintext secret leaked to disk at {}",
                file.display()
            );
        }
    }
}
