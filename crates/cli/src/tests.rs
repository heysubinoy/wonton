//! End-to-end tests for the identity/workspace commands. Each test drives the command *logic* in
//! `crate::commands` directly (not the compiled binary) against BOTH a real `wonton-server`
//! (bound to an ephemeral port over a temp-file SQLite DB, mirroring `wonton-sync`'s integration
//! tests) and a real in-process agent daemon (over a temp socket, mirroring
//! `crate::agent::tests`), using a temp config path so nothing touches the real
//! `~/.config/wonton`.
//!
//! `wonton.toml`/`.wonton.local` discovery and config save/load round-trips are covered by unit
//! tests in `crate::config`; these tests focus on the networked/agent-backed flows.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use wonton_crypto::EncryptedValue;
use wonton_objects::{Blob, Commit, Hash, Tree};
use wonton_shared::Role;
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

fn temp_dir() -> PathBuf {
    let dir = unique("dir");
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The `org/store/branch` key every fixture below uses by default.
fn key(branch: &str) -> String {
    format!("acme/backend/{branch}")
}

/// Everything a directory-bound command needs: a real server, an in-process agent, a project
/// directory already `init`ed (fully local — no network calls happen in `ready_fixture` itself)
/// at `acme/backend`, branch `main`.
struct Fixture {
    base: String,
    config_path: PathBuf,
    state_path: PathBuf,
    socket: PathBuf,
    dir: PathBuf,
    user_id: String,
}

/// Log `user` in (registering on first use) against `base` (starting a fresh server if `None`)
/// and `init` a fresh project directory at `acme/backend` (branch `main`) — fully local, no
/// network calls beyond `login` itself. Reuses `base` if given, so two "machines" (or two
/// directories) can share one server/account.
async fn ready_fixture(user: &str, base: Option<String>) -> Fixture {
    let base = match base {
        Some(b) => b,
        None => start_server().await,
    };
    let socket = spawn_agent().await;
    let config_path = temp_config_path();
    let state_path = temp_state_path();
    let dir = temp_dir();

    commands::login(&config_path, &socket, Some(base.clone()), user, format!("pw-{user}"))
        .await
        .unwrap();
    let id = Config::load_from(&config_path).unwrap().find_identity(user).unwrap().clone();

    commands::init(
        &config_path,
        &socket,
        &dir,
        Some("acme".into()),
        Some("backend".into()),
        Some("main".into()),
        None,
    )
    .await
    .expect("init must be fully local and always succeed");

    Fixture {
        base,
        config_path,
        state_path,
        socket,
        dir,
        user_id: id.user_id,
    }
}

/// A logged-in-but-otherwise-fresh "machine": its own agent/config/state, the user registered
/// but no project directory bound yet. Used for a share/clone *target* who has no DEK until
/// shared or cloned.
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

fn tip_of(state_path: &std::path::Path, branch_key: &str) -> Hash {
    LocalState::load_from(state_path)
        .unwrap()
        .branch(branch_key)
        .and_then(|b| b.tip)
        .unwrap_or_else(|| panic!("no tip recorded for '{branch_key}'"))
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
fn blob_hash_for_key(state_path: &std::path::Path, tip: Hash, entry_key: &str) -> Hash {
    let store = open_object_store(&object_store_dir_for(state_path)).unwrap();
    let commit = Commit::from_bytes(&store.get(&tip).unwrap().unwrap()).unwrap();
    let tree = Tree::from_bytes(&store.get(&commit.fields.tree_hash).unwrap().unwrap()).unwrap();
    *tree.entries.get(entry_key).unwrap()
}

/// Read one env var's value out of `fx`'s current working tree via `wonton run`, for asserting a
/// result without touching the object store's internals.
async fn read_via_run(fx: &Fixture, entry_key: &str) -> String {
    let out = unique(&format!("read-{entry_key}"));
    let out_str = out.to_string_lossy().to_string();
    let code = commands::run(
        &fx.config_path,
        &fx.state_path,
        &fx.socket,
        &fx.dir,
        vec!["sh".into(), "-c".into(), format!("printf '%s' \"${entry_key}\" > {out_str}")],
    )
    .await
    .unwrap();
    assert_eq!(code, 0);
    let value = std::fs::read_to_string(&out).unwrap();
    let _ = std::fs::remove_file(&out);
    value
}

// ---- init / push provisioning --------------------------------------------------------------

/// `wonton init` must be entirely local: no store/branch exists server-side until the first
/// `push`, at which point `push` provisions the org/store/branch and self-grants DEK v1.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn init_is_fully_local_then_push_provisions_and_self_grants() {
    let base = start_server().await;
    let fx = ready_fixture("bootstrapper", Some(base.clone())).await;

    let identity = Config::load_from(&fx.config_path).unwrap().find_identity("bootstrapper").unwrap().clone();
    let mut client = SyncClient::new(&base);
    client.set_token(identity.session_token.clone().unwrap());
    let err = client.get_ref("acme", "backend", "main").await.unwrap_err();
    assert!(
        matches!(err, wonton_sync::SyncError::NotFound(_) | wonton_sync::SyncError::Forbidden),
        "branch must not exist server-side right after init, got {err:?}"
    );

    commands::set(
        &fx.config_path,
        &fx.state_path,
        &fx.socket,
        &fx.dir,
        vec![("WIDGET_KEY".into(), "sk-widget-123".into())],
    )
    .await
    .unwrap();
    commands::commit(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, "first commit".into())
        .await
        .unwrap();

    let out = unique("bootstrapout");
    let out_str = out.to_string_lossy().to_string();
    let code = commands::run(
        &fx.config_path,
        &fx.state_path,
        &fx.socket,
        &fx.dir,
        vec!["sh".into(), "-c".into(), format!("printf '%s' \"$WIDGET_KEY\" > {out_str}")],
    )
    .await
    .unwrap();
    assert_eq!(code, 0, "set/commit/run must all work offline before any push");
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "sk-widget-123");
    let _ = std::fs::remove_file(&out);

    commands::push(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir)
        .await
        .expect("push must provision org/store/branch and self-grant");

    let state = LocalState::load_from(&fx.state_path).unwrap();
    assert_eq!(state.branch(&key("main")).unwrap().dek_version, 1);

    let ref_now = client.get_ref("acme", "backend", "main").await.unwrap();
    assert!(ref_now.is_some(), "branch must exist server-side after push");
}

/// A second, independently-`init`ed local workspace for the SAME org/store/branch (its own
/// unrelated DEK) must hard-fail on `push` once the branch already exists — there is no
/// cryptographic way to reconcile two different DEKs, so this must not silently "win" or merge.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_workspace_that_inits_same_name_before_pushing_is_rejected_on_push() {
    let base = start_server().await;
    let a = ready_fixture("racer", Some(base.clone())).await;
    commands::set(&a.config_path, &a.state_path, &a.socket, &a.dir, vec![("K".into(), "a-value".into())])
        .await
        .unwrap();
    commands::commit(&a.config_path, &a.state_path, &a.socket, &a.dir, "a's commit".into())
        .await
        .unwrap();
    commands::push(&a.config_path, &a.state_path, &a.socket, &a.dir).await.unwrap();

    // A second local workspace (same identity, but a fresh agent => a genuinely different
    // randomly-generated DEK), `init`ed independently for the exact same org/store/branch.
    let b = ready_fixture("racer", Some(base.clone())).await;
    commands::set(&b.config_path, &b.state_path, &b.socket, &b.dir, vec![("K".into(), "b-value".into())])
        .await
        .unwrap();
    commands::commit(&b.config_path, &b.state_path, &b.socket, &b.dir, "b's commit".into())
        .await
        .unwrap();

    let err = commands::push(&b.config_path, &b.state_path, &b.socket, &b.dir).await.unwrap_err();
    assert!(err.to_string().contains("already exists"), "got: {err}");
}

/// `init` refuses to clobber a `wonton.toml` that already names a different org/store, and is a
/// no-op (not an error) when re-run with the exact same org/store.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn init_refuses_to_clobber_a_different_projects_marker() {
    let base = start_server().await;
    let fx = ready_fixture("initclobber", Some(base)).await;

    commands::init(
        &fx.config_path,
        &fx.socket,
        &fx.dir,
        Some("acme".into()),
        Some("backend".into()),
        Some("main".into()),
        None,
    )
    .await
    .expect("re-init with the same org/store is a no-op");

    let err = commands::init(
        &fx.config_path,
        &fx.socket,
        &fx.dir,
        Some("acme".into()),
        Some("other-store".into()),
        Some("main".into()),
        None,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("refusing to overwrite"), "got: {err}");
}

// ---- store create (advanced/manual path) --------------------------------------------------

/// A second `store create` with the same org/name must be an idempotent no-op (`mkdir -p`
/// style), not an error — a repeated onboarding flow needs to be safe to re-run. Also exercises
/// `--identity` being omitted entirely: with exactly one identity logged in, it must be inferred
/// without error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn store_create_is_idempotent_on_a_duplicate_name() {
    let base = start_server().await;
    let machine = login_only("dupstore", &base).await;
    commands::store_create(&machine.config_path, None, "dupstore", "acme").await.unwrap();
    commands::store_create(&machine.config_path, None, "dupstore", "acme")
        .await
        .expect("re-creating an existing org/store must be a no-op, not an error");
}

/// With more than one identity cached in the same config, omitting `--identity` must be a clear
/// error naming the ambiguity rather than silently picking one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn store_create_without_identity_defaults_to_the_current_identity() {
    let base = start_server().await;
    let socket = spawn_agent().await;
    let config_path = temp_config_path();
    commands::login(&config_path, &socket, Some(base.clone()), "multi-a", "pw-a".into())
        .await
        .unwrap();
    commands::login(&config_path, &socket, Some(base), "multi-b", "pw-b".into())
        .await
        .unwrap();

    // "multi-b" was the most recent login (the agent only ever holds one identity resident —
    // see `Config::current_identity`'s docs), so omitting --identity must default to it instead
    // of erroring about ambiguity.
    commands::store_create(&config_path, None, "multi-b", "acme")
        .await
        .expect("should default to the current identity ('multi-b') instead of erroring");
}

/// A config with more than one cached identity and no resolvable `current_identity` (e.g.
/// hand-edited, or inherited from another machine) must still error clearly rather than silently
/// guess.
#[tokio::test]
async fn store_create_without_identity_errors_clearly_when_truly_ambiguous() {
    let base = start_server().await;
    let socket = spawn_agent().await;
    let config_path = temp_config_path();
    commands::login(&config_path, &socket, Some(base.clone()), "multi-a", "pw-a".into())
        .await
        .unwrap();
    commands::login(&config_path, &socket, Some(base), "multi-b", "pw-b".into())
        .await
        .unwrap();

    let mut config = Config::load_from(&config_path).unwrap();
    config.current_identity = None;
    config.save_to(&config_path).unwrap();

    let err = commands::store_create(&config_path, None, "multi-a", "acme").await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("multi-a") && msg.contains("multi-b"), "got: {msg}");
}

// ---- branch list / switch / create ---------------------------------------------------------

/// `wonton branch` (list) shows the current branch; `branch -b <name>` creates one with its own
/// DEK and switches to it (purely local, no network).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn branch_create_and_switch_are_local_and_update_the_marker() {
    let base = start_server().await;
    let fx = ready_fixture("brancher", Some(base)).await;

    assert_eq!(crate::config::read_local_branch(&fx.dir), Some("main".to_string()));

    commands::branch_create(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, "feature", None, None)
        .await
        .expect("creating a branch with no --from is fully local");
    assert_eq!(crate::config::read_local_branch(&fx.dir), Some("feature".to_string()));

    // Creating the same name again must be rejected, not silently overwritten.
    let err = commands::branch_create(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, "feature", None, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("already exists"), "got: {err}");

    commands::branch_switch(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, "main")
        .await
        .expect("switching back to main");
    assert_eq!(crate::config::read_local_branch(&fx.dir), Some("main".to_string()));
}

/// `branch -b <name> --from <source>` seeds the new branch's first commit from the source
/// branch's current values, re-encrypted under the new branch's own (different) DEK.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn branch_create_from_source_seeds_a_root_commit_under_its_own_dek() {
    let base = start_server().await;
    let fx = ready_fixture("forker", Some(base)).await;
    commands::set(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, vec![("K".into(), "v".into())])
        .await
        .unwrap();
    commands::commit(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, "root".into())
        .await
        .unwrap();

    commands::branch_create(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, "dev", Some("main"), None)
        .await
        .expect("forking from main");

    let state = LocalState::load_from(&fx.state_path).unwrap();
    let dev = state.branch(&key("dev")).unwrap();
    let root = dev.tip.expect("branch -b --from must produce a root commit");
    assert_eq!(dev.forked_from.as_ref().unwrap().branch, key("main"));
    assert_eq!(dev.forked_from.as_ref().unwrap().root, root);

    // The value is readable on "dev" (re-encrypted under dev's own DEK).
    assert_eq!(read_via_run(&fx, "K").await, "v");

    // And the object it's stored under is genuinely different ciphertext from main's own blob
    // for the same key (different DEK+nonce), even though the plaintext is identical.
    let main_tip = tip_of(&fx.state_path, &key("main"));
    let main_hash = blob_hash_for_key(&fx.state_path, main_tip, "K");
    let dev_hash = blob_hash_for_key(&fx.state_path, root, "K");
    assert_ne!(main_hash, dev_hash, "forked branch must re-encrypt under its own DEK, not reuse the source's blob");
}

/// `wonton branch` (list) must succeed and exercise the "sync with remote" path (it queries
/// `list_branches` on the server, not just locally-known state) — here that reconfirms the one
/// branch bob cloned, but the point is the network round-trip doesn't error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn branch_list_succeeds_and_syncs_with_remote() {
    let owner = ready_fixture("blistowner", None).await;
    commands::set(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, vec![("K".into(), "v".into())])
        .await
        .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "c1".into())
        .await
        .unwrap();
    commands::push(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir).await.unwrap();

    let bob = login_only("blistbob", &owner.base).await;
    commands::share(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, None, "blistbob", Role::Reader)
        .await
        .unwrap();
    let bob_dir = temp_dir();
    commands::clone(&bob.config_path, &bob.state_path, &bob.socket, &bob_dir, "acme", "backend", Some("main"), None)
        .await
        .unwrap();

    commands::branch_list(&bob.config_path, &bob.state_path, &bob_dir)
        .await
        .expect("branch list must succeed and sync with remote");
}

/// `status` must work cleanly across every remote-comparison state: before any push
/// (`dek_version == 0`, nothing to compare), right after a push (up to date), and after a local
/// commit that hasn't been pushed yet (ahead).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_reports_across_not_yet_pushed_up_to_date_and_ahead_states() {
    let fx = ready_fixture("statuscheck", None).await;
    commands::status(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir)
        .await
        .expect("status must work before any push");

    commands::set(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, vec![("K".into(), "v".into())])
        .await
        .unwrap();
    commands::commit(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, "c1".into())
        .await
        .unwrap();
    commands::push(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir).await.unwrap();
    commands::status(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir)
        .await
        .expect("status must work right after push (up to date)");

    commands::set(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, vec![("K2".into(), "v2".into())])
        .await
        .unwrap();
    commands::commit(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, "c2".into())
        .await
        .unwrap();
    commands::status(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir)
        .await
        .expect("status must work while ahead of the remote (unpushed local commit)");
}

/// A project's `wonton.toml` `server` field must narrow identity resolution: with two
/// identities logged into two DIFFERENT servers, a directory-bound command picks the one
/// matching this project's server, with no ambiguity error and no `--identity` needed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn identity_resolution_is_scoped_by_the_projects_server() {
    let base_a = start_server().await;
    let base_b = start_server().await;
    let socket = spawn_agent().await;
    let config_path = temp_config_path();
    let state_path = temp_state_path();

    // Two identities, same local config, but logged into two DIFFERENT servers.
    commands::login(&config_path, &socket, Some(base_a.clone()), "alice-a", "pw-a".into())
        .await
        .unwrap();
    commands::login(&config_path, &socket, Some(base_b.clone()), "alice-b", "pw-b".into())
        .await
        .unwrap();

    let dir = temp_dir();
    // `init` has no project server yet to narrow by, so the whole-list ambiguity still applies
    // there — pass --identity explicitly for the bootstrap step itself.
    commands::init(
        &config_path,
        &socket,
        &dir,
        Some("acme".into()),
        Some("backend".into()),
        Some("main".into()),
        Some("alice-a"),
    )
    .await
    .unwrap();

    // But now that wonton.toml names base_a's server, an ordinary directory-bound command needs
    // NO --identity at all, despite two identities being cached locally — the project's server
    // narrows it to exactly one.
    commands::status(&config_path, &state_path, &socket, &dir)
        .await
        .expect("must resolve unambiguously via the project's declared server");
}

// ---- the VCS porcelain ----------------------------------------------------------------------

/// `set` stages an encrypted blob; `status` runs; `unset` overwrites it with a tombstone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_status_and_unset_manage_the_staging_area() {
    let fx = ready_fixture("erin", None).await;

    commands::set(
        &fx.config_path,
        &fx.state_path,
        &fx.socket,
        &fx.dir,
        vec![("API_KEY".into(), "sk-live-123".into())],
    )
    .await
    .unwrap();

    let state = LocalState::load_from(&fx.state_path).unwrap();
    let staged = &state.branch(&key("main")).unwrap().staged;
    assert!(matches!(staged.get("API_KEY"), Some(crate::state::StagedEntry::Set(_))));

    // status must run without error against the staged tree.
    commands::status(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir).await.unwrap();

    // `unset` replaces the staged Set with an Unset tombstone.
    commands::unset(&fx.config_path, &fx.state_path, &fx.dir, vec!["API_KEY".into()]).unwrap();
    let state = LocalState::load_from(&fx.state_path).unwrap();
    assert_eq!(
        state.branch(&key("main")).unwrap().staged.get("API_KEY"),
        Some(&crate::state::StagedEntry::Unset)
    );
}

/// `commit` clears staging, advances the tip, and `log` shows the commit with the REAL
/// server-assigned `author_id`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_advances_tip_and_log_shows_real_author_id() {
    let fx = ready_fixture("frank", None).await;

    commands::set(
        &fx.config_path,
        &fx.state_path,
        &fx.socket,
        &fx.dir,
        vec![("DATABASE_URL".into(), "postgres://x".into())],
    )
    .await
    .unwrap();
    commands::commit(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, "initial".into())
        .await
        .unwrap();

    let state = LocalState::load_from(&fx.state_path).unwrap();
    let bs = state.branch(&key("main")).unwrap();
    assert!(bs.staged.is_empty(), "staging must be cleared after commit");
    let tip = bs.tip.expect("tip advanced");

    let store = open_object_store(&object_store_dir_for(&fx.state_path)).unwrap();
    let bytes = store.get(&tip).unwrap().unwrap();
    let commit = Commit::from_bytes(&bytes).unwrap();
    assert_eq!(commit.fields.author_id, uuid::Uuid::parse_str(&fx.user_id).unwrap());
    assert_eq!(commit.fields.message, "initial");

    commands::log(&fx.config_path, &fx.state_path, &fx.dir).await.unwrap();
}

/// `diff` between two real commits reports the right Added/Changed keys, and re-committing an
/// identical value must NOT report `Changed`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn diff_reports_added_and_changed_but_not_unchanged() {
    let fx = ready_fixture("grace", None).await;

    commands::set(
        &fx.config_path,
        &fx.state_path,
        &fx.socket,
        &fx.dir,
        vec![("A".into(), "apple".into()), ("B".into(), "banana".into())],
    )
    .await
    .unwrap();
    commands::commit(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, "c1".into())
        .await
        .unwrap();
    let c1 = tip_of(&fx.state_path, &key("main"));

    commands::set(
        &fx.config_path,
        &fx.state_path,
        &fx.socket,
        &fx.dir,
        vec![
            ("A".into(), "apple".into()),
            ("B".into(), "blueberry".into()),
            ("C".into(), "cherry".into()),
        ],
    )
    .await
    .unwrap();
    commands::commit(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, "c2".into())
        .await
        .unwrap();
    let c2 = tip_of(&fx.state_path, &key("main"));

    let entries = commands::diff(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, Some(c1.to_hex()), Some(c2.to_hex()))
        .await
        .unwrap();

    use wonton_vcs::DiffEntry;
    assert_eq!(entries, vec![DiffEntry::Changed("B".into()), DiffEntry::Added("C".into())]);
    assert!(
        !entries.iter().any(|e| matches!(e, DiffEntry::Changed(k) if k == "A")),
        "re-committing the same value must not show Changed"
    );

    let entries_short = commands::diff(
        &fx.config_path,
        &fx.state_path,
        &fx.socket,
        &fx.dir,
        Some(c1.to_hex()[..10].to_string()),
        Some(c2.to_hex()[..10].to_string()),
    )
    .await
    .expect("an unambiguous 10-char prefix must resolve");
    assert_eq!(entries_short, entries, "prefix and full-hash forms must resolve to the same diff");
}

/// A hash prefix that matches nothing, and one that's simply malformed, must both be clear
/// errors — never a panic or a silent empty diff.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn diff_rejects_an_unknown_prefix_and_malformed_input() {
    let fx = ready_fixture("prefixerr", None).await;
    commands::set(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, vec![("K".into(), "v".into())])
        .await
        .unwrap();
    commands::commit(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, "root".into())
        .await
        .unwrap();

    let err = commands::diff(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, Some("deadbeef00".into()), None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no commit matches"), "got: {err}");

    let err = commands::diff(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, Some("not-hex!!".into()), None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not a valid commit hash"), "got: {err}");
}

/// `run` injects the effective secrets as env vars into a child process (never touching disk) and
/// propagates its exit code.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_injects_secrets_as_env_vars() {
    let fx = ready_fixture("heidi", None).await;

    commands::set(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, vec![("MY_SECRET".into(), "hunter2".into())])
        .await
        .unwrap();
    commands::commit(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, "c1".into())
        .await
        .unwrap();

    assert_eq!(read_via_run(&fx, "MY_SECRET").await, "hunter2");
}

/// `export --format dotenv` writes a file whose parsed content matches the committed + staged
/// values. (The plaintext warning is emitted to stderr; we assert the file's correctness.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn export_writes_dotenv_matching_the_working_tree() {
    let fx = ready_fixture("ivan", None).await;

    commands::set(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, vec![("TOKEN".into(), "abc123".into())])
        .await
        .unwrap();
    commands::commit(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, "c1".into())
        .await
        .unwrap();
    commands::set(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, vec![("EXTRA".into(), "with space".into())])
        .await
        .unwrap();

    let out = unique("dotenv");
    commands::export(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, commands::ExportFormat::Dotenv, &out)
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap();
    assert!(contents.contains("TOKEN=abc123\n"), "got: {contents}");
    assert!(contents.contains("EXTRA=\"with space\"\n"), "got: {contents}");
    let _ = std::fs::remove_file(&out);
}

/// End-to-end: machine A commits + pushes; a second, fresh directory (`clone`, same account —
/// mirrors "two machines sharing one account") auto-unwraps the self-granted DEK and
/// auto-pulls the history immediately, seeing the same tip and the same decrypted value with
/// zero extra commands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_then_fresh_clone_sees_the_same_secrets() {
    let a = ready_fixture("judy", None).await;
    commands::set(&a.config_path, &a.state_path, &a.socket, &a.dir, vec![("SHARED".into(), "top-secret".into())])
        .await
        .unwrap();
    commands::commit(&a.config_path, &a.state_path, &a.socket, &a.dir, "seed".into())
        .await
        .unwrap();
    commands::push(&a.config_path, &a.state_path, &a.socket, &a.dir).await.unwrap();
    let a_tip = tip_of(&a.state_path, &key("main"));

    let socket = spawn_agent().await;
    let config_path = temp_config_path();
    let state_path = temp_state_path();
    let dir = temp_dir();
    commands::login(&config_path, &socket, Some(a.base.clone()), "judy", "pw-judy".into())
        .await
        .unwrap();
    commands::clone(&config_path, &state_path, &socket, &dir, "acme", "backend", Some("main"), None)
        .await
        .unwrap();

    let b_tip = tip_of(&state_path, &key("main"));
    assert_eq!(a_tip, b_tip, "clone should fast-forward to A's tip immediately");

    commands::log(&config_path, &state_path, &dir).await.unwrap();
    let out = unique("bpull");
    let out_str = out.to_string_lossy().to_string();
    let code = commands::run(
        &config_path,
        &state_path,
        &socket,
        &dir,
        vec!["sh".into(), "-c".into(), format!("printf '%s' \"$SHARED\" > {out_str}")],
    )
    .await
    .unwrap();
    assert_eq!(code, 0);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "top-secret");
    let _ = std::fs::remove_file(&out);
}

/// The join flow: before being `share`d, the target's first command clearly reports "no
/// access"; after `share`, the very next command (no separate `use`/`pull`) just works —
/// auto-unwrapping the DEK and auto-pulling the history.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clone_reports_no_access_then_works_after_share() {
    let owner = ready_fixture("cloneowner", None).await;
    commands::set(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, vec![("SHARED".into(), "top-secret".into())])
        .await
        .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "seed".into())
        .await
        .unwrap();
    commands::push(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir).await.unwrap();

    let bob = login_only("cloneBob", &owner.base).await;
    let bob_dir = temp_dir();
    commands::clone(&bob.config_path, &bob.state_path, &bob.socket, &bob_dir, "acme", "backend", Some("main"), None)
        .await
        .expect("clone itself just writes markers; it doesn't require access");

    let err = commands::run(&bob.config_path, &bob.state_path, &bob.socket, &bob_dir, vec!["true".into()])
        .await
        .unwrap_err();
    assert!(err.to_string().contains("don't have access"), "got: {err}");

    commands::share(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, None, "cloneBob", Role::Reader)
        .await
        .unwrap();

    let out = unique("cloneout");
    let out_str = out.to_string_lossy().to_string();
    let code = commands::run(
        &bob.config_path,
        &bob.state_path,
        &bob.socket,
        &bob_dir,
        vec!["sh".into(), "-c".into(), format!("printf '%s' \"$SHARED\" > {out_str}")],
    )
    .await
    .expect("the next command after being shared must just work: auto-unwrap + auto-pull");
    assert_eq!(code, 0);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "top-secret");
    let _ = std::fs::remove_file(&out);
}

// ---- login / whoami --------------------------------------------------------------------------

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

/// `whoami` with no identities logged in must say so clearly, not print nothing or error.
#[tokio::test]
async fn whoami_reports_not_logged_in_with_no_identities() {
    let config_path = temp_config_path();
    Config::default().save_to(&config_path).unwrap();
    let config = Config::load_from(&config_path).unwrap();
    let mut out = Vec::new();
    commands::whoami_report(&config, &mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("Not logged in"), "got: {text}");
}

/// `whoami` with exactly one identity must name it, its username, and its server.
#[tokio::test]
async fn whoami_reports_the_sole_identity() {
    let base = start_server().await;
    let socket = spawn_agent().await;
    let config_path = temp_config_path();
    commands::login(&config_path, &socket, Some(base.clone()), "solo", "pw-solo".into())
        .await
        .unwrap();

    let config = Config::load_from(&config_path).unwrap();
    let mut out = Vec::new();
    commands::whoami_report(&config, &mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("solo"), "got: {text}");
    assert!(text.contains(&base), "got: {text}");
}

/// `whoami` with more than one identity must list all of them and flag the ambiguity, not just
/// pick one silently.
#[tokio::test]
async fn whoami_lists_every_identity_when_there_are_several() {
    let base = start_server().await;
    let socket = spawn_agent().await;
    let config_path = temp_config_path();
    commands::login(&config_path, &socket, Some(base.clone()), "first", "pw-first".into())
        .await
        .unwrap();
    commands::login(&config_path, &socket, Some(base), "second", "pw-second".into())
        .await
        .unwrap();

    let config = Config::load_from(&config_path).unwrap();
    let mut out = Vec::new();
    commands::whoami_report(&config, &mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("first") && text.contains("second"), "got: {text}");
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

/// `login` with no `--server` and no already-known identity falls back to the global config's
/// `default_server` (set via `wonton config set-server`) instead of erroring.
#[tokio::test]
async fn login_falls_back_to_the_configured_default_server() {
    let base = start_server().await;
    let socket = spawn_agent().await;
    let config_path = temp_config_path();

    commands::config_set_server(&config_path, &base).unwrap();
    commands::login(&config_path, &socket, None, "dana", "pw-dana".into())
        .await
        .expect("login should fall back to the configured default server");

    let config = Config::load_from(&config_path).unwrap();
    let id = config.find_identity("dana").unwrap();
    assert_eq!(id.server_url, base);
}

/// With no `--server`, no already-known identity, and no configured default, `login` must still
/// error clearly rather than panic — and the error should point at how to fix it either way.
#[tokio::test]
async fn login_without_any_server_source_errors_clearly() {
    let socket = spawn_agent().await;
    let config_path = temp_config_path();

    let err = commands::login(&config_path, &socket, None, "erin", "pw-erin".into())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("wonton config set-server"), "got: {err}");
}

/// `config set-server` persists across loads, and `config show` reports it; before it's ever
/// set, `config show` says so explicitly instead of printing nothing.
#[test]
fn config_set_server_persists_and_show_reports_it() {
    let config_path = temp_config_path();

    commands::config_show(&config_path).unwrap(); // no default yet — must not error

    commands::config_set_server(&config_path, "https://wonton.example.com").unwrap();
    let config = Config::load_from(&config_path).unwrap();
    assert_eq!(config.default_server, Some("https://wonton.example.com".to_string()));

    // Setting it again overwrites rather than erroring or duplicating.
    commands::config_set_server(&config_path, "https://wonton2.example.com").unwrap();
    let config = Config::load_from(&config_path).unwrap();
    assert_eq!(config.default_server, Some("https://wonton2.example.com".to_string()));
}

/// Each `login` becomes the new `current_identity` (mirrors the agent only ever holding one
/// identity's key material resident at a time), and a sole cached identity's `logout` forgets it
/// entirely from config *and* locks the agent, since that identity's key is the one resident.
#[tokio::test]
async fn logout_forgets_the_identity_and_locks_the_resident_agent() {
    let base = start_server().await;
    let socket = spawn_agent().await;
    let config_path = temp_config_path();
    commands::login(&config_path, &socket, Some(base), "gina", "pw-gina".into())
        .await
        .unwrap();
    assert_eq!(Config::load_from(&config_path).unwrap().current_identity, Some("gina".to_string()));
    assert!(agent::status(&socket).await.unwrap().unlocked);

    commands::logout(&config_path, &socket, None).await.expect("logout should succeed");

    let config = Config::load_from(&config_path).unwrap();
    assert!(config.find_identity("gina").is_none(), "identity should be forgotten");
    assert_eq!(config.current_identity, None);
    assert!(!agent::status(&socket).await.unwrap().unlocked, "resident agent should be locked");
}

/// Logging out an identity that is NOT the one currently resident in the agent (two identities
/// cached; the second login replaced the first as resident) must forget it from config without
/// disturbing the agent's actually-resident identity.
#[tokio::test]
async fn logout_of_a_non_resident_identity_does_not_lock_the_agent() {
    let base = start_server().await;
    let socket = spawn_agent().await;
    let config_path = temp_config_path();
    commands::login(&config_path, &socket, Some(base.clone()), "multi-a", "pw-a".into())
        .await
        .unwrap();
    commands::login(&config_path, &socket, Some(base), "multi-b", "pw-b".into())
        .await
        .unwrap(); // agent is now resident as multi-b

    commands::logout(&config_path, &socket, Some("multi-a")).await.unwrap();

    let config = Config::load_from(&config_path).unwrap();
    assert!(config.find_identity("multi-a").is_none());
    assert!(config.find_identity("multi-b").is_some(), "multi-b should be untouched");
    assert_eq!(config.current_identity, Some("multi-b".to_string()));
    assert!(
        agent::status(&socket).await.unwrap().unlocked,
        "multi-b's key is still resident and should remain unlocked"
    );
}

/// `logout` with nothing cached at all is a clear error, not a panic.
#[tokio::test]
async fn logout_with_no_identities_errors_clearly() {
    let socket = spawn_agent().await;
    let config_path = temp_config_path();
    let err = commands::logout(&config_path, &socket, None).await.unwrap_err();
    assert!(err.to_string().contains("no identity logged in"), "got: {err}");
}

/// A directory with no `wonton.toml` anywhere in its ancestry is a clear error pointing at
/// `init`/`clone`, not a panic or a silent no-op.
#[tokio::test]
async fn commands_without_a_wonton_toml_error_clearly() {
    let dir = temp_dir();
    let config_path = temp_config_path();
    let state_path = temp_state_path();
    let err = commands::log(&config_path, &state_path, &dir).await.unwrap_err();
    assert!(err.to_string().contains("wonton init"), "got: {err}");
}

// ---- sharing, revocation, key rotation --------------------------------------------------------

/// `share` grants a second user access with NO re-encryption (O(1)): the object count is
/// unchanged, and the target can then `clone` + read the same secret the sharer committed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn share_grants_access_without_re_encryption() {
    let owner = ready_fixture("p5owner", None).await;
    commands::set(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, vec![("SECRET".into(), "sk-shared".into())])
        .await
        .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "seed".into())
        .await
        .unwrap();
    commands::push(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir).await.unwrap();

    let bob = login_only("p5bob", &owner.base).await;
    let bob_dir = temp_dir();

    let before = count_objects(&owner.state_path);
    commands::share(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, None, "p5bob", Role::Reader)
        .await
        .expect("share should grant access");
    let after = count_objects(&owner.state_path);
    assert_eq!(before, after, "share must not re-encrypt / create objects");

    commands::clone(&bob.config_path, &bob.state_path, &bob.socket, &bob_dir, "acme", "backend", Some("main"), None)
        .await
        .unwrap();

    let out = unique("shareout");
    let out_str = out.to_string_lossy().to_string();
    let code = commands::run(
        &bob.config_path,
        &bob.state_path,
        &bob.socket,
        &bob_dir,
        vec!["sh".into(), "-c".into(), format!("printf '%s' \"$SECRET\" > {out_str}")],
    )
    .await
    .unwrap();
    assert_eq!(code, 0);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "sk-shared");
    let _ = std::fs::remove_file(&out);
}

/// `log` used to verify every commit against the *local caller's own* pubkey; a second identity
/// reading a history genuinely authored by BOTH users (each committing in turn) must succeed,
/// resolving each commit against its own author.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn log_verifies_a_history_with_more_than_one_real_author() {
    let alice = ready_fixture("p5xalice", None).await;
    commands::set(&alice.config_path, &alice.state_path, &alice.socket, &alice.dir, vec![("K".into(), "alice-value".into())])
        .await
        .unwrap();
    commands::commit(&alice.config_path, &alice.state_path, &alice.socket, &alice.dir, "alice's commit".into())
        .await
        .unwrap();
    commands::push(&alice.config_path, &alice.state_path, &alice.socket, &alice.dir).await.unwrap();

    let bob = login_only("p5xbob", &alice.base).await;
    commands::share(&alice.config_path, &alice.state_path, &alice.socket, &alice.dir, None, "p5xbob", Role::Writer)
        .await
        .unwrap();
    let bob_dir = temp_dir();
    commands::clone(&bob.config_path, &bob.state_path, &bob.socket, &bob_dir, "acme", "backend", Some("main"), None)
        .await
        .unwrap();

    commands::set(&bob.config_path, &bob.state_path, &bob.socket, &bob_dir, vec![("K2".into(), "bob-value".into())])
        .await
        .unwrap();
    commands::commit(&bob.config_path, &bob.state_path, &bob.socket, &bob_dir, "bob's commit".into())
        .await
        .unwrap();

    commands::log(&bob.config_path, &bob.state_path, &bob_dir).await.unwrap();
    commands::push(&bob.config_path, &bob.state_path, &bob.socket, &bob_dir).await.unwrap();
    commands::pull(&alice.config_path, &alice.state_path, &alice.dir).await.unwrap();
    commands::log(&alice.config_path, &alice.state_path, &alice.dir).await.unwrap();
}

/// After `revoke` + the fresh commit that follows, the revoked user's STALE cached DEK can no
/// longer decrypt a value committed after the revocation (AEAD auth failure, fail-closed — never
/// garbage).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoke_denies_the_revoked_users_stale_dek() {
    let owner = ready_fixture("p5rowner", None).await;
    commands::set(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, vec![("OLD".into(), "old-value".into())])
        .await
        .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "v1".into())
        .await
        .unwrap();
    commands::push(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir).await.unwrap();

    let mallory = login_only("p5mallory", &owner.base).await;
    commands::share(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, None, "p5mallory", Role::Reader)
        .await
        .unwrap();
    let mallory_dir = temp_dir();
    commands::clone(&mallory.config_path, &mallory.state_path, &mallory.socket, &mallory_dir, "acme", "backend", Some("main"), None)
        .await
        .expect("mallory clones and caches DEK v1");

    commands::revoke(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, None, "p5mallory")
        .await
        .expect("revoke + rotate");
    let state = LocalState::load_from(&owner.state_path).unwrap();
    assert_eq!(state.branch(&key("main")).unwrap().dek_version, 2, "owner is on v2 after rotation");

    commands::set(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, vec![("NEW".into(), "post-revocation-secret".into())])
        .await
        .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "v2-secret".into())
        .await
        .unwrap();

    let tip = tip_of(&owner.state_path, &key("main"));
    let blob_hash = blob_hash_for_key(&owner.state_path, tip, "NEW");
    let store = open_object_store(&object_store_dir_for(&owner.state_path)).unwrap();
    let blob = Blob::from_bytes(&store.get(&blob_hash).unwrap().unwrap()).unwrap();
    let value = EncryptedValue {
        nonce: blob.nonce,
        ciphertext: blob.ciphertext,
    };

    let mallory_cipher = AgentCipher::new(mallory.socket.clone(), key("main"));
    let result = tokio::task::spawn_blocking(move || mallory_cipher.decrypt(&value)).await.unwrap();
    assert!(result.is_err(), "revoked user's stale DEK must not decrypt post-rotation ciphertext");
}

/// `key rotate` alone (no membership change): advances the tip, changes an existing key's blob
/// hash (re-encrypted under a fresh DEK), and a remaining member can still log + decrypt after.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn key_rotate_alone_advances_tip_and_reencrypts() {
    let owner = ready_fixture("p5kowner", None).await;
    commands::set(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, vec![("KEY".into(), "the-value".into())])
        .await
        .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "v1".into())
        .await
        .unwrap();
    commands::push(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir).await.unwrap();

    let tip1 = tip_of(&owner.state_path, &key("main"));
    let h1 = blob_hash_for_key(&owner.state_path, tip1, "KEY");

    commands::rotate(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, None)
        .await
        .expect("key rotate");

    let state = LocalState::load_from(&owner.state_path).unwrap();
    assert_eq!(state.branch(&key("main")).unwrap().dek_version, 2, "version advanced to 2");
    let tip2 = tip_of(&owner.state_path, &key("main"));
    assert_ne!(tip1, tip2, "rotation must advance the tip");
    let h2 = blob_hash_for_key(&owner.state_path, tip2, "KEY");
    assert_ne!(h1, h2, "the same plaintext under a fresh DEK+nonce must yield a different blob");

    commands::log(&owner.config_path, &owner.state_path, &owner.dir).await.unwrap();
    assert_eq!(read_via_run(&owner, "KEY").await, "the-value");
}

// ---- three-way merge across two DEKs --------------------------------------------------------

/// Two branches (each with their own DEK) that each add a different, non-overlapping key
/// auto-merge with zero conflicts, producing a real 2-parent commit that `wonton log` walks
/// through without erroring. Exercises the fork-root-as-merge-base path since `feature` was
/// created via `--from main`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn merge_with_no_conflicts_produces_a_two_parent_commit() {
    let owner = ready_fixture("p5bmerge1", None).await;
    commands::set(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, vec![("ROOT".into(), "root-value".into())])
        .await
        .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "root".into())
        .await
        .unwrap();

    commands::branch_create(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "feature", Some("main"), None)
        .await
        .unwrap();
    commands::set(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, vec![("FEATURE_KEY".into(), "feature-value".into())])
        .await
        .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "feature commit".into())
        .await
        .unwrap();

    commands::branch_switch(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "main")
        .await
        .unwrap();
    commands::set(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, vec![("MAIN_KEY".into(), "main-value".into())])
        .await
        .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "main commit".into())
        .await
        .unwrap();
    let main_tip_before = tip_of(&owner.state_path, &key("main"));

    commands::merge(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "feature")
        .await
        .expect("no conflicts, must merge cleanly across the two branches' different DEKs");

    let merged_tip = tip_of(&owner.state_path, &key("main"));
    assert_ne!(merged_tip, main_tip_before);

    let store = open_object_store(&object_store_dir_for(&owner.state_path)).unwrap();
    let commit = Commit::from_bytes(&store.get(&merged_tip).unwrap().unwrap()).unwrap();
    assert_eq!(commit.fields.parent_hashes.len(), 2, "a merge commit must have exactly 2 parents");
    assert!(commit.fields.parent_hashes.contains(&main_tip_before));

    commands::log(&owner.config_path, &owner.state_path, &owner.dir).await.unwrap();

    assert_eq!(read_via_run(&owner, "ROOT").await, "root-value");
    assert_eq!(read_via_run(&owner, "MAIN_KEY").await, "main-value");
    assert_eq!(read_via_run(&owner, "FEATURE_KEY").await, "feature-value");

    let state = LocalState::load_from(&owner.state_path).unwrap();
    assert!(state.branch(&key("main")).unwrap().merge.is_none(), "no merge state persisted for a clean merge");
}

/// A same-key divergent edit on both (differently-keyed) branches conflicts. Since the test
/// process's stdin is non-interactive (immediate EOF), `merge` pauses on it exactly like a
/// skipped prompt would, persisting only content hashes (never plaintext) into `state.toml`.
/// Manually completing the resolution and calling `merge --continue` must then finalize the
/// 2-parent commit and clear the paused state.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn merge_conflict_pauses_with_hash_only_state_then_continue_resolves() {
    let owner = ready_fixture("p5bmerge2", None).await;
    commands::set(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, vec![("KEY".into(), "base-value".into())])
        .await
        .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "root".into())
        .await
        .unwrap();

    commands::branch_create(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "feature", Some("main"), None)
        .await
        .unwrap();
    commands::set(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, vec![("KEY".into(), "feature-value".into())])
        .await
        .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "feature edit".into())
        .await
        .unwrap();

    commands::branch_switch(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "main")
        .await
        .unwrap();
    commands::set(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, vec![("KEY".into(), "main-value".into())])
        .await
        .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "main edit".into())
        .await
        .unwrap();

    commands::merge(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "feature")
        .await
        .expect("merge itself succeeds even though it pauses on an unresolved conflict");

    let state = LocalState::load_from(&owner.state_path).unwrap();
    let merge_state = state
        .branch(&key("main"))
        .unwrap()
        .merge
        .clone()
        .expect("a paused merge must be persisted");
    assert_eq!(merge_state.branch, key("feature"));
    assert_eq!(merge_state.conflicts.len(), 1);
    assert!(merge_state.conflicts.contains_key("KEY"));
    assert!(merge_state.resolved.is_empty());

    let raw = std::fs::read_to_string(&owner.state_path).unwrap();
    assert!(!raw.contains("base-value"));
    assert!(!raw.contains("feature-value"));
    assert!(!raw.contains("main-value"));

    // Resolve "KEY" to "ours" (main-value) exactly as a completed interactive prompt would, by
    // editing the persisted hashes directly, then finish via `--continue`.
    {
        let mut state = LocalState::load_from(&owner.state_path).unwrap();
        let bs = state.branch_mut(&key("main"));
        let mut merge_state = bs.merge.clone().unwrap();
        let conflict = merge_state.conflicts.remove("KEY").unwrap();
        merge_state.resolved.insert("KEY".to_string(), ResolvedEntry::Set(conflict.ours.unwrap()));
        bs.merge = Some(merge_state);
        state.save_to(&owner.state_path).unwrap();
    }

    commands::merge_continue(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir)
        .await
        .expect("continue finalizes once every conflict is resolved");

    let state = LocalState::load_from(&owner.state_path).unwrap();
    assert!(state.branch(&key("main")).unwrap().merge.is_none(), "merge state must be cleared after finalizing");

    let merged_tip = tip_of(&owner.state_path, &key("main"));
    let store = open_object_store(&object_store_dir_for(&owner.state_path)).unwrap();
    let commit = Commit::from_bytes(&store.get(&merged_tip).unwrap().unwrap()).unwrap();
    assert_eq!(commit.fields.parent_hashes.len(), 2);
    commands::log(&owner.config_path, &owner.state_path, &owner.dir).await.unwrap();

    assert_eq!(read_via_run(&owner, "KEY").await, "main-value", "resolved to ours (main-value)");
}

/// `merge --abort` discards a paused merge entirely: the merge state is cleared, no commit is
/// ever created, the branch tip is untouched, and ordinary work (a fresh commit) continues to
/// work normally afterward.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn merge_abort_discards_a_paused_merge_without_a_trace() {
    let owner = ready_fixture("p5babort", None).await;
    commands::set(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, vec![("KEY".into(), "base-value".into())])
        .await
        .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "root".into())
        .await
        .unwrap();

    commands::branch_create(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "feature", Some("main"), None)
        .await
        .unwrap();
    commands::set(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, vec![("KEY".into(), "feature-value".into())])
        .await
        .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "feature edit".into())
        .await
        .unwrap();

    commands::branch_switch(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "main")
        .await
        .unwrap();
    commands::set(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, vec![("KEY".into(), "main-value".into())])
        .await
        .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "main edit".into())
        .await
        .unwrap();
    let main_tip_before_merge = tip_of(&owner.state_path, &key("main"));

    commands::merge(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "feature")
        .await
        .expect("pauses on the KEY conflict");
    let state = LocalState::load_from(&owner.state_path).unwrap();
    assert!(state.branch(&key("main")).unwrap().merge.is_some(), "a merge must be paused");

    commands::merge_abort(&owner.config_path, &owner.state_path, &owner.dir)
        .await
        .expect("abort must succeed while a merge is paused");

    let state = LocalState::load_from(&owner.state_path).unwrap();
    assert!(state.branch(&key("main")).unwrap().merge.is_none(), "merge state must be cleared");
    assert_eq!(
        tip_of(&owner.state_path, &key("main")),
        main_tip_before_merge,
        "aborting must not create or move to any merge commit"
    );

    commands::set(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, vec![("AFTER_ABORT".into(), "still-works".into())])
        .await
        .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "post-abort commit".into())
        .await
        .unwrap();
    assert_eq!(read_via_run(&owner, "AFTER_ABORT").await, "still-works");
}

/// `merge --abort` with nothing paused is a clear user error, not a silent no-op.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn merge_abort_without_a_paused_merge_errors() {
    let owner = ready_fixture("p5babort2", None).await;
    let err = commands::merge_abort(&owner.config_path, &owner.state_path, &owner.dir).await.unwrap_err();
    assert!(err.to_string().contains("no merge in progress"), "got: {err}");
}

/// `merge --continue` with nothing paused is a clear user error, not a silent no-op.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn merge_continue_without_a_paused_merge_errors() {
    let owner = ready_fixture("p5bmerge3", None).await;
    let err = commands::merge_continue(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no merge in progress"), "got: {err}");
}

/// Merging a branch name that was never created (locally or server-side) is a clear user error,
/// not a silent no-op.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn merge_unknown_branch_errors() {
    let owner = ready_fixture("p5bmerge4", None).await;
    commands::set(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, vec![("K".into(), "v".into())])
        .await
        .unwrap();
    commands::commit(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "root".into())
        .await
        .unwrap();

    let err = commands::merge(&owner.config_path, &owner.state_path, &owner.socket, &owner.dir, "nonexistent")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("wrapped-DEK map"), "got: {err}");
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
/// named exits (`wonton run`'s child-process environment and `wonton export`'s named file). This
/// drives a full `set` -> `commit` -> `run` cycle and then scans every file under the state
/// directory (object store + `state.toml`), the config directory (`config.toml`, cached wrapped
/// keys), and the project directory (`wonton.toml` + `.wonton.local`) for the literal plaintext
/// bytes, asserting they never appear — only ciphertext/hashes/non-secret metadata may.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_plaintext_secret_touches_disk_outside_the_named_export_exit() {
    let fx = ready_fixture("nopt", None).await;
    let plaintext = "sk-super-secret-plaintext-marker-9f3a";

    commands::set(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, vec![("SECRET".into(), plaintext.into())])
        .await
        .unwrap();
    commands::commit(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, "seed".into())
        .await
        .unwrap();

    let code = commands::run(&fx.config_path, &fx.state_path, &fx.socket, &fx.dir, vec!["true".into()])
        .await
        .unwrap();
    assert_eq!(code, 0);

    let needle = plaintext.as_bytes();
    for dir in [
        fx.state_path.parent().expect("state_path has a parent dir"),
        fx.config_path.parent().expect("config_path has a parent dir"),
        fx.dir.as_path(),
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
