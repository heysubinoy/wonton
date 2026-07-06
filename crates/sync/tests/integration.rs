//! Integration tests for `wonton-sync` against a REAL `wonton-server` bound to a real port.
//!
//! `reqwest` needs a live HTTP server (unlike `wonton-server`'s own `oneshot` route tests), so
//! each test spins up `wonton_server::build_router` over a fresh SQLite database, serves it with
//! `axum::serve` on `127.0.0.1:0` (OS-assigned free port) in a spawned task, and points a
//! `SyncClient` at it.
//!
//! ## SQLite pool note
//! We back each server with its **own temp-file** SQLite database rather than `sqlite::memory:`.
//! An in-memory DB is scoped to a single connection, so it only works with a one-connection
//! pool; `wonton_server::connect` uses a default (multi-connection) pool. A temp file is shared
//! across every connection the pool opens, sidestepping that pitfall entirely and letting the
//! server handle the client's concurrent HTTP connections normally. (This is the temp-file
//! alternative the task brief mentions; `wonton-server`'s own tests instead cap the pool to one
//! connection — both are valid, we pick the one that fits a real bound server.)
//!
//! ## Dependency-direction note
//! `wonton-server`, `wonton-vcs`, `wonton-crypto`, and `ed25519-dalek` are **dev-dependencies**
//! only (see this crate's Cargo.toml). Nothing here leaks `wonton-crypto` into `wonton-sync`'s
//! production graph: they are used solely to build/serve fixtures. The `SyncClient` under test
//! signs nothing itself — the login test signs the challenge nonce with `ed25519-dalek`
//! directly, exactly as a real caller would using `wonton-crypto` externally.

use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use sqlx::SqlitePool;
use uuid::Uuid;
use wonton_crypto::{generate_dek, generate_identity, sign, unlock, Dek, UnlockedIdentity};
use wonton_objects::{Hash, LocalObjectStore};
use wonton_shared::{
    Argon2ParamsDto, CreateEnvRequest, CreateStoreRequest, LoginCompleteRequest, LoginStartRequest,
    RefConflict, RegisterRequest,
};
use wonton_sync::{pull, push, PullOutcome, SyncClient, SyncError};
use wonton_vcs::{commit, WorkingSet};

// ---- server / fixture infrastructure --------------------------------------------------

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A unique path under the OS temp dir (removed on drop).
struct TempPath(PathBuf);
impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
        let _ = std::fs::remove_file(&self.0);
    }
}
fn unique_temp(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("wonton-sync-{tag}-{}-{}", std::process::id(), Uuid::new_v4()));
    p
}

/// Start a server over a fresh temp-file DB and return (base_url, pool, db-guard).
async fn start_server() -> (String, SqlitePool, TempPath) {
    let db = unique_temp("db");
    let url = format!("sqlite://{}", db.display());
    let pool = wonton_server::connect(&url).await.expect("connect + migrate");
    let router = wonton_server::build_router(pool.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (format!("http://{addr}"), pool, TempPath(db))
}

async fn seed_user(pool: &SqlitePool, username: &str, ed25519_pubkey: &[u8]) -> String {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO users \
         (id, username, ed25519_pubkey, x25519_pubkey, wrapped_privkey, argon2_salt, \
          argon2_m_cost_kib, argon2_t_cost, argon2_p_cost, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(username)
    .bind(ed25519_pubkey)
    .bind(&[2u8; 32][..])
    .bind(b"opaque-wrapped-privkey".to_vec())
    .bind(b"0123456789abcdef".to_vec())
    .bind(19456_i64)
    .bind(2_i64)
    .bind(1_i64)
    .bind(now_unix())
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn seed_store(pool: &SqlitePool, name: &str) -> String {
    let id = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO stores (id, name, created_at) VALUES (?, ?, ?)")
        .bind(&id)
        .bind(name)
        .bind(now_unix())
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn seed_env(pool: &SqlitePool, store_id: &str, name: &str) -> String {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO environments (id, store_id, name, active_dek_version, created_at) \
         VALUES (?, ?, ?, 1, ?)",
    )
    .bind(&id)
    .bind(store_id)
    .bind(name)
    .bind(now_unix())
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn seed_member(pool: &SqlitePool, env_id: &str, user_id: &str, role: &str) {
    sqlx::query("INSERT INTO env_members (env_id, user_id, role) VALUES (?, ?, ?)")
        .bind(env_id)
        .bind(user_id)
        .bind(role)
        .execute(pool)
        .await
        .unwrap();
}

/// Mint a session token directly (bypassing the login flow) for `user_id`.
async fn seed_session(pool: &SqlitePool, user_id: &str) -> String {
    // The server's `Actor` extractor looks a bearer token up by its BLAKE2b-256 hash. We
    // reproduce that here using `wonton_objects::Hash::of` — which is exactly BLAKE2b-256, the
    // same primitive the server hashes tokens with — so we don't need a `blake2` dev-dep or a
    // wider server API just to seed a fixture token. A UUIDv4-derived hex string is an
    // unguessable-enough token for a test.
    let token = Uuid::new_v4().simple().to_string() + &Uuid::new_v4().simple().to_string();
    let token_hash = Hash::of(token.as_bytes()).as_bytes().to_vec();
    sqlx::query(
        "INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(user_id)
    .bind(token_hash)
    .bind(now_unix() + 3600)
    .bind(now_unix())
    .execute(pool)
    .await
    .unwrap();
    token
}

// ---- object-store fixtures ------------------------------------------------------------

/// A `LocalObjectStore` rooted in a temp dir (removed on drop).
struct TempStore {
    _guard: TempPath,
    store: LocalObjectStore,
    root: PathBuf,
}
fn temp_store() -> TempStore {
    let root = unique_temp("store");
    std::fs::create_dir_all(&root).unwrap();
    let store = LocalObjectStore::open(root.clone()).unwrap();
    TempStore {
        _guard: TempPath(root.clone()),
        store,
        root,
    }
}

fn new_identity() -> UnlockedIdentity {
    let (_public, wrapped) = generate_identity(b"passphrase");
    unlock(&wrapped, b"passphrase").unwrap()
}
fn new_dek() -> Dek {
    generate_dek()
}

/// Enumerate every object hash physically present in a store (git-style `<2>/<62>` layout).
fn all_object_hashes(root: &PathBuf) -> Vec<Hash> {
    let mut out = Vec::new();
    let Ok(top) = std::fs::read_dir(root) else {
        return out;
    };
    for e1 in top.flatten() {
        if !e1.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let prefix = e1.file_name().to_string_lossy().to_string();
        if prefix.len() != 2 {
            continue;
        }
        if let Ok(inner) = std::fs::read_dir(e1.path()) {
            for e2 in inner.flatten() {
                let rest = e2.file_name().to_string_lossy().to_string();
                if let Ok(h) = Hash::from_hex(&format!("{prefix}{rest}")) {
                    out.push(h);
                }
            }
        }
    }
    out
}

// ---- tests ----------------------------------------------------------------------------

/// `fetch_object` must reject a server that returns bytes not matching the requested hash.
#[tokio::test]
async fn fetch_object_rejects_content_hash_mismatch() {
    let (base, pool, _db) = start_server().await;
    let user_id = seed_user(&pool, "alice", &[1u8; 32]).await;
    let token = seed_session(&pool, &user_id).await;

    // A legitimately-stored object round-trips.
    let good = b"authentic object bytes".to_vec();
    let good_hash = Hash::of(&good);
    sqlx::query("INSERT INTO objects (hash, kind, body, created_at) VALUES (?, 'blob', ?, ?)")
        .bind(good_hash.to_hex())
        .bind(&good)
        .bind(now_unix())
        .execute(&pool)
        .await
        .unwrap();

    // A poisoned row: stored under `lie_hash`, but the body hashes to something else. The
    // server serves bytes verbatim (it only verifies on upload), simulating a lying server.
    let lie_hash = Hash::of(b"what the client will ask for");
    sqlx::query("INSERT INTO objects (hash, kind, body, created_at) VALUES (?, 'blob', ?, ?)")
        .bind(lie_hash.to_hex())
        .bind(b"tampered body that does not match the hash".to_vec())
        .bind(now_unix())
        .execute(&pool)
        .await
        .unwrap();

    let mut client = SyncClient::new(base);
    client.set_token(token);

    let fetched = client.fetch_object(&good_hash).await.unwrap();
    assert_eq!(fetched, good);

    let err = client.fetch_object(&lie_hash).await.unwrap_err();
    match err {
        SyncError::IntegrityMismatch { requested, .. } => {
            assert_eq!(requested, lie_hash.to_hex());
        }
        other => panic!("expected IntegrityMismatch, got {other:?}"),
    }
}

/// A multi-commit history built in one store, pushed, then pulled into a second empty store
/// (two machines sharing one account): the second store ends up with every object byte-for-byte
/// and the pull reports a fast-forward.
#[tokio::test]
async fn push_then_pull_round_trips_a_linear_history() {
    let (base, pool, _db) = start_server().await;
    let user_id = seed_user(&pool, "alice", &[1u8; 32]).await;
    let store_id = seed_store(&pool, "acme").await;
    let env_id = seed_env(&pool, &store_id, "dev").await;
    seed_member(&pool, &env_id, &user_id, "writer").await;
    let token = seed_session(&pool, &user_id).await;

    let mut client = SyncClient::new(base);
    client.set_token(token);

    // Machine 1: build a two-commit linear history.
    let src = temp_store();
    let identity = new_identity();
    let dek = new_dek();
    let mut ws = WorkingSet::new();
    ws.set("DATABASE_URL", b"postgres://db".to_vec());
    let root = commit(&src.store, &dek, &identity, None, &ws, "root").unwrap();
    ws.set("API_KEY", b"sk-live-xyz".to_vec());
    let tip = commit(&src.store, &dek, &identity, Some(root), &ws, "add api key").unwrap();

    // Push everything, then create the ref.
    let objects = all_object_hashes(&src.root);
    push(&client, &src.store, "acme", "dev", "main", &objects, None, tip)
        .await
        .unwrap();

    // Machine 2: a fresh empty store, full clone.
    let dst = temp_store();
    let outcome = pull(&client, &dst.store, "acme", "dev", "main", None)
        .await
        .unwrap();
    assert_eq!(outcome, PullOutcome::FastForward { new_tip: tip });

    // Every object the source had is now present in the destination, byte-identical.
    for hash in &objects {
        let want = src.store.get(hash).unwrap().unwrap();
        let got = dst
            .store
            .get(hash)
            .unwrap()
            .unwrap_or_else(|| panic!("object {} missing after pull", hash.to_hex()));
        assert_eq!(got, want, "object {} differs after pull", hash.to_hex());
    }
    // ...and nothing extra beyond what the source had.
    let mut pulled = all_object_hashes(&dst.root);
    let mut expected = objects.clone();
    pulled.sort_by_key(|h| h.to_hex());
    expected.sort_by_key(|h| h.to_hex());
    assert_eq!(pulled, expected);
}

/// `pull` returns `UpToDate` when the caller's local tip already equals the remote tip.
#[tokio::test]
async fn pull_reports_up_to_date_when_tips_match() {
    let (base, pool, _db) = start_server().await;
    let user_id = seed_user(&pool, "alice", &[1u8; 32]).await;
    let store_id = seed_store(&pool, "acme").await;
    let env_id = seed_env(&pool, &store_id, "dev").await;
    seed_member(&pool, &env_id, &user_id, "writer").await;
    let token = seed_session(&pool, &user_id).await;

    let mut client = SyncClient::new(base);
    client.set_token(token);

    let src = temp_store();
    let identity = new_identity();
    let dek = new_dek();
    let mut ws = WorkingSet::new();
    ws.set("K", b"v".to_vec());
    let tip = commit(&src.store, &dek, &identity, None, &ws, "only").unwrap();
    let objects = all_object_hashes(&src.root);
    push(&client, &src.store, "acme", "dev", "main", &objects, None, tip)
        .await
        .unwrap();

    // A second, empty store — but local_tip already equals the remote tip, so nothing is
    // fetched and the result is UpToDate.
    let dst = temp_store();
    let outcome = pull(&client, &dst.store, "acme", "dev", "main", Some(tip))
        .await
        .unwrap();
    assert_eq!(outcome, PullOutcome::UpToDate);
    // Nothing was fetched.
    assert!(all_object_hashes(&dst.root).is_empty());
}

/// `pull` reports `Diverged` when the local tip is on an unrelated history (a different root).
#[tokio::test]
async fn pull_reports_diverged_for_unrelated_histories() {
    let (base, pool, _db) = start_server().await;
    let user_id = seed_user(&pool, "alice", &[1u8; 32]).await;
    let store_id = seed_store(&pool, "acme").await;
    let env_id = seed_env(&pool, &store_id, "dev").await;
    seed_member(&pool, &env_id, &user_id, "writer").await;
    let token = seed_session(&pool, &user_id).await;

    let mut client = SyncClient::new(base);
    client.set_token(token);

    // Remote history: an independent root commit R.
    let remote_src = temp_store();
    let identity = new_identity();
    let dek = new_dek();
    let mut ws = WorkingSet::new();
    ws.set("REMOTE", b"r".to_vec());
    let remote_tip = commit(&remote_src.store, &dek, &identity, None, &ws, "remote root").unwrap();
    let objects = all_object_hashes(&remote_src.root);
    push(
        &client,
        &remote_src.store,
        "acme",
        "dev",
        "main",
        &objects,
        None,
        remote_tip,
    )
    .await
    .unwrap();

    // Local history: a totally independent root commit L (different content => different hash),
    // never pushed. Pulling with local_tip = L must report divergence, not a fast-forward.
    let local_src = temp_store();
    let mut ws2 = WorkingSet::new();
    ws2.set("LOCAL", b"l".to_vec());
    let local_tip = commit(&local_src.store, &dek, &identity, None, &ws2, "local root").unwrap();
    assert_ne!(local_tip, remote_tip);

    let dst = temp_store();
    let outcome = pull(&client, &dst.store, "acme", "dev", "main", Some(local_tip))
        .await
        .unwrap();
    assert_eq!(
        outcome,
        PullOutcome::Diverged {
            local_tip,
            remote_tip,
        }
    );
}

/// A `push` with a stale `old_hash` (the ref has already moved past it) surfaces
/// `SyncError::Conflict` reporting the ref's actual current value.
#[tokio::test]
async fn push_with_stale_old_hash_surfaces_conflict() {
    let (base, pool, _db) = start_server().await;
    let user_id = seed_user(&pool, "alice", &[1u8; 32]).await;
    let store_id = seed_store(&pool, "acme").await;
    let env_id = seed_env(&pool, &store_id, "dev").await;
    seed_member(&pool, &env_id, &user_id, "writer").await;
    let token = seed_session(&pool, &user_id).await;

    let mut client = SyncClient::new(base);
    client.set_token(token);

    let src = temp_store();
    let identity = new_identity();
    let dek = new_dek();
    let mut ws = WorkingSet::new();
    ws.set("K", b"v1".to_vec());
    let a = commit(&src.store, &dek, &identity, None, &ws, "A").unwrap();
    ws.set("K", b"v2".to_vec());
    let b = commit(&src.store, &dek, &identity, Some(a), &ws, "B").unwrap();
    let objects = all_object_hashes(&src.root);

    // Establish main -> A, then advance main A -> B.
    push(&client, &src.store, "acme", "dev", "main", &objects, None, a)
        .await
        .unwrap();
    push(&client, &src.store, "acme", "dev", "main", &objects, Some(a), b)
        .await
        .unwrap();

    // A stale writer still thinks the tip is A and tries to move it again — the ref is now B.
    let err = push(&client, &src.store, "acme", "dev", "main", &[], Some(a), b)
        .await
        .unwrap_err();
    match err {
        SyncError::Conflict(RefConflict { current }) => {
            assert_eq!(current, Some(b.to_hex()));
        }
        other => panic!("expected Conflict, got {other:?}"),
    }
}

/// A route requiring a role the token lacks surfaces `Forbidden` (403); a bogus token surfaces
/// `Unauthorized` (401).
#[tokio::test]
async fn rbac_and_auth_errors_are_surfaced() {
    let (base, pool, _db) = start_server().await;
    let reader_id = seed_user(&pool, "reader", &[1u8; 32]).await;
    let outsider_id = seed_user(&pool, "outsider", &[3u8; 32]).await;
    let store_id = seed_store(&pool, "acme").await;
    let env_id = seed_env(&pool, &store_id, "dev").await;
    seed_member(&pool, &env_id, &reader_id, "reader").await;
    let reader_token = seed_session(&pool, &reader_id).await;
    let outsider_token = seed_session(&pool, &outsider_id).await;

    // Build a pushable object so `push` reaches the ref-move (role-gated) step.
    let src = temp_store();
    let identity = new_identity();
    let dek = new_dek();
    let ws = WorkingSet::new();
    let tip = commit(&src.store, &dek, &identity, None, &ws, "c").unwrap();
    let objects = all_object_hashes(&src.root);

    // Forbidden: a reader may not move a ref (push).
    let mut reader = SyncClient::new(base.clone());
    reader.set_token(reader_token);
    let err = push(&reader, &src.store, "acme", "dev", "main", &objects, None, tip)
        .await
        .unwrap_err();
    assert!(matches!(err, SyncError::Forbidden), "expected Forbidden, got {err:?}");

    // Forbidden: a non-member cannot even read refs (so `pull` fails at get_refs).
    let mut outsider = SyncClient::new(base.clone());
    outsider.set_token(outsider_token);
    let err = pull(&outsider, &src.store, "acme", "dev", "main", None)
        .await
        .unwrap_err();
    assert!(matches!(err, SyncError::Forbidden), "expected Forbidden, got {err:?}");

    // Unauthorized: a bogus token.
    let mut bogus = SyncClient::new(base.clone());
    bogus.set_token("definitely-not-a-real-token");
    let err = bogus.get_refs("acme", "dev").await.unwrap_err();
    assert!(matches!(err, SyncError::Unauthorized), "expected Unauthorized, got {err:?}");

    // Unauthorized: no token at all.
    let none = SyncClient::new(base);
    let err = none.get_refs("acme", "dev").await.unwrap_err();
    assert!(matches!(err, SyncError::Unauthorized), "expected Unauthorized, got {err:?}");
}

/// The provisioning trio (`register` + `create_store` + `create_env`): a brand-new user
/// registers, logs in with the two-step flow, then creates a store and an environment (becoming
/// its admin). Exercises all three new `SyncClient` methods end-to-end against a real server.
#[tokio::test]
async fn register_login_and_provision_store_and_env() {
    let (base, _pool, _db) = start_server().await;
    let client = SyncClient::new(base);

    // Register a fresh identity (client generates it locally, per the wire framing convention).
    let (public, wrapped) = generate_identity(b"provision-pass");
    let mut blob = wrapped.nonce.to_vec();
    blob.extend_from_slice(&wrapped.ciphertext);
    let reg = client
        .register(&RegisterRequest {
            username: "provisioner".to_string(),
            ed25519_pubkey: STANDARD.encode(public.ed25519_pubkey),
            x25519_pubkey: STANDARD.encode(public.x25519_pubkey),
            wrapped_privkey: STANDARD.encode(&blob),
            argon2_params: Argon2ParamsDto {
                salt: STANDARD.encode(wrapped.argon2_params.salt),
                m_cost_kib: wrapped.argon2_params.m_cost_kib,
                t_cost: wrapped.argon2_params.t_cost,
                p_cost: wrapped.argon2_params.p_cost,
            },
        })
        .await
        .unwrap();
    assert!(!reg.user_id.is_empty());

    // Log in to get a bearer token (needed for create_store / create_env).
    let start = client
        .login_start(&LoginStartRequest {
            username: "provisioner".to_string(),
        })
        .await
        .unwrap();
    let nonce = STANDARD.decode(&start.challenge_nonce).unwrap();
    let identity = unlock(&wrapped, b"provision-pass").unwrap();
    let signature = sign(&identity, &nonce);
    let complete = client
        .login_complete(&LoginCompleteRequest {
            username: "provisioner".to_string(),
            challenge_nonce: start.challenge_nonce.clone(),
            signature: STANDARD.encode(signature),
        })
        .await
        .unwrap();
    assert_eq!(complete.user_id, reg.user_id);

    let mut client = client;
    client.set_token(complete.token);

    // Create a store, then an environment inside it.
    let store = client
        .create_store(&CreateStoreRequest {
            name: "provisioned-store".to_string(),
        })
        .await
        .unwrap();
    assert!(!store.store_id.is_empty());
    let env = client
        .create_env(
            "provisioned-store",
            &CreateEnvRequest {
                name: "prod".to_string(),
            },
        )
        .await
        .unwrap();
    assert!(!env.env_id.is_empty());

    // The creator is admin of the new env, so it shows up in their env listing with that role.
    let envs = client.list_envs("provisioned-store").await.unwrap();
    assert_eq!(envs.len(), 1);
    assert_eq!(envs[0].name, "prod");
    assert_eq!(envs[0].role, wonton_shared::Role::Admin);

    // A duplicate store name is a clean conflict, not a crash.
    let err = client
        .create_store(&CreateStoreRequest {
            name: "provisioned-store".to_string(),
        })
        .await
        .unwrap_err();
    assert!(matches!(err, SyncError::ServerError(_, _) | SyncError::Conflict(_)));
}

/// The two-step login round-trip: the client transports a nonce + externally-computed Ed25519
/// signature (this crate signs nothing itself) and receives a token that then authenticates a
/// subsequent request.
#[tokio::test]
async fn login_round_trip_yields_a_working_token() {
    let (base, pool, _db) = start_server().await;
    let seed = [7u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let user_id = seed_user(&pool, "alice", signing_key.verifying_key().as_bytes()).await;
    let store_id = seed_store(&pool, "acme").await;
    let env_id = seed_env(&pool, &store_id, "dev").await;
    seed_member(&pool, &env_id, &user_id, "reader").await;

    let mut client = SyncClient::new(base);

    let start = client
        .login_start(&LoginStartRequest {
            username: "alice".to_string(),
        })
        .await
        .unwrap();
    let nonce = STANDARD.decode(&start.challenge_nonce).unwrap();

    // The caller signs the raw nonce bytes externally (here with ed25519-dalek, as a real caller
    // would with wonton-crypto) and hands the base64 signature to the transport-only client.
    let signature = signing_key.sign(&nonce);
    let complete = client
        .login_complete(&LoginCompleteRequest {
            username: "alice".to_string(),
            challenge_nonce: start.challenge_nonce.clone(),
            signature: STANDARD.encode(signature.to_bytes()),
        })
        .await
        .unwrap();
    assert!(complete.expires_at > now_unix());

    client.set_token(complete.token);
    // The freshly minted token authenticates a real request.
    let envs = client.list_envs("acme").await.unwrap();
    assert_eq!(envs.len(), 1);
    assert_eq!(envs[0].name, "dev");
}
