//! Route-level tests for `wonton-server`, driven through the axum `Router` directly via
//! `tower::ServiceExt::oneshot` (no bound TCP listener — faster, and avoids any
//! sandbox/network restriction on binding a real port).
//!
//! ## SQLite-in-tests note
//! Every test gets its own `sqlite::memory:` pool capped to **one connection**
//! (`SqlitePoolOptions::max_connections(1)`). An in-memory SQLite database is scoped to a
//! single connection; a multi-connection pool over `sqlite::memory:` would silently hand out
//! a fresh, empty database per connection, causing writes on one connection to be invisible on
//! another. Capping to one connection keeps every query in a test on the same in-memory DB.
//! (The alternative documented in the task brief — a real temp file per test — was not used
//! here to avoid filesystem cleanup bookkeeping; this is the one approach, used consistently.)

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::str::FromStr;
use tower::ServiceExt;
use uuid::Uuid;
use wonton_objects::Hash;

use crate::auth::{hash_token, mint_token};
use crate::{build_router, now_unix};

// ---- test infrastructure ---------------------------------------------------------------

async fn test_pool() -> SqlitePool {
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")
        .unwrap()
        .create_if_missing(true)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    pool
}

async fn seed_user(pool: &SqlitePool, username: &str, ed25519_pubkey: &[u8], x25519_pubkey: &[u8]) -> String {
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
    .bind(x25519_pubkey)
    .bind(b"opaque-wrapped-privkey-ciphertext".to_vec())
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

/// Mint a session token for `user_id` directly (bypassing the login flow, which has its own
/// dedicated tests) with a given expiry, so RBAC/object/ref tests don't need a real keypair.
async fn seed_session(pool: &SqlitePool, user_id: &str, expires_at: i64) -> String {
    let token = mint_token();
    sqlx::query(
        "INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(user_id)
    .bind(hash_token(&token))
    .bind(expires_at)
    .bind(now_unix())
    .execute(pool)
    .await
    .unwrap();
    token
}

/// Send a JSON request, return (status, parsed JSON body). Body is `Value::Null` if empty.
async fn send_json(router: &Router, method: &str, uri: &str, token: Option<&str>, body: Option<Value>) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    let payload = match body {
        Some(v) => serde_json::to_vec(&v).unwrap(),
        None => Vec::new(),
    };
    let req = builder.body(Body::from(payload)).unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

/// Send a request expecting a raw-bytes response (`GET /objects/:hash`).
async fn send_raw(router: &Router, method: &str, uri: &str, token: Option<&str>) -> (StatusCode, Vec<u8>) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    let req = builder.body(Body::empty()).unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    (status, bytes.to_vec())
}

fn object_upload_body(kind: &str, content: &[u8]) -> Value {
    json!({
        "hash": Hash::of(content).to_hex(),
        "kind": kind,
        "body": STANDARD.encode(content),
    })
}

// ---- Provisioning: register / create store / create env ----------------------------------

fn register_body(username: &str) -> Value {
    json!({
        "username": username,
        "ed25519_pubkey": STANDARD.encode([1u8; 32]),
        "x25519_pubkey": STANDARD.encode([2u8; 32]),
        "wrapped_privkey": STANDARD.encode(b"opaque-wrapped-privkey"),
        "argon2_params": {
            "salt": STANDARD.encode([3u8; 16]),
            "m_cost_kib": 19456,
            "t_cost": 2,
            "p_cost": 1,
        },
    })
}

#[tokio::test]
async fn register_creates_user_and_rejects_duplicate_username() {
    let pool = test_pool().await;
    let router = build_router(pool);

    let (status, body) = send_json(&router, "POST", "/auth/register", None, Some(register_body("alice"))).await;
    assert_eq!(status, StatusCode::OK);
    let user_id = body["user_id"].as_str().unwrap().to_string();
    assert!(!user_id.is_empty());

    // A different username is fine.
    let (status, _) = send_json(&router, "POST", "/auth/register", None, Some(register_body("bob"))).await;
    assert_eq!(status, StatusCode::OK);

    // Re-registering the same username is a 409.
    let (status, _) = send_json(&router, "POST", "/auth/register", None, Some(register_body("alice"))).await;
    assert_eq!(status, StatusCode::CONFLICT);

    // The registered user is real enough to log in against (start returns the stored blob).
    let (status, start) = send_json(
        &router,
        "POST",
        "/auth/login/start",
        None,
        Some(json!({ "username": "alice" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(start["wrapped_privkey"], json!(STANDARD.encode(b"opaque-wrapped-privkey")));
}

#[tokio::test]
async fn create_store_succeeds_and_rejects_duplicate_name() {
    let pool = test_pool().await;
    let user_id = seed_user(&pool, "alice", &[1u8; 32], &[2u8; 32]).await;
    let token = seed_session(&pool, &user_id, now_unix() + 3600).await;
    let router = build_router(pool);

    let (status, body) = send_json(
        &router,
        "POST",
        "/stores",
        Some(&token),
        Some(json!({ "name": "acme/backend" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body["store_id"].as_str().unwrap().is_empty());

    // Duplicate name -> 409.
    let (status, _) = send_json(
        &router,
        "POST",
        "/stores",
        Some(&token),
        Some(json!({ "name": "acme/backend" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Unauthenticated -> 401.
    let (status, _) = send_json(
        &router,
        "POST",
        "/stores",
        None,
        Some(json!({ "name": "other" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn create_env_bootstraps_creator_as_admin_and_rejects_duplicate_and_unknown_store() {
    let pool = test_pool().await;
    let user_id = seed_user(&pool, "alice", &[1u8; 32], &[2u8; 32]).await;
    let token = seed_session(&pool, &user_id, now_unix() + 3600).await;
    let router = build_router(pool);

    // Create the store first.
    let (status, _) = send_json(
        &router,
        "POST",
        "/stores",
        Some(&token),
        Some(json!({ "name": "acme" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // 404 when the store doesn't exist.
    let (status, _) = send_json(
        &router,
        "POST",
        "/stores/ghost/envs",
        Some(&token),
        Some(json!({ "name": "dev" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Create the environment.
    let (status, body) = send_json(
        &router,
        "POST",
        "/stores/acme/envs",
        Some(&token),
        Some(json!({ "name": "dev" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body["env_id"].as_str().unwrap().is_empty());

    // Duplicate env name in the same store -> 409.
    let (status, _) = send_json(
        &router,
        "POST",
        "/stores/acme/envs",
        Some(&token),
        Some(json!({ "name": "dev" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // The creator is now an admin member: the env shows up for them via GET with role "admin",
    // which it could not if `create_env` had failed to insert the bootstrap membership row.
    let (status, envs) = send_json(&router, "GET", "/stores/acme/envs", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(envs[0]["name"], json!("dev"));
    assert_eq!(envs[0]["role"], json!("admin"));
}

#[tokio::test]
async fn create_env_creator_can_grant_a_key_proving_admin_membership() {
    // A tighter proof than the membership listing: the creator can immediately call the
    // existing writer+-gated grant-key route on the env they just created, which requires a
    // real membership row (403 otherwise). This is the exact bootstrap PLAN.md §8.2 depends on.
    let pool = test_pool().await;
    let user_id = seed_user(&pool, "alice", &[1u8; 32], &[2u8; 32]).await;
    let token = seed_session(&pool, &user_id, now_unix() + 3600).await;
    let router = build_router(pool);

    let (status, _) = send_json(&router, "POST", "/stores", Some(&token), Some(json!({ "name": "acme" }))).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send_json(&router, "POST", "/stores/acme/envs", Some(&token), Some(json!({ "name": "prod" }))).await;
    assert_eq!(status, StatusCode::OK);

    // Grant the creator (a real user row) their own wrapped DEK on the new env.
    let (status, _) = send_json(
        &router,
        "POST",
        "/envs/acme/prod/keys",
        Some(&token),
        Some(json!({ "user_id": user_id, "dek_version": 1, "sealed_box": STANDARD.encode(b"sealed") })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ---- Objects ----------------------------------------------------------------------------

#[tokio::test]
async fn object_upload_and_fetch_round_trip_is_idempotent() {
    let pool = test_pool().await;
    let user_id = seed_user(&pool, "alice", &[1u8; 32], &[2u8; 32]).await;
    let token = seed_session(&pool, &user_id, now_unix() + 3600).await;
    let router = build_router(pool);

    let content = b"hello wonton";
    let body = object_upload_body("blob", content);

    // First upload.
    let (status, _) = send_json(&router, "POST", "/objects", Some(&token), Some(body.clone())).await;
    assert_eq!(status, StatusCode::OK);

    // Re-upload of the exact same (hash, body) is idempotent, not an error.
    let (status, _) = send_json(&router, "POST", "/objects", Some(&token), Some(body)).await;
    assert_eq!(status, StatusCode::OK);

    // Fetch round-trips the exact bytes back.
    let hash = Hash::of(content).to_hex();
    let (status, fetched) = send_raw(&router, "GET", &format!("/objects/{hash}"), Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fetched, content);
}

#[tokio::test]
async fn object_upload_with_wrong_claimed_hash_is_rejected() {
    let pool = test_pool().await;
    let user_id = seed_user(&pool, "alice", &[1u8; 32], &[2u8; 32]).await;
    let token = seed_session(&pool, &user_id, now_unix() + 3600).await;
    let router = build_router(pool);

    let mut body = object_upload_body("blob", b"real content");
    // Corrupt the claimed hash so it no longer matches the body.
    body["hash"] = json!(Hash::of(b"different content").to_hex());

    let (status, _) = send_json(&router, "POST", "/objects", Some(&token), Some(body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn object_fetch_nonexistent_hash_is_404() {
    let pool = test_pool().await;
    let user_id = seed_user(&pool, "alice", &[1u8; 32], &[2u8; 32]).await;
    let token = seed_session(&pool, &user_id, now_unix() + 3600).await;
    let router = build_router(pool);

    let bogus = Hash::of(b"never uploaded").to_hex();
    let (status, _) = send_raw(&router, "GET", &format!("/objects/{bogus}"), Some(&token)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---- Refs / CAS ---------------------------------------------------------------------------

#[tokio::test]
async fn ref_cas_move_succeeds_and_rejects_stale_old_hash() {
    let pool = test_pool().await;
    let user_id = seed_user(&pool, "alice", &[1u8; 32], &[2u8; 32]).await;
    let store_id = seed_store(&pool, "acme").await;
    let env_id = seed_env(&pool, &store_id, "dev").await;
    seed_member(&pool, &env_id, &user_id, "writer").await;
    let token = seed_session(&pool, &user_id, now_unix() + 3600).await;
    let router = build_router(pool);

    let commit_a = Hash::of(b"commit-a").to_hex();
    let commit_b = Hash::of(b"commit-b").to_hex();
    for content in [b"commit-a".as_slice(), b"commit-b".as_slice()] {
        let (status, _) = send_json(
            &router,
            "POST",
            "/objects",
            Some(&token),
            Some(object_upload_body("commit", content)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    // Create the branch: old_hash None means "must not currently exist".
    let (status, _) = send_json(
        &router,
        "POST",
        "/refs/acme/dev/main",
        Some(&token),
        Some(json!({ "old_hash": Value::Null, "new_hash": commit_a })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Creating it again (old_hash None) fails: it already exists.
    let (status, body) = send_json(
        &router,
        "POST",
        "/refs/acme/dev/main",
        Some(&token),
        Some(json!({ "old_hash": Value::Null, "new_hash": commit_a })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["current"], json!(commit_a));

    // A stale old_hash is rejected with 409 and reports the actual current value.
    let (status, body) = send_json(
        &router,
        "POST",
        "/refs/acme/dev/main",
        Some(&token),
        Some(json!({ "old_hash": Value::Null, "new_hash": commit_b })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["current"], json!(commit_a));

    // A correct CAS move succeeds.
    let (status, _) = send_json(
        &router,
        "POST",
        "/refs/acme/dev/main",
        Some(&token),
        Some(json!({ "old_hash": commit_a, "new_hash": commit_b })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, refs) = send_json(&router, "GET", "/refs/acme/dev", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(refs["main"], json!(commit_b));
}

#[tokio::test]
async fn ref_cas_concurrent_race_exactly_one_winner() {
    let pool = test_pool().await;
    let user_id = seed_user(&pool, "alice", &[1u8; 32], &[2u8; 32]).await;
    let store_id = seed_store(&pool, "acme").await;
    let env_id = seed_env(&pool, &store_id, "dev").await;
    seed_member(&pool, &env_id, &user_id, "writer").await;
    let token = seed_session(&pool, &user_id, now_unix() + 3600).await;
    let router = build_router(pool);

    let commit_base = Hash::of(b"base").to_hex();
    let commit_x = Hash::of(b"race-x").to_hex();
    let commit_y = Hash::of(b"race-y").to_hex();
    for content in [b"base".as_slice(), b"race-x".as_slice(), b"race-y".as_slice()] {
        let (status, _) = send_json(
            &router,
            "POST",
            "/objects",
            Some(&token),
            Some(object_upload_body("commit", content)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    let (status, _) = send_json(
        &router,
        "POST",
        "/refs/acme/dev/main",
        Some(&token),
        Some(json!({ "old_hash": Value::Null, "new_hash": commit_base })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Two racing CAS attempts from the same old_hash to two different new_hash values.
    let req_x = send_json(
        &router,
        "POST",
        "/refs/acme/dev/main",
        Some(&token),
        Some(json!({ "old_hash": commit_base, "new_hash": commit_x })),
    );
    let req_y = send_json(
        &router,
        "POST",
        "/refs/acme/dev/main",
        Some(&token),
        Some(json!({ "old_hash": commit_base, "new_hash": commit_y })),
    );
    let ((status_x, _), (status_y, _)) = tokio::join!(req_x, req_y);

    let outcomes = [status_x, status_y];
    let wins = outcomes.iter().filter(|s| **s == StatusCode::OK).count();
    let conflicts = outcomes.iter().filter(|s| **s == StatusCode::CONFLICT).count();
    assert_eq!(wins, 1, "exactly one racer must win the CAS");
    assert_eq!(conflicts, 1, "exactly one racer must be rejected with 409");

    // The ref must now point at whichever one actually won.
    let (_, refs) = send_json(&router, "GET", "/refs/acme/dev", Some(&token), None).await;
    let winner = if status_x == StatusCode::OK { &commit_x } else { &commit_y };
    assert_eq!(refs["main"], json!(winner));
}

// ---- Auth: challenge-response login -------------------------------------------------------

#[tokio::test]
async fn login_start_and_complete_round_trip_issues_a_working_token() {
    let pool = test_pool().await;
    let seed = [7u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let user_id = seed_user(&pool, "alice", verifying_key.as_bytes(), &[9u8; 32]).await;
    let store_id = seed_store(&pool, "acme").await;
    let env_id = seed_env(&pool, &store_id, "dev").await;
    seed_member(&pool, &env_id, &user_id, "reader").await;
    let router = build_router(pool);

    let (status, start) = send_json(
        &router,
        "POST",
        "/auth/login/start",
        None,
        Some(json!({ "username": "alice" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let nonce_b64 = start["challenge_nonce"].as_str().unwrap().to_string();
    let nonce = STANDARD.decode(&nonce_b64).unwrap();

    let signature = signing_key.sign(&nonce);
    let (status, complete) = send_json(
        &router,
        "POST",
        "/auth/login/complete",
        None,
        Some(json!({
            "username": "alice",
            "challenge_nonce": nonce_b64,
            "signature": STANDARD.encode(signature.to_bytes()),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token = complete["token"].as_str().unwrap().to_string();
    assert!(complete["expires_at"].as_i64().unwrap() > now_unix());
    // The response carries the server-assigned user id (used by the CLI to find its own
    // wrapped-DEK entry in the keys map).
    assert_eq!(complete["user_id"].as_str().unwrap(), user_id);

    // The freshly minted token actually authenticates a subsequent request.
    let (status, _) = send_json(&router, "GET", "/stores/acme/envs", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn login_complete_with_wrong_signature_is_rejected() {
    let pool = test_pool().await;
    let real_key = SigningKey::from_bytes(&[11u8; 32]);
    let wrong_key = SigningKey::from_bytes(&[22u8; 32]);
    seed_user(&pool, "alice", real_key.verifying_key().as_bytes(), &[9u8; 32]).await;
    let router = build_router(pool);

    let (_, start) = send_json(
        &router,
        "POST",
        "/auth/login/start",
        None,
        Some(json!({ "username": "alice" })),
    )
    .await;
    let nonce_b64 = start["challenge_nonce"].as_str().unwrap().to_string();
    let nonce = STANDARD.decode(&nonce_b64).unwrap();

    // Signed with the WRONG key.
    let bad_signature = wrong_key.sign(&nonce);
    let (status, _) = send_json(
        &router,
        "POST",
        "/auth/login/complete",
        None,
        Some(json!({
            "username": "alice",
            "challenge_nonce": nonce_b64,
            "signature": STANDARD.encode(bad_signature.to_bytes()),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_complete_with_expired_or_consumed_challenge_is_rejected() {
    let pool = test_pool().await;
    let signing_key = SigningKey::from_bytes(&[33u8; 32]);
    seed_user(&pool, "alice", signing_key.verifying_key().as_bytes(), &[9u8; 32]).await;
    let router = build_router(pool);

    let (_, start) = send_json(
        &router,
        "POST",
        "/auth/login/start",
        None,
        Some(json!({ "username": "alice" })),
    )
    .await;
    let nonce_b64 = start["challenge_nonce"].as_str().unwrap().to_string();
    let nonce = STANDARD.decode(&nonce_b64).unwrap();
    let signature = signing_key.sign(&nonce);
    let sig_b64 = STANDARD.encode(signature.to_bytes());

    // First completion succeeds and consumes the challenge.
    let (status, _) = send_json(
        &router,
        "POST",
        "/auth/login/complete",
        None,
        Some(json!({ "username": "alice", "challenge_nonce": nonce_b64, "signature": sig_b64 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Replaying the exact same (now-consumed) challenge is rejected.
    let (status, _) = send_json(
        &router,
        "POST",
        "/auth/login/complete",
        None,
        Some(json!({ "username": "alice", "challenge_nonce": nonce_b64, "signature": sig_b64 })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_challenge_is_rejected_even_with_a_correct_signature() {
    let pool = test_pool().await;
    let signing_key = SigningKey::from_bytes(&[44u8; 32]);
    let user_id = seed_user(&pool, "alice", signing_key.verifying_key().as_bytes(), &[9u8; 32]).await;

    // Insert an already-expired challenge directly, simulating a client that took too long.
    let nonce = [55u8; 32];
    sqlx::query(
        "INSERT INTO login_challenges (id, user_id, nonce, expires_at, created_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&user_id)
    .bind(nonce.to_vec())
    .bind(now_unix() - 10)
    .bind(now_unix() - 130)
    .execute(&pool)
    .await
    .unwrap();

    let router = build_router(pool);
    let signature = signing_key.sign(&nonce);
    let (status, _) = send_json(
        &router,
        "POST",
        "/auth/login/complete",
        None,
        Some(json!({
            "username": "alice",
            "challenge_nonce": STANDARD.encode(nonce),
            "signature": STANDARD.encode(signature.to_bytes()),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---- Auth: bearer-token gate ---------------------------------------------------------------

#[tokio::test]
async fn missing_invalid_and_expired_tokens_are_all_401() {
    let pool = test_pool().await;
    let user_id = seed_user(&pool, "alice", &[1u8; 32], &[2u8; 32]).await;
    let expired_token = seed_session(&pool, &user_id, now_unix() - 10).await;
    let router = build_router(pool);

    let (status, _) = send_json(&router, "GET", "/stores/acme/envs", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = send_json(&router, "GET", "/stores/acme/envs", Some("not-a-real-token"), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = send_json(&router, "GET", "/stores/acme/envs", Some(&expired_token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---- RBAC ------------------------------------------------------------------------------

struct RbacFixture {
    router: Router,
    reader_token: String,
    writer_token: String,
    admin_token: String,
    /// A real (but unrelated) registered user, distinct from reader/writer/admin, for tests
    /// that grant/revoke membership or wrapped-DEK entries — `env_members`/`wrapped_deks` both
    /// have a `REFERENCES users(id)` foreign key, so the target must be a real user row.
    target_user_id: String,
}

async fn rbac_fixture() -> RbacFixture {
    let pool = test_pool().await;
    let reader_id = seed_user(&pool, "reader", &[1u8; 32], &[2u8; 32]).await;
    let writer_id = seed_user(&pool, "writer", &[3u8; 32], &[4u8; 32]).await;
    let admin_id = seed_user(&pool, "admin", &[5u8; 32], &[6u8; 32]).await;
    let target_user_id = seed_user(&pool, "target", &[8u8; 32], &[9u8; 32]).await;
    let store_id = seed_store(&pool, "acme").await;
    let env_id = seed_env(&pool, &store_id, "dev").await;
    seed_member(&pool, &env_id, &reader_id, "reader").await;
    seed_member(&pool, &env_id, &writer_id, "writer").await;
    seed_member(&pool, &env_id, &admin_id, "admin").await;
    let reader_token = seed_session(&pool, &reader_id, now_unix() + 3600).await;
    let writer_token = seed_session(&pool, &writer_id, now_unix() + 3600).await;
    let admin_token = seed_session(&pool, &admin_id, now_unix() + 3600).await;
    RbacFixture {
        router: build_router(pool),
        reader_token,
        writer_token,
        admin_token,
        target_user_id,
    }
}

#[tokio::test]
async fn reader_can_get_refs_but_not_move_them() {
    let fx = rbac_fixture().await;

    let (status, _) = send_json(&fx.router, "GET", "/refs/acme/dev", Some(&fx.reader_token), None).await;
    assert_eq!(status, StatusCode::OK);

    // Needs an object to move the ref to, but role is checked before object existence, so this
    // exercises the 403 path regardless.
    let bogus = Hash::of(b"whatever").to_hex();
    let (status, _) = send_json(
        &fx.router,
        "POST",
        "/refs/acme/dev/main",
        Some(&fx.reader_token),
        Some(json!({ "old_hash": Value::Null, "new_hash": bogus })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn writer_can_push_objects_and_refs_but_not_manage_members() {
    let fx = rbac_fixture().await;

    let (status, _) = send_json(
        &fx.router,
        "POST",
        "/objects",
        Some(&fx.writer_token),
        Some(object_upload_body("commit", b"writer-commit")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let commit_hash = Hash::of(b"writer-commit").to_hex();
    let (status, _) = send_json(
        &fx.router,
        "POST",
        "/refs/acme/dev/main",
        Some(&fx.writer_token),
        Some(json!({ "old_hash": Value::Null, "new_hash": commit_hash })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = send_json(
        &fx.router,
        "POST",
        "/envs/acme/dev/members",
        Some(&fx.writer_token),
        Some(json!({ "user_id": fx.target_user_id, "role": "reader" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_can_do_everything() {
    let fx = rbac_fixture().await;

    let (status, _) = send_json(
        &fx.router,
        "POST",
        "/objects",
        Some(&fx.admin_token),
        Some(object_upload_body("commit", b"admin-commit")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let commit_hash = Hash::of(b"admin-commit").to_hex();
    let (status, _) = send_json(
        &fx.router,
        "POST",
        "/refs/acme/dev/main",
        Some(&fx.admin_token),
        Some(json!({ "old_hash": Value::Null, "new_hash": commit_hash })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = send_json(
        &fx.router,
        "POST",
        "/envs/acme/dev/members",
        Some(&fx.admin_token),
        Some(json!({ "user_id": fx.target_user_id, "role": "reader" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = send_json(
        &fx.router,
        "DELETE",
        &format!("/envs/acme/dev/members/{}", fx.target_user_id),
        Some(&fx.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = send_json(
        &fx.router,
        "POST",
        "/envs/acme/dev/keys",
        Some(&fx.admin_token),
        Some(json!({ "user_id": fx.target_user_id, "dek_version": 1, "sealed_box": STANDARD.encode(b"sealed") })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = send_json(
        &fx.router,
        "POST",
        "/envs/acme/dev/rotate",
        Some(&fx.admin_token),
        Some(json!({
            "new_dek_version": 2,
            "objects": [],
            "wrapped_deks": [],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}
