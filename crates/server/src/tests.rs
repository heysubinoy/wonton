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
use sqlx::{Row, SqlitePool};
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

async fn seed_org(pool: &SqlitePool, name: &str) -> String {
    let id = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO orgs (id, name, created_at) VALUES (?, ?, ?)")
        .bind(&id)
        .bind(name)
        .bind(now_unix())
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn seed_org_member(pool: &SqlitePool, org_id: &str, user_id: &str, role: &str) {
    sqlx::query("INSERT INTO org_members (org_id, user_id, role) VALUES (?, ?, ?)")
        .bind(org_id)
        .bind(user_id)
        .bind(role)
        .execute(pool)
        .await
        .unwrap();
}

async fn seed_store(pool: &SqlitePool, org_id: &str, name: &str) -> String {
    let id = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO stores (id, org_id, name, created_at) VALUES (?, ?, ?, ?)")
        .bind(&id)
        .bind(org_id)
        .bind(name)
        .bind(now_unix())
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn seed_branch(pool: &SqlitePool, store_id: &str, name: &str) -> String {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO branches (id, store_id, name, active_dek_version, created_at) \
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

async fn seed_branch_member(pool: &SqlitePool, branch_id: &str, user_id: &str, role: &str) {
    sqlx::query("INSERT INTO branch_members (branch_id, user_id, role) VALUES (?, ?, ?)")
        .bind(branch_id)
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

// ---- Provisioning: register / create org / create store / create branch -----------------

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
async fn create_org_bootstraps_creator_as_owner_and_rejects_duplicate_name() {
    let pool = test_pool().await;
    let user_id = seed_user(&pool, "alice", &[1u8; 32], &[2u8; 32]).await;
    let token = seed_session(&pool, &user_id, now_unix() + 3600).await;
    let router = build_router(pool);

    let (status, body) = send_json(&router, "POST", "/orgs", Some(&token), Some(json!({ "name": "acme" }))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body["org_id"].as_str().unwrap().is_empty());

    // Duplicate name -> 409.
    let (status, _) = send_json(&router, "POST", "/orgs", Some(&token), Some(json!({ "name": "acme" }))).await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Unauthenticated -> 401.
    let (status, _) = send_json(&router, "POST", "/orgs", None, Some(json!({ "name": "other" }))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // The creator is now an owner: they can create a store in the org, which requires org
    // membership — a tighter proof than a membership listing (no such listing route exists).
    let (status, _) = send_json(
        &router,
        "POST",
        "/orgs/acme/stores",
        Some(&token),
        Some(json!({ "name": "backend" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn create_store_requires_org_membership_and_rejects_duplicate_name() {
    let pool = test_pool().await;
    let member_id = seed_user(&pool, "alice", &[1u8; 32], &[2u8; 32]).await;
    let outsider_id = seed_user(&pool, "outsider", &[3u8; 32], &[4u8; 32]).await;
    let org_id = seed_org(&pool, "acme").await;
    seed_org_member(&pool, &org_id, &member_id, "owner").await;
    let member_token = seed_session(&pool, &member_id, now_unix() + 3600).await;
    let outsider_token = seed_session(&pool, &outsider_id, now_unix() + 3600).await;
    let router = build_router(pool);

    // 404 for an unknown org.
    let (status, _) = send_json(
        &router,
        "POST",
        "/orgs/ghost/stores",
        Some(&member_token),
        Some(json!({ "name": "backend" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A non-member of a real org is forbidden.
    let (status, _) = send_json(
        &router,
        "POST",
        "/orgs/acme/stores",
        Some(&outsider_token),
        Some(json!({ "name": "backend" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, body) = send_json(
        &router,
        "POST",
        "/orgs/acme/stores",
        Some(&member_token),
        Some(json!({ "name": "backend" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body["store_id"].as_str().unwrap().is_empty());

    // Duplicate name within the same org -> 409.
    let (status, _) = send_json(
        &router,
        "POST",
        "/orgs/acme/stores",
        Some(&member_token),
        Some(json!({ "name": "backend" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn create_branch_bootstraps_creator_as_admin_and_rejects_duplicate_and_unknown_store() {
    let pool = test_pool().await;
    let user_id = seed_user(&pool, "alice", &[1u8; 32], &[2u8; 32]).await;
    let org_id = seed_org(&pool, "acme").await;
    seed_org_member(&pool, &org_id, &user_id, "owner").await;
    let token = seed_session(&pool, &user_id, now_unix() + 3600).await;
    let router = build_router(pool);

    // Create the store first.
    let (status, _) = send_json(
        &router,
        "POST",
        "/orgs/acme/stores",
        Some(&token),
        Some(json!({ "name": "backend" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // 404 when the store doesn't exist.
    let (status, _) = send_json(
        &router,
        "POST",
        "/orgs/acme/stores/ghost/branches",
        Some(&token),
        Some(json!({ "name": "dev" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Create the branch.
    let (status, body) = send_json(
        &router,
        "POST",
        "/orgs/acme/stores/backend/branches",
        Some(&token),
        Some(json!({ "name": "dev" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body["branch_id"].as_str().unwrap().is_empty());

    // Duplicate branch name in the same store -> 409.
    let (status, _) = send_json(
        &router,
        "POST",
        "/orgs/acme/stores/backend/branches",
        Some(&token),
        Some(json!({ "name": "dev" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // The creator is now an admin member: the branch shows up for them via GET with role
    // "admin", which it could not if `create_branch` had failed to insert the bootstrap
    // membership row.
    let (status, branches) = send_json(&router, "GET", "/orgs/acme/stores/backend/branches", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(branches[0]["name"], json!("dev"));
    assert_eq!(branches[0]["role"], json!("admin"));
}

#[tokio::test]
async fn create_branch_creator_can_grant_a_key_proving_admin_membership() {
    // A tighter proof than the membership listing: the creator can immediately call the
    // existing writer+-gated grant-key route on the branch they just created, which requires a
    // real membership row (403 otherwise). This is the exact bootstrap the key agent depends on.
    let pool = test_pool().await;
    let user_id = seed_user(&pool, "alice", &[1u8; 32], &[2u8; 32]).await;
    let org_id = seed_org(&pool, "acme").await;
    seed_org_member(&pool, &org_id, &user_id, "owner").await;
    let token = seed_session(&pool, &user_id, now_unix() + 3600).await;
    let router = build_router(pool);

    let (status, _) = send_json(&router, "POST", "/orgs/acme/stores", Some(&token), Some(json!({ "name": "backend" }))).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send_json(
        &router,
        "POST",
        "/orgs/acme/stores/backend/branches",
        Some(&token),
        Some(json!({ "name": "prod" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Grant the creator (a real user row) their own wrapped DEK on the new branch.
    let (status, _) = send_json(
        &router,
        "POST",
        "/orgs/acme/stores/backend/branches/prod/keys",
        Some(&token),
        Some(json!({ "user_id": user_id, "dek_version": 1, "sealed_box": STANDARD.encode(b"sealed") })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ---- User directory / branch details / members --------------------------------------------

#[tokio::test]
async fn get_user_returns_public_keys_and_404s_for_unknown() {
    let pool = test_pool().await;
    let ed = [7u8; 32];
    let x = [8u8; 32];
    let user_id = seed_user(&pool, "alice", &ed, &x).await;
    // A second user provides the authenticated caller (any valid actor may look users up).
    let caller_id = seed_user(&pool, "caller", &[1u8; 32], &[2u8; 32]).await;
    let token = seed_session(&pool, &caller_id, now_unix() + 3600).await;
    let router = build_router(pool);

    let (status, body) = send_json(&router, "GET", "/users/alice", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user_id"].as_str().unwrap(), user_id);
    assert_eq!(body["ed25519_pubkey"], json!(STANDARD.encode(ed)));
    assert_eq!(body["x25519_pubkey"], json!(STANDARD.encode(x)));

    // Unknown username -> 404.
    let (status, _) = send_json(&router, "GET", "/users/nobody", Some(&token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Unauthenticated -> 401 (avoids unauthenticated user enumeration).
    let (status, _) = send_json(&router, "GET", "/users/alice", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// `GET /users/by-id/:user_id` resolves the same public keys as `GET /users/:username`, but by
/// server-assigned id — needed so a client can verify a commit's `author_id` even for a user who
/// is no longer a member of the branch that commit lives in.
#[tokio::test]
async fn get_user_by_id_returns_public_keys_and_404s_for_unknown() {
    let pool = test_pool().await;
    let ed = [9u8; 32];
    let x = [10u8; 32];
    let user_id = seed_user(&pool, "alice", &ed, &x).await;
    let caller_id = seed_user(&pool, "caller", &[1u8; 32], &[2u8; 32]).await;
    let token = seed_session(&pool, &caller_id, now_unix() + 3600).await;
    let router = build_router(pool);

    let (status, body) = send_json(
        &router,
        "GET",
        &format!("/users/by-id/{user_id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user_id"].as_str().unwrap(), user_id);
    assert_eq!(body["ed25519_pubkey"], json!(STANDARD.encode(ed)));
    assert_eq!(body["x25519_pubkey"], json!(STANDARD.encode(x)));

    // Unknown id -> 404.
    let (status, _) = send_json(
        &router,
        "GET",
        "/users/by-id/00000000-0000-0000-0000-000000000000",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Unauthenticated -> 401.
    let (status, _) = send_json(&router, "GET", &format!("/users/by-id/{user_id}"), None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn get_branch_details_returns_active_version_for_a_reader_and_403s_for_non_members() {
    let pool = test_pool().await;
    let reader_id = seed_user(&pool, "reader", &[1u8; 32], &[2u8; 32]).await;
    let outsider_id = seed_user(&pool, "outsider", &[3u8; 32], &[4u8; 32]).await;
    let org_id = seed_org(&pool, "acme").await;
    let store_id = seed_store(&pool, &org_id, "backend").await;
    let branch_id = seed_branch(&pool, &store_id, "dev").await;
    seed_branch_member(&pool, &branch_id, &reader_id, "reader").await;
    // Bump the active version so we can assert a non-default value round-trips.
    sqlx::query("UPDATE branches SET active_dek_version = 5 WHERE id = ?")
        .bind(&branch_id)
        .execute(&pool)
        .await
        .unwrap();
    let reader_token = seed_session(&pool, &reader_id, now_unix() + 3600).await;
    let outsider_token = seed_session(&pool, &outsider_id, now_unix() + 3600).await;
    let router = build_router(pool);

    let (status, body) = send_json(&router, "GET", "/orgs/acme/stores/backend/branches/dev", Some(&reader_token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["branch_id"].as_str().unwrap(), branch_id);
    assert_eq!(body["active_dek_version"], json!(5));

    // A non-member is forbidden (403), even though the branch exists.
    let (status, _) = send_json(&router, "GET", "/orgs/acme/stores/backend/branches/dev", Some(&outsider_token), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A missing branch is 404.
    let (status, _) = send_json(&router, "GET", "/orgs/acme/stores/backend/branches/ghost", Some(&reader_token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn list_members_joins_users_and_returns_x25519_keys_for_a_reader() {
    let pool = test_pool().await;
    let admin_id = seed_user(&pool, "admin", &[1u8; 32], &[2u8; 32]).await;
    let reader_id = seed_user(&pool, "reader", &[3u8; 32], &[4u8; 32]).await;
    let outsider_id = seed_user(&pool, "outsider", &[9u8; 32], &[9u8; 32]).await;
    let org_id = seed_org(&pool, "acme").await;
    let store_id = seed_store(&pool, &org_id, "backend").await;
    let branch_id = seed_branch(&pool, &store_id, "dev").await;
    seed_branch_member(&pool, &branch_id, &admin_id, "admin").await;
    seed_branch_member(&pool, &branch_id, &reader_id, "reader").await;
    let admin_token = seed_session(&pool, &admin_id, now_unix() + 3600).await;
    let outsider_token = seed_session(&pool, &outsider_id, now_unix() + 3600).await;
    let router = build_router(pool);

    let (status, body) = send_json(&router, "GET", "/orgs/acme/stores/backend/branches/dev/members", Some(&admin_token), None).await;
    assert_eq!(status, StatusCode::OK);
    let members = body.as_array().unwrap();
    assert_eq!(members.len(), 2);
    // Find the reader's entry and check its role + X25519 key round-trip (ordered by user_id, so
    // we look it up by id rather than assume position).
    let reader_entry = members
        .iter()
        .find(|m| m["user_id"].as_str() == Some(reader_id.as_str()))
        .expect("reader is listed");
    assert_eq!(reader_entry["role"], json!("reader"));
    assert_eq!(reader_entry["x25519_pubkey"], json!(STANDARD.encode([4u8; 32])));

    // A non-member cannot list members (403).
    let (status, _) = send_json(&router, "GET", "/orgs/acme/stores/backend/branches/dev/members", Some(&outsider_token), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn add_member_auto_joins_the_target_to_the_org() {
    // Sharing a branch with someone who isn't yet in the org adds them to it (scoped by the
    // branch grant they actually got — see `handlers::add_member`'s doc comment). A second,
    // already-a-member add must not duplicate/error on the org_members row.
    let pool = test_pool().await;
    let admin_id = seed_user(&pool, "admin", &[1u8; 32], &[2u8; 32]).await;
    let target_id = seed_user(&pool, "target", &[3u8; 32], &[4u8; 32]).await;
    let org_id = seed_org(&pool, "acme").await;
    seed_org_member(&pool, &org_id, &admin_id, "owner").await;
    let store_id = seed_store(&pool, &org_id, "backend").await;
    let branch_id = seed_branch(&pool, &store_id, "dev").await;
    seed_branch_member(&pool, &branch_id, &admin_id, "admin").await;
    let admin_token = seed_session(&pool, &admin_id, now_unix() + 3600).await;
    let router = build_router(pool.clone());

    // Target is not yet an org member.
    let before: i64 = sqlx::query("SELECT COUNT(*) AS n FROM org_members WHERE org_id = ? AND user_id = ?")
        .bind(&org_id)
        .bind(&target_id)
        .fetch_one(&pool)
        .await
        .unwrap()
        .get("n");
    assert_eq!(before, 0);

    let (status, _) = send_json(
        &router,
        "POST",
        "/orgs/acme/stores/backend/branches/dev/members",
        Some(&admin_token),
        Some(json!({ "user_id": target_id, "role": "reader" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let after: i64 = sqlx::query("SELECT COUNT(*) AS n FROM org_members WHERE org_id = ? AND user_id = ?")
        .bind(&org_id)
        .bind(&target_id)
        .fetch_one(&pool)
        .await
        .unwrap()
        .get("n");
    assert_eq!(after, 1, "sharing a branch must auto-join the target to the org");

    // Re-sharing (e.g. role update) does not error or duplicate the org_members row.
    let (status, _) = send_json(
        &router,
        "POST",
        "/orgs/acme/stores/backend/branches/dev/members",
        Some(&admin_token),
        Some(json!({ "user_id": target_id, "role": "writer" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let still: i64 = sqlx::query("SELECT COUNT(*) AS n FROM org_members WHERE org_id = ? AND user_id = ?")
        .bind(&org_id)
        .bind(&target_id)
        .fetch_one(&pool)
        .await
        .unwrap()
        .get("n");
    assert_eq!(still, 1);
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

// ---- Ref / CAS ---------------------------------------------------------------------------

#[tokio::test]
async fn ref_cas_move_succeeds_and_rejects_stale_old_hash() {
    let pool = test_pool().await;
    let user_id = seed_user(&pool, "alice", &[1u8; 32], &[2u8; 32]).await;
    let org_id = seed_org(&pool, "acme").await;
    let store_id = seed_store(&pool, &org_id, "backend").await;
    let branch_id = seed_branch(&pool, &store_id, "dev").await;
    seed_branch_member(&pool, &branch_id, &user_id, "writer").await;
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

    // Create the ref: old_hash None means "must not currently exist".
    let (status, _) = send_json(
        &router,
        "POST",
        "/orgs/acme/stores/backend/branches/dev/ref",
        Some(&token),
        Some(json!({ "old_hash": Value::Null, "new_hash": commit_a })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Creating it again (old_hash None) fails: it already exists.
    let (status, body) = send_json(
        &router,
        "POST",
        "/orgs/acme/stores/backend/branches/dev/ref",
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
        "/orgs/acme/stores/backend/branches/dev/ref",
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
        "/orgs/acme/stores/backend/branches/dev/ref",
        Some(&token),
        Some(json!({ "old_hash": commit_a, "new_hash": commit_b })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, ref_body) = send_json(&router, "GET", "/orgs/acme/stores/backend/branches/dev/ref", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ref_body["commit_hash"], json!(commit_b));
}

#[tokio::test]
async fn ref_get_on_a_never_pushed_branch_returns_none() {
    let pool = test_pool().await;
    let user_id = seed_user(&pool, "alice", &[1u8; 32], &[2u8; 32]).await;
    let org_id = seed_org(&pool, "acme").await;
    let store_id = seed_store(&pool, &org_id, "backend").await;
    let branch_id = seed_branch(&pool, &store_id, "dev").await;
    seed_branch_member(&pool, &branch_id, &user_id, "reader").await;
    let token = seed_session(&pool, &user_id, now_unix() + 3600).await;
    let router = build_router(pool);

    let (status, ref_body) = send_json(&router, "GET", "/orgs/acme/stores/backend/branches/dev/ref", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ref_body["commit_hash"], Value::Null);
}

#[tokio::test]
async fn ref_cas_concurrent_race_exactly_one_winner() {
    let pool = test_pool().await;
    let user_id = seed_user(&pool, "alice", &[1u8; 32], &[2u8; 32]).await;
    let org_id = seed_org(&pool, "acme").await;
    let store_id = seed_store(&pool, &org_id, "backend").await;
    let branch_id = seed_branch(&pool, &store_id, "dev").await;
    seed_branch_member(&pool, &branch_id, &user_id, "writer").await;
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
        "/orgs/acme/stores/backend/branches/dev/ref",
        Some(&token),
        Some(json!({ "old_hash": Value::Null, "new_hash": commit_base })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Two racing CAS attempts from the same old_hash to two different new_hash values.
    let req_x = send_json(
        &router,
        "POST",
        "/orgs/acme/stores/backend/branches/dev/ref",
        Some(&token),
        Some(json!({ "old_hash": commit_base, "new_hash": commit_x })),
    );
    let req_y = send_json(
        &router,
        "POST",
        "/orgs/acme/stores/backend/branches/dev/ref",
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
    let (_, ref_body) = send_json(&router, "GET", "/orgs/acme/stores/backend/branches/dev/ref", Some(&token), None).await;
    let winner = if status_x == StatusCode::OK { &commit_x } else { &commit_y };
    assert_eq!(ref_body["commit_hash"], json!(winner));
}

// ---- Auth: challenge-response login -------------------------------------------------------

#[tokio::test]
async fn login_start_and_complete_round_trip_issues_a_working_token() {
    let pool = test_pool().await;
    let seed = [7u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let user_id = seed_user(&pool, "alice", verifying_key.as_bytes(), &[9u8; 32]).await;
    let org_id = seed_org(&pool, "acme").await;
    seed_org_member(&pool, &org_id, &user_id, "owner").await;
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
    let (status, _) = send_json(&router, "POST", "/orgs/acme/stores", Some(&token), Some(json!({ "name": "backend" }))).await;
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

    let (status, _) = send_json(&router, "POST", "/orgs", None, Some(json!({ "name": "acme" }))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = send_json(&router, "POST", "/orgs", Some("not-a-real-token"), Some(json!({ "name": "acme" }))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = send_json(&router, "POST", "/orgs", Some(&expired_token), Some(json!({ "name": "acme" }))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---- RBAC ------------------------------------------------------------------------------

struct RbacFixture {
    router: Router,
    reader_token: String,
    writer_token: String,
    admin_token: String,
    /// A real (but unrelated) registered user, distinct from reader/writer/admin, for tests
    /// that grant/revoke membership or wrapped-DEK entries — `branch_members`/`wrapped_deks`
    /// both have a `REFERENCES users(id)` foreign key, so the target must be a real user row.
    target_user_id: String,
}

async fn rbac_fixture() -> RbacFixture {
    let pool = test_pool().await;
    let reader_id = seed_user(&pool, "reader", &[1u8; 32], &[2u8; 32]).await;
    let writer_id = seed_user(&pool, "writer", &[3u8; 32], &[4u8; 32]).await;
    let admin_id = seed_user(&pool, "admin", &[5u8; 32], &[6u8; 32]).await;
    let target_user_id = seed_user(&pool, "target", &[8u8; 32], &[9u8; 32]).await;
    let org_id = seed_org(&pool, "acme").await;
    let store_id = seed_store(&pool, &org_id, "backend").await;
    let branch_id = seed_branch(&pool, &store_id, "dev").await;
    seed_branch_member(&pool, &branch_id, &reader_id, "reader").await;
    seed_branch_member(&pool, &branch_id, &writer_id, "writer").await;
    seed_branch_member(&pool, &branch_id, &admin_id, "admin").await;
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
async fn reader_can_get_ref_but_not_move_it() {
    let fx = rbac_fixture().await;

    let (status, _) = send_json(&fx.router, "GET", "/orgs/acme/stores/backend/branches/dev/ref", Some(&fx.reader_token), None).await;
    assert_eq!(status, StatusCode::OK);

    // Needs an object to move the ref to, but role is checked before object existence, so this
    // exercises the 403 path regardless.
    let bogus = Hash::of(b"whatever").to_hex();
    let (status, _) = send_json(
        &fx.router,
        "POST",
        "/orgs/acme/stores/backend/branches/dev/ref",
        Some(&fx.reader_token),
        Some(json!({ "old_hash": Value::Null, "new_hash": bogus })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn writer_can_push_objects_and_ref_but_not_manage_members() {
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
        "/orgs/acme/stores/backend/branches/dev/ref",
        Some(&fx.writer_token),
        Some(json!({ "old_hash": Value::Null, "new_hash": commit_hash })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = send_json(
        &fx.router,
        "POST",
        "/orgs/acme/stores/backend/branches/dev/members",
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
        "/orgs/acme/stores/backend/branches/dev/ref",
        Some(&fx.admin_token),
        Some(json!({ "old_hash": Value::Null, "new_hash": commit_hash })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = send_json(
        &fx.router,
        "POST",
        "/orgs/acme/stores/backend/branches/dev/members",
        Some(&fx.admin_token),
        Some(json!({ "user_id": fx.target_user_id, "role": "reader" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = send_json(
        &fx.router,
        "DELETE",
        &format!("/orgs/acme/stores/backend/branches/dev/members/{}", fx.target_user_id),
        Some(&fx.admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = send_json(
        &fx.router,
        "POST",
        "/orgs/acme/stores/backend/branches/dev/keys",
        Some(&fx.admin_token),
        Some(json!({ "user_id": fx.target_user_id, "dek_version": 1, "sealed_box": STANDARD.encode(b"sealed") })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = send_json(
        &fx.router,
        "POST",
        "/orgs/acme/stores/backend/branches/dev/rotate",
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

/// A rotation that fails partway through its transaction must apply **nothing** — the whole
/// batch (new objects + wrapped-DEK map + active-version bump) is one all-or-nothing `sqlx`
/// transaction. We force a failure by making the *second* wrapped-DEK entry reference a
/// `user_id` that does not exist: `wrapped_deks.user_id REFERENCES users(id)` with foreign-key
/// enforcement on (see `test_pool`), so that INSERT raises a constraint violation *after* the
/// batch object and the first (valid) wrapped-DEK row have already been written inside the same
/// transaction. The rollback must undo all of it.
#[tokio::test]
async fn rotation_that_fails_partway_rolls_back_the_whole_batch() {
    let pool = test_pool().await;
    let admin_id = seed_user(&pool, "admin", &[1u8; 32], &[2u8; 32]).await;
    let org_id = seed_org(&pool, "acme").await;
    let store_id = seed_store(&pool, &org_id, "backend").await;
    let branch_id = seed_branch(&pool, &store_id, "dev").await;
    seed_branch_member(&pool, &branch_id, &admin_id, "admin").await;
    let admin_token = seed_session(&pool, &admin_id, now_unix() + 3600).await;
    // Keep a handle to the pool so we can inspect the DB after the request; the router owns a
    // clone.
    let router = build_router(pool.clone());

    // A brand-new object the batch would insert first. Its hash is not present beforehand, so if
    // it survives the failed rotation we know the object insert was not rolled back.
    let batch_content = b"rotation-batch-object-that-must-not-persist";
    let batch_hash = Hash::of(batch_content).to_hex();

    let (status, _) = send_json(
        &router,
        "POST",
        "/orgs/acme/stores/backend/branches/dev/rotate",
        Some(&admin_token),
        Some(json!({
            "new_dek_version": 2,
            "objects": [object_upload_body("blob", batch_content)],
            "wrapped_deks": [
                // First entry is valid (references the real admin user) and is written inside
                // the transaction before the failing one.
                { "user_id": admin_id, "dek_version": 2, "sealed_box": STANDARD.encode(b"valid-sealed") },
                // Second entry references a user that does not exist -> FK violation, mid-tx.
                { "user_id": "00000000-0000-0000-0000-000000000000", "dek_version": 2, "sealed_box": STANDARD.encode(b"orphan-sealed") },
            ],
        })),
    )
    .await;
    // The rotation did not succeed. (The constraint violation surfaces as a 500; the point of
    // the test is the atomicity that follows, not the exact status.)
    assert_ne!(status, StatusCode::OK);
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

    // 1. The branch's active DEK version never moved off its original value of 1.
    let version: i64 = sqlx::query("SELECT active_dek_version FROM branches WHERE id = ?")
        .bind(&branch_id)
        .fetch_one(&pool)
        .await
        .unwrap()
        .get("active_dek_version");
    assert_eq!(version, 1, "active_dek_version must not move on a failed rotation");

    // 2. No wrapped-DEK row for the branch survived — not even the first, valid one.
    let dek_rows: i64 = sqlx::query("SELECT COUNT(*) AS n FROM wrapped_deks WHERE branch_id = ?")
        .bind(&branch_id)
        .fetch_one(&pool)
        .await
        .unwrap()
        .get("n");
    assert_eq!(dek_rows, 0, "no wrapped-DEK row may survive a rolled-back rotation");

    // 3. The batch's new object was not persisted, so it can never be confused with committed
    //    state on a later read.
    let obj_rows: i64 = sqlx::query("SELECT COUNT(*) AS n FROM objects WHERE hash = ?")
        .bind(&batch_hash)
        .fetch_one(&pool)
        .await
        .unwrap()
        .get("n");
    assert_eq!(obj_rows, 0, "no batch object may survive a rolled-back rotation");
}

// ---- OAuth-gated registration (Part 1) ----------------------------------------------------

fn router_with_mock_oauth(pool: SqlitePool, provider: crate::oauth::test_support::MockProvider) -> Router {
    let providers = crate::OAuthProviders::none().register(provider);
    crate::build_router_with_oauth(pool, providers)
}

/// Plain `POST /auth/register` (no `oauth_ticket`) must behave exactly as it always has — the
/// OAuth gate is additive, not a breaking change to the existing open registration path.
#[tokio::test]
async fn register_without_a_ticket_is_unchanged() {
    let pool = test_pool().await;
    let router = build_router(pool);
    let (status, body) = send_json(&router, "POST", "/auth/register", None, Some(register_body("plainuser"))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body["user_id"].as_str().unwrap().is_empty());
}

/// `GET /auth/oauth/:provider/authorize` 404s for a provider name nothing registered under.
#[tokio::test]
async fn oauth_authorize_404s_for_an_unconfigured_provider() {
    let pool = test_pool().await;
    let router = build_router(pool); // no providers registered at all
    let req = Request::builder()
        .method("GET")
        .uri("/auth/oauth/google/authorize")
        .body(Body::empty())
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

/// The full happy path: `authorize` redirects, `callback` exchanges the code (via the mock
/// provider) and mints a single-use ticket, and `register` with that ticket both succeeds and
/// records the verified email/provider/subject — while the ticket cannot be presented twice.
#[tokio::test]
async fn oauth_callback_mints_a_ticket_that_register_consumes_exactly_once() {
    let pool = test_pool().await;
    let router = router_with_mock_oauth(
        pool.clone(),
        crate::oauth::test_support::MockProvider::always_succeeds("mock", "subj-123", "alice@example.com"),
    );

    // authorize redirects somewhere (a real consent screen for a real provider).
    let req = Request::builder().method("GET").uri("/auth/oauth/mock/authorize").body(Body::empty()).unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert!(res.status().is_redirection());

    // callback (mock exchange never inspects `code`) redirects with a ticket in the fragment.
    let req = Request::builder()
        .method("GET")
        .uri("/auth/oauth/mock/callback?code=whatever")
        .body(Body::empty())
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert!(res.status().is_redirection());
    let location = res.headers().get("location").unwrap().to_str().unwrap().to_string();
    let ticket = location.split("oauth_ticket=").nth(1).unwrap().split('&').next().unwrap().to_string();
    assert!(!ticket.is_empty());

    // A single row was minted with the mock provider's identity.
    let row_count: i64 = sqlx::query("SELECT COUNT(*) AS n FROM oauth_verifications")
        .fetch_one(&pool)
        .await
        .unwrap()
        .get("n");
    assert_eq!(row_count, 1);

    // register() with the ticket succeeds and records the verified identity.
    let mut body = register_body("alice");
    body["oauth_ticket"] = json!(ticket);
    let (status, resp) = send_json(&router, "POST", "/auth/register", None, Some(body)).await;
    assert_eq!(status, StatusCode::OK);
    let user_id = resp["user_id"].as_str().unwrap().to_string();

    let row = sqlx::query("SELECT email, oauth_provider, oauth_subject FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("email"), "alice@example.com");
    assert_eq!(row.get::<String, _>("oauth_provider"), "mock");
    assert_eq!(row.get::<String, _>("oauth_subject"), "subj-123");

    // The ticket was consumed (single-use) — a second registration attempt with the same ticket
    // must be rejected, not silently accepted or re-verified.
    let mut body2 = register_body("alice-again");
    body2["oauth_ticket"] = json!(ticket);
    let (status, _) = send_json(&router, "POST", "/auth/register", None, Some(body2)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// A garbage/unknown ticket is a clean 400, not a crash or a silently-unverified registration.
#[tokio::test]
async fn register_with_a_bogus_ticket_is_rejected() {
    let pool = test_pool().await;
    let router = build_router(pool);
    let mut body = register_body("bob");
    body["oauth_ticket"] = json!("this-ticket-was-never-minted");
    let (status, _) = send_json(&router, "POST", "/auth/register", None, Some(body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// A provider that fails the code exchange (e.g. Google rejected the code) surfaces as a clean
/// error from `callback`, not a ticket that gets minted anyway.
#[tokio::test]
async fn oauth_callback_with_a_failing_provider_mints_no_ticket() {
    let pool = test_pool().await;
    let router = router_with_mock_oauth(pool.clone(), crate::oauth::test_support::MockProvider::always_fails("mock"));

    let req = Request::builder()
        .method("GET")
        .uri("/auth/oauth/mock/callback?code=whatever")
        .body(Body::empty())
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert!(!res.status().is_redirection(), "a failed exchange must not redirect with a ticket");

    let row_count: i64 = sqlx::query("SELECT COUNT(*) AS n FROM oauth_verifications")
        .fetch_one(&pool)
        .await
        .unwrap()
        .get("n");
    assert_eq!(row_count, 0, "no ticket may be minted when the provider exchange fails");
}
