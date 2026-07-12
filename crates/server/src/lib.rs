//! `wonton-server` — the blind blob + ref store.
//!
//! # Blind by construction
//! This crate stores and moves **opaque bytes** and enforces **metadata-level** access
//! control. It deliberately does NOT depend on `wonton-crypto` and holds no code path that
//! receives a DEK or a private key. It depends on `wonton-objects` solely to
//! recompute an uploaded object's BLAKE2b-256 hash and reject a push whose hash doesn't match
//! its content — that is hash *verification of opaque bytes*, not decryption. It uses
//! `ed25519-dalek` to verify a login-challenge signature against a stored PUBLIC key, and
//! `blake2` to hash bearer tokens for storage — neither is value cryptography.
//!
//! # Authentication (challenge-response — a deliberate design decision this phase makes)
//! The original sketch for this API only described a single-step `POST /auth/login`. Because
//! the server never sees a passphrase or a private key, this implementation authenticates a
//! login with a **challenge-response over the user's Ed25519 public key** (which the server
//! already stores, and which is not secret):
//! 1. `POST /auth/login/start { username }` returns the (ciphertext) wrapped private key, the
//!    Argon2id parameters, and a fresh random `challenge_nonce`. No auth required — all three
//!    are non-secret.
//! 2. The client unlocks its Ed25519 key locally with the passphrase, signs the nonce, and
//!    calls `POST /auth/login/complete { username, challenge_nonce, signature }`. The server
//!    verifies the signature against the stored public key, consumes the challenge, and mints
//!    a session bearer token.

mod auth;
mod error;
mod handlers;
mod oauth;
#[cfg(test)]
mod tests;

use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::routing::{delete, get, post};
use axum::Router;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use wonton_shared::Role;

pub use auth::{Actor, ActorKind};
pub use error::ApiError;
pub use oauth::{GoogleProvider, OAuthProvider, OAuthProviders, VerifiedIdentity};

/// Shared application state handed to every handler.
#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub oauth: OAuthProviders,
}

/// Startup errors (connecting + running migrations). Distinct from the per-request `ApiError`.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

/// Current unix time in seconds. A pre-epoch clock yields 0 (timestamps are descriptive
/// metadata, not a security boundary).
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Connect to a SQLite database (file path or `sqlite::memory:`), enabling foreign-key
/// enforcement, then run migrations. `create_if_missing` lets a fresh file be provisioned.
pub async fn connect(url: &str) -> Result<SqlitePool, ServerError> {
    let opts = SqliteConnectOptions::from_str(url)?
        .create_if_missing(true)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));
    let pool = SqlitePoolOptions::new().connect_with(opts).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

/// Build the axum router over an already-connected pool. Split out from `connect` so tests can
/// supply their own pool (see the test helper in `handlers`).
pub fn build_router(pool: SqlitePool) -> Router {
    build_router_with_oauth(pool, OAuthProviders::none())
}

/// Same as [`build_router`], but with OAuth providers registered (see `oauth` module docs) so
/// `/auth/oauth/{provider}/authorize` and `/auth/oauth/{provider}/callback` resolve to
/// something. The `wonton-server` binary calls this with `OAuthProviders::none()
/// .register(GoogleProvider::from_env()...)` when Google's env vars are set; every existing
/// caller of plain `build_router` (every test in this workspace, notably) is unaffected.
pub fn build_router_with_oauth(pool: SqlitePool, oauth: OAuthProviders) -> Router {
    let state = AppState { pool, oauth };
    Router::new()
        // Auth (the routes that do NOT require a bearer token: register + the two login steps +
        // machine-token issuance). Machine-token issuance is
        // intentionally unauthenticated for this phase (a known hardening gap: real
        // deployments would gate it behind an authenticated admin).
        .route("/auth/register", post(handlers::register))
        .route("/auth/login/start", post(handlers::login_start))
        .route("/auth/login/complete", post(handlers::login_complete))
        .route("/auth/machine/token", post(handlers::machine_token))
        // OAuth registration gate (Part 1) — 404s for a provider name that isn't registered.
        .route("/auth/oauth/{provider}/authorize", get(handlers::oauth_authorize))
        .route("/auth/oauth/{provider}/callback", get(handlers::oauth_callback))
        // Orgs. `POST /orgs` requires any valid token; the creator is bootstrapped as its first
        // `owner` member.
        .route("/orgs", post(handlers::create_org))
        // Stores (repos), scoped under an org. `POST` requires the caller to already be a member
        // of `org` (any role).
        .route(
            "/orgs/{org}/stores",
            post(handlers::create_store),
        )
        // Branches — the crypto/ACL unit (was "environments"). The creator is bootstrapped as
        // that branch's first admin member.
        .route(
            "/orgs/{org}/stores/{store}/branches",
            get(handlers::list_branches).post(handlers::create_branch),
        )
        // User directory (any valid token — public keys, gated only to avoid enumeration)
        .route("/users/{username}", get(handlers::get_user))
        .route("/users/by-id/{user_id}", get(handlers::get_user_by_id))
        // Objects (content-addressed; any valid token — no per-branch scoping in this phase)
        .route("/objects/{hash}", get(handlers::get_object))
        .route("/objects", post(handlers::upload_object))
        // Ref — ONE per branch (no named sub-branches anymore).
        .route(
            "/orgs/{org}/stores/{store}/branches/{branch}/ref",
            get(handlers::get_ref).post(handlers::move_ref),
        )
        // Branch details
        .route(
            "/orgs/{org}/stores/{store}/branches/{branch}",
            get(handlers::get_branch_details),
        )
        // Wrapped-DEK maps
        .route(
            "/orgs/{org}/stores/{store}/branches/{branch}/keys",
            get(handlers::list_keys).post(handlers::grant_key),
        )
        .route(
            "/orgs/{org}/stores/{store}/branches/{branch}/rotate",
            post(handlers::rotate),
        )
        // Membership (list requires >= reader; add is admin-only and auto-joins the org)
        .route(
            "/orgs/{org}/stores/{store}/branches/{branch}/members",
            get(handlers::list_members).post(handlers::add_member),
        )
        .route(
            "/orgs/{org}/stores/{store}/branches/{branch}/members/{user_id}",
            delete(handlers::remove_member),
        )
        .with_state(state)
}

// ---- RBAC helpers (shared by handlers) ------------------------------------------------

/// Numeric rank so "at least reader/writer/admin" is a simple comparison.
fn role_rank(role: &str) -> i32 {
    match role {
        "admin" => 3,
        "writer" => 2,
        "reader" => 1,
        _ => 0,
    }
}

fn required_rank(min: Role) -> i32 {
    match min {
        Role::Admin => 3,
        Role::Writer => 2,
        Role::Reader => 1,
    }
}

/// Serialize a `Role` to its stored/wire string.
fn role_str(role: Role) -> &'static str {
    match role {
        Role::Admin => "admin",
        Role::Writer => "writer",
        Role::Reader => "reader",
    }
}

/// Parse a stored role string back into a `Role` (defaults to `Reader` on an unknown value,
/// which the CHECK constraint makes unreachable in practice).
fn parse_role(role: &str) -> Role {
    match role {
        "admin" => Role::Admin,
        "writer" => Role::Writer,
        _ => Role::Reader,
    }
}

/// Resolve an org name to its id, or 404 if it doesn't exist.
async fn resolve_org(pool: &SqlitePool, org: &str) -> Result<String, ApiError> {
    use sqlx::Row;
    let row = sqlx::query("SELECT id FROM orgs WHERE name = ?")
        .bind(org)
        .fetch_optional(pool)
        .await?;
    row.map(|r| r.get::<String, _>("id")).ok_or(ApiError::NotFound("org"))
}

/// Require the actor to already be a member of `org` (any role). Returns the org id on success.
/// 404 if the org doesn't exist; 403 if the actor isn't a member.
async fn authorize_org_member(pool: &SqlitePool, org: &str, actor: &Actor) -> Result<String, ApiError> {
    let org_id = resolve_org(pool, org).await?;
    let row = sqlx::query("SELECT 1 AS one FROM org_members WHERE org_id = ? AND user_id = ?")
        .bind(&org_id)
        .bind(&actor.id)
        .fetch_optional(pool)
        .await?;
    if row.is_some() {
        Ok(org_id)
    } else {
        Err(ApiError::Forbidden)
    }
}

/// Resolve `(org name, store name, branch name)` to a branch id, or 404 if any segment doesn't
/// exist.
async fn resolve_branch(pool: &SqlitePool, org: &str, store: &str, branch: &str) -> Result<String, ApiError> {
    use sqlx::Row;
    let row = sqlx::query(
        "SELECT b.id AS id FROM branches b \
         JOIN stores s ON b.store_id = s.id \
         JOIN orgs o ON s.org_id = o.id \
         WHERE o.name = ? AND s.name = ? AND b.name = ?",
    )
    .bind(org)
    .bind(store)
    .bind(branch)
    .fetch_optional(pool)
    .await?;
    row.map(|r| r.get::<String, _>("id"))
        .ok_or(ApiError::NotFound("branch"))
}

/// Resolve `(org name, store name)` to a store id, or 404 if either segment doesn't exist.
async fn resolve_store(pool: &SqlitePool, org: &str, store: &str) -> Result<String, ApiError> {
    use sqlx::Row;
    let row = sqlx::query(
        "SELECT s.id AS id FROM stores s JOIN orgs o ON s.org_id = o.id \
         WHERE o.name = ? AND s.name = ?",
    )
    .bind(org)
    .bind(store)
    .fetch_optional(pool)
    .await?;
    row.map(|r| r.get::<String, _>("id")).ok_or(ApiError::NotFound("store"))
}

/// Resolve the branch, then require the actor to hold at least `min` role on it.
///
/// Returns the branch id on success. 404 if the branch doesn't exist; 403 if the actor is not a
/// member or holds an insufficient role. (Note: machine identities are not rows in `users`,
/// so they currently match no `branch_members` row and are denied on role-gated routes.)
async fn authorize_branch(
    pool: &SqlitePool,
    org: &str,
    store: &str,
    branch: &str,
    actor: &Actor,
    min: Role,
) -> Result<String, ApiError> {
    use sqlx::Row;
    let branch_id = resolve_branch(pool, org, store, branch).await?;
    let row = sqlx::query("SELECT role FROM branch_members WHERE branch_id = ? AND user_id = ?")
        .bind(&branch_id)
        .bind(&actor.id)
        .fetch_optional(pool)
        .await?;
    let role: String = row.map(|r| r.get::<String, _>("role")).ok_or(ApiError::Forbidden)?;
    if role_rank(&role) >= required_rank(min) {
        Ok(branch_id)
    } else {
        Err(ApiError::Forbidden)
    }
}
