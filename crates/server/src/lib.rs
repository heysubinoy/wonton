//! `wonton-server` — the blind blob + ref store (PLAN.md §7).
//!
//! # Blind by construction
//! This crate stores and moves **opaque bytes** and enforces **metadata-level** access
//! control. It deliberately does NOT depend on `wonton-crypto` and holds no code path that
//! receives a DEK or a private key (PLAN.md §12.7). It depends on `wonton-objects` solely to
//! recompute an uploaded object's BLAKE2b-256 hash and reject a push whose hash doesn't match
//! its content — that is hash *verification of opaque bytes*, not decryption. It uses
//! `ed25519-dalek` to verify a login-challenge signature against a stored PUBLIC key, and
//! `blake2` to hash bearer tokens for storage — neither is value cryptography.
//!
//! # Authentication (challenge-response — a deliberate design decision this phase makes)
//! PLAN.md §7 only sketched a single-step `POST /auth/login`. Because the server never sees a
//! passphrase or a private key, this implementation authenticates a login with a
//! **challenge-response over the user's Ed25519 public key** (which the server already
//! stores, and which is not secret):
//! 1. `POST /auth/login/start { username }` returns the (ciphertext) wrapped private key, the
//!    Argon2id parameters, and a fresh random `challenge_nonce`. No auth required — all three
//!    are non-secret.
//! 2. The client unlocks its Ed25519 key locally with the passphrase, signs the nonce, and
//!    calls `POST /auth/login/complete { username, challenge_nonce, signature }`. The server
//!    verifies the signature against the stored public key, consumes the challenge, and mints
//!    a session bearer token.
//!
//! See `PROGRESS.md` for the rationale and how to revise it.

mod auth;
mod error;
mod handlers;
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

/// Shared application state handed to every handler.
#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
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
    let state = AppState { pool };
    Router::new()
        // Auth (the routes that do NOT require a bearer token: register + the two login steps +
        // machine-token issuance). Machine-token issuance is
        // intentionally unauthenticated for this phase — see PROGRESS.md open items (a Phase 6
        // hardening gap: real deployments would gate it behind an authenticated admin).
        .route("/auth/register", post(handlers::register))
        .route("/auth/login/start", post(handlers::login_start))
        .route("/auth/login/complete", post(handlers::login_complete))
        .route("/auth/machine/token", post(handlers::machine_token))
        // Stores / environments. `POST /stores` and `POST /stores/{store}/envs` require any
        // valid token; the env-creator is bootstrapped as that env's first admin member.
        .route("/stores", post(handlers::create_store))
        .route(
            "/stores/{store}/envs",
            get(handlers::list_envs).post(handlers::create_env),
        )
        // User directory (any valid token — public keys, gated only to avoid enumeration)
        .route("/users/{username}", get(handlers::get_user))
        .route("/users/by-id/{user_id}", get(handlers::get_user_by_id))
        // Objects (content-addressed; any valid token — see PROGRESS.md re: no per-object env
        // scoping in this phase)
        .route("/objects/{hash}", get(handlers::get_object))
        .route("/objects", post(handlers::upload_object))
        // Refs
        .route("/refs/{store}/{env}", get(handlers::list_refs))
        .route("/refs/{store}/{env}/{branch}", post(handlers::move_ref))
        // Environment details
        .route("/envs/{store}/{env}", get(handlers::get_env_details))
        // Wrapped-DEK maps
        .route(
            "/envs/{store}/{env}/keys",
            get(handlers::list_keys).post(handlers::grant_key),
        )
        .route("/envs/{store}/{env}/rotate", post(handlers::rotate))
        // Membership (list requires >= reader; add is admin-only)
        .route(
            "/envs/{store}/{env}/members",
            get(handlers::list_members).post(handlers::add_member),
        )
        .route(
            "/envs/{store}/{env}/members/{user_id}",
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

/// Resolve `(store name, env name)` to an environment id, or 404 if it doesn't exist.
async fn resolve_env(pool: &SqlitePool, store: &str, env: &str) -> Result<String, ApiError> {
    use sqlx::Row;
    let row = sqlx::query(
        "SELECT e.id AS id FROM environments e \
         JOIN stores s ON e.store_id = s.id \
         WHERE s.name = ? AND e.name = ?",
    )
    .bind(store)
    .bind(env)
    .fetch_optional(pool)
    .await?;
    row.map(|r| r.get::<String, _>("id"))
        .ok_or(ApiError::NotFound("environment"))
}

/// Resolve the env, then require the actor to hold at least `min` role on it.
///
/// Returns the env id on success. 404 if the env doesn't exist; 403 if the actor is not a
/// member or holds an insufficient role. (Note: machine identities are not rows in `users`,
/// so they currently match no `env_members` row and are denied on role-gated routes — see
/// PROGRESS.md open items.)
async fn authorize_env(
    pool: &SqlitePool,
    store: &str,
    env: &str,
    actor: &Actor,
    min: Role,
) -> Result<String, ApiError> {
    use sqlx::Row;
    let env_id = resolve_env(pool, store, env).await?;
    let row = sqlx::query("SELECT role FROM env_members WHERE env_id = ? AND user_id = ?")
        .bind(&env_id)
        .bind(&actor.id)
        .fetch_optional(pool)
        .await?;
    let role: String = row.map(|r| r.get::<String, _>("role")).ok_or(ApiError::Forbidden)?;
    if role_rank(&role) >= required_rank(min) {
        Ok(env_id)
    } else {
        Err(ApiError::Forbidden)
    }
}
