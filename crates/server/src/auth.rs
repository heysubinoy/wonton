//! Bearer-token authentication.
//!
//! Tokens are opaque random strings minted by the server. We store only their BLAKE2b-256
//! hash (`token_hash`), so a stolen database yields no usable live tokens — the same reasoning
//! as storing a password hash instead of a password. This BLAKE2b use is deliberately kept
//! separate from `wonton_objects::Hash` (content addressing) and from `wonton-crypto` (value
//! cryptography): it is an unrelated, server-local use of the same primitive family. The
//! server never touches a DEK or a private key here.

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use sqlx::Row;

use crate::error::ApiError;
use crate::{now_unix, AppState};

type Blake2b256 = Blake2b<U32>;

/// Length in bytes of the random material behind a bearer token (hex-encoded on the wire).
const TOKEN_BYTES: usize = 32;

/// Mint a fresh, unguessable bearer token as a lowercase hex string.
pub fn mint_token() -> String {
    let mut buf = [0u8; TOKEN_BYTES];
    getrandom::getrandom(&mut buf).expect("OS CSPRNG must be available to mint tokens");
    hex::encode(buf)
}

/// Fresh random challenge nonce for the login flow. Returned raw so the caller can both store
/// it and hand it to the client.
pub fn mint_nonce() -> [u8; 32] {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).expect("OS CSPRNG must be available to mint nonces");
    buf
}

/// Hash a presented token for storage / lookup. Never store the raw token.
pub fn hash_token(token: &str) -> Vec<u8> {
    let mut hasher = Blake2b256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().to_vec()
}

/// Whether the caller is a human user or a machine identity. Both authenticate the same way
/// (a bearer token); they differ only in which table backs the token and in RBAC reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorKind {
    User,
    Machine,
}

/// An authenticated caller. `id` is the `users.id` for a user token, or the
/// `machine_identities.id` for a machine token; role checks query `env_members` by this id.
#[derive(Debug, Clone)]
pub struct Actor {
    pub id: String,
    pub kind: ActorKind,
}

impl FromRequestParts<AppState> for Actor {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(ApiError::Unauthorized)?;
        let token = header
            .strip_prefix("Bearer ")
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .ok_or(ApiError::Unauthorized)?;

        let token_hash = hash_token(token);
        let now = now_unix();

        // Try a user session first, then a machine identity. Expired tokens are treated as
        // absent (401), never as valid.
        if let Some(row) = sqlx::query("SELECT user_id, expires_at FROM sessions WHERE token_hash = ?")
            .bind(&token_hash)
            .fetch_optional(&state.pool)
            .await?
        {
            let expires_at: i64 = row.get("expires_at");
            if expires_at >= now {
                return Ok(Actor {
                    id: row.get("user_id"),
                    kind: ActorKind::User,
                });
            }
        }

        if let Some(row) =
            sqlx::query("SELECT id, expires_at FROM machine_identities WHERE token_hash = ?")
                .bind(&token_hash)
                .fetch_optional(&state.pool)
                .await?
        {
            let expires_at: i64 = row.get("expires_at");
            if expires_at >= now {
                return Ok(Actor {
                    id: row.get("id"),
                    kind: ActorKind::Machine,
                });
            }
        }

        Err(ApiError::Unauthorized)
    }
}
