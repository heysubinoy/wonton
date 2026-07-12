//! Axum request handlers for every route this server exposes.
//!
//! Every handler except the three `/auth/*` routes takes an `Actor` extractor, which enforces
//! a valid bearer token (401 otherwise). Role-gated handlers additionally call
//! `authorize_branch`, which yields 404 if the branch doesn't exist and 403 if the actor's role
//! is insufficient — so a caller can tell "who are you" (401) from "not allowed" (403) from
//! "no such branch" (404).

use std::collections::HashMap;

use axum::extract::{Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;
use wonton_objects::Hash;
use wonton_shared::{
    Argon2ParamsDto, BranchDetails, BranchSummary, GrantKeyRequest, KeysMap, LoginCompleteRequest,
    LoginCompleteResponse, LoginStartRequest, LoginStartResponse, MachineTokenRequest,
    MachineTokenResponse, MemberInfo, MemberRequest, ObjectUploadRequest, RefConflict,
    RefMoveRequest, RefResponse, Role, RotateRequest, UserPublicInfo, WrappedDekEntry,
};

use crate::auth::{hash_token, mint_nonce, mint_token};
use crate::error::ApiError;
use crate::{authorize_branch, authorize_org_member, now_unix, parse_role, resolve_store, role_str, Actor, ActorKind, AppState};
use wonton_shared::{
    CreateBranchRequest, CreateBranchResponse, CreateOrgRequest, CreateOrgResponse,
    CreateStoreRequest, CreateStoreResponse, RegisterRequest, RegisterResponse,
};

/// Login challenges expire quickly — they only need to survive one client sign-and-return.
const CHALLENGE_TTL_SECS: i64 = 120;
/// User session lifetime after a successful login.
const SESSION_TTL_SECS: i64 = 86_400;
/// Upper bound on a requested machine-token lifetime (30 days).
const MAX_MACHINE_TTL_SECS: i64 = 2_592_000;

// ---- Auth -----------------------------------------------------------------------------

/// `POST /auth/login/start` — no auth. Issues a challenge nonce and returns the (ciphertext)
/// wrapped private key + Argon2id params so the client can unlock locally.
pub async fn login_start(
    State(st): State<AppState>,
    Json(req): Json<LoginStartRequest>,
) -> Result<Json<LoginStartResponse>, ApiError> {
    let row = sqlx::query(
        "SELECT id, wrapped_privkey, argon2_salt, argon2_m_cost_kib, argon2_t_cost, argon2_p_cost \
         FROM users WHERE username = ?",
    )
    .bind(&req.username)
    .fetch_optional(&st.pool)
    .await?
    .ok_or(ApiError::NotFound("user"))?;

    let user_id: String = row.get("id");
    let wrapped: Vec<u8> = row.get("wrapped_privkey");
    let salt: Vec<u8> = row.get("argon2_salt");
    let m_cost_kib: i64 = row.get("argon2_m_cost_kib");
    let t_cost: i64 = row.get("argon2_t_cost");
    let p_cost: i64 = row.get("argon2_p_cost");

    let nonce = mint_nonce();
    let now = now_unix();
    sqlx::query(
        "INSERT INTO login_challenges (id, user_id, nonce, expires_at, created_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&user_id)
    .bind(nonce.to_vec())
    .bind(now + CHALLENGE_TTL_SECS)
    .bind(now)
    .execute(&st.pool)
    .await?;

    Ok(Json(LoginStartResponse {
        wrapped_privkey: STANDARD.encode(&wrapped),
        argon2_params: Argon2ParamsDto {
            salt: STANDARD.encode(&salt),
            m_cost_kib: m_cost_kib as u32,
            t_cost: t_cost as u32,
            p_cost: p_cost as u32,
        },
        challenge_nonce: STANDARD.encode(nonce),
    }))
}

/// `POST /auth/login/complete` — no auth. Verifies the Ed25519 signature over the challenge
/// nonce against the user's stored PUBLIC key, consumes the challenge, and mints a session.
pub async fn login_complete(
    State(st): State<AppState>,
    Json(req): Json<LoginCompleteRequest>,
) -> Result<Json<LoginCompleteResponse>, ApiError> {
    let nonce = STANDARD
        .decode(&req.challenge_nonce)
        .map_err(|_| ApiError::BadRequest("challenge_nonce not base64".into()))?;
    let sig_bytes = STANDARD
        .decode(&req.signature)
        .map_err(|_| ApiError::BadRequest("signature not base64".into()))?;

    // Unknown user is treated as an auth failure (401), not distinguished from a bad signature.
    let user = sqlx::query("SELECT id, ed25519_pubkey FROM users WHERE username = ?")
        .bind(&req.username)
        .fetch_optional(&st.pool)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let user_id: String = user.get("id");
    let pubkey: Vec<u8> = user.get("ed25519_pubkey");

    let now = now_unix();
    let challenge =
        sqlx::query("SELECT id, expires_at FROM login_challenges WHERE user_id = ? AND nonce = ?")
            .bind(&user_id)
            .bind(&nonce)
            .fetch_optional(&st.pool)
            .await?
            .ok_or(ApiError::Unauthorized)?;
    let challenge_id: String = challenge.get("id");
    let expires_at: i64 = challenge.get("expires_at");
    if expires_at < now {
        sqlx::query("DELETE FROM login_challenges WHERE id = ?")
            .bind(&challenge_id)
            .execute(&st.pool)
            .await?;
        return Err(ApiError::Unauthorized);
    }

    verify_ed25519(&pubkey, &nonce, &sig_bytes)?;

    // Signature is valid: consume the challenge (single-use) and mint a session token.
    sqlx::query("DELETE FROM login_challenges WHERE id = ?")
        .bind(&challenge_id)
        .execute(&st.pool)
        .await?;
    let token = mint_token();
    let session_expires = now + SESSION_TTL_SECS;
    sqlx::query(
        "INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&user_id)
    .bind(hash_token(&token))
    .bind(session_expires)
    .bind(now)
    .execute(&st.pool)
    .await?;

    Ok(Json(LoginCompleteResponse {
        token,
        expires_at: session_expires,
        user_id,
    }))
}

/// `POST /auth/machine/token` — no auth for this phase (a known hardening gap).
pub async fn machine_token(
    State(st): State<AppState>,
    Json(req): Json<MachineTokenRequest>,
) -> Result<Json<MachineTokenResponse>, ApiError> {
    let ed = STANDARD
        .decode(&req.ed25519_pubkey)
        .map_err(|_| ApiError::BadRequest("ed25519_pubkey not base64".into()))?;
    let x = STANDARD
        .decode(&req.x25519_pubkey)
        .map_err(|_| ApiError::BadRequest("x25519_pubkey not base64".into()))?;

    let now = now_unix();
    let ttl = req.requested_ttl_seconds.clamp(1, MAX_MACHINE_TTL_SECS);
    let expires = now + ttl;
    let token = mint_token();
    sqlx::query(
        "INSERT INTO machine_identities \
         (id, label, ed25519_pubkey, x25519_pubkey, token_hash, expires_at, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&req.label)
    .bind(ed)
    .bind(x)
    .bind(hash_token(&token))
    .bind(expires)
    .bind(now)
    .execute(&st.pool)
    .await?;

    Ok(Json(MachineTokenResponse {
        token,
        expires_at: expires,
    }))
}

/// `POST /auth/register` — no auth. This *is* the auth bootstrap (like any signup endpoint):
/// it persists a new user's public identity + opaque wrapped private key. The client must have
/// already run `wonton_crypto::generate_identity` locally; the server only stores the results.
pub async fn register(
    State(st): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, ApiError> {
    let ed = STANDARD
        .decode(&req.ed25519_pubkey)
        .map_err(|_| ApiError::BadRequest("ed25519_pubkey not base64".into()))?;
    let x = STANDARD
        .decode(&req.x25519_pubkey)
        .map_err(|_| ApiError::BadRequest("x25519_pubkey not base64".into()))?;
    let wrapped = STANDARD
        .decode(&req.wrapped_privkey)
        .map_err(|_| ApiError::BadRequest("wrapped_privkey not base64".into()))?;
    let salt = STANDARD
        .decode(&req.argon2_params.salt)
        .map_err(|_| ApiError::BadRequest("argon2 salt not base64".into()))?;

    // Optional OAuth gate: if a ticket was supplied, it must be a real, unexpired, unused
    // ticket minted by a completed `/auth/oauth/{provider}/callback` exchange. Consuming it here
    // (single-use) proves this registration is by someone who verified a real email — but
    // registration itself stays open when no ticket is given, exactly as before.
    let verified = match &req.oauth_ticket {
        Some(ticket) => Some(consume_oauth_ticket(&st, ticket).await?),
        None => None,
    };

    // Explicit pre-check so a taken username is a clean 409 rather than a raw UNIQUE-violation
    // 500. (A race between check and insert would surface as the insert's own error; acceptable
    // for this phase — usernames are provisioned rarely.)
    let existing = sqlx::query("SELECT 1 AS one FROM users WHERE username = ?")
        .bind(&req.username)
        .fetch_optional(&st.pool)
        .await?;
    if existing.is_some() {
        return Err(ApiError::Conflict("username"));
    }

    let user_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO users \
         (id, username, ed25519_pubkey, x25519_pubkey, wrapped_privkey, argon2_salt, \
          argon2_m_cost_kib, argon2_t_cost, argon2_p_cost, created_at, email, oauth_provider, \
          oauth_subject) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&user_id)
    .bind(&req.username)
    .bind(ed)
    .bind(x)
    .bind(wrapped)
    .bind(salt)
    .bind(req.argon2_params.m_cost_kib as i64)
    .bind(req.argon2_params.t_cost as i64)
    .bind(req.argon2_params.p_cost as i64)
    .bind(now_unix())
    .bind(verified.as_ref().map(|v| v.email.as_str()))
    .bind(verified.as_ref().map(|v| v.provider.as_str()))
    .bind(verified.as_ref().map(|v| v.subject.as_str()))
    .execute(&st.pool)
    .await?;

    Ok(Json(RegisterResponse { user_id }))
}

struct ConsumedOAuthTicket {
    email: String,
    provider: String,
    subject: String,
}

/// Look up, validate (unexpired), and consume (single-use — deleted regardless of outcome) an
/// OAuth registration ticket minted by [`oauth_callback`]. A missing, expired, or already-used
/// ticket is a 400, not a 401/403 — this isn't an auth failure, it's a bad/stale request.
async fn consume_oauth_ticket(st: &AppState, ticket: &str) -> Result<ConsumedOAuthTicket, ApiError> {
    let ticket_hash = hash_token(ticket);
    let row = sqlx::query("SELECT id, provider, verified_email, oauth_subject, expires_at FROM oauth_verifications WHERE ticket_hash = ?")
        .bind(&ticket_hash)
        .fetch_optional(&st.pool)
        .await?
        .ok_or_else(|| ApiError::BadRequest("oauth ticket is invalid or already used".into()))?;

    let id: String = row.get("id");
    let expires_at: i64 = row.get("expires_at");
    // Single-use regardless of outcome: an expired ticket must not be presentable twice either.
    sqlx::query("DELETE FROM oauth_verifications WHERE id = ?").bind(&id).execute(&st.pool).await?;
    if expires_at < now_unix() {
        return Err(ApiError::BadRequest("oauth ticket has expired".into()));
    }

    Ok(ConsumedOAuthTicket {
        email: row.get("verified_email"),
        provider: row.get("provider"),
        subject: row.get("oauth_subject"),
    })
}

/// Login challenges are short-lived; reuse the same duration for an OAuth registration ticket —
/// it only needs to survive one browser redirect + one `POST /auth/register` call.
const OAUTH_TICKET_TTL_SECS: i64 = CHALLENGE_TTL_SECS;

/// `GET /auth/oauth/:provider/authorize` — redirect to the provider's consent screen. 404 if
/// that provider isn't configured on this server (see `OAuthProviders`).
pub async fn oauth_authorize(State(st): State<AppState>, Path(provider): Path<String>) -> Result<Response, ApiError> {
    let provider_impl = st.oauth.get(&provider).ok_or(ApiError::NotFound("oauth provider"))?;
    // A random, unbound `state` value (CSRF-mitigation convention) — not stored/checked
    // server-side in v1 since the ticket minted after a successful exchange is itself single-use
    // and short-lived, which is what actually grants anything. A production deployment fronted
    // by a browser session/cookie could bind and verify this; flagged as a v1 simplification.
    let csrf_state = mint_token();
    Ok(axum::response::Redirect::to(&provider_impl.authorize_url(&csrf_state)).into_response())
}

#[derive(serde::Deserialize)]
pub struct OAuthCallbackQuery {
    code: String,
}

/// `GET /auth/oauth/:provider/callback?code=...` — exchange the code for a verified email, mint
/// a single-use registration ticket, and redirect to the dashboard with it in the URL fragment
/// (fragments are never sent to any server, including this one, in a request/log — the only way
/// the ticket leaves this response is via that fragment).
pub async fn oauth_callback(
    State(st): State<AppState>,
    Path(provider): Path<String>,
    axum::extract::Query(q): axum::extract::Query<OAuthCallbackQuery>,
) -> Result<Response, ApiError> {
    let provider_impl = st.oauth.get(&provider).ok_or(ApiError::NotFound("oauth provider"))?;
    let identity = provider_impl.exchange_code(&q.code).await?;

    let ticket = mint_token();
    let now = now_unix();
    sqlx::query(
        "INSERT INTO oauth_verifications (id, provider, verified_email, oauth_subject, ticket_hash, expires_at, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&provider)
    .bind(&identity.email)
    .bind(&identity.subject)
    .bind(hash_token(&ticket))
    .bind(now + OAUTH_TICKET_TTL_SECS)
    .bind(now)
    .execute(&st.pool)
    .await?;

    let dashboard_url = std::env::var("WONTON_DASHBOARD_URL").unwrap_or_else(|_| "/".to_string());
    Ok(axum::response::Redirect::to(&format!(
        "{dashboard_url}#oauth_ticket={ticket}&email={}",
        urlencoding::encode(&identity.email)
    ))
    .into_response())
}

/// Verify an Ed25519 signature over `msg` against a 32-byte public key. Any malformed input or
/// verification failure collapses to 401 — the server never reveals *why* auth failed.
fn verify_ed25519(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), ApiError> {
    let pk: [u8; 32] = pubkey.try_into().map_err(|_| ApiError::Unauthorized)?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|_| ApiError::Unauthorized)?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| ApiError::Unauthorized)?;
    let signature = Signature::from_bytes(&sig);
    vk.verify_strict(msg, &signature)
        .map_err(|_| ApiError::Unauthorized)
}

// ---- Orgs / stores (repos) / branches ---------------------------------------------------

/// `POST /orgs` — create an org, and make the creating actor its first `owner` member in the
/// same transaction. Any authenticated human actor may create one. 409 if the name is taken.
pub async fn create_org(
    State(st): State<AppState>,
    actor: Actor,
    Json(req): Json<CreateOrgRequest>,
) -> Result<Json<CreateOrgResponse>, ApiError> {
    if actor.kind == ActorKind::Machine {
        return Err(ApiError::BadRequest(
            "machine identities cannot create orgs (no org_members row can reference a machine \
             identity)"
                .into(),
        ));
    }
    let existing = sqlx::query("SELECT 1 AS one FROM orgs WHERE name = ?")
        .bind(&req.name)
        .fetch_optional(&st.pool)
        .await?;
    if existing.is_some() {
        return Err(ApiError::Conflict("org"));
    }

    let org_id = Uuid::new_v4().to_string();
    let mut tx = st.pool.begin().await?;
    sqlx::query("INSERT INTO orgs (id, name, created_at) VALUES (?, ?, ?)")
        .bind(&org_id)
        .bind(&req.name)
        .bind(now_unix())
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO org_members (org_id, user_id, role) VALUES (?, ?, 'owner')")
        .bind(&org_id)
        .bind(&actor.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(Json(CreateOrgResponse { org_id }))
}

/// `GET /orgs/:org/stores/:store/branches` — branches the caller is a member of, with their role.
pub async fn list_branches(
    State(st): State<AppState>,
    actor: Actor,
    Path((org, store)): Path<(String, String)>,
) -> Result<Json<Vec<BranchSummary>>, ApiError> {
    let rows = sqlx::query(
        "SELECT b.name AS name, m.role AS role \
         FROM branches b \
         JOIN stores s ON b.store_id = s.id \
         JOIN orgs o ON s.org_id = o.id \
         JOIN branch_members m ON m.branch_id = b.id \
         WHERE o.name = ? AND s.name = ? AND m.user_id = ? \
         ORDER BY b.name",
    )
    .bind(&org)
    .bind(&store)
    .bind(&actor.id)
    .fetch_all(&st.pool)
    .await?;

    let out = rows
        .iter()
        .map(|r| BranchSummary {
            name: r.get("name"),
            role: parse_role(&r.get::<String, _>("role")),
        })
        .collect();
    Ok(Json(out))
}

/// `POST /orgs/:org/stores` — create a store (repo) within an org. Requires the caller to
/// already be a member of `org` (any role) — 404 if the org doesn't exist, 403 if the actor
/// isn't a member. There is no store-level ownership beyond that (access control is per-branch
/// via `branch_members`). 409 if the name is already taken within the org.
pub async fn create_store(
    State(st): State<AppState>,
    actor: Actor,
    Path(org): Path<String>,
    Json(req): Json<CreateStoreRequest>,
) -> Result<Json<CreateStoreResponse>, ApiError> {
    let org_id = authorize_org_member(&st.pool, &org, &actor).await?;

    let existing = sqlx::query("SELECT 1 AS one FROM stores WHERE org_id = ? AND name = ?")
        .bind(&org_id)
        .bind(&req.name)
        .fetch_optional(&st.pool)
        .await?;
    if existing.is_some() {
        return Err(ApiError::Conflict("store"));
    }

    let store_id = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO stores (id, org_id, name, created_at) VALUES (?, ?, ?, ?)")
        .bind(&store_id)
        .bind(&org_id)
        .bind(&req.name)
        .bind(now_unix())
        .execute(&st.pool)
        .await?;
    Ok(Json(CreateStoreResponse { store_id }))
}

/// `POST /orgs/:org/stores/:store/branches` — create a branch, and make the creating actor its
/// first `admin` member in the *same transaction* (all-or-nothing). This is the access-control
/// bootstrap: whoever creates a branch becomes its first admin, so they can then grant
/// themselves the DEK they generate client-side and invite others. 404 if the org/store doesn't
/// exist; 409 if a branch with that name already exists in the store.
///
/// Only human users can hold `branch_members` rows (`branch_members.user_id` references
/// `users`), so a machine identity creating a branch is rejected with 400.
pub async fn create_branch(
    State(st): State<AppState>,
    actor: Actor,
    Path((org, store)): Path<(String, String)>,
    Json(req): Json<CreateBranchRequest>,
) -> Result<Json<CreateBranchResponse>, ApiError> {
    if actor.kind == ActorKind::Machine {
        return Err(ApiError::BadRequest(
            "machine identities cannot create branches (no branch_members row can reference a \
             machine identity)"
                .into(),
        ));
    }

    let store_id = resolve_store(&st.pool, &org, &store).await?;

    let mut tx = st.pool.begin().await?;
    let duplicate = sqlx::query("SELECT 1 AS one FROM branches WHERE store_id = ? AND name = ?")
        .bind(&store_id)
        .bind(&req.name)
        .fetch_optional(&mut *tx)
        .await?;
    if duplicate.is_some() {
        return Err(ApiError::Conflict("branch"));
    }

    let branch_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO branches (id, store_id, name, active_dek_version, created_at) \
         VALUES (?, ?, ?, 1, ?)",
    )
    .bind(&branch_id)
    .bind(&store_id)
    .bind(&req.name)
    .bind(now_unix())
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO branch_members (branch_id, user_id, role) VALUES (?, ?, 'admin')")
        .bind(&branch_id)
        .bind(&actor.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(Json(CreateBranchResponse { branch_id }))
}

// ---- User directory -------------------------------------------------------------------

/// `GET /users/:username` — a user's public identity keys (all non-secret: public keys + a
/// server-assigned id). Requires any valid actor: usernames are already known to whoever is
/// sharing and the keys are non-secret, but auth is still required to avoid unauthenticated user
/// enumeration. 404 if the username doesn't exist.
pub async fn get_user(
    State(st): State<AppState>,
    _actor: Actor,
    Path(username): Path<String>,
) -> Result<Json<UserPublicInfo>, ApiError> {
    let row = sqlx::query("SELECT id, ed25519_pubkey, x25519_pubkey FROM users WHERE username = ?")
        .bind(&username)
        .fetch_optional(&st.pool)
        .await?
        .ok_or(ApiError::NotFound("user"))?;
    let user_id: String = row.get("id");
    let ed: Vec<u8> = row.get("ed25519_pubkey");
    let x: Vec<u8> = row.get("x25519_pubkey");
    Ok(Json(UserPublicInfo {
        user_id,
        ed25519_pubkey: STANDARD.encode(ed),
        x25519_pubkey: STANDARD.encode(x),
    }))
}

/// `GET /users/by-id/:user_id` — the same public identity keys as [`get_user`], looked up by the
/// server-assigned user id (a commit's `author_id`) rather than by username. Needed so a client
/// can verify a shared/multi-author commit history: `list_members` only reflects *current* env
/// membership, but a commit's author remains verifiable by their (permanent, global) public key
/// even after they lose access to that particular environment. Requires any valid token; a
/// user's public keys are not secret (same trust level as `get_user`).
pub async fn get_user_by_id(
    State(st): State<AppState>,
    _actor: Actor,
    Path(user_id): Path<String>,
) -> Result<Json<UserPublicInfo>, ApiError> {
    let row = sqlx::query("SELECT id, ed25519_pubkey, x25519_pubkey FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_optional(&st.pool)
        .await?
        .ok_or(ApiError::NotFound("user"))?;
    let user_id: String = row.get("id");
    let ed: Vec<u8> = row.get("ed25519_pubkey");
    let x: Vec<u8> = row.get("x25519_pubkey");
    Ok(Json(UserPublicInfo {
        user_id,
        ed25519_pubkey: STANDARD.encode(ed),
        x25519_pubkey: STANDARD.encode(x),
    }))
}

// ---- Objects --------------------------------------------------------------------------

/// `GET /objects/:hash` — opaque bytes, 404 if absent. Any valid token (no per-object env
/// scoping in this phase).
pub async fn get_object(
    State(st): State<AppState>,
    _actor: Actor,
    Path(hash): Path<String>,
) -> Result<Response, ApiError> {
    let row = sqlx::query("SELECT body FROM objects WHERE hash = ?")
        .bind(&hash)
        .fetch_optional(&st.pool)
        .await?;
    match row {
        Some(r) => {
            let body: Vec<u8> = r.get("body");
            Ok(([(CONTENT_TYPE, "application/octet-stream")], body).into_response())
        }
        None => Err(ApiError::NotFound("object")),
    }
}

/// `POST /objects` — verify `Hash::of(body) == hash`, then store. Idempotent: re-uploading the
/// same object is a 200, not an error.
pub async fn upload_object(
    State(st): State<AppState>,
    _actor: Actor,
    Json(req): Json<ObjectUploadRequest>,
) -> Result<StatusCode, ApiError> {
    let body = decode_object(&req)?;
    sqlx::query(
        "INSERT INTO objects (hash, kind, body, created_at) VALUES (?, ?, ?, ?) \
         ON CONFLICT(hash) DO NOTHING",
    )
    .bind(&req.hash)
    .bind(&req.kind)
    .bind(body)
    .bind(now_unix())
    .execute(&st.pool)
    .await?;
    Ok(StatusCode::OK)
}

/// Validate an upload request (kind is legal, body is base64, and the claimed hash matches the
/// content) and return the decoded body. Shared by `upload_object` and `rotate`.
fn decode_object(req: &ObjectUploadRequest) -> Result<Vec<u8>, ApiError> {
    if !matches!(req.kind.as_str(), "blob" | "tree" | "commit") {
        return Err(ApiError::BadRequest(format!(
            "invalid object kind: {}",
            req.kind
        )));
    }
    let body = STANDARD
        .decode(&req.body)
        .map_err(|_| ApiError::BadRequest("body not base64".into()))?;
    let claimed =
        Hash::from_hex(&req.hash).map_err(|_| ApiError::BadRequest(format!("invalid hash: {}", req.hash)))?;
    let actual = Hash::of(&body);
    if actual != claimed {
        return Err(ApiError::BadRequest(format!(
            "hash mismatch: claimed {claimed}, computed {actual}"
        )));
    }
    Ok(body)
}

// ---- Ref (one per branch) ---------------------------------------------------------------

/// `GET /orgs/:org/stores/:store/branches/:branch/ref` — the branch's current tip, or `None` if
/// it has never been pushed to. Requires >= reader.
pub async fn get_ref(
    State(st): State<AppState>,
    actor: Actor,
    Path((org, store, branch)): Path<(String, String, String)>,
) -> Result<Json<RefResponse>, ApiError> {
    let branch_id = authorize_branch(&st.pool, &org, &store, &branch, &actor, Role::Reader).await?;
    let commit_hash = current_ref(&st.pool, &branch_id).await?;
    Ok(Json(RefResponse { commit_hash }))
}

/// `POST /orgs/:org/stores/:store/branches/:branch/ref` — compare-and-swap ref move. Requires
/// >= writer.
///
/// `old_hash: None` creates the ref (must not already exist); `Some(h)` moves it only if it
/// currently equals `h`. On any mismatch, 409 with the actual current value. The CAS is a
/// single atomic SQL statement (`INSERT ... ON CONFLICT DO NOTHING` for create, guarded
/// `UPDATE` for move), so two racing callers can never both win — see the concurrency test.
pub async fn move_ref(
    State(st): State<AppState>,
    actor: Actor,
    Path((org, store, branch)): Path<(String, String, String)>,
    Json(req): Json<RefMoveRequest>,
) -> Result<Response, ApiError> {
    let branch_id = authorize_branch(&st.pool, &org, &store, &branch, &actor, Role::Writer).await?;
    // The target commit object must already have been pushed (content-addressed store); give a
    // friendly 400 rather than surfacing a raw foreign-key error.
    if !object_exists(&st.pool, &req.new_hash).await? {
        return Err(ApiError::BadRequest(format!(
            "unknown object: {}",
            req.new_hash
        )));
    }

    let affected = match &req.old_hash {
        None => {
            sqlx::query(
                "INSERT INTO refs (branch_id, commit_hash) VALUES (?, ?) \
                 ON CONFLICT(branch_id) DO NOTHING",
            )
            .bind(&branch_id)
            .bind(&req.new_hash)
            .execute(&st.pool)
            .await?
            .rows_affected()
        }
        Some(old) => {
            sqlx::query("UPDATE refs SET commit_hash = ? WHERE branch_id = ? AND commit_hash = ?")
                .bind(&req.new_hash)
                .bind(&branch_id)
                .bind(old)
                .execute(&st.pool)
                .await?
                .rows_affected()
        }
    };

    if affected == 1 {
        Ok(StatusCode::OK.into_response())
    } else {
        let current = current_ref(&st.pool, &branch_id).await?;
        Ok((StatusCode::CONFLICT, Json(RefConflict { current })).into_response())
    }
}

async fn object_exists(pool: &SqlitePool, hash: &str) -> Result<bool, ApiError> {
    let row = sqlx::query("SELECT 1 AS one FROM objects WHERE hash = ?")
        .bind(hash)
        .fetch_optional(pool)
        .await?;
    Ok(row.is_some())
}

async fn current_ref(pool: &SqlitePool, branch_id: &str) -> Result<Option<String>, ApiError> {
    let row = sqlx::query("SELECT commit_hash FROM refs WHERE branch_id = ?")
        .bind(branch_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.get::<String, _>("commit_hash")))
}

// ---- Branch details / members ----------------------------------------------------------

/// `GET /orgs/:org/stores/:store/branches/:branch` — branch metadata (its id + current active
/// DEK version). Requires >= reader. `share` reads the version to grant at it; `rotate` to pick
/// the next one.
pub async fn get_branch_details(
    State(st): State<AppState>,
    actor: Actor,
    Path((org, store, branch)): Path<(String, String, String)>,
) -> Result<Json<BranchDetails>, ApiError> {
    let branch_id = authorize_branch(&st.pool, &org, &store, &branch, &actor, Role::Reader).await?;
    let row = sqlx::query("SELECT active_dek_version FROM branches WHERE id = ?")
        .bind(&branch_id)
        .fetch_optional(&st.pool)
        .await?
        .ok_or(ApiError::NotFound("branch"))?;
    let active_dek_version: i64 = row.get("active_dek_version");
    Ok(Json(BranchDetails {
        branch_id,
        active_dek_version: active_dek_version as u32,
    }))
}

/// `GET /orgs/:org/stores/:store/branches/:branch/members` — every member's id, role, and
/// X25519 public key (joining `branch_members` × `users`). Requires >= reader. `key rotate`
/// re-wraps the new DEK for each.
pub async fn list_members(
    State(st): State<AppState>,
    actor: Actor,
    Path((org, store, branch)): Path<(String, String, String)>,
) -> Result<Json<Vec<MemberInfo>>, ApiError> {
    let branch_id = authorize_branch(&st.pool, &org, &store, &branch, &actor, Role::Reader).await?;
    let rows = sqlx::query(
        "SELECT bm.user_id AS user_id, bm.role AS role, u.x25519_pubkey AS x25519_pubkey \
         FROM branch_members bm JOIN users u ON u.id = bm.user_id \
         WHERE bm.branch_id = ? ORDER BY bm.user_id",
    )
    .bind(&branch_id)
    .fetch_all(&st.pool)
    .await?;

    let out = rows
        .iter()
        .map(|r| {
            let x: Vec<u8> = r.get("x25519_pubkey");
            MemberInfo {
                user_id: r.get("user_id"),
                role: parse_role(&r.get::<String, _>("role")),
                x25519_pubkey: STANDARD.encode(x),
            }
        })
        .collect();
    Ok(Json(out))
}

// ---- Wrapped-DEK maps ---------------------------------------------------------------------

/// `GET /orgs/:org/stores/:store/branches/:branch/keys` — `user_id -> [wrapped-DEK entries]`.
/// Requires >= reader.
pub async fn list_keys(
    State(st): State<AppState>,
    actor: Actor,
    Path((org, store, branch)): Path<(String, String, String)>,
) -> Result<Json<KeysMap>, ApiError> {
    let branch_id = authorize_branch(&st.pool, &org, &store, &branch, &actor, Role::Reader).await?;
    let rows = sqlx::query(
        "SELECT user_id, dek_version, sealed_box FROM wrapped_deks WHERE branch_id = ? \
         ORDER BY user_id, dek_version",
    )
    .bind(&branch_id)
    .fetch_all(&st.pool)
    .await?;

    let mut map: KeysMap = HashMap::new();
    for r in rows {
        let user_id: String = r.get("user_id");
        let dek_version: i64 = r.get("dek_version");
        let sealed_box: Vec<u8> = r.get("sealed_box");
        map.entry(user_id).or_default().push(WrappedDekEntry {
            dek_version: dek_version as u32,
            sealed_box: STANDARD.encode(sealed_box),
        });
    }
    Ok(Json(map))
}

/// `POST /orgs/:org/stores/:store/branches/:branch/keys` — grant/update one user's wrapped DEK.
/// Requires >= writer.
pub async fn grant_key(
    State(st): State<AppState>,
    actor: Actor,
    Path((org, store, branch)): Path<(String, String, String)>,
    Json(req): Json<GrantKeyRequest>,
) -> Result<StatusCode, ApiError> {
    let branch_id = authorize_branch(&st.pool, &org, &store, &branch, &actor, Role::Writer).await?;
    let sealed_box = STANDARD
        .decode(&req.sealed_box)
        .map_err(|_| ApiError::BadRequest("sealed_box not base64".into()))?;
    sqlx::query(
        "INSERT INTO wrapped_deks (branch_id, user_id, dek_version, sealed_box) VALUES (?, ?, ?, ?) \
         ON CONFLICT(branch_id, user_id, dek_version) DO UPDATE SET sealed_box = excluded.sealed_box",
    )
    .bind(&branch_id)
    .bind(&req.user_id)
    .bind(req.dek_version as i64)
    .bind(sealed_box)
    .execute(&st.pool)
    .await?;
    Ok(StatusCode::OK)
}

/// `POST /orgs/:org/stores/:store/branches/:branch/rotate` — atomic rotation. Requires **admin**
/// (rotation affects every member, so it is admin-level, not writer-level). Applies the new
/// object batch, the complete new wrapped-DEK map, and the active-DEK-version bump in ONE
/// transaction.
pub async fn rotate(
    State(st): State<AppState>,
    actor: Actor,
    Path((org, store, branch)): Path<(String, String, String)>,
    Json(req): Json<RotateRequest>,
) -> Result<StatusCode, ApiError> {
    let branch_id = authorize_branch(&st.pool, &org, &store, &branch, &actor, Role::Admin).await?;

    // Validate the whole batch before touching the DB, so a bad object fails cleanly (400)
    // without a partially-applied rotation.
    let mut objs = Vec::with_capacity(req.objects.len());
    for o in &req.objects {
        objs.push((o.hash.clone(), o.kind.clone(), decode_object(o)?));
    }
    let mut deks = Vec::with_capacity(req.wrapped_deks.len());
    for w in &req.wrapped_deks {
        let sealed_box = STANDARD
            .decode(&w.sealed_box)
            .map_err(|_| ApiError::BadRequest("sealed_box not base64".into()))?;
        deks.push((w.user_id.clone(), w.dek_version, sealed_box));
    }

    let now = now_unix();
    let mut tx = st.pool.begin().await?;
    for (hash, kind, body) in &objs {
        sqlx::query(
            "INSERT INTO objects (hash, kind, body, created_at) VALUES (?, ?, ?, ?) \
             ON CONFLICT(hash) DO NOTHING",
        )
        .bind(hash)
        .bind(kind)
        .bind(body)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }
    for (user_id, dek_version, sealed_box) in &deks {
        sqlx::query(
            "INSERT INTO wrapped_deks (branch_id, user_id, dek_version, sealed_box) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT(branch_id, user_id, dek_version) DO UPDATE SET sealed_box = excluded.sealed_box",
        )
        .bind(&branch_id)
        .bind(user_id)
        .bind(*dek_version as i64)
        .bind(sealed_box)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("UPDATE branches SET active_dek_version = ? WHERE id = ?")
        .bind(req.new_dek_version as i64)
        .bind(&branch_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::OK)
}

// ---- Membership (admin-only) ----------------------------------------------------------

/// `POST /orgs/:org/stores/:store/branches/:branch/members` — add/update a member's role.
/// Requires admin. Also auto-joins the target to the org (as a plain `member`, if they aren't
/// already an org member) in the same transaction — this is the mechanism for "sharing a branch
/// with someone adds them to the org": org membership on its own grants nothing, it's just a
/// side effect of being granted a branch, and `branch_members` stays the real authorization
/// boundary.
pub async fn add_member(
    State(st): State<AppState>,
    actor: Actor,
    Path((org, store, branch)): Path<(String, String, String)>,
    Json(req): Json<MemberRequest>,
) -> Result<StatusCode, ApiError> {
    let branch_id = authorize_branch(&st.pool, &org, &store, &branch, &actor, Role::Admin).await?;
    let org_id = resolve_org_id_for_store(&st.pool, &store, &branch_id).await?;

    let mut tx = st.pool.begin().await?;
    sqlx::query(
        "INSERT INTO org_members (org_id, user_id, role) VALUES (?, ?, 'member') \
         ON CONFLICT(org_id, user_id) DO NOTHING",
    )
    .bind(&org_id)
    .bind(&req.user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO branch_members (branch_id, user_id, role) VALUES (?, ?, ?) \
         ON CONFLICT(branch_id, user_id) DO UPDATE SET role = excluded.role",
    )
    .bind(&branch_id)
    .bind(&req.user_id)
    .bind(role_str(req.role))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(StatusCode::OK)
}

/// Resolve the org id a branch's store belongs to, given the branch id already validated by
/// `authorize_branch` (avoids re-parsing `org` — `authorize_branch` already proved `org` names
/// the right org for the given `store`/`branch`, but `add_member` still needs the org's id, not
/// just its name, to write `org_members`).
async fn resolve_org_id_for_store(pool: &SqlitePool, store: &str, branch_id: &str) -> Result<String, ApiError> {
    let row = sqlx::query(
        "SELECT s.org_id AS org_id FROM branches b JOIN stores s ON b.store_id = s.id \
         WHERE b.id = ? AND s.name = ?",
    )
    .bind(branch_id)
    .bind(store)
    .fetch_optional(pool)
    .await?
    .ok_or(ApiError::NotFound("store"))?;
    Ok(row.get("org_id"))
}

/// `DELETE /orgs/:org/stores/:store/branches/:branch/members/:user_id` — remove a member.
/// Requires admin. Does NOT trigger rotation (revocation rotation is a separate explicit call)
/// and does NOT remove the org membership (org membership may still be needed for other
/// branches/stores in the org).
pub async fn remove_member(
    State(st): State<AppState>,
    actor: Actor,
    Path((org, store, branch, user_id)): Path<(String, String, String, String)>,
) -> Result<StatusCode, ApiError> {
    let branch_id = authorize_branch(&st.pool, &org, &store, &branch, &actor, Role::Admin).await?;
    sqlx::query("DELETE FROM branch_members WHERE branch_id = ? AND user_id = ?")
        .bind(&branch_id)
        .bind(&user_id)
        .execute(&st.pool)
        .await?;
    Ok(StatusCode::OK)
}
