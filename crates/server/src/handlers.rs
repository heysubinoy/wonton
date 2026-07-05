//! Axum request handlers for every route in `PROGRESS.md` §3.4.
//!
//! Every handler except the three `/auth/*` routes takes an `Actor` extractor, which enforces
//! a valid bearer token (401 otherwise). Role-gated handlers additionally call
//! `authorize_env`, which yields 404 if the env doesn't exist and 403 if the actor's role is
//! insufficient — so a caller can tell "who are you" (401) from "not allowed" (403) from
//! "no such env" (404).

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
    Argon2ParamsDto, EnvSummary, GrantKeyRequest, KeysMap, LoginCompleteRequest,
    LoginCompleteResponse, LoginStartRequest, LoginStartResponse, MachineTokenRequest,
    MachineTokenResponse, MemberRequest, ObjectUploadRequest, RefConflict, RefMap,
    RefMoveRequest, Role, RotateRequest, WrappedDekEntry,
};

use crate::auth::{hash_token, mint_nonce, mint_token};
use crate::error::ApiError;
use crate::{authorize_env, now_unix, parse_role, role_str, Actor, AppState};

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
    }))
}

/// `POST /auth/machine/token` — no auth for this phase (hardening gap, see PROGRESS.md).
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

// ---- Stores / environments ------------------------------------------------------------

/// `GET /stores/:store/envs` — environments the caller is a member of, with their role.
pub async fn list_envs(
    State(st): State<AppState>,
    actor: Actor,
    Path(store): Path<String>,
) -> Result<Json<Vec<EnvSummary>>, ApiError> {
    let rows = sqlx::query(
        "SELECT e.name AS name, m.role AS role \
         FROM environments e \
         JOIN stores s ON e.store_id = s.id \
         JOIN env_members m ON m.env_id = e.id \
         WHERE s.name = ? AND m.user_id = ? \
         ORDER BY e.name",
    )
    .bind(&store)
    .bind(&actor.id)
    .fetch_all(&st.pool)
    .await?;

    let out = rows
        .iter()
        .map(|r| EnvSummary {
            name: r.get("name"),
            role: parse_role(&r.get::<String, _>("role")),
        })
        .collect();
    Ok(Json(out))
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

// ---- Refs -----------------------------------------------------------------------------

/// `GET /refs/:store/:env` — `branch_name -> commit_hash`. Requires >= reader.
pub async fn list_refs(
    State(st): State<AppState>,
    actor: Actor,
    Path((store, env)): Path<(String, String)>,
) -> Result<Json<RefMap>, ApiError> {
    let env_id = authorize_env(&st.pool, &store, &env, &actor, Role::Reader).await?;
    let rows = sqlx::query("SELECT branch_name, commit_hash FROM refs WHERE env_id = ?")
        .bind(&env_id)
        .fetch_all(&st.pool)
        .await?;
    let map = rows
        .iter()
        .map(|r| {
            (
                r.get::<String, _>("branch_name"),
                r.get::<String, _>("commit_hash"),
            )
        })
        .collect();
    Ok(Json(map))
}

/// `POST /refs/:store/:env/:branch` — compare-and-swap ref move. Requires >= writer.
///
/// `old_hash: None` creates the branch (must not already exist); `Some(h)` moves it only if it
/// currently equals `h`. On any mismatch, 409 with the actual current value. The CAS is a
/// single atomic SQL statement (`INSERT ... ON CONFLICT DO NOTHING` for create, guarded
/// `UPDATE` for move), so two racing callers can never both win — see the concurrency test.
pub async fn move_ref(
    State(st): State<AppState>,
    actor: Actor,
    Path((store, env, branch)): Path<(String, String, String)>,
    Json(req): Json<RefMoveRequest>,
) -> Result<Response, ApiError> {
    let env_id = authorize_env(&st.pool, &store, &env, &actor, Role::Writer).await?;
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
                "INSERT INTO refs (env_id, branch_name, commit_hash) VALUES (?, ?, ?) \
                 ON CONFLICT(env_id, branch_name) DO NOTHING",
            )
            .bind(&env_id)
            .bind(&branch)
            .bind(&req.new_hash)
            .execute(&st.pool)
            .await?
            .rows_affected()
        }
        Some(old) => {
            sqlx::query(
                "UPDATE refs SET commit_hash = ? \
                 WHERE env_id = ? AND branch_name = ? AND commit_hash = ?",
            )
            .bind(&req.new_hash)
            .bind(&env_id)
            .bind(&branch)
            .bind(old)
            .execute(&st.pool)
            .await?
            .rows_affected()
        }
    };

    if affected == 1 {
        Ok(StatusCode::OK.into_response())
    } else {
        let current = current_ref(&st.pool, &env_id, &branch).await?;
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

async fn current_ref(
    pool: &SqlitePool,
    env_id: &str,
    branch: &str,
) -> Result<Option<String>, ApiError> {
    let row = sqlx::query("SELECT commit_hash FROM refs WHERE env_id = ? AND branch_name = ?")
        .bind(env_id)
        .bind(branch)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.get::<String, _>("commit_hash")))
}

// ---- Wrapped-DEK maps -----------------------------------------------------------------

/// `GET /envs/:store/:env/keys` — `user_id -> [wrapped-DEK entries]`. Requires >= reader.
pub async fn list_keys(
    State(st): State<AppState>,
    actor: Actor,
    Path((store, env)): Path<(String, String)>,
) -> Result<Json<KeysMap>, ApiError> {
    let env_id = authorize_env(&st.pool, &store, &env, &actor, Role::Reader).await?;
    let rows = sqlx::query(
        "SELECT user_id, dek_version, sealed_box FROM wrapped_deks WHERE env_id = ? \
         ORDER BY user_id, dek_version",
    )
    .bind(&env_id)
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

/// `POST /envs/:store/:env/keys` — grant/update one user's wrapped DEK. Requires >= writer.
pub async fn grant_key(
    State(st): State<AppState>,
    actor: Actor,
    Path((store, env)): Path<(String, String)>,
    Json(req): Json<GrantKeyRequest>,
) -> Result<StatusCode, ApiError> {
    let env_id = authorize_env(&st.pool, &store, &env, &actor, Role::Writer).await?;
    let sealed_box = STANDARD
        .decode(&req.sealed_box)
        .map_err(|_| ApiError::BadRequest("sealed_box not base64".into()))?;
    sqlx::query(
        "INSERT INTO wrapped_deks (env_id, user_id, dek_version, sealed_box) VALUES (?, ?, ?, ?) \
         ON CONFLICT(env_id, user_id, dek_version) DO UPDATE SET sealed_box = excluded.sealed_box",
    )
    .bind(&env_id)
    .bind(&req.user_id)
    .bind(req.dek_version as i64)
    .bind(sealed_box)
    .execute(&st.pool)
    .await?;
    Ok(StatusCode::OK)
}

/// `POST /envs/:store/:env/rotate` — atomic rotation. Requires **admin** (rotation affects
/// every member, so it is admin-level, not writer-level). Applies the new object batch, the
/// complete new wrapped-DEK map, and the active-DEK-version bump in ONE transaction.
pub async fn rotate(
    State(st): State<AppState>,
    actor: Actor,
    Path((store, env)): Path<(String, String)>,
    Json(req): Json<RotateRequest>,
) -> Result<StatusCode, ApiError> {
    let env_id = authorize_env(&st.pool, &store, &env, &actor, Role::Admin).await?;

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
            "INSERT INTO wrapped_deks (env_id, user_id, dek_version, sealed_box) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT(env_id, user_id, dek_version) DO UPDATE SET sealed_box = excluded.sealed_box",
        )
        .bind(&env_id)
        .bind(user_id)
        .bind(*dek_version as i64)
        .bind(sealed_box)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("UPDATE environments SET active_dek_version = ? WHERE id = ?")
        .bind(req.new_dek_version as i64)
        .bind(&env_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::OK)
}

// ---- Membership (admin-only) ----------------------------------------------------------

/// `POST /envs/:store/:env/members` — add/update a member's role. Requires admin.
pub async fn add_member(
    State(st): State<AppState>,
    actor: Actor,
    Path((store, env)): Path<(String, String)>,
    Json(req): Json<MemberRequest>,
) -> Result<StatusCode, ApiError> {
    let env_id = authorize_env(&st.pool, &store, &env, &actor, Role::Admin).await?;
    sqlx::query(
        "INSERT INTO env_members (env_id, user_id, role) VALUES (?, ?, ?) \
         ON CONFLICT(env_id, user_id) DO UPDATE SET role = excluded.role",
    )
    .bind(&env_id)
    .bind(&req.user_id)
    .bind(role_str(req.role))
    .execute(&st.pool)
    .await?;
    Ok(StatusCode::OK)
}

/// `DELETE /envs/:store/:env/members/:user_id` — remove a member. Requires admin. Does NOT
/// trigger rotation (per PLAN.md §4.4, revocation rotation is a separate explicit call).
pub async fn remove_member(
    State(st): State<AppState>,
    actor: Actor,
    Path((store, env, user_id)): Path<(String, String, String)>,
) -> Result<StatusCode, ApiError> {
    let env_id = authorize_env(&st.pool, &store, &env, &actor, Role::Admin).await?;
    sqlx::query("DELETE FROM env_members WHERE env_id = ? AND user_id = ?")
        .bind(&env_id)
        .bind(&user_id)
        .execute(&st.pool)
        .await?;
    Ok(StatusCode::OK)
}
