//! Wire DTOs shared between `wonton-server` and the (future) `wonton-sync` HTTP client.
//!
//! This crate is **pure data**: serde `Serialize`/`Deserialize` structs describing the JSON
//! request/response shapes of the REST API in `PROGRESS.md` §3.4. It has no logic, no
//! database access, and no HTTP-framework dependency, so both sides of the wire can depend on
//! exactly the same types instead of hand-duplicating them.
//!
//! ## Encoding conventions (important for anyone constructing these by hand)
//! - **Content hashes** (`ObjectUploadRequest::hash`, ref commit hashes) are lowercase hex of
//!   a BLAKE2b-256 digest — the same 64-char form `wonton_objects::Hash` uses.
//! - **All other binary fields** (object bodies, sealed boxes, wrapped private keys, public
//!   keys, nonces, signatures, salts) are **standard base64** (with padding). The client is
//!   responsible for encoding/decoding; the server treats every one of them as opaque bytes.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Metadata-level RBAC role within one environment (PLAN.md §10). Ordering (for "at least"
/// checks) is enforced server-side, not encoded here — this stays pure data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Writer,
    Reader,
}

// ---------------------------------------------------------------------------------------
// Auth (challenge-response login + machine tokens) — PROGRESS.md §3.4
// ---------------------------------------------------------------------------------------

/// `POST /auth/login/start` request. No authentication required for this step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginStartRequest {
    pub username: String,
}

/// Argon2id parameters needed for the client to re-derive its unlock key. Mirrors
/// `wonton_crypto::Argon2Params` on the wire without depending on `wonton-crypto`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2ParamsDto {
    /// base64 of the 16-byte salt.
    pub salt: String,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

/// `POST /auth/login/start` response. Everything here is non-secret: the wrapped private key
/// is useless without the passphrase, and the nonce is a public random challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginStartResponse {
    /// base64 of the `WrappedPrivateKey` ciphertext blob.
    pub wrapped_privkey: String,
    pub argon2_params: Argon2ParamsDto,
    /// base64 of the random challenge nonce the client must sign.
    pub challenge_nonce: String,
}

/// `POST /auth/login/complete` request. The client unlocks its Ed25519 key locally and signs
/// the `challenge_nonce` bytes it received from `/auth/login/start`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginCompleteRequest {
    pub username: String,
    /// base64, echoes the nonce from the matching `/auth/login/start`.
    pub challenge_nonce: String,
    /// base64 of the 64-byte Ed25519 signature over the raw nonce bytes.
    pub signature: String,
}

/// `POST /auth/login/complete` response: a bearer token and its unix-seconds expiry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginCompleteResponse {
    pub token: String,
    pub expires_at: i64,
}

/// `POST /auth/machine/token` request (CI/server identities, §10).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineTokenRequest {
    pub label: String,
    /// base64 of the machine's 32-byte Ed25519 public key.
    pub ed25519_pubkey: String,
    /// base64 of the machine's 32-byte X25519 public key.
    pub x25519_pubkey: String,
    pub requested_ttl_seconds: i64,
}

/// `POST /auth/machine/token` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineTokenResponse {
    pub token: String,
    pub expires_at: i64,
}

// ---------------------------------------------------------------------------------------
// Stores / environments
// ---------------------------------------------------------------------------------------

/// One entry of `GET /stores/:store/envs`: an environment the caller can see and their role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvSummary {
    pub name: String,
    pub role: Role,
}

// ---------------------------------------------------------------------------------------
// Objects
// ---------------------------------------------------------------------------------------

/// `POST /objects` request. `hash` is hex BLAKE2b-256; the server recomputes it over the
/// decoded `body` and rejects a mismatch with 400.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectUploadRequest {
    /// hex BLAKE2b-256 of the decoded `body`.
    pub hash: String,
    /// `"blob"` | `"tree"` | `"commit"`.
    pub kind: String,
    /// base64 of the opaque object bytes.
    pub body: String,
}

// ---------------------------------------------------------------------------------------
// Refs (branch pointers, CAS-moved)
// ---------------------------------------------------------------------------------------

/// `GET /refs/:store/:env` response: `branch_name -> commit_hash` (hex).
pub type RefMap = HashMap<String, String>;

/// `POST /refs/:store/:env/:branch` request. `old_hash: None` means "create — must not
/// currently exist"; `Some` means "move only if the ref currently equals this hash".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefMoveRequest {
    pub old_hash: Option<String>,
    pub new_hash: String,
}

/// 409 body for a failed CAS ref move: the ref's actual current value (or `None` if it does
/// not currently exist), so the caller can reconcile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefConflict {
    pub current: Option<String>,
}

// ---------------------------------------------------------------------------------------
// Wrapped-DEK maps (the crypto access boundary, §4.2/§4.4)
// ---------------------------------------------------------------------------------------

/// One wrapped-DEK entry for a user in an environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedDekEntry {
    pub dek_version: u32,
    /// base64 of the `crypto_box` sealed box wrapping the DEK for the user's X25519 pubkey.
    pub sealed_box: String,
}

/// `GET /envs/:store/:env/keys` response: `user_id -> [wrapped-DEK entries]` (a user may have
/// entries for multiple DEK versions after a rotation).
pub type KeysMap = HashMap<String, Vec<WrappedDekEntry>>;

/// `POST /envs/:store/:env/keys` request: grant/update one user's wrapped DEK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantKeyRequest {
    pub user_id: String,
    pub dek_version: u32,
    /// base64 of the sealed box.
    pub sealed_box: String,
}

/// `POST /envs/:store/:env/rotate` request: an atomic rotation batch — the freshly
/// re-encrypted objects, the complete new wrapped-DEK map, and the new active DEK version.
/// The server applies all of it in one transaction (all-or-nothing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateRequest {
    pub new_dek_version: u32,
    pub objects: Vec<ObjectUploadRequest>,
    pub wrapped_deks: Vec<GrantKeyRequest>,
}

// ---------------------------------------------------------------------------------------
// Membership (admin-only)
// ---------------------------------------------------------------------------------------

/// `POST /envs/:store/:env/members` request: add or update a member's role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberRequest {
    pub user_id: String,
    pub role: Role,
}
