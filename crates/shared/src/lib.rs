//! Wire DTOs shared between `wonton-server` and the (future) `wonton-sync` HTTP client.
//!
//! This crate is **pure data**: serde `Serialize`/`Deserialize` structs describing the JSON
//! request/response shapes of the REST API. It has no logic, no
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

/// Metadata-level RBAC role within one environment. Ordering (for "at least"
/// checks) is enforced server-side, not encoded here — this stays pure data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Writer,
    Reader,
}

// ---------------------------------------------------------------------------------------
// Auth (challenge-response login + machine tokens)
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

/// `POST /auth/login/complete` response: a bearer token, its unix-seconds expiry, and the
/// server-assigned user id. The `user_id` lets the client look up its own wrapped-DEK entry in
/// `GET /envs/:store/:env/keys`'s response (a `KeysMap` keyed by user id).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginCompleteResponse {
    pub token: String,
    pub expires_at: i64,
    pub user_id: String,
}

/// `POST /auth/register` request. No authentication required — this *is* the auth bootstrap
/// (like any signup endpoint). The caller must have already run `wonton_crypto::generate_identity`
/// locally; this route just persists the public identity + opaque wrapped private key blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    /// base64 of the 32-byte Ed25519 public key.
    pub ed25519_pubkey: String,
    /// base64 of the 32-byte X25519 public key.
    pub x25519_pubkey: String,
    /// base64 of the `WrappedPrivateKey` ciphertext blob (opaque to the server).
    pub wrapped_privkey: String,
    pub argon2_params: Argon2ParamsDto,
    /// Optional single-use ticket minted by a completed `/auth/oauth/{provider}/callback`
    /// exchange, proving this registration is by someone who verified a real email with that
    /// provider. Omit for the plain (unverified) registration path, which still works exactly
    /// as before — this is an additional gate, not a replacement. Never a passphrase or key.
    #[serde(default)]
    pub oauth_ticket: Option<String>,
}

/// `POST /auth/register` response: the server-assigned user id (UUID).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub user_id: String,
}

/// `POST /auth/machine/token` request (CI/server identities).
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
// Orgs / stores (repos) / branches
// ---------------------------------------------------------------------------------------

/// `POST /orgs` request: create a new org. Any authenticated user may create one; the creator
/// becomes its first `owner` member (the access-control bootstrap, same pattern as branch
/// creation making its creator an admin).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOrgRequest {
    pub name: String,
}

/// `POST /orgs` response: the server-assigned org id (UUID).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOrgResponse {
    pub org_id: String,
}

/// One entry of `GET /orgs/:org/stores/:store/branches`: a branch the caller can see and their
/// role on it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchSummary {
    pub name: String,
    pub role: Role,
}

/// `POST /orgs/:org/stores` request: create a new store (repo) within an org. Requires the
/// caller to already be a member of `org` (any role) — there is no store-level ownership beyond
/// that; access control is per-branch via `branch_members`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateStoreRequest {
    pub name: String,
}

/// `POST /orgs/:org/stores` response: the server-assigned store id (UUID).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateStoreResponse {
    pub store_id: String,
}

/// `POST /orgs/:org/stores/:store/branches` request: create a new branch within a store. The
/// creating actor is made an `admin` member of the new branch in the same transaction (the
/// access-control bootstrap — a branch is its own DEK/ACL boundary, same role a fresh
/// environment's first admin used to play).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateBranchRequest {
    pub name: String,
}

/// `POST /orgs/:org/stores/:store/branches` response: the server-assigned branch id (UUID).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateBranchResponse {
    pub branch_id: String,
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
// Ref (one tip per branch, CAS-moved — a branch no longer contains named sub-branches, so
// there's exactly one ref per branch instead of a `branch_name -> commit_hash` map)
// ---------------------------------------------------------------------------------------

/// `GET /orgs/:org/stores/:store/branches/:branch/ref` response: the branch's current tip
/// commit hash (hex), or `None` if it has never been pushed to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefResponse {
    pub commit_hash: Option<String>,
}

/// `POST /orgs/:org/stores/:store/branches/:branch/ref` request. `old_hash: None` means
/// "create — must not currently exist"; `Some` means "move only if the ref currently equals
/// this hash".
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
// Wrapped-DEK maps (the crypto access boundary)
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

// ---------------------------------------------------------------------------------------
// Directory / lookup responses (Phase 5a: needed by `share` / `revoke` / `key rotate`)
// ---------------------------------------------------------------------------------------

/// `GET /users/:username` response: a user's public identity keys. Everything here is
/// non-secret (public keys + a server-assigned id); it is what `share` needs to wrap a DEK for
/// a target and what a client uses to resolve a username to a user id before granting/revoking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPublicInfo {
    pub user_id: String,
    /// The server-facing login handle. Not secret — same trust level as the public keys below;
    /// lets a client show a real name (`wonton log`) instead of a raw `author_id` UUID.
    pub username: String,
    /// base64 of the 32-byte Ed25519 public key.
    pub ed25519_pubkey: String,
    /// base64 of the 32-byte X25519 public key.
    pub x25519_pubkey: String,
}

/// One entry of `GET /orgs/:org/stores/:store/branches/:branch/members` response: a member's id,
/// role, and the X25519 public key needed to re-wrap a rotated DEK for them (`key rotate`
/// re-wraps for every member).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberInfo {
    pub user_id: String,
    pub role: Role,
    /// base64 of the member's 32-byte X25519 public key.
    pub x25519_pubkey: String,
}

/// `GET /orgs/:org/stores/:store/branches/:branch` response: branch metadata a client needs to
/// grant/rotate at the correct version. `active_dek_version` is tracked server-side
/// (`branches.active_dek_version`) and never otherwise exposed; `share` grants at it, `rotate`
/// advances it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchDetails {
    pub branch_id: String,
    pub active_dek_version: u32,
}
