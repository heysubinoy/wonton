//! [`SyncClient`] — a thin, typed REST client over the `wonton-server` API (`PROGRESS.md`
//! §3.4). One method per route, using the exact `wonton_shared` wire DTOs. Every non-success
//! status is mapped to a [`SyncError`] variant (parsing the `{"error": ...}` body for a
//! message when present).
//!
//! The only method that does more than transport is [`SyncClient::fetch_object`], which
//! verifies the returned bytes hash to the requested [`Hash`] before handing them back — the
//! transport-layer half of PLAN.md §9's "every pulled object is verified before use."

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use serde::de::DeserializeOwned;
use wonton_objects::Hash;
use wonton_shared::{
    CreateEnvRequest, CreateEnvResponse, CreateStoreRequest, CreateStoreResponse, EnvSummary,
    GrantKeyRequest, KeysMap, LoginCompleteRequest, LoginCompleteResponse, LoginStartRequest,
    LoginStartResponse, MachineTokenRequest, MachineTokenResponse, MemberRequest,
    ObjectUploadRequest, RefConflict, RefMap, RefMoveRequest, RegisterRequest, RegisterResponse,
    RotateRequest,
};

use crate::error::SyncError;

/// A stateful HTTP client for one `wonton-server`. Holds a base URL and an optional bearer
/// token; call [`SyncClient::set_token`] after a successful login to authenticate subsequent
/// calls. Cheap to construct; wraps a connection-pooling [`reqwest::Client`].
pub struct SyncClient {
    http: Client,
    base_url: String,
    token: Option<String>,
}

impl SyncClient {
    /// Build a client for `base_url` (e.g. `https://wonton.example.com`) with a fresh
    /// [`reqwest::Client`] and no token.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_http(Client::new(), base_url)
    }

    /// Build a client reusing a caller-provided [`reqwest::Client`] (e.g. one configured with
    /// custom timeouts or a proxy). Trailing slashes on `base_url` are trimmed so route
    /// concatenation is unambiguous.
    pub fn with_http(http: Client, base_url: impl Into<String>) -> Self {
        let mut base = base_url.into();
        while base.ends_with('/') {
            base.pop();
        }
        Self {
            http,
            base_url: base,
            token: None,
        }
    }

    /// Set the bearer token used for all authenticated routes (typically the token returned by
    /// [`SyncClient::login_complete`] or [`SyncClient::machine_token`]).
    pub fn set_token(&mut self, token: impl Into<String>) {
        self.token = Some(token.into());
    }

    /// Drop the current bearer token (subsequent authenticated calls will get 401).
    pub fn clear_token(&mut self) {
        self.token = None;
    }

    /// The current bearer token, if any.
    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Attach the bearer token to a request if one is set.
    fn authed(&self, rb: RequestBuilder) -> RequestBuilder {
        match &self.token {
            Some(t) => rb.bearer_auth(t),
            None => rb,
        }
    }

    // ---- Auth (no token required) -----------------------------------------------------

    /// `POST /auth/register`. No authentication — this *is* the auth bootstrap (like any signup
    /// endpoint). The caller must have already run `wonton_crypto::generate_identity` locally and
    /// filled `req` with the public keys + opaque wrapped-privkey blob; this method only
    /// transports them. Returns the server-assigned user id. 409 if the username is taken.
    pub async fn register(&self, req: &RegisterRequest) -> Result<RegisterResponse, SyncError> {
        let resp = self
            .http
            .post(self.url("/auth/register"))
            .json(req)
            .send()
            .await?;
        json_response(resp).await
    }

    /// `POST /auth/login/start`. Returns the (ciphertext) wrapped private key, Argon2id params,
    /// and a challenge nonce. All non-secret. 404 if the username is unknown.
    pub async fn login_start(
        &self,
        req: &LoginStartRequest,
    ) -> Result<LoginStartResponse, SyncError> {
        let resp = self
            .http
            .post(self.url("/auth/login/start"))
            .json(req)
            .send()
            .await?;
        json_response(resp).await
    }

    /// `POST /auth/login/complete`. `req.signature` must already be a base64-encoded Ed25519
    /// signature over the *raw decoded* `challenge_nonce` bytes — this client never signs
    /// anything itself (it has no `wonton-crypto` dependency); the caller computes it
    /// externally and this method just transports it. 401 on a bad/expired/consumed challenge.
    pub async fn login_complete(
        &self,
        req: &LoginCompleteRequest,
    ) -> Result<LoginCompleteResponse, SyncError> {
        let resp = self
            .http
            .post(self.url("/auth/login/complete"))
            .json(req)
            .send()
            .await?;
        json_response(resp).await
    }

    /// `POST /auth/machine/token`. Issues a short-lived machine bearer token.
    pub async fn machine_token(
        &self,
        req: &MachineTokenRequest,
    ) -> Result<MachineTokenResponse, SyncError> {
        let resp = self
            .http
            .post(self.url("/auth/machine/token"))
            .json(req)
            .send()
            .await?;
        json_response(resp).await
    }

    // ---- Stores / environments --------------------------------------------------------

    /// `GET /stores/{store}/envs`. Environments the caller is a member of, with their role.
    pub async fn list_envs(&self, store: &str) -> Result<Vec<EnvSummary>, SyncError> {
        let resp = self
            .authed(self.http.get(self.url(&format!("/stores/{store}/envs"))))
            .send()
            .await?;
        json_response(resp).await
    }

    /// `POST /stores`. Create a store. Requires any valid token (no store-level ownership in the
    /// schema — access control is per-environment via `env_members`). 409 on a duplicate name.
    pub async fn create_store(
        &self,
        req: &CreateStoreRequest,
    ) -> Result<CreateStoreResponse, SyncError> {
        let resp = self
            .authed(self.http.post(self.url("/stores")).json(req))
            .send()
            .await?;
        json_response(resp).await
    }

    /// `POST /stores/{store}/envs`. Create an environment inside a store; the creating actor is
    /// made its first `admin` member server-side. Requires any valid token. 404 if the store is
    /// unknown, 409 if the env name already exists in that store.
    pub async fn create_env(
        &self,
        store: &str,
        req: &CreateEnvRequest,
    ) -> Result<CreateEnvResponse, SyncError> {
        let resp = self
            .authed(
                self.http
                    .post(self.url(&format!("/stores/{store}/envs")))
                    .json(req),
            )
            .send()
            .await?;
        json_response(resp).await
    }

    // ---- Objects ----------------------------------------------------------------------

    /// `GET /objects/{hash}`. Fetch an object by its (hex) content hash **and verify** the
    /// returned bytes hash back to `hash` before returning them.
    ///
    /// This integrity check is the point of this method: a malicious or buggy server that
    /// returns bytes not matching the requested hash is rejected with
    /// [`SyncError::IntegrityMismatch`], never silently accepted — even though a caller that
    /// immediately `put`s the result into a `LocalObjectStore` would get a second, independent
    /// check there (the store re-verifies on `put`). A caller that merely inspects the bytes
    /// without storing them still gets the guarantee here.
    pub async fn fetch_object(&self, hash: &Hash) -> Result<Vec<u8>, SyncError> {
        let resp = self
            .authed(
                self.http
                    .get(self.url(&format!("/objects/{}", hash.to_hex()))),
            )
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(into_error(resp).await);
        }
        let bytes = resp.bytes().await?.to_vec();
        let actual = Hash::of(&bytes);
        if actual != *hash {
            return Err(SyncError::IntegrityMismatch {
                requested: hash.to_hex(),
                actual: actual.to_hex(),
            });
        }
        Ok(bytes)
    }

    /// `POST /objects`. Upload an object. `kind` is `"blob"` | `"tree"` | `"commit"`; the body
    /// is base64-encoded on the wire. Idempotent server-side: re-uploading the same `(hash,
    /// body)` is a success, not an error.
    pub async fn upload_object(
        &self,
        hash: &Hash,
        kind: &str,
        body: &[u8],
    ) -> Result<(), SyncError> {
        let req = ObjectUploadRequest {
            hash: hash.to_hex(),
            kind: kind.to_string(),
            body: STANDARD.encode(body),
        };
        let resp = self
            .authed(self.http.post(self.url("/objects")).json(&req))
            .send()
            .await?;
        ok_response(resp).await
    }

    // ---- Refs -------------------------------------------------------------------------

    /// `GET /refs/{store}/{env}`. `branch_name -> commit_hash` (hex). Requires >= reader.
    pub async fn get_refs(&self, store: &str, env: &str) -> Result<RefMap, SyncError> {
        let resp = self
            .authed(self.http.get(self.url(&format!("/refs/{store}/{env}"))))
            .send()
            .await?;
        json_response(resp).await
    }

    /// `POST /refs/{store}/{env}/{branch}`. Compare-and-swap ref move. Requires >= writer.
    /// `old_hash: None` means "create — must not currently exist"; `Some` means "move only if
    /// the ref currently equals this". A losing CAS is surfaced as [`SyncError::Conflict`]
    /// carrying the ref's actual current value.
    pub async fn move_ref(
        &self,
        store: &str,
        env: &str,
        branch: &str,
        old_hash: Option<&Hash>,
        new_hash: &Hash,
    ) -> Result<(), SyncError> {
        let req = RefMoveRequest {
            old_hash: old_hash.map(Hash::to_hex),
            new_hash: new_hash.to_hex(),
        };
        let resp = self
            .authed(
                self.http
                    .post(self.url(&format!("/refs/{store}/{env}/{branch}")))
                    .json(&req),
            )
            .send()
            .await?;
        if resp.status() == StatusCode::CONFLICT {
            let conflict: RefConflict = resp.json().await?;
            return Err(SyncError::Conflict(conflict));
        }
        ok_response(resp).await
    }

    // ---- Wrapped-DEK maps / membership ------------------------------------------------

    /// `GET /envs/{store}/{env}/keys`. `user_id -> [wrapped-DEK entries]`. Requires >= reader.
    pub async fn list_keys(&self, store: &str, env: &str) -> Result<KeysMap, SyncError> {
        let resp = self
            .authed(
                self.http
                    .get(self.url(&format!("/envs/{store}/{env}/keys"))),
            )
            .send()
            .await?;
        json_response(resp).await
    }

    /// `POST /envs/{store}/{env}/keys`. Grant/update one user's wrapped DEK. Requires >= writer.
    pub async fn grant_key(
        &self,
        store: &str,
        env: &str,
        req: &GrantKeyRequest,
    ) -> Result<(), SyncError> {
        let resp = self
            .authed(
                self.http
                    .post(self.url(&format!("/envs/{store}/{env}/keys")))
                    .json(req),
            )
            .send()
            .await?;
        ok_response(resp).await
    }

    /// `POST /envs/{store}/{env}/rotate`. Atomic rotation batch. Requires admin.
    pub async fn rotate(
        &self,
        store: &str,
        env: &str,
        req: &RotateRequest,
    ) -> Result<(), SyncError> {
        let resp = self
            .authed(
                self.http
                    .post(self.url(&format!("/envs/{store}/{env}/rotate")))
                    .json(req),
            )
            .send()
            .await?;
        ok_response(resp).await
    }

    /// `POST /envs/{store}/{env}/members`. Add/update a member's role. Requires admin.
    pub async fn add_member(
        &self,
        store: &str,
        env: &str,
        req: &MemberRequest,
    ) -> Result<(), SyncError> {
        let resp = self
            .authed(
                self.http
                    .post(self.url(&format!("/envs/{store}/{env}/members")))
                    .json(req),
            )
            .send()
            .await?;
        ok_response(resp).await
    }

    /// `DELETE /envs/{store}/{env}/members/{user_id}`. Remove a member. Requires admin.
    pub async fn remove_member(
        &self,
        store: &str,
        env: &str,
        user_id: &str,
    ) -> Result<(), SyncError> {
        let resp = self
            .authed(self.http.delete(self.url(&format!(
                "/envs/{store}/{env}/members/{user_id}"
            ))))
            .send()
            .await?;
        ok_response(resp).await
    }
}

// ---- shared status-code mapping -------------------------------------------------------

/// Deserialize a success body, or map a non-success status to a [`SyncError`].
async fn json_response<T: DeserializeOwned>(resp: Response) -> Result<T, SyncError> {
    if resp.status().is_success() {
        Ok(resp.json::<T>().await?)
    } else {
        Err(into_error(resp).await)
    }
}

/// Treat any success status as `Ok(())`; map a non-success status to a [`SyncError`].
async fn ok_response(resp: Response) -> Result<(), SyncError> {
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(into_error(resp).await)
    }
}

/// Map a non-success response to the matching [`SyncError`], parsing its `{"error": ...}` body
/// for a human-readable message. (409 is handled by `move_ref` directly and never reaches here.)
async fn into_error(resp: Response) -> SyncError {
    let status = resp.status();
    let msg = error_message(resp).await;
    match status {
        StatusCode::UNAUTHORIZED => SyncError::Unauthorized,
        StatusCode::FORBIDDEN => SyncError::Forbidden,
        StatusCode::NOT_FOUND => SyncError::NotFound(msg),
        StatusCode::BAD_REQUEST => SyncError::BadRequest(msg),
        other => SyncError::ServerError(other, msg),
    }
}

/// Best-effort extraction of the server's `{"error": "<message>"}` body. Falls back to the raw
/// body text, then to the transport error string, so a message is always available.
async fn error_message(resp: Response) -> String {
    #[derive(serde::Deserialize)]
    struct ErrBody {
        error: String,
    }
    match resp.text().await {
        Ok(body) => serde_json::from_str::<ErrBody>(&body)
            .map(|e| e.error)
            .unwrap_or(body),
        Err(e) => e.to_string(),
    }
}
