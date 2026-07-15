//! OAuth registration gate: a provider trait, a real Google implementation, and the
//! `OAuthProviders` registry the router looks providers up in by name.
//!
//! This module exists to answer one question — *"does this browser really control this
//! email?"* — before `POST /auth/register` is allowed to create a user row claiming it. It has
//! nothing to do with the zero-knowledge crypto identity: the Ed25519/X25519 keys and the
//! Argon2id-wrapped private key are generated and encrypted entirely client-side, exactly as
//! they are for a plain (non-OAuth) registration. See `handlers::register`'s doc comment for how
//! the two paths converge.

use std::collections::HashMap;
use std::sync::Arc;

use serde::Deserialize;

use crate::error::ApiError;

/// A verified identity handed back by a completed OAuth exchange. Only ever an email + a
/// provider-stable subject id — never anything resembling key material.
#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    pub subject: String,
    pub email: String,
}

/// One OAuth provider's authorize-URL construction + code-exchange-and-verify logic. A trait so
/// a second provider (GitHub, Microsoft, ...) is a small additional impl, not a rewrite, and so
/// tests can register a [`MockProvider`] instead of making a real network call.
#[async_trait::async_trait]
pub trait OAuthProvider: Send + Sync {
    /// The provider's name as it appears in the `/auth/oauth/{provider}/...` route and the
    /// `oauth_verifications.provider` / `users.oauth_provider` columns.
    fn name(&self) -> &'static str;

    /// Build the URL to redirect the browser to for the provider's consent screen.
    fn authorize_url(&self, state: &str) -> String;

    /// Exchange an authorization code for a verified identity — does the code-for-token network
    /// round-trip and the token's signature verification itself.
    async fn exchange_code(&self, code: &str) -> Result<VerifiedIdentity, ApiError>;
}

/// The set of OAuth providers this server has configured, keyed by [`OAuthProvider::name`].
/// Empty by default (`OAuthProviders::none()`) — every existing caller of
/// [`crate::build_router`] keeps working unchanged; only a caller that explicitly opts in via
/// [`crate::build_router_with_oauth`] gets `/auth/oauth/*` routes that resolve to anything.
#[derive(Clone, Default)]
pub struct OAuthProviders(HashMap<&'static str, Arc<dyn OAuthProvider>>);

impl OAuthProviders {
    pub fn none() -> Self {
        Self::default()
    }

    pub fn register(mut self, provider: impl OAuthProvider + 'static) -> Self {
        self.0.insert(provider.name(), Arc::new(provider));
        self
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn OAuthProvider>> {
        self.0.get(name).cloned()
    }

    /// Whether any provider is configured — the signal `handlers::register`/`auth_config` use
    /// to decide whether this server is in "hosted mode" (web verification required for new
    /// accounts) or "local mode" (open registration, exactly as before OAuth existed).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Any one configured provider's name, for building `AuthConfigResponse::verification_uri`.
    /// Only Google exists today, so "any one" is unambiguous; a second provider would need the
    /// dashboard to offer a picker rather than this picking arbitrarily — out of scope here.
    pub fn first_name(&self) -> Option<&'static str> {
        self.0.keys().next().copied()
    }
}

/// Google's OAuth 2.0 / OpenID Connect implementation. Configured from
/// `WONTON_GOOGLE_CLIENT_ID` / `WONTON_GOOGLE_CLIENT_SECRET` / `WONTON_GOOGLE_REDIRECT_URI` (see
/// [`GoogleProvider::from_env`]) — a self-hosted deployment that doesn't set these simply never
/// registers this provider, and `/auth/oauth/google/*` 404s, exactly like an unconfigured route.
pub struct GoogleProvider {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    http: reqwest::Client,
}

impl GoogleProvider {
    /// `None` if any of the three required env vars is unset — the caller (the `wonton-server`
    /// binary) treats that as "Google isn't configured" rather than an error.
    pub fn from_env() -> Option<Self> {
        let client_id = std::env::var("WONTON_GOOGLE_CLIENT_ID").ok()?;
        let client_secret = std::env::var("WONTON_GOOGLE_CLIENT_SECRET").ok()?;
        let redirect_uri = std::env::var("WONTON_GOOGLE_REDIRECT_URI").ok()?;
        Some(Self {
            client_id,
            client_secret,
            redirect_uri,
            http: reqwest::Client::new(),
        })
    }
}

#[derive(Deserialize)]
struct GoogleTokenResponse {
    id_token: String,
}

#[derive(Deserialize)]
struct GoogleClaims {
    sub: String,
    email: String,
    #[serde(default)]
    email_verified: bool,
}

#[async_trait::async_trait]
impl OAuthProvider for GoogleProvider {
    fn name(&self) -> &'static str {
        "google"
    }

    fn authorize_url(&self, state: &str) -> String {
        format!(
            "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email&state={}",
            urlencoding::encode(&self.client_id),
            urlencoding::encode(&self.redirect_uri),
            urlencoding::encode(state),
        )
    }

    async fn exchange_code(&self, code: &str) -> Result<VerifiedIdentity, ApiError> {
        let token_resp: GoogleTokenResponse = self
            .http
            .post("https://oauth2.googleapis.com/token")
            .form(&[
                ("code", code),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("redirect_uri", self.redirect_uri.as_str()),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(|e| ApiError::Internal(format!("google token exchange failed: {e}")))?
            .error_for_status()
            .map_err(|_| ApiError::BadRequest("google rejected the authorization code".into()))?
            .json()
            .await
            .map_err(|e| ApiError::Internal(format!("google token response was malformed: {e}")))?;

        let claims = verify_google_id_token(&self.http, &token_resp.id_token, &self.client_id).await?;
        if !claims.email_verified {
            return Err(ApiError::BadRequest("google account email is not verified".into()));
        }
        Ok(VerifiedIdentity {
            subject: claims.sub,
            email: claims.email,
        })
    }
}

/// Verify a Google id_token's signature against Google's published JWKS and check standard
/// claims (issuer, audience, expiry — handled by `jsonwebtoken`'s `Validation`). Fetches the
/// JWKS fresh on every call rather than caching — correctness over performance for v1; caching
/// with the `Cache-Control` header Google sends is a reasonable follow-up if this becomes hot.
async fn verify_google_id_token(http: &reqwest::Client, id_token: &str, audience: &str) -> Result<GoogleClaims, ApiError> {
    #[derive(Deserialize)]
    struct Jwks {
        keys: Vec<serde_json::Value>,
    }
    let jwks: Jwks = http
        .get("https://www.googleapis.com/oauth2/v3/certs")
        .send()
        .await
        .map_err(|e| ApiError::Internal(format!("could not fetch google's signing keys: {e}")))?
        .json()
        .await
        .map_err(|e| ApiError::Internal(format!("google's JWKS response was malformed: {e}")))?;

    let header = jsonwebtoken::decode_header(id_token).map_err(|_| ApiError::BadRequest("malformed id_token".into()))?;
    let kid = header.kid.ok_or_else(|| ApiError::BadRequest("id_token has no key id".into()))?;
    let key = jwks
        .keys
        .into_iter()
        .find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(kid.as_str()))
        .ok_or_else(|| ApiError::BadRequest("id_token signed by an unknown key".into()))?;
    let n = key
        .get("n")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::Internal("malformed JWKS entry (missing n)".into()))?;
    let e = key
        .get("e")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::Internal("malformed JWKS entry (missing e)".into()))?;
    let decoding_key =
        jsonwebtoken::DecodingKey::from_rsa_components(n, e).map_err(|_| ApiError::Internal("could not build RSA key from JWKS".into()))?;

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[audience]);
    validation.set_issuer(&["https://accounts.google.com", "accounts.google.com"]);
    let data = jsonwebtoken::decode::<GoogleClaims>(id_token, &decoding_key, &validation).map_err(|_| ApiError::Unauthorized)?;
    Ok(data.claims)
}

#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    //! A provider that always succeeds (or always fails, if constructed with `failing`) without
    //! any network call — what `crate::tests` registers instead of a real `GoogleProvider`, so
    //! the OAuth-ticket-issuance-and-consumption flow is testable without real credentials.

    use super::*;

    pub struct MockProvider {
        name: &'static str,
        identity: Result<VerifiedIdentity, String>,
    }

    impl MockProvider {
        pub fn always_succeeds(name: &'static str, subject: &str, email: &str) -> Self {
            Self {
                name,
                identity: Ok(VerifiedIdentity {
                    subject: subject.to_string(),
                    email: email.to_string(),
                }),
            }
        }

        pub fn always_fails(name: &'static str) -> Self {
            Self {
                name,
                identity: Err("mock provider configured to fail".to_string()),
            }
        }
    }

    #[async_trait::async_trait]
    impl OAuthProvider for MockProvider {
        fn name(&self) -> &'static str {
            self.name
        }

        fn authorize_url(&self, state: &str) -> String {
            format!("https://mock.example.com/authorize?state={state}")
        }

        async fn exchange_code(&self, _code: &str) -> Result<VerifiedIdentity, ApiError> {
            self.identity.clone().map_err(ApiError::BadRequest)
        }
    }
}
