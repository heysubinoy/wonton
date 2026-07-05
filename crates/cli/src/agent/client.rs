//! The agent client (PLAN.md §8.2): connects to the daemon's Unix socket, sends a single
//! newline-delimited request, and parses the matching response.
//!
//! Two connection strategies:
//! - [`send_request`] connects to a given socket path and does NOT auto-start a daemon. Used by
//!   `wonton agent status` / `wonton agent lock` (which must be able to report "not running")
//!   and by tests (which talk to an in-process daemon over a temp socket).
//! - [`ensure_running`] resolves the default socket, and if nothing is listening, detaches a
//!   `wonton agent start` child process and retries connecting. Used by the future CLI commands
//!   that need the agent to exist.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use super::protocol::{Argon2ParamsWire, Request, Response};

/// Errors talking to the agent.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Nothing is listening on the socket (daemon not running / not reachable). Distinct from a
    /// mid-conversation I/O error so callers can report "not running" cleanly.
    #[error("agent not reachable")]
    Unreachable,
    /// The agent replied with an `Error` response.
    #[error("agent error: {0}")]
    Agent(String),
    /// The agent replied, but with a variant that doesn't match the request.
    #[error("unexpected response from agent")]
    Unexpected,
    /// The response line couldn't be parsed as JSON.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// An I/O error after a connection was established.
    #[error("i/o error: {0}")]
    Io(std::io::Error),
    /// Failed to resolve the socket path or spawn the daemon.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// The resident identity's public keys, as returned by [`public_identity`].
#[derive(Debug, Clone)]
pub struct PublicKeys {
    pub ed25519_pubkey_b64: String,
    pub x25519_pubkey_b64: String,
}

/// A nonce + ciphertext pair, as returned by [`encrypt_value`].
#[derive(Debug, Clone)]
pub struct Encrypted {
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

/// Whether the agent is unlocked, and which contexts have a cached DEK.
#[derive(Debug, Clone)]
pub struct AgentStatus {
    pub unlocked: bool,
    pub cached_contexts: Vec<String>,
}

/// Send one request to the daemon at `path` and return its response. Does not auto-start.
pub async fn send_request(path: &Path, request: &Request) -> Result<Response, ClientError> {
    let stream = UnixStream::connect(path)
        .await
        .map_err(|_| ClientError::Unreachable)?;
    exchange(stream, request).await
}

/// Write one request line and read one response line over an established stream.
async fn exchange(stream: UnixStream, request: &Request) -> Result<Response, ClientError> {
    let (read_half, mut write_half) = stream.into_split();

    let mut line = serde_json::to_string(request).map_err(|e| ClientError::Protocol(e.to_string()))?;
    line.push('\n');
    write_half.write_all(line.as_bytes()).await.map_err(ClientError::Io)?;
    write_half.flush().await.map_err(ClientError::Io)?;

    let mut reader = BufReader::new(read_half);
    let mut response_line = String::new();
    let n = reader
        .read_line(&mut response_line)
        .await
        .map_err(ClientError::Io)?;
    if n == 0 {
        // Connection closed before a full response line — treat as unreachable.
        return Err(ClientError::Unreachable);
    }
    serde_json::from_str::<Response>(response_line.trim())
        .map_err(|e| ClientError::Protocol(e.to_string()))
}

/// Map an `Error` response to [`ClientError::Agent`], leaving other variants to the caller.
fn reject_error(response: Response) -> Result<Response, ClientError> {
    match response {
        Response::Error { message } => Err(ClientError::Agent(message)),
        other => Ok(other),
    }
}

// ---- Typed convenience wrappers (one per Request variant) ------------------------------------

/// Liveness check: `Ok(())` iff the daemon answers `Pong`.
pub async fn ping(path: &Path) -> Result<(), ClientError> {
    match reject_error(send_request(path, &Request::Ping).await?)? {
        Response::Pong => Ok(()),
        _ => Err(ClientError::Unexpected),
    }
}

/// Unlock the agent's identity with a passphrase (sent once over the local 0600 socket).
pub async fn login(
    path: &Path,
    wrapped_privkey_b64: String,
    argon2_params: Argon2ParamsWire,
    passphrase: String,
) -> Result<(), ClientError> {
    let request = Request::Login {
        wrapped_privkey_b64,
        argon2_params,
        passphrase,
    };
    match reject_error(send_request(path, &request).await?)? {
        Response::Ok => Ok(()),
        _ => Err(ClientError::Unexpected),
    }
}

/// Fetch the resident identity's public keys (errors if locked).
pub async fn public_identity(path: &Path) -> Result<PublicKeys, ClientError> {
    match reject_error(send_request(path, &Request::PublicIdentity).await?)? {
        Response::PublicIdentity {
            ed25519_pubkey_b64,
            x25519_pubkey_b64,
        } => Ok(PublicKeys {
            ed25519_pubkey_b64,
            x25519_pubkey_b64,
        }),
        _ => Err(ClientError::Unexpected),
    }
}

/// Sign a base64 message with the resident Ed25519 key; returns the base64 signature.
pub async fn sign(path: &Path, message_b64: String) -> Result<String, ClientError> {
    match reject_error(send_request(path, &Request::Sign { message_b64 }).await?)? {
        Response::Signature { signature_b64 } => Ok(signature_b64),
        _ => Err(ClientError::Unexpected),
    }
}

/// Unwrap a sealed DEK and cache it under `context` (the DEK never leaves the agent).
pub async fn unwrap_dek(
    path: &Path,
    context: String,
    sealed_box_b64: String,
) -> Result<(), ClientError> {
    let request = Request::UnwrapDek {
        context,
        sealed_box_b64,
    };
    match reject_error(send_request(path, &request).await?)? {
        Response::Ok => Ok(()),
        _ => Err(ClientError::Unexpected),
    }
}

/// Encrypt a base64 plaintext under the DEK cached for `context`.
pub async fn encrypt_value(
    path: &Path,
    context: String,
    plaintext_b64: String,
) -> Result<Encrypted, ClientError> {
    let request = Request::EncryptValue {
        context,
        plaintext_b64,
    };
    match reject_error(send_request(path, &request).await?)? {
        Response::EncryptedValue {
            nonce_b64,
            ciphertext_b64,
        } => Ok(Encrypted {
            nonce_b64,
            ciphertext_b64,
        }),
        _ => Err(ClientError::Unexpected),
    }
}

/// Decrypt a nonce/ciphertext pair under the DEK cached for `context`; returns base64 plaintext.
pub async fn decrypt_value(
    path: &Path,
    context: String,
    nonce_b64: String,
    ciphertext_b64: String,
) -> Result<String, ClientError> {
    let request = Request::DecryptValue {
        context,
        nonce_b64,
        ciphertext_b64,
    };
    match reject_error(send_request(path, &request).await?)? {
        Response::PlaintextValue { plaintext_b64 } => Ok(plaintext_b64),
        _ => Err(ClientError::Unexpected),
    }
}

/// Wipe the agent's in-memory state (identity + all cached DEKs).
pub async fn lock(path: &Path) -> Result<(), ClientError> {
    match reject_error(send_request(path, &Request::Lock).await?)? {
        Response::Ok => Ok(()),
        _ => Err(ClientError::Unexpected),
    }
}

/// Query the agent's lock/cache status.
pub async fn status(path: &Path) -> Result<AgentStatus, ClientError> {
    match reject_error(send_request(path, &Request::Status).await?)? {
        Response::Status {
            unlocked,
            cached_contexts,
        } => Ok(AgentStatus {
            unlocked,
            cached_contexts,
        }),
        _ => Err(ClientError::Unexpected),
    }
}

// ---- Auto-start ------------------------------------------------------------------------------

/// Resolve the default socket path and ensure a daemon is listening on it, auto-starting one if
/// not. Returns the socket path so callers can then use the typed wrappers above.
///
/// If the socket doesn't answer, we detach a `wonton agent start` child with all stdio nulled
/// (so it neither inherits the terminal nor blocks), then retry connecting for up to ~1s.
///
/// Currently unused by the built subcommands (`status`/`lock` deliberately don't auto-start),
/// but it is the entry point the future `login`/`use`/etc. commands will call — kept here so the
/// auto-start logic lives with the rest of the client. Hence the `allow(dead_code)`.
#[allow(dead_code)]
pub async fn ensure_running() -> Result<PathBuf, ClientError> {
    let path = super::default_socket_path()?;

    if UnixStream::connect(&path).await.is_ok() {
        return Ok(path);
    }

    let exe = std::env::current_exe()
        .map_err(|e| ClientError::Other(anyhow::anyhow!("cannot locate current exe: {e}")))?;
    std::process::Command::new(exe)
        .args(["agent", "start"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| ClientError::Other(anyhow::anyhow!("failed to spawn agent: {e}")))?;

    // Retry: ~20 attempts, 50ms apart — half a second is plenty for a bind.
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if UnixStream::connect(&path).await.is_ok() {
            return Ok(path);
        }
    }
    Err(ClientError::Unreachable)
}
