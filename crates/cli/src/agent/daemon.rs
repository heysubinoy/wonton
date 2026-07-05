//! The key-agent daemon (PLAN.md §8.2) — an ssh-agent-style process that holds all raw key
//! material and performs operations on behalf of short-lived CLI invocations.
//!
//! # Security model
//! The daemon is the *only* process that ever holds an [`UnlockedIdentity`] (the identity seed)
//! or an unwrapped [`Dek`]. Clients send operation requests over the socket and get back only
//! non-secret results. The in-memory state (`identity` + `deks`) drops its secrets via
//! `ZeroizeOnDrop` when cleared or when the process exits — [`Request::Lock`] is literally just
//! "replace the state with empty", which runs those destructors.
//!
//! # Fail-closed discipline
//! Every request is handled without ever `.unwrap()`ing on socket input: a malformed JSON line,
//! a bad base64 field, a wrong passphrase, a sealed box that doesn't open, an absent cached DEK,
//! or an AEAD auth failure all produce a [`Response::Error`] for *that one request*. A single
//! bad request never crashes the connection task, let alone the daemon.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use wonton_crypto::{
    decrypt_value, encrypt_value, sign, unlock, unwrap_dek, Argon2Params, Dek, EncryptedValue,
    SealedDek, UnlockedIdentity, WrappedPrivateKey,
};

use super::protocol::{Argon2ParamsWire, Request, Response};

/// XChaCha20-Poly1305 nonce length (192-bit extended nonce), used both for the wrapped-privkey
/// blob framing (`nonce || ciphertext`) and for an `EncryptedValue` nonce. Mirrors the
/// (crate-private) constant inside `wonton-crypto`.
const NONCE_LEN: usize = 24;
/// Argon2id salt length in bytes (128-bit), mirrors `wonton_crypto::kdf::SALT_LEN`.
const SALT_LEN: usize = 16;

/// The agent's resident, in-memory state. All secret material lives here and nowhere else.
#[derive(Default)]
pub struct AgentState {
    /// The unlocked identity, present after a successful `Login` and until `Lock`.
    pub identity: Option<UnlockedIdentity>,
    /// Cached DEKs keyed by an opaque CLI-chosen context string.
    pub deks: HashMap<String, Dek>,
}

/// Shared, lock-guarded state. One instance is shared across every accepted connection.
pub type SharedState = Arc<Mutex<AgentState>>;

/// Fresh empty shared state.
pub fn new_state() -> SharedState {
    Arc::new(Mutex::new(AgentState::default()))
}

/// Run the daemon in the foreground of the current process: resolve the default socket path,
/// bind it (0600), and serve until the process is killed. Used by `wonton agent start`.
pub async fn run() -> anyhow::Result<()> {
    let path = super::default_socket_path()?;
    let listener = bind_listener(&path).await?;
    tracing::info!(socket = %path.display(), "wonton-agent listening");
    serve(listener, new_state()).await;
    Ok(())
}

/// Bind a `UnixListener` at `path` and set the socket file's permissions to 0600.
///
/// If the path is already in use we distinguish a *live* daemon (connect succeeds — bail, we
/// don't want two) from a *stale* socket file left by a dead daemon (connect fails — remove the
/// file and rebind). This is deliberately "good enough for local dev", not production-grade
/// process management (no pidfile, no signal handling — see PROGRESS.md open items).
pub async fn bind_listener(path: &Path) -> anyhow::Result<UnixListener> {
    match UnixListener::bind(path) {
        Ok(listener) => {
            secure_socket(path)?;
            Ok(listener)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            if UnixStream::connect(path).await.is_ok() {
                anyhow::bail!("an agent is already running at {}", path.display());
            }
            // Stale socket file from a dead daemon: reclaim it.
            std::fs::remove_file(path)?;
            let listener = UnixListener::bind(path)?;
            secure_socket(path)?;
            Ok(listener)
        }
        Err(e) => Err(e.into()),
    }
}

/// Restrict the socket file to owner read/write (0600). On a shared machine this is the actual
/// access-control boundary for who may talk to the agent, so it is a real security property.
fn secure_socket(path: &Path) -> anyhow::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Accept connections forever, spawning a task per connection.
pub async fn serve(listener: UnixListener, state: SharedState) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let state = state.clone();
                tokio::spawn(handle_connection(stream, state));
            }
            Err(e) => {
                // A single accept error shouldn't kill the daemon; log and keep serving.
                tracing::warn!(error = %e, "accept failed");
            }
        }
    }
}

/// Read newline-delimited requests and write newline-delimited responses until the client
/// disconnects. A parse failure on one line errors that one request and keeps the connection
/// open for the next.
async fn handle_connection(stream: UnixStream, state: SharedState) {
    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();

    loop {
        let line = match lines.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) => break,  // clean disconnect
            Err(_) => break,    // broken pipe / read error: end this connection
        };
        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Request>(&line) {
            Ok(request) => handle_request(request, &state).await,
            Err(e) => Response::Error {
                message: format!("malformed request: {e}"),
            },
        };

        let mut out = match serde_json::to_string(&response) {
            Ok(s) => s,
            // Serializing our own Response cannot realistically fail; fall back rather than panic.
            Err(_) => r#"{"result":"Error","message":"internal serialization error"}"#.to_string(),
        };
        out.push('\n');
        if write_half.write_all(out.as_bytes()).await.is_err() {
            break; // client went away mid-write
        }
    }
}

/// Dispatch a single request against the shared state and produce a response. Never panics on
/// caller input.
pub async fn handle_request(request: Request, state: &SharedState) -> Response {
    match request {
        Request::Ping => Response::Pong,

        Request::Login {
            wrapped_privkey_b64,
            argon2_params,
            passphrase,
        } => {
            let wrapped = match wrapped_from(&wrapped_privkey_b64, &argon2_params) {
                Ok(w) => w,
                Err(message) => return Response::Error { message },
            };
            // Attempt the unlock, then drop the passphrase promptly — it is never cached.
            let result = unlock(&wrapped, passphrase.as_bytes());
            drop(passphrase);
            match result {
                Ok(identity) => {
                    state.lock().await.identity = Some(identity);
                    Response::Ok
                }
                // Mirror wonton-crypto's deliberately coarse message; don't leak internal detail.
                Err(_) => Response::Error {
                    message: "unlock failed".to_string(),
                },
            }
        }

        Request::PublicIdentity => {
            let guard = state.lock().await;
            match guard.identity.as_ref() {
                Some(id) => {
                    let public = id.public();
                    Response::PublicIdentity {
                        ed25519_pubkey_b64: STANDARD.encode(public.ed25519_pubkey),
                        x25519_pubkey_b64: STANDARD.encode(public.x25519_pubkey),
                    }
                }
                None => locked(),
            }
        }

        Request::Sign { message_b64 } => {
            let message = match STANDARD.decode(&message_b64) {
                Ok(m) => m,
                Err(_) => return bad_base64("message_b64"),
            };
            let guard = state.lock().await;
            match guard.identity.as_ref() {
                Some(id) => Response::Signature {
                    signature_b64: STANDARD.encode(sign(id, &message)),
                },
                None => locked(),
            }
        }

        Request::UnwrapDek {
            context,
            sealed_box_b64,
        } => {
            let sealed_bytes = match STANDARD.decode(&sealed_box_b64) {
                Ok(b) => b,
                Err(_) => return bad_base64("sealed_box_b64"),
            };
            let mut guard = state.lock().await;
            // Scope the immutable borrow of `identity` so we can insert into `deks` afterward.
            let dek = {
                let id = match guard.identity.as_ref() {
                    Some(id) => id,
                    None => return locked(),
                };
                match unwrap_dek(&SealedDek(sealed_bytes), id) {
                    Ok(dek) => dek,
                    Err(_) => {
                        return Response::Error {
                            message: "dek unwrap failed".to_string(),
                        }
                    }
                }
            };
            guard.deks.insert(context, dek);
            Response::Ok
        }

        Request::EncryptValue {
            context,
            plaintext_b64,
        } => {
            let plaintext = match STANDARD.decode(&plaintext_b64) {
                Ok(p) => p,
                Err(_) => return bad_base64("plaintext_b64"),
            };
            let guard = state.lock().await;
            match guard.deks.get(&context) {
                Some(dek) => {
                    let value = encrypt_value(dek, &plaintext);
                    Response::EncryptedValue {
                        nonce_b64: STANDARD.encode(value.nonce),
                        ciphertext_b64: STANDARD.encode(value.ciphertext),
                    }
                }
                None => no_dek(&context),
            }
        }

        Request::DecryptValue {
            context,
            nonce_b64,
            ciphertext_b64,
        } => {
            let nonce_bytes = match STANDARD.decode(&nonce_b64) {
                Ok(n) => n,
                Err(_) => return bad_base64("nonce_b64"),
            };
            let nonce: [u8; NONCE_LEN] = match nonce_bytes.as_slice().try_into() {
                Ok(n) => n,
                Err(_) => {
                    return Response::Error {
                        message: format!("nonce must be {NONCE_LEN} bytes"),
                    }
                }
            };
            let ciphertext = match STANDARD.decode(&ciphertext_b64) {
                Ok(c) => c,
                Err(_) => return bad_base64("ciphertext_b64"),
            };
            let value = EncryptedValue { nonce, ciphertext };
            let guard = state.lock().await;
            match guard.deks.get(&context) {
                Some(dek) => match decrypt_value(dek, &value) {
                    Ok(plaintext) => Response::PlaintextValue {
                        plaintext_b64: STANDARD.encode(plaintext),
                    },
                    // Fail closed on an auth-tag failure; never return partial plaintext.
                    Err(_) => Response::Error {
                        message: "decryption failed".to_string(),
                    },
                },
                None => no_dek(&context),
            }
        }

        Request::Lock => {
            // Replacing the state runs ZeroizeOnDrop on the identity and every cached DEK.
            let mut guard = state.lock().await;
            guard.identity = None;
            guard.deks.clear();
            Response::Ok
        }

        Request::Status => {
            let guard = state.lock().await;
            let mut cached_contexts: Vec<String> = guard.deks.keys().cloned().collect();
            cached_contexts.sort(); // deterministic ordering for callers/tests
            Response::Status {
                unlocked: guard.identity.is_some(),
                cached_contexts,
            }
        }
    }
}

/// Reconstruct a `WrappedPrivateKey` from the wire form: `wrapped_privkey_b64` is base64 of
/// `nonce(24) || ciphertext`, and the Argon2id params come from `argon2_params`. This mirrors
/// exactly what `POST /auth/login/start` returns (an opaque wrapped-key blob + separate params),
/// so a future `wonton login` can forward those response fields to the agent almost verbatim.
fn wrapped_from(
    wrapped_privkey_b64: &str,
    params: &Argon2ParamsWire,
) -> Result<WrappedPrivateKey, String> {
    let blob = STANDARD
        .decode(wrapped_privkey_b64)
        .map_err(|_| "wrapped_privkey_b64 not base64".to_string())?;
    if blob.len() < NONCE_LEN {
        return Err(format!(
            "wrapped_privkey too short: need at least {NONCE_LEN} nonce bytes"
        ));
    }
    let (nonce_slice, ciphertext) = blob.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce_slice
        .try_into()
        .map_err(|_| "invalid nonce length".to_string())?;

    let salt_bytes = STANDARD
        .decode(&params.salt_b64)
        .map_err(|_| "argon2 salt_b64 not base64".to_string())?;
    let salt: [u8; SALT_LEN] = salt_bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("argon2 salt must be {SALT_LEN} bytes"))?;

    Ok(WrappedPrivateKey {
        argon2_params: Argon2Params {
            salt,
            m_cost_kib: params.m_cost_kib,
            t_cost: params.t_cost,
            p_cost: params.p_cost,
        },
        nonce,
        ciphertext: ciphertext.to_vec(),
    })
}

fn locked() -> Response {
    Response::Error {
        message: "agent is locked".to_string(),
    }
}

fn no_dek(context: &str) -> Response {
    Response::Error {
        message: format!("no cached DEK for context '{context}'"),
    }
}

fn bad_base64(field: &str) -> Response {
    Response::Error {
        message: format!("{field} not base64"),
    }
}
