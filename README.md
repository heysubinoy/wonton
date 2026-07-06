# Wonton

A zero-knowledge, git-like secrets manager. Environment variables and secrets are versioned,
diffed, branched, and merged the way source code is — except every value is end-to-end
encrypted, and the server that stores and syncs your history never has the keys to read it.

```
$ wonton set DATABASE_URL=postgres://prod-db/acme API_KEY=sk-live-...
$ wonton commit -m "seed prod secrets"
$ wonton push
$ wonton share bob --env acme-dev --role reader
$ wonton run -- ./start-server
```

## Why

Most teams either paste secrets into a chat, hand-roll a shared `.env` file, or trust a vault
service to hold plaintext on their behalf. Wonton is built around a simpler premise: the party
storing and relaying your secrets' history should be *incapable* of reading them, even if fully
compromised. The server sees ciphertext, content hashes, and metadata (who pushed what, when) —
never a decrypted value, a data-encryption key, or a private key.

## How it works

Each **environment** (e.g. `acme/backend@prod`) has its own random 256-bit **data encryption
key (DEK)**. Every secret value is encrypted under that DEK with a fresh nonce
(XChaCha20-Poly1305). The DEK itself is wrapped separately for every authorized user with their
X25519 public key (`crypto_box` sealed box) — granting access is just wrapping a copy of the DEK
for one more person, no re-encryption required:

```
passphrase --Argon2id--> unlock key --decrypts--> your private key (Ed25519 + X25519)
                                                          |
                                         unwraps (X25519 sealed box)
                                                          v
                                    environment's Data Encryption Key (DEK)
                                                          |
                                         encrypts (XChaCha20-Poly1305)
                                                          v
                                              individual secret values
```

History is a content-addressed Merkle DAG of blob/tree/commit objects (BLAKE2b-256), with every
commit Ed25519-signed by its author. `push`/`pull` move encrypted objects and compare-and-swap
branch refs; the server never touches a key, and every object is content-hash-verified and every
commit signature-verified on the client before it's trusted.

Revoking access is the one operation that can't be free: it generates a fresh DEK, re-encrypts
the environment's history under it, and re-wraps it for every *remaining* member — a revoked
user's cached key provably cannot decrypt anything committed afterward.

A key agent (`wonton agent`, ssh-agent-style) holds unlocked key material in memory behind a
local Unix socket so you unlock your passphrase once per session, not on every command.

See [`PLAN.md`](PLAN.md) for the full design spec (threat model, cryptographic architecture,
command surface, security rules) and [`PROGRESS.md`](PROGRESS.md) for the live implementation
status and session-by-session build log.

## Status

Core functionality (Phases 0–5 of the build plan) is complete and tested: crypto primitives,
local commit/log/diff, the server + sync layer, the full CLI command surface, sharing/revocation/
key rotation, and three-way client-side merge with conflict resolution. A metadata/leakage audit
and an extended security test pass have also been done. Recovery (a lost-passphrase story) and
deeper machine-identity hardening remain intentionally deferred — see `PROGRESS.md` §0 and §5.

## Project layout

```
crates/
  crypto   (wonton-crypto)   primitives: Argon2id, XChaCha20-Poly1305, X25519 sealed box, Ed25519
  objects  (wonton-objects)  content-addressed blob/tree/commit objects, BLAKE2b hashing
  vcs      (wonton-vcs)      local commit/log/diff/merge — the client-side history engine
  sync     (wonton-sync)     push/pull client: CAS refs, integrity verification (never touches crypto)
  server   (wonton-server)   the blind blob+ref store: auth, RBAC, wrapped-DEK maps (never touches crypto)
  shared   (wonton-shared)   wire types shared between client and server (ciphertext only)
  cli      (wonton)          the `wonton` binary: CLI porcelain, the key agent, the crypto engine
```

Dependency direction is enforced by Cargo (and a compile-time test): `wonton-server` and
`wonton-sync` can never depend on `wonton-crypto` — the server must be structurally incapable of
decryption.

## Building

Requires a stable Rust toolchain (edition 2021).

```
cargo build --workspace
```

## Testing

```
cargo test --workspace          # or: cargo nextest run --workspace
cargo clippy --workspace --all-targets
cargo audit
```

## Quickstart

This assumes a `wonton-server` is already running somewhere and a store/environment (e.g.
`acme/dev`) has already been provisioned for you — provisioning a brand-new environment is an
administrative action outside the CLI's command surface (see `PLAN.md` §8).

```
# Unlock your identity into the local key agent (registers on first use).
wonton login alice --server https://wonton.example.com

# Bind a context to a store + environment, then switch to it.
wonton context add acme-dev --store acme --env dev --identity alice
wonton use acme-dev

# Optionally bind the current directory to that context.
wonton link acme-dev

# Stage, commit, and push secrets.
wonton set DATABASE_URL=postgres://prod-db/acme API_KEY=sk-live-...
wonton commit -m "seed prod secrets"
wonton push

# Inject the decrypted values into a subprocess — never written to disk.
wonton run -- ./start-server

# Or materialize them explicitly (prints a plaintext warning first).
wonton export --format dotenv .env

# Share access, branch, and merge like git.
wonton share bob --env acme-dev --role reader
wonton switch feature
wonton set FEATURE_FLAG=on
wonton commit -m "enable feature flag"
wonton switch main
wonton merge feature

# Revoke access (rotates the DEK; a revoked user's cached key stops working).
wonton revoke bob --env acme-dev
```

Run `wonton --help` for the full command list.

## License

MIT OR Apache-2.0
