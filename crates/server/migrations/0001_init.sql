-- Wonton server schema, v1 (PROGRESS.md §3.3).
--
-- The server is a blind, content-addressed blob + ref store (PLAN.md §7). It stores only
-- opaque ciphertext (objects.body, wrapped_deks.sealed_box, users.wrapped_privkey) plus
-- non-secret metadata it is allowed to see (§3 "accepted leakage": object sizes/kinds/counts,
-- plaintext key names inside trees, ref topology, who pushed and when). No column here ever
-- holds a DEK or a private key in unwrapped form.
--
-- Note: `users.username` is NOT in the original PROGRESS.md §3.3 sketch. It was added here
-- because the challenge-response login flow (PROGRESS.md §3.4 / this phase's auth design)
-- looks a user up by a human-facing name before it has a session. It is non-secret metadata.

CREATE TABLE users (
    id                  TEXT PRIMARY KEY,           -- UUID
    username            TEXT NOT NULL UNIQUE,        -- human-facing login handle (non-secret)
    ed25519_pubkey      BLOB NOT NULL,               -- 32 bytes, public
    x25519_pubkey       BLOB NOT NULL,               -- 32 bytes, public
    wrapped_privkey     BLOB NOT NULL,               -- WrappedPrivateKey ciphertext (opaque)
    argon2_salt         BLOB NOT NULL,
    argon2_m_cost_kib   INTEGER NOT NULL,
    argon2_t_cost       INTEGER NOT NULL,
    argon2_p_cost       INTEGER NOT NULL,
    created_at          INTEGER NOT NULL             -- unix seconds
);

CREATE TABLE machine_identities (                    -- CI/server identities (§10)
    id                  TEXT PRIMARY KEY,
    label               TEXT NOT NULL,
    ed25519_pubkey      BLOB NOT NULL,
    x25519_pubkey       BLOB NOT NULL,
    token_hash          BLOB NOT NULL,               -- BLAKE2b-256 of the bearer token
    expires_at          INTEGER NOT NULL,
    created_at          INTEGER NOT NULL
);

CREATE TABLE stores (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,                -- e.g. "acme/backend"
    created_at  INTEGER NOT NULL
);

CREATE TABLE environments (
    id                  TEXT PRIMARY KEY,
    store_id            TEXT NOT NULL REFERENCES stores(id),
    name                TEXT NOT NULL,               -- "dev" / "staging" / "prod"
    active_dek_version  INTEGER NOT NULL DEFAULT 1,
    created_at          INTEGER NOT NULL,
    UNIQUE(store_id, name)
);

CREATE TABLE env_members (                           -- metadata-level RBAC (§10)
    env_id      TEXT NOT NULL REFERENCES environments(id),
    user_id     TEXT NOT NULL REFERENCES users(id),
    role        TEXT NOT NULL CHECK (role IN ('admin', 'writer', 'reader')),
    PRIMARY KEY (env_id, user_id)
);

CREATE TABLE wrapped_deks (                          -- §4.2/§4.4: the crypto access boundary
    env_id        TEXT NOT NULL REFERENCES environments(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    dek_version   INTEGER NOT NULL,
    sealed_box    BLOB NOT NULL,                     -- crypto_box seal(DEK, user_x25519_pubkey)
    PRIMARY KEY (env_id, user_id, dek_version)
);

CREATE TABLE objects (                               -- content-addressed blob/tree/commit store
    hash        TEXT PRIMARY KEY,                    -- hex BLAKE2b-256
    kind        TEXT NOT NULL CHECK (kind IN ('blob', 'tree', 'commit')),
    body        BLOB NOT NULL,                       -- opaque bytes; server verifies hash(body)==hash on insert
    created_at  INTEGER NOT NULL
);

CREATE TABLE refs (                                  -- branch pointers, CAS-updated
    env_id        TEXT NOT NULL REFERENCES environments(id),
    branch_name   TEXT NOT NULL,
    commit_hash   TEXT NOT NULL REFERENCES objects(hash),
    PRIMARY KEY (env_id, branch_name)
);

-- Sessions: bearer tokens issued to a user after a successful challenge-response login.
-- Only the token's BLAKE2b-256 hash is stored, so a DB leak does not hand out live tokens.
CREATE TABLE sessions (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id),
    token_hash   BLOB NOT NULL,
    expires_at   INTEGER NOT NULL,
    created_at   INTEGER NOT NULL
);

-- Login challenges: short-lived random nonces issued by POST /auth/login/start and consumed
-- by POST /auth/login/complete once the client signs them with its Ed25519 private key.
CREATE TABLE login_challenges (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id),
    nonce        BLOB NOT NULL,
    expires_at   INTEGER NOT NULL,
    created_at   INTEGER NOT NULL
);
