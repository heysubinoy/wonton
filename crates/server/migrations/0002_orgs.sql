-- Orgs -> stores (repos) -> branches. Branch replaces environment as the crypto/ACL unit: every
-- branch has its own DEK, own membership, and exactly one ref (no more named sub-branches within
-- an environment — a "branch" IS the top-level unit now). Clean-slate migration: no production
-- deployment exists yet, so this drops and recreates rather than preserving data.

DROP TABLE IF EXISTS refs;
DROP TABLE IF EXISTS wrapped_deks;
DROP TABLE IF EXISTS env_members;
DROP TABLE IF EXISTS environments;
DROP TABLE IF EXISTS stores;

CREATE TABLE orgs (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    created_at  INTEGER NOT NULL
);

CREATE TABLE org_members (                           -- membership grants nothing on its own;
    org_id      TEXT NOT NULL REFERENCES orgs(id),    -- branch_members is the real authorization
    user_id     TEXT NOT NULL REFERENCES users(id),   -- boundary. A row here just records "this
    role        TEXT NOT NULL CHECK (role IN ('owner', 'member')),
    PRIMARY KEY (org_id, user_id)
);

CREATE TABLE stores (                                -- = repo
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id),
    name        TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    UNIQUE(org_id, name)
);

CREATE TABLE branches (                              -- was `environments`; now the crypto/ACL unit
    id                  TEXT PRIMARY KEY,
    store_id            TEXT NOT NULL REFERENCES stores(id),
    name                TEXT NOT NULL,
    active_dek_version  INTEGER NOT NULL DEFAULT 1,
    created_at          INTEGER NOT NULL,
    UNIQUE(store_id, name)
);

CREATE TABLE branch_members (                        -- was `env_members`
    branch_id   TEXT NOT NULL REFERENCES branches(id),
    user_id     TEXT NOT NULL REFERENCES users(id),
    role        TEXT NOT NULL CHECK (role IN ('admin', 'writer', 'reader')),
    PRIMARY KEY (branch_id, user_id)
);

CREATE TABLE wrapped_deks (                          -- the crypto access boundary, keyed by branch
    branch_id     TEXT NOT NULL REFERENCES branches(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    dek_version   INTEGER NOT NULL,
    sealed_box    BLOB NOT NULL,
    PRIMARY KEY (branch_id, user_id, dek_version)
);

CREATE TABLE refs (                                  -- ONE ref per branch (no sub-branch table)
    branch_id     TEXT PRIMARY KEY REFERENCES branches(id),
    commit_hash   TEXT NOT NULL REFERENCES objects(hash)
);
