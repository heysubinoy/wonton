-- OAuth-gated registration (Part 1). Registration itself stays open (POST /auth/register still
-- works exactly as before with no oauth_ticket) -- this adds an ADDITIONAL, parallel path: a
-- client that completed an OAuth flow can attach a verified ticket to register, so the server
-- learns (and records) that the new user really controls that email. The server never learns a
-- passphrase or private key either way -- OAuth only gates who is allowed to CLAIM a username,
-- not the zero-knowledge crypto identity itself.

ALTER TABLE users ADD COLUMN email TEXT;             -- verified email, nullable
ALTER TABLE users ADD COLUMN oauth_provider TEXT;    -- e.g. "google", nullable
ALTER TABLE users ADD COLUMN oauth_subject TEXT;     -- provider's stable subject id, nullable

-- Single-use, short-lived ticket proving a verified email, minted after a successful OAuth
-- code exchange and consumed by `POST /auth/register`'s optional `oauth_ticket` field. Mirrors
-- `login_challenges`' shape and single-use/expiry discipline exactly.
CREATE TABLE oauth_verifications (
    id             TEXT PRIMARY KEY,
    provider       TEXT NOT NULL,
    verified_email TEXT NOT NULL,
    oauth_subject  TEXT NOT NULL,        -- provider's stable subject id
    ticket_hash    BLOB NOT NULL,        -- BLAKE2b-256 of the ticket; never the raw ticket
    expires_at     INTEGER NOT NULL,
    created_at     INTEGER NOT NULL
);
