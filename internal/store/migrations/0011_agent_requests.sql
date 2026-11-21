-- 0011_agent_requests: custom keys, "agent asks, you tap" (ADR-008).
--
-- 1. `keys` is rebuilt (SQLite cannot widen a CHECK in place):
--      - grant_kind also allows 'self' (an owner granted their own agent a key) and 'bootstrap' (the request-only
--        key an agent is enrolled with: it holds no op);
--      - expires_at is no longer immutable, but it may only grow (an extension, one tap plus Hello). The lifetime
--        CHECKs still count from issued_at, so a key never lives longer than 30 days in all (7 for a sensitive key).
--    Every row, index and trigger is put back; key_agents keeps its foreign key.
-- 2. `key_requests`: what an agent (or its owner, for an extension) asked for, and what was granted. A request
--    is de-duplicated by its scope hash for as long as it is pending.
-- 3. `key_enrolments`: the device-code enrolment of an agent. Only hashes of the two codes are stored.
-- 4. `key_extensions`: one row per extension of a key's life, keyed by the op that made it (idempotent).
--
-- Deferred foreign keys: key_agents points at keys. The rebuild drops keys and puts every row back in this
-- one transaction; the foreign-key check runs at commit, when the parent is back.

PRAGMA defer_foreign_keys = ON;

CREATE TEMP TABLE keys_keep AS SELECT * FROM keys;
DROP TABLE keys;

CREATE TABLE keys (
    id             TEXT PRIMARY KEY CHECK (id GLOB 'k-[0-9a-f]*' AND length(id) = 18),
    project        TEXT NOT NULL,
    owner_id       TEXT NOT NULL CHECK (length(owner_id) > 0),
    holder_kind    TEXT NOT NULL CHECK (holder_kind IN ('person', 'agent')),
    holder         TEXT NOT NULL CHECK (length(holder) > 0),
    ops_json       TEXT NOT NULL,
    units_json     TEXT NOT NULL,
    sensitive      INTEGER NOT NULL CHECK (sensitive IN (0, 1)),
    rate_per_hour  INTEGER NOT NULL CHECK (rate_per_hour BETWEEN 1 AND 300),
    issued_at      INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    claim_deadline INTEGER NOT NULL,
    claimant       TEXT NOT NULL,
    granted_by     TEXT NOT NULL,
    grant_kind     TEXT NOT NULL CHECK (grant_kind IN ('approved', 'self', 'bootstrap')),
    approval_id    TEXT NOT NULL REFERENCES approvals (approval_id),
    request_id     TEXT NOT NULL UNIQUE,
    token_sha256   TEXT UNIQUE CHECK (token_sha256 IS NULL OR length(token_sha256) = 64),
    fingerprint    TEXT,
    claimed_at     INTEGER,
    revoked_at     INTEGER,
    revoked_by     TEXT,
    revoke_reason  TEXT,
    human_stopped  INTEGER NOT NULL DEFAULT 0 CHECK (human_stopped IN (0, 1)),
    last_used_at   INTEGER,
    CHECK (expires_at > issued_at AND expires_at - issued_at <= 30 * 86400),
    CHECK (sensitive = 0 OR expires_at - issued_at <= 7 * 86400),
    CHECK ((token_sha256 IS NULL) = (claimed_at IS NULL)),
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)),
    -- a bootstrap key holds no op and belongs to an agent
    CHECK (grant_kind <> 'bootstrap' OR (ops_json = '[]' AND holder_kind = 'agent')),
    CHECK (grant_kind = 'bootstrap' OR ops_json <> '[]')
) STRICT;

INSERT INTO keys (id, project, owner_id, holder_kind, holder, ops_json, units_json, sensitive, rate_per_hour, issued_at,
        expires_at, claim_deadline, claimant, granted_by, grant_kind, approval_id, request_id, token_sha256, fingerprint,
        claimed_at, revoked_at, revoked_by, revoke_reason, human_stopped, last_used_at)
    SELECT id, project, owner_id, holder_kind, holder, ops_json, units_json, sensitive, rate_per_hour, issued_at,
        expires_at, claim_deadline, claimant, granted_by, grant_kind, approval_id, request_id, token_sha256, fingerprint,
        claimed_at, revoked_at, revoked_by, revoke_reason, human_stopped, last_used_at
    FROM keys_keep;
DROP TABLE keys_keep;

CREATE INDEX keys_owner ON keys (owner_id, issued_at);
CREATE INDEX keys_holder ON keys (owner_id, holder_kind, holder);

CREATE TRIGGER keys_scope_immutable
BEFORE UPDATE OF id, project, owner_id, holder_kind, holder, ops_json, units_json, sensitive, rate_per_hour,
                 issued_at, claim_deadline, claimant, granted_by, grant_kind, approval_id, request_id ON keys
BEGIN
    SELECT RAISE(ABORT, 'a key''s scope never changes');
END;

-- The one scope column that moves is the expiry, and only later.
CREATE TRIGGER keys_expiry_only_grows
BEFORE UPDATE OF expires_at ON keys
WHEN NEW.expires_at <= OLD.expires_at OR OLD.revoked_at IS NOT NULL OR OLD.claimed_at IS NULL
BEGIN
    SELECT RAISE(ABORT, 'a key''s expiry only moves later, and only for a live key');
END;

CREATE TRIGGER keys_token_once
BEFORE UPDATE OF token_sha256, fingerprint, claimed_at ON keys
WHEN OLD.token_sha256 IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'a key is claimed once');
END;

CREATE TRIGGER keys_revoked_once
BEFORE UPDATE OF revoked_at, revoked_by, revoke_reason, human_stopped ON keys
WHEN OLD.revoked_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'a key is revoked once');
END;

CREATE TRIGGER keys_no_delete
BEFORE DELETE ON keys
BEGIN
    SELECT RAISE(ABORT, 'keys are never deleted');
END;

------------------------------------------------------------- key_requests

-- One row per ask. `state` moves pending -> granted | denied | withdrawn | expired | cancelled, once. The grant_*
-- columns are what the owner decided (never more than the ops, units, hours and rate asked for): the
-- requester reads both, so it sees what was removed. A request is a row, not an op: the op that made it
-- is request_op_id; the op that carries the card that signs the grant is issue_op_id.
CREATE TABLE key_requests (
    id               TEXT PRIMARY KEY CHECK (id GLOB 'kr-[0-9a-f]*' AND length(id) = 19),
    kind             TEXT NOT NULL CHECK (kind IN ('new', 'extend')),
    project          TEXT NOT NULL,
    owner_id         TEXT NOT NULL CHECK (length(owner_id) > 0),
    holder           TEXT NOT NULL CHECK (length(holder) > 0),   -- the agent's label
    requester_key_id TEXT NOT NULL REFERENCES keys (id),         -- the key that asked, and the one that claims the grant
    ops_json         TEXT NOT NULL,                              -- 'new': the ops asked for; 'extend': the extended key's ops
    units_json       TEXT NOT NULL,
    ttl_hours        INTEGER NOT NULL CHECK (ttl_hours BETWEEN 1 AND 720), -- 'extend': hours added
    rate_per_hour    INTEGER NOT NULL CHECK (rate_per_hour BETWEEN 1 AND 300),
    reason           TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    needed_today     INTEGER NOT NULL DEFAULT 0 CHECK (needed_today IN (0, 1)),
    scope_hash       TEXT NOT NULL CHECK (length(scope_hash) = 64),
    extends_key_id   TEXT REFERENCES keys (id),
    request_op_id    TEXT NOT NULL,
    state            TEXT NOT NULL CHECK (state IN ('pending', 'granted', 'denied', 'withdrawn', 'expired', 'cancelled')),
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL,
    decided_at       INTEGER,
    decided_by       TEXT,
    deny_reason      TEXT,
    grant_ops_json   TEXT,
    grant_units_json TEXT,
    grant_ttl_hours  INTEGER,
    grant_rate       INTEGER,
    issue_op_id      TEXT,                                       -- the keys.issue or keys.extend op the owner started
    granted_key_id   TEXT,
    CHECK ((kind = 'extend') = (extends_key_id IS NOT NULL)),
    CHECK (state NOT IN ('granted', 'denied') OR decided_at IS NOT NULL),
    CHECK (state <> 'granted' OR (grant_ops_json IS NOT NULL AND grant_units_json IS NOT NULL AND grant_ttl_hours IS NOT NULL AND grant_rate IS NOT NULL))
) STRICT;

CREATE INDEX key_requests_owner ON key_requests (owner_id, state, created_at);
CREATE INDEX key_requests_agent ON key_requests (owner_id, holder, created_at);
CREATE INDEX key_requests_asker ON key_requests (requester_key_id, state);
-- ten identical asks are one pending request (a cap on requests)
CREATE UNIQUE INDEX key_requests_one_pending ON key_requests (owner_id, holder, scope_hash) WHERE state = 'pending';

CREATE TRIGGER key_requests_identity_immutable
BEFORE UPDATE OF id, kind, project, owner_id, holder, requester_key_id, ops_json, units_json, ttl_hours, rate_per_hour, reason,
                 needed_today, scope_hash, extends_key_id, request_op_id, created_at, expires_at ON key_requests
BEGIN
    SELECT RAISE(ABORT, 'a key request''s ask never changes');
END;

CREATE TRIGGER key_requests_decided_once
BEFORE UPDATE ON key_requests
WHEN OLD.state <> 'pending' AND (NEW.state IS NOT OLD.state OR NEW.decided_at IS NOT OLD.decided_at OR NEW.granted_key_id IS NOT OLD.granted_key_id
                                 OR NEW.grant_ops_json IS NOT OLD.grant_ops_json OR NEW.grant_units_json IS NOT OLD.grant_units_json
                                 OR NEW.grant_ttl_hours IS NOT OLD.grant_ttl_hours OR NEW.grant_rate IS NOT OLD.grant_rate)
BEGIN
    SELECT RAISE(ABORT, 'a key request is decided once');
END;

CREATE TRIGGER key_requests_no_delete
BEFORE DELETE ON key_requests
BEGIN
    SELECT RAISE(ABORT, 'key requests are never deleted');
END;

----------------------------------------------------------- key_enrolments

-- The device-code enrolment of an agent (RFC 8628 shape). The agent holds the device code and polls; the owner
-- reads the short user code off the agent's terminal and approves the enrolment at the console. Neither code is
-- stored: only its SHA-256.
CREATE TABLE key_enrolments (
    id               TEXT PRIMARY KEY CHECK (id GLOB 'en-[0-9a-f]*' AND length(id) = 19),
    project          TEXT NOT NULL,
    label            TEXT NOT NULL CHECK (length(label) > 0),
    user_code_sha256 TEXT NOT NULL UNIQUE CHECK (length(user_code_sha256) = 64),
    device_sha256    TEXT NOT NULL CHECK (length(device_sha256) = 64),
    state            TEXT NOT NULL CHECK (state IN ('pending', 'issued', 'claimed', 'expired', 'cancelled')),
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL,
    owner_id         TEXT,
    issue_op_id      TEXT,                                -- the keys.issue op carrying the owner's card
    key_id           TEXT REFERENCES keys (id),
    CHECK (state <> 'issued' OR key_id IS NOT NULL)
) STRICT;

CREATE INDEX key_enrolments_state ON key_enrolments (state, expires_at);

CREATE TRIGGER key_enrolments_identity_immutable
BEFORE UPDATE OF id, project, label, user_code_sha256, device_sha256, created_at, expires_at ON key_enrolments
BEGIN
    SELECT RAISE(ABORT, 'a key enrolment''s identity never changes');
END;

CREATE TRIGGER key_enrolments_no_delete
BEFORE DELETE ON key_enrolments
BEGIN
    SELECT RAISE(ABORT, 'key enrolments are never deleted');
END;

----------------------------------------------------------- key_extensions

-- One row per extension of a key's life (keys.extend, one tap plus Hello). The primary key is the op, so an
-- execution that is retried after a crash finds its extension instead of adding the hours twice.
CREATE TABLE key_extensions (
    request_id     TEXT PRIMARY KEY,                      -- the keys.extend op
    key_id         TEXT NOT NULL REFERENCES keys (id),
    approval_id    TEXT NOT NULL REFERENCES approvals (approval_id),
    extended_by    TEXT NOT NULL,                         -- the spec approver id that signed the card
    hours          INTEGER NOT NULL CHECK (hours BETWEEN 1 AND 720),
    old_expires_at INTEGER NOT NULL,
    new_expires_at INTEGER NOT NULL CHECK (new_expires_at > old_expires_at),
    created_at     INTEGER NOT NULL
) STRICT;

CREATE INDEX key_extensions_key ON key_extensions (key_id, created_at);

CREATE TRIGGER key_extensions_immutable
BEFORE UPDATE ON key_extensions
BEGIN
    SELECT RAISE(ABORT, 'an extension is never changed');
END;

CREATE TRIGGER key_extensions_no_delete
BEFORE DELETE ON key_extensions
BEGIN
    SELECT RAISE(ABORT, 'extensions are never deleted');
END;
