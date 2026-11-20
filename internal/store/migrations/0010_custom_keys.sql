-- 0010_custom_keys: custom keys (ADR-008).
--
-- 1. A third requester kind, `key`, on `ops` and `approvals`, with the key's id
--    and its owner. SQLite cannot widen a CHECK in place, so both tables are
--    rebuilt inside this migration's own transaction; every index and trigger
--    they had is recreated, with the new columns added to the immutable set.
--    `denials` keys only on the text of requester_key ('key:<id>' fits) and is
--    not touched. The ledger is a different table and is not touched.
-- 2. `keys`: the key rows. Only the SHA-256 of a token is ever stored, and only
--    once the key is claimed (the token is made at the claim, so no plaintext
--    exists anywhere before the holder has it).
-- 3. `key_agents`: an agent a human stopped (operator decision): a
--    stopped agent can be given no new key until its owner resumes it.
--
-- Deferred foreign keys: approvals is the parent of rows in four tables. The
-- rebuild drops it and puts every row back in this one transaction; the
-- foreign-key check runs at commit, when each parent is back.

PRAGMA defer_foreign_keys = ON;

---------------------------------------------------------------------- ops

CREATE TEMP TABLE ops_keep AS SELECT * FROM ops;
DROP TABLE ops;

CREATE TABLE ops (
    id              TEXT PRIMARY KEY CHECK (id GLOB 'q-[0-9a-z]*'),
    state           TEXT NOT NULL CHECK (state IN (
                        'requested', 'denied', 'pending_approval', 'allowed', 'executing',
                        'succeeded', 'refused', 'failed', 'expired', 'cancelled', 'unconfirmed')),
    op              TEXT NOT NULL,
    project         TEXT NOT NULL,
    target_adapter  TEXT NOT NULL,
    target_ref      TEXT NOT NULL,
    params_json     TEXT NOT NULL,          -- JCS form: exactly what op_hash covers
    op_hash         TEXT NOT NULL CHECK (op_hash GLOB 'sha256:*'),
    requester_kind  TEXT NOT NULL CHECK (requester_kind IN ('run', 'orchestrator', 'key')),
    requester_key   TEXT NOT NULL,          -- 'run:<id>', 'orchestrator:<id>' or 'key:<id>'
    run_id          TEXT,
    orchestrator_id TEXT,
    profile         TEXT,
    token_jti       TEXT,
    class           TEXT NOT NULL CHECK (class IN ('routine', 'gated', 'high', 'critical')),
    reversibility   TEXT NOT NULL CHECK (reversibility IN ('reversible', 'compensable', 'irreversible')),
    policy_version  TEXT NOT NULL,
    reason          TEXT,
    traceparent     TEXT,
    requested_at    INTEGER NOT NULL,       -- unix seconds
    expires_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    approval_id     TEXT,
    execution_id    TEXT,
    outcome         TEXT CHECK (outcome IS NULL OR outcome IN ('succeeded', 'refused', 'failed', 'unconfirmed')),
    cause_code      TEXT,
    external_ref    TEXT,
    result_json     TEXT,
    checks_json     TEXT,
    denial_json     TEXT,
    scope_json      TEXT,
    key_id          TEXT,                   -- requester_kind 'key': the key
    owner_id        TEXT,                   -- requester_kind 'key': who the key acts for
    CHECK ((requester_kind = 'run' AND run_id IS NOT NULL AND orchestrator_id IS NULL AND key_id IS NULL)
        OR (requester_kind = 'orchestrator' AND orchestrator_id IS NOT NULL AND run_id IS NULL AND key_id IS NULL)
        OR (requester_kind = 'key' AND key_id IS NOT NULL AND owner_id IS NOT NULL AND run_id IS NULL AND orchestrator_id IS NULL))
) STRICT;

INSERT INTO ops (id, state, op, project, target_adapter, target_ref, params_json, op_hash,
        requester_kind, requester_key, run_id, orchestrator_id, profile, token_jti,
        class, reversibility, policy_version, reason, traceparent, requested_at, expires_at, updated_at,
        approval_id, execution_id, outcome, cause_code, external_ref, result_json, checks_json, denial_json, scope_json)
    SELECT id, state, op, project, target_adapter, target_ref, params_json, op_hash,
        requester_kind, requester_key, run_id, orchestrator_id, profile, token_jti,
        class, reversibility, policy_version, reason, traceparent, requested_at, expires_at, updated_at,
        approval_id, execution_id, outcome, cause_code, external_ref, result_json, checks_json, denial_json, scope_json
    FROM ops_keep;
DROP TABLE ops_keep;

CREATE INDEX ops_requester_time ON ops (requester_key, requested_at);
CREATE INDEX ops_requester_hash ON ops (requester_key, op_hash);
CREATE INDEX ops_state ON ops (state, expires_at);
CREATE INDEX ops_project_state ON ops (project, state);
CREATE UNIQUE INDEX ops_one_live ON ops (requester_key, op_hash)
    WHERE state IN ('requested', 'pending_approval', 'allowed', 'executing', 'unconfirmed');

CREATE TRIGGER ops_state_machine
BEFORE UPDATE OF state ON ops
WHEN OLD.state <> NEW.state
 AND NOT EXISTS (SELECT 1 FROM ops_transitions WHERE from_state = OLD.state AND to_state = NEW.state)
BEGIN
    SELECT RAISE(ABORT, 'illegal op state transition');
END;

CREATE TRIGGER ops_identity_immutable
BEFORE UPDATE OF id, op, project, target_adapter, target_ref, params_json, op_hash,
                 requester_kind, requester_key, run_id, orchestrator_id, requested_at, key_id, owner_id ON ops
BEGIN
    SELECT RAISE(ABORT, 'op identity is immutable');
END;

CREATE TRIGGER ops_no_delete
BEFORE DELETE ON ops
BEGIN
    SELECT RAISE(ABORT, 'ops are never deleted');
END;

CREATE TRIGGER ops_scope_immutable
BEFORE UPDATE OF scope_json ON ops
WHEN OLD.scope_json IS NOT NEW.scope_json
BEGIN
    SELECT RAISE(ABORT, 'op scope is immutable');
END;

--------------------------------------------------------------- approvals

CREATE TEMP TABLE approvals_keep AS SELECT * FROM approvals;
DROP TABLE approvals;

CREATE TABLE approvals (
	approval_id          TEXT    PRIMARY KEY CHECK (approval_id GLOB 'a-*'),
	request_id           TEXT    NOT NULL UNIQUE CHECK (request_id GLOB 'q-*'),
	requester_kind       TEXT    NOT NULL CHECK (requester_kind IN ('run', 'orchestrator', 'key')),
	requester_key        TEXT    NOT NULL CHECK (length(requester_key) > 0),
	run_id               TEXT    CHECK ((requester_kind = 'run') = (run_id IS NOT NULL)),
	project              TEXT    NOT NULL,
	op                   TEXT    NOT NULL,
	op_hash              TEXT    NOT NULL CHECK (op_hash GLOB 'sha256:*'),
	class                TEXT    NOT NULL CHECK (class IN ('gated', 'high', 'critical')),
	policy_version       TEXT    NOT NULL,
	request_json         TEXT    NOT NULL,
	checks_json          TEXT    NOT NULL,
	evidence_json        TEXT    NOT NULL,
	card_text            TEXT    NOT NULL,
	display_sha256       TEXT    NOT NULL CHECK (display_sha256 GLOB 'sha256:*'),
	state                TEXT    NOT NULL CHECK (state IN ('pending', 'approved', 'denied', 'expired', 'cancelled', 'consumed')),
	created_unix         INTEGER NOT NULL,
	request_expires_unix INTEGER NOT NULL,
	decided_unix         INTEGER,
	approver             TEXT,
	reason               TEXT,
	approval_expires_unix INTEGER,
	nonce                TEXT,
	challenge_sha256     TEXT,
	record_json          TEXT,
	consumed_unix        INTEGER,
	key_id               TEXT    CHECK ((requester_kind = 'key') = (key_id IS NOT NULL)),
	CHECK (state NOT IN ('approved', 'denied', 'consumed') OR (decided_unix IS NOT NULL AND approver IS NOT NULL
		AND nonce IS NOT NULL AND challenge_sha256 IS NOT NULL AND record_json IS NOT NULL)),
	CHECK ((state = 'consumed') = (consumed_unix IS NOT NULL))
) STRICT;

INSERT INTO approvals (approval_id, request_id, requester_kind, requester_key, run_id, project, op, op_hash, class,
        policy_version, request_json, checks_json, evidence_json, card_text, display_sha256, state, created_unix,
        request_expires_unix, decided_unix, approver, reason, approval_expires_unix, nonce, challenge_sha256,
        record_json, consumed_unix)
    SELECT approval_id, request_id, requester_kind, requester_key, run_id, project, op, op_hash, class,
        policy_version, request_json, checks_json, evidence_json, card_text, display_sha256, state, created_unix,
        request_expires_unix, decided_unix, approver, reason, approval_expires_unix, nonce, challenge_sha256,
        record_json, consumed_unix
    FROM approvals_keep;
DROP TABLE approvals_keep;

CREATE UNIQUE INDEX approvals_one_pending ON approvals (op_hash, requester_kind, requester_key) WHERE state = 'pending';
CREATE INDEX approvals_state ON approvals (state, request_expires_unix);
CREATE INDEX approvals_op_hash ON approvals (op_hash, decided_unix);
CREATE INDEX approvals_requester ON approvals (requester_kind, requester_key, state);
CREATE INDEX approvals_project ON approvals (project, state);

CREATE TRIGGER approvals_no_delete BEFORE DELETE ON approvals
BEGIN
	SELECT RAISE(ABORT, 'approvals: rows are never deleted');
END;

CREATE TRIGGER approvals_immutable BEFORE UPDATE ON approvals
WHEN NEW.approval_id IS NOT OLD.approval_id OR NEW.request_id IS NOT OLD.request_id
	OR NEW.requester_kind IS NOT OLD.requester_kind OR NEW.requester_key IS NOT OLD.requester_key
	OR NEW.run_id IS NOT OLD.run_id OR NEW.key_id IS NOT OLD.key_id OR NEW.project IS NOT OLD.project OR NEW.op IS NOT OLD.op
	OR NEW.op_hash IS NOT OLD.op_hash OR NEW.class IS NOT OLD.class OR NEW.policy_version IS NOT OLD.policy_version
	OR NEW.request_json IS NOT OLD.request_json OR NEW.checks_json IS NOT OLD.checks_json
	OR NEW.evidence_json IS NOT OLD.evidence_json OR NEW.card_text IS NOT OLD.card_text
	OR NEW.display_sha256 IS NOT OLD.display_sha256 OR NEW.created_unix IS NOT OLD.created_unix
	OR NEW.request_expires_unix IS NOT OLD.request_expires_unix
BEGIN
	SELECT RAISE(ABORT, 'approvals: the request and its card are immutable');
END;

CREATE TRIGGER approvals_state_machine BEFORE UPDATE ON approvals
WHEN OLD.state IN ('denied', 'expired', 'cancelled', 'consumed')
	OR NOT (NEW.state = OLD.state
		OR (OLD.state = 'pending' AND NEW.state IN ('approved', 'denied', 'expired', 'cancelled'))
		OR (OLD.state = 'approved' AND NEW.state IN ('consumed', 'expired', 'cancelled')))
	OR (OLD.decided_unix IS NOT NULL AND (NEW.decided_unix IS NOT OLD.decided_unix OR NEW.record_json IS NOT OLD.record_json
		OR NEW.challenge_sha256 IS NOT OLD.challenge_sha256 OR NEW.nonce IS NOT OLD.nonce OR NEW.approver IS NOT OLD.approver))
BEGIN
	SELECT RAISE(ABORT, 'approvals: illegal state change');
END;

------------------------------------------------------------------- keys

-- One row per key. `state` is derived, never stored:
--   granted  token_sha256 IS NULL, not revoked, claim_deadline not passed
--   live     claimed, not revoked, expires_at not passed
--   revoked  revoked_at IS NOT NULL (a key not claimed by its deadline is revoked by the sweeper)
-- The scope (ops, units, rate, expiry) is frozen at issue; no column of it ever changes.
CREATE TABLE keys (
    id             TEXT PRIMARY KEY CHECK (id GLOB 'k-[0-9a-f]*' AND length(id) = 18),
    project        TEXT NOT NULL,
    owner_id       TEXT NOT NULL CHECK (length(owner_id) > 0),   -- who the key acts for (the orchestrator that asked)
    holder_kind    TEXT NOT NULL CHECK (holder_kind IN ('person', 'agent')),
    holder         TEXT NOT NULL CHECK (length(holder) > 0),     -- a person's or an agent's label
    ops_json       TEXT NOT NULL,                                -- JSON array of op names, sorted
    units_json     TEXT NOT NULL,                                -- JSON array of repositories, sorted; [] for project-only ops
    sensitive      INTEGER NOT NULL CHECK (sensitive IN (0, 1)), -- holds an ask-only (non-routine) op
    rate_per_hour  INTEGER NOT NULL CHECK (rate_per_hour BETWEEN 1 AND 300),
    issued_at      INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    claim_deadline INTEGER NOT NULL,
    claimant       TEXT NOT NULL,                                -- Caller.Key() of who may claim it
    granted_by     TEXT NOT NULL,                                -- the spec approver id that signed the card
    grant_kind     TEXT NOT NULL CHECK (grant_kind IN ('approved')),
    approval_id    TEXT NOT NULL REFERENCES approvals (approval_id),
    request_id     TEXT NOT NULL UNIQUE,                         -- the keys.issue op: one op, one key
    token_sha256   TEXT UNIQUE CHECK (token_sha256 IS NULL OR length(token_sha256) = 64),
    fingerprint    TEXT,
    claimed_at     INTEGER,
    revoked_at     INTEGER,
    revoked_by     TEXT,
    revoke_reason  TEXT,
    human_stopped  INTEGER NOT NULL DEFAULT 0 CHECK (human_stopped IN (0, 1)),
    last_used_at   INTEGER,
    -- operator decisions: at most 30 days; a sensitive key at most 7 days (checked again here, defence in depth)
    CHECK (expires_at > issued_at AND expires_at - issued_at <= 30 * 86400),
    CHECK (sensitive = 0 OR expires_at - issued_at <= 7 * 86400),
    CHECK ((token_sha256 IS NULL) = (claimed_at IS NULL)),
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
) STRICT;

CREATE INDEX keys_owner ON keys (owner_id, issued_at);
CREATE INDEX keys_holder ON keys (owner_id, holder_kind, holder);

CREATE TRIGGER keys_scope_immutable
BEFORE UPDATE OF id, project, owner_id, holder_kind, holder, ops_json, units_json, sensitive, rate_per_hour,
                 issued_at, expires_at, claim_deadline, claimant, granted_by, grant_kind, approval_id, request_id ON keys
BEGIN
    SELECT RAISE(ABORT, 'a key''s scope never changes');
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

-- Agents a human stopped. A row exists only for a stopped agent; resuming it (not built yet; it would need a card signed with Hello) would end it.
CREATE TABLE key_agents (
    owner_id    TEXT NOT NULL,
    label       TEXT NOT NULL,
    stopped_at  INTEGER NOT NULL,
    stopped_by  TEXT NOT NULL,
    key_id      TEXT NOT NULL REFERENCES keys (id),
    PRIMARY KEY (owner_id, label)
) STRICT, WITHOUT ROWID;
