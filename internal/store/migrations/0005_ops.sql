-- L1-07: op lifecycle (internal/ops).
--
-- One row per operation request. The state column moves only along the edges
-- of ops_transitions; the trigger below refuses every other change, so a bug in
-- the Go code cannot, for example, resurrect a denied op. Each state change is
-- made in the same BEGIN IMMEDIATE transaction as its ledger event (ADR-006).

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
    requester_kind  TEXT NOT NULL CHECK (requester_kind IN ('run', 'orchestrator')),
    requester_key   TEXT NOT NULL,          -- 'run:<id>' or 'orchestrator:<id>'
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
    CHECK ((requester_kind = 'run' AND run_id IS NOT NULL AND orchestrator_id IS NULL)
        OR (requester_kind = 'orchestrator' AND orchestrator_id IS NOT NULL AND run_id IS NULL))
) STRICT;

CREATE INDEX ops_requester_time ON ops (requester_key, requested_at);
CREATE INDEX ops_requester_hash ON ops (requester_key, op_hash);
CREATE INDEX ops_state ON ops (state, expires_at);
CREATE INDEX ops_project_state ON ops (project, state);

-- One live op per caller and action: two simultaneous identical requests cannot
-- both insert (the idempotency rule, enforced by the database).
CREATE UNIQUE INDEX ops_one_live ON ops (requester_key, op_hash)
    WHERE state IN ('requested', 'pending_approval', 'allowed', 'executing', 'unconfirmed');

CREATE TABLE ops_transitions (
    from_state TEXT NOT NULL,
    to_state   TEXT NOT NULL,
    PRIMARY KEY (from_state, to_state)
) STRICT, WITHOUT ROWID;

INSERT INTO ops_transitions (from_state, to_state) VALUES
    ('requested', 'denied'),
    ('requested', 'pending_approval'),
    ('requested', 'allowed'),
    ('pending_approval', 'allowed'),
    ('pending_approval', 'denied'),
    ('pending_approval', 'expired'),
    ('pending_approval', 'cancelled'),
    ('allowed', 'executing'),
    ('allowed', 'refused'),
    ('allowed', 'expired'),
    ('allowed', 'cancelled'),
    ('executing', 'succeeded'),
    ('executing', 'failed'),
    ('executing', 'refused'),
    ('executing', 'unconfirmed'),
    ('unconfirmed', 'succeeded'),
    ('unconfirmed', 'failed');

CREATE TRIGGER ops_state_machine
BEFORE UPDATE OF state ON ops
WHEN OLD.state <> NEW.state
 AND NOT EXISTS (SELECT 1 FROM ops_transitions WHERE from_state = OLD.state AND to_state = NEW.state)
BEGIN
    SELECT RAISE(ABORT, 'illegal op state transition');
END;

-- The identity of an op never changes after insert.
CREATE TRIGGER ops_identity_immutable
BEFORE UPDATE OF id, op, project, target_adapter, target_ref, params_json, op_hash,
                 requester_kind, requester_key, run_id, orchestrator_id, requested_at ON ops
BEGIN
    SELECT RAISE(ABORT, 'op identity is immutable');
END;

CREATE TRIGGER ops_no_delete
BEFORE DELETE ON ops
BEGIN
    SELECT RAISE(ABORT, 'ops are never deleted');
END;

-- Denials, for the thrash counter: repeated refusals of the same
-- (surface, action) by one caller inside the policy window.
CREATE TABLE denials (
    denial_id     TEXT PRIMARY KEY,
    at            INTEGER NOT NULL,         -- unix seconds
    requester_key TEXT NOT NULL,
    project       TEXT NOT NULL,
    surface       TEXT NOT NULL,
    verb          TEXT NOT NULL,
    target        TEXT NOT NULL,
    cause_code    TEXT NOT NULL,
    request_id    TEXT
) STRICT;

CREATE INDEX denials_thrash ON denials (requester_key, surface, verb, target, at);
