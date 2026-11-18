-- 0006_approvals: the approvals engine (ticket L1-12, ADR-004).
-- Times named *_unix are Unix seconds (compared in SQL); the spec's own
-- documents carry RFC 3339 text and are stored whole in record_json.

-- One row per approval card. The request document, the policy checks and the
-- adapter's evidence are stored exactly as the card was made from them; card_text
-- is a pure function of those and display_sha256 is its SHA-256 (ADR-004
-- section 3). op_hash is the spec hash of the request (section 1).
--
-- state:  pending ─► approved ─► consumed
--            │           └─► expired | cancelled
--            └─► denied | expired | cancelled
-- Single use is the compare-and-set `UPDATE ... WHERE state = 'approved'`
-- inside one BEGIN IMMEDIATE transaction; the triggers below stop a bug from
-- taking any other path.
CREATE TABLE approvals (
	approval_id          TEXT    PRIMARY KEY CHECK (approval_id GLOB 'a-*'),
	request_id           TEXT    NOT NULL UNIQUE CHECK (request_id GLOB 'q-*'),
	requester_kind       TEXT    NOT NULL CHECK (requester_kind IN ('run', 'orchestrator')),
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
	-- set by a decision (approved or denied):
	decided_unix         INTEGER,
	approver             TEXT,
	reason               TEXT,
	approval_expires_unix INTEGER,
	nonce                TEXT,
	challenge_sha256     TEXT,
	record_json          TEXT,
	-- set when the op was released:
	consumed_unix        INTEGER,
	CHECK (state NOT IN ('approved', 'denied', 'consumed') OR (decided_unix IS NOT NULL AND approver IS NOT NULL
		AND nonce IS NOT NULL AND challenge_sha256 IS NOT NULL AND record_json IS NOT NULL)),
	CHECK ((state = 'consumed') = (consumed_unix IS NOT NULL))
) STRICT;

-- At most one live card per caller and op hash: the dedupe of ADR-004 section 6.
CREATE UNIQUE INDEX approvals_one_pending ON approvals (op_hash, requester_kind, requester_key) WHERE state = 'pending';
CREATE INDEX approvals_state ON approvals (state, request_expires_unix);
CREATE INDEX approvals_op_hash ON approvals (op_hash, decided_unix);
CREATE INDEX approvals_requester ON approvals (requester_kind, requester_key, state);
CREATE INDEX approvals_project ON approvals (project, state);

CREATE TRIGGER approvals_no_delete BEFORE DELETE ON approvals
BEGIN
	SELECT RAISE(ABORT, 'approvals: rows are never deleted');
END;

-- The request and its card never change after the row exists.
CREATE TRIGGER approvals_immutable BEFORE UPDATE ON approvals
WHEN NEW.approval_id IS NOT OLD.approval_id OR NEW.request_id IS NOT OLD.request_id
	OR NEW.requester_kind IS NOT OLD.requester_kind OR NEW.requester_key IS NOT OLD.requester_key
	OR NEW.run_id IS NOT OLD.run_id OR NEW.project IS NOT OLD.project OR NEW.op IS NOT OLD.op
	OR NEW.op_hash IS NOT OLD.op_hash OR NEW.class IS NOT OLD.class OR NEW.policy_version IS NOT OLD.policy_version
	OR NEW.request_json IS NOT OLD.request_json OR NEW.checks_json IS NOT OLD.checks_json
	OR NEW.evidence_json IS NOT OLD.evidence_json OR NEW.card_text IS NOT OLD.card_text
	OR NEW.display_sha256 IS NOT OLD.display_sha256 OR NEW.created_unix IS NOT OLD.created_unix
	OR NEW.request_expires_unix IS NOT OLD.request_expires_unix
BEGIN
	SELECT RAISE(ABORT, 'approvals: the request and its card are immutable');
END;

-- Only the transitions in the diagram above; a terminal row never changes, and
-- a decision, once recorded, is never rewritten.
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

-- A decision challenge in flight (ADR-004 section 1). id is the random handle
-- the browser holds; challenge_sha256 is spec.ApprovalChallenge over the
-- approval, the decision, the approver, this nonce and approval_expires. It
-- is single use: the finish step deletes the row before it reads the
-- response. binding_sha256 ties it to the browser that began it (the csrf
-- cookie), as console_ceremonies does.
CREATE TABLE approval_challenges (
	id                    BLOB    PRIMARY KEY CHECK (length(id) = 16),
	approval_id           TEXT    NOT NULL REFERENCES approvals (approval_id),
	decision              TEXT    NOT NULL CHECK (decision = 'approved'),
	approver              TEXT    NOT NULL,
	approver_row          INTEGER NOT NULL REFERENCES approvers (id),
	origin                TEXT    NOT NULL,
	binding_sha256        BLOB    NOT NULL,
	nonce                 TEXT    NOT NULL,
	challenge_sha256      TEXT    NOT NULL,
	approval_expires_unix INTEGER NOT NULL,
	valid_until_unix      INTEGER NOT NULL
) STRICT;
CREATE INDEX approval_challenges_approval ON approval_challenges (approval_id);

-- The signed assertion that approved a card, kept as received, next to the
-- ledger (ADR-004 section 1). assertion_sha256 is the value the approval
-- record's confirmations carry. Insert only.
CREATE TABLE approval_assertions (
	approval_id      TEXT PRIMARY KEY REFERENCES approvals (approval_id),
	channel          TEXT NOT NULL CHECK (channel IN ('pc', 'phone')),
	credential_id    BLOB NOT NULL,
	rp_id            TEXT NOT NULL,
	origin           TEXT NOT NULL,
	assertion_json   BLOB NOT NULL,
	assertion_sha256 TEXT NOT NULL CHECK (assertion_sha256 GLOB 'sha256:*'),
	created_at       TEXT NOT NULL
) STRICT;

CREATE TRIGGER approval_assertions_no_update BEFORE UPDATE ON approval_assertions
BEGIN
	SELECT RAISE(ABORT, 'approval_assertions is insert-only');
END;

CREATE TRIGGER approval_assertions_no_delete BEFORE DELETE ON approval_assertions
BEGIN
	SELECT RAISE(ABORT, 'approval_assertions is insert-only');
END;
