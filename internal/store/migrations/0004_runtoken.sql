-- 0004_runtoken: run registry, revoked token ids, single-use control token ids
-- and orchestrator tokens (ADR-005, ADR-007; ticket L1-04). Times are Unix
-- seconds.

-- One row per registered run. claims_json is the grant Chaperone recorded (the
-- verified claims at registration); claims_sha256 is SHA-256 of their JCS form,
-- compared on every request so a token whose scope differs is TOKEN_INVALID.
CREATE TABLE runs (
	run_id          TEXT PRIMARY KEY,
	jti             TEXT NOT NULL UNIQUE,
	project         TEXT NOT NULL,
	profile_name    TEXT NOT NULL,
	profile_version TEXT NOT NULL,
	issuer          TEXT NOT NULL,
	kid             TEXT NOT NULL,
	interim         INTEGER NOT NULL CHECK (interim IN (0, 1)),
	iat             INTEGER NOT NULL,
	exp             INTEGER NOT NULL,
	claims_json     TEXT NOT NULL,
	claims_sha256   TEXT NOT NULL,
	state           TEXT NOT NULL CHECK (state IN ('active', 'ended')),
	registered_at   INTEGER NOT NULL,
	ended_at        INTEGER,
	end_reason      TEXT CHECK (end_reason IN ('run_end', 'stop', 'operator')),
	end_cause_code  TEXT,
	CHECK ((state = 'active') = (ended_at IS NULL))
) STRICT;

CREATE INDEX runs_active_exp ON runs (exp) WHERE state = 'active';

-- Token ids that are refused until exp. A row is written in the same
-- transaction that ends the run; the reaper deletes it once exp is long past.
CREATE TABLE revoked_jti (
	jti        TEXT PRIMARY KEY,
	run_id     TEXT NOT NULL,
	exp        INTEGER NOT NULL,
	revoked_at INTEGER NOT NULL,
	reason     TEXT NOT NULL,
	cause_code TEXT
) STRICT;

-- jti of every control token seen: single use (ADR-005 "Registration").
CREATE TABLE control_jti (
	jti  TEXT PRIMARY KEY,
	exp  INTEGER NOT NULL,
	seen INTEGER NOT NULL
) STRICT;

-- Orchestrator tokens (ADR-007). Only SHA-256 of the token is stored. An id
-- has at most one live (not revoked) token: issuing again revokes the first.
CREATE TABLE orchestrators (
	token_sha256 TEXT PRIMARY KEY CHECK (length(token_sha256) = 64),
	id           TEXT NOT NULL,
	scope        TEXT NOT NULL,
	issued_at    INTEGER NOT NULL,
	expires_at   INTEGER NOT NULL,
	revoked_at   INTEGER,
	revoked_by   TEXT,
	CHECK (expires_at > issued_at),
	CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
) STRICT;

CREATE UNIQUE INDEX orchestrators_live_id ON orchestrators (id) WHERE revoked_at IS NULL;
