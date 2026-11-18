-- 0002_console_approvers: approvers, their WebAuthn credentials, console
-- sessions, single-use ceremony challenges and enrolment tokens (ticket L1-06,
-- ADR-004). Times named *_unix are Unix seconds (compared in SQL); created_at
-- is RFC 3339 text for people.

-- One row per person who may approve. user_handle is the WebAuthn user.id
-- (32 random bytes, never shown); it is stored once here, not per credential.
CREATE TABLE approvers (
	id          INTEGER PRIMARY KEY,
	user_handle BLOB NOT NULL UNIQUE CHECK (length(user_handle) = 32),
	name        TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
	created_at  TEXT NOT NULL,
	disabled_at TEXT
) STRICT;

-- One row per passkey. rp_id and origin are the ones the credential was
-- registered at; an assertion is only accepted at that same origin (ADR-004
-- section 1: the server stores rp_id and origin per credential from day one).
-- user_verified is always 1: registration without user verification is refused,
-- and the CHECK keeps a hand-edited row from lowering the bar.
CREATE TABLE credentials (
	id                 INTEGER PRIMARY KEY,
	approver_id        INTEGER NOT NULL REFERENCES approvers (id),
	credential_id      BLOB NOT NULL UNIQUE,
	rp_id              TEXT NOT NULL,
	origin             TEXT NOT NULL,
	public_key         BLOB NOT NULL,
	attestation_type   TEXT NOT NULL,
	attestation_format TEXT NOT NULL,
	aaguid             BLOB NOT NULL,
	transports         TEXT NOT NULL,
	attachment         TEXT NOT NULL,
	sign_count         INTEGER NOT NULL CHECK (sign_count >= 0),
	user_verified      INTEGER NOT NULL CHECK (user_verified = 1),
	backup_eligible    INTEGER NOT NULL CHECK (backup_eligible IN (0, 1)),
	backup_state       INTEGER NOT NULL CHECK (backup_state IN (0, 1)),
	label              TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 64),
	created_at         TEXT NOT NULL,
	last_used_at       TEXT,
	revoked_at         TEXT
) STRICT;
CREATE INDEX credentials_approver ON credentials (approver_id);

-- A console session, made by one verified Hello (or passkey) assertion. Only
-- the SHA-256 of the cookie value is stored.
CREATE TABLE console_sessions (
	token_sha256 BLOB PRIMARY KEY CHECK (length(token_sha256) = 32),
	approver_id  INTEGER NOT NULL REFERENCES approvers (id),
	credential   INTEGER NOT NULL REFERENCES credentials (id),
	origin       TEXT NOT NULL,
	created_at   TEXT NOT NULL,
	last_seen_unix INTEGER NOT NULL,
	expires_unix   INTEGER NOT NULL,
	revoked_at   TEXT
) STRICT;

-- A WebAuthn ceremony in flight: the go-webauthn SessionData (challenge,
-- rp id, origin, user verification requirement) as JSON. Single use: Finish
-- deletes the row before it looks at the response, so a replayed or retried
-- response finds nothing. csrf_sha256 binds the ceremony to the browser that
-- started it.
CREATE TABLE console_ceremonies (
	id             BLOB PRIMARY KEY CHECK (length(id) = 16),
	kind           TEXT NOT NULL CHECK (kind IN ('register', 'login')),
	origin         TEXT NOT NULL,
	csrf_sha256    BLOB NOT NULL,
	session_json   TEXT NOT NULL,
	approver_id    INTEGER REFERENCES approvers (id),
	new_user_handle BLOB,
	approver_name  TEXT,
	credential_label TEXT,
	enrollment_sha256 BLOB,
	expires_unix   INTEGER NOT NULL
) STRICT;

-- A one-time enrolment token from `chapd enroll` (H3). approver_id NULL means
-- "create the first approver"; set, it adds a credential (a phone passkey,
-- ADR-004 section 5) to that approver. Only the SHA-256 is stored.
CREATE TABLE console_enrollments (
	token_sha256 BLOB PRIMARY KEY CHECK (length(token_sha256) = 32),
	approver_id  INTEGER REFERENCES approvers (id),
	created_at   TEXT NOT NULL,
	expires_unix INTEGER NOT NULL,
	used_at      TEXT
) STRICT;
