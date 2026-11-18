-- 0003_ledger_events: the Chaperone ledger (ADR-006, ticket L1-02).
--
-- ledger_events holds each spec event as canonical (RFC 8785) JSON in `event`,
-- plus indexed copies of the fields queries need. The copies are checked
-- against `event` by `chap ledger verify`. The table is append-only: UPDATE and
-- DELETE abort. This stops bugs, not an attacker with file access; the hash
-- chain, the JSONL export and anchors cover that.
CREATE TABLE ledger_events (
	chain          TEXT    NOT NULL,
	seq            INTEGER NOT NULL,
	hash           TEXT    NOT NULL,
	prev_hash      TEXT    NOT NULL,
	time_unix_nano INTEGER NOT NULL,
	event_name     TEXT    NOT NULL,
	run_id         TEXT,
	event          TEXT    NOT NULL,
	PRIMARY KEY (chain, seq)
) STRICT, WITHOUT ROWID;

CREATE INDEX ledger_events_run  ON ledger_events (run_id, seq) WHERE run_id IS NOT NULL;
CREATE INDEX ledger_events_name ON ledger_events (event_name, time_unix_nano);
CREATE INDEX ledger_events_time ON ledger_events (time_unix_nano);

CREATE TRIGGER ledger_events_no_update BEFORE UPDATE ON ledger_events
BEGIN
	SELECT RAISE(ABORT, 'ledger_events is append-only: UPDATE refused');
END;

CREATE TRIGGER ledger_events_no_delete BEFORE DELETE ON ledger_events
BEGIN
	SELECT RAISE(ABORT, 'ledger_events is append-only: DELETE refused');
END;

-- ledger_chains keeps, per chain, the head the appender last committed and the
-- last event written to the JSONL export. Verify compares both with the
-- events, so a truncated tail (SQLite or export) is found even though a chain
-- alone cannot show it. Both marks only move forward, and only to an event
-- that exists.
CREATE TABLE ledger_chains (
	chain         TEXT    PRIMARY KEY,
	head_seq      INTEGER NOT NULL,
	head_hash     TEXT    NOT NULL,
	exported_seq  INTEGER NOT NULL DEFAULT -1,
	exported_hash TEXT    NOT NULL DEFAULT ''
) STRICT;

CREATE TRIGGER ledger_chains_no_delete BEFORE DELETE ON ledger_chains
BEGIN
	SELECT RAISE(ABORT, 'ledger_chains is append-only: DELETE refused');
END;

CREATE TRIGGER ledger_chains_guard BEFORE UPDATE ON ledger_chains
BEGIN
	SELECT CASE WHEN NEW.chain <> OLD.chain
		THEN RAISE(ABORT, 'ledger_chains: chain id is immutable') END;
	SELECT CASE WHEN NEW.head_seq < OLD.head_seq
		OR (NEW.head_seq = OLD.head_seq AND NEW.head_hash <> OLD.head_hash)
		OR (NEW.head_seq > OLD.head_seq AND NOT EXISTS (
			SELECT 1 FROM ledger_events
			WHERE chain = NEW.chain AND seq = NEW.head_seq AND hash = NEW.head_hash))
		THEN RAISE(ABORT, 'ledger_chains: head may only advance to an existing event') END;
	SELECT CASE WHEN NEW.exported_seq < OLD.exported_seq
		OR (NEW.exported_seq = OLD.exported_seq AND NEW.exported_hash <> OLD.exported_hash)
		OR (NEW.exported_seq > OLD.exported_seq AND NOT EXISTS (
			SELECT 1 FROM ledger_events
			WHERE chain = NEW.chain AND seq = NEW.exported_seq AND hash = NEW.exported_hash))
		THEN RAISE(ABORT, 'ledger_chains: export mark may only advance to an existing event') END;
END;
