-- 0007_phone: number matching for the phone passkey (ticket L1-22, ADR-004
-- section 5). Times named *_unix are Unix seconds.

-- The numbers of one approval card. code is the two-digit number the server card
-- shows; choices are the three numbers the phone page shows (code and two
-- decoys), comma separated, in the order shown. They are made once, so a reload
-- of the phone page cannot reveal the code by comparing two renders. Rows are
-- never changed or deleted: a card's numbers are part of what was decided.
CREATE TABLE approval_phone_numbers (
	approval_id  TEXT    PRIMARY KEY REFERENCES approvals (approval_id),
	code         TEXT    NOT NULL CHECK (code GLOB '[1-9][0-9]'),
	choices      TEXT    NOT NULL CHECK (choices GLOB '[1-9][0-9],[1-9][0-9],[1-9][0-9]'),
	created_unix INTEGER NOT NULL,
	CHECK (instr(choices, code) > 0)
) STRICT;

CREATE TRIGGER approval_phone_numbers_immutable BEFORE UPDATE ON approval_phone_numbers
BEGIN
	SELECT RAISE(ABORT, 'approval_phone_numbers: rows never change');
END;

CREATE TRIGGER approval_phone_numbers_no_delete BEFORE DELETE ON approval_phone_numbers
BEGIN
	SELECT RAISE(ABORT, 'approval_phone_numbers: rows are never deleted');
END;

-- A right number, chosen on the phone by one approver in one browser. The phone
-- decision (BeginDecision at the phone origin) takes this row; without it no
-- challenge is made. A wrong number never gets a row: it denies the card.
CREATE TABLE approval_phone_matches (
	approval_id      TEXT    NOT NULL REFERENCES approvals (approval_id),
	approver_row     INTEGER NOT NULL REFERENCES approvers (id),
	binding_sha256   BLOB    NOT NULL,
	valid_until_unix INTEGER NOT NULL,
	PRIMARY KEY (approval_id, approver_row, binding_sha256)
) STRICT;
