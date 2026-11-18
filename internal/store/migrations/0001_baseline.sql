-- 0001_baseline: the first migration. A key/value table for facts about this
-- database itself (for example the ledger chain id, ticket L1-02).
CREATE TABLE store_meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
) STRICT;
