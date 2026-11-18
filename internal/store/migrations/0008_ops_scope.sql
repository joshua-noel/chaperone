-- The task scope a run asked under, kept on the op row.
--
-- chapd re-checks and releases an op after the request is answered, and by then
-- the run token is out of reach. The adapter must see the same scope it saw at
-- the request (repo, base, branch, paths), or a run's own pr.open fails its
-- scope check at release (SCOPE_PATH, first the runner run 25 Oct 2026). JSON:
-- {"repo":..,"base":..,"branch":..,"paths":[..]}. NULL for an orchestrator and
-- for a row written before this migration: both rebuild as "no scope", which a
-- run-scoped adapter refuses (fails closed).

ALTER TABLE ops ADD COLUMN scope_json TEXT;

-- Like the rest of an op's identity, the scope never changes after insert.
CREATE TRIGGER ops_scope_immutable
BEFORE UPDATE OF scope_json ON ops
WHEN OLD.scope_json IS NOT NEW.scope_json
BEGIN
    SELECT RAISE(ABORT, 'op scope is immutable');
END;
