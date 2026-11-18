-- How a run ended: done, failed, killed or blocked (the outcome the runner names in its end call, or killed for a
-- stop, an operator revoke and the reaper).
--
-- It was only in the run.end ledger event. `ci.report` (ADR-002 amendment 10) states a CI run's result on GitHub, and
-- it must take that result from chapd's own record of the run, never from the caller, so the outcome is kept on the
-- row. NULL for a run that is still active and for a run that ended before this migration (ci.report refuses those).

ALTER TABLE runs ADD COLUMN end_outcome TEXT CHECK (end_outcome IN ('done', 'failed', 'killed', 'blocked'));

-- Like the rest of how a run ended, it is written once, with the end.
CREATE TRIGGER runs_end_outcome_once
BEFORE UPDATE OF end_outcome ON runs
WHEN OLD.end_outcome IS NOT NULL AND OLD.end_outcome IS NOT NEW.end_outcome
BEGIN
    SELECT RAISE(ABORT, 'a run''s outcome is written once');
END;
