package runtoken

import (
	"context"
	"testing"
)

// Migration 0009: the row of an ended run keeps how it ended. ci.report (ADR-002 amendment 10) reads its
// conclusion from it, never from the caller.

func endWith(e *env, runID, outcome, cause string) error {
	return e.runs.End(context.Background(), EndRequest{Control: e.ctl(actRunEnd, runID), RunID: runID, Outcome: outcome, CauseCode: cause})
}

func TestRunRecordKeepsHowTheRunEnded(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	c := e.claims()
	e.register(c)
	if rec, err := e.runs.Get(ctx, c.RunID); err != nil || rec.EndOutcome != "" {
		t.Fatalf("an active run has no outcome: %+v %v", rec, err)
	}
	mustNil(t, e.end(c.RunID))
	if rec, _ := e.runs.Get(ctx, c.RunID); rec.EndOutcome != "done" {
		t.Errorf("end without an outcome: %q, want done", rec.EndOutcome)
	}
	// A second end changes nothing, even with another outcome.
	mustNil(t, endWith(e, c.RunID, "failed", ""))
	if rec, _ := e.runs.Get(ctx, c.RunID); rec.EndOutcome != "done" {
		t.Errorf("a second end rewrote the outcome: %q", rec.EndOutcome)
	}

	for i, o := range []string{"failed", "blocked"} {
		x := e.claims()
		x.RunID, x.Sub, x.JTI = "r-4d4"+string(rune('a'+i)), "run:r-4d4"+string(rune('a'+i)), "dddddddddddddddddddddd"[:21]+string(rune('a'+i))
		x.TaskScope.Branch = "agent/" + x.RunID
		e.register(x)
		mustNil(t, endWith(e, x.RunID, o, ""))
		if rec, _ := e.runs.Get(ctx, x.RunID); rec.EndOutcome != o {
			t.Errorf("outcome %q recorded as %q", o, rec.EndOutcome)
		}
	}

	// An operator revoke is killed.
	k := e.claims()
	k.RunID, k.Sub, k.JTI = "r-5e5e", "run:r-5e5e", "eeeeeeeeeeeeeeeeeeeeee"
	k.TaskScope.Branch = "agent/r-5e5e"
	e.register(k)
	mustNil(t, e.runs.Revoke(ctx, k.RunID, StopOperatorStopRun))
	if rec, _ := e.runs.Get(ctx, k.RunID); rec.EndOutcome != "killed" {
		t.Errorf("operator revoke recorded as %q, want killed", rec.EndOutcome)
	}
}

func TestRunOutcomeIsWrittenOnce(t *testing.T) {
	e := newEnv(t)
	c := e.claims()
	e.register(c)
	mustNil(t, endWith(e, c.RunID, "failed", ""))
	_, err := e.db.SQL().Exec(`UPDATE runs SET end_outcome = 'done' WHERE run_id = ?`, c.RunID)
	if err == nil {
		t.Fatal("a run's outcome was rewritten")
	}
	if _, err := e.db.SQL().Exec(`UPDATE runs SET end_outcome = 'bogus' WHERE run_id = ?`, c.RunID); err == nil {
		t.Fatal("an outcome outside the set was accepted")
	}
}
