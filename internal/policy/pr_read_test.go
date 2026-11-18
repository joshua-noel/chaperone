package policy

import "testing"

var prReadOps = []string{"pr.view", "pr.diff", "pr.checks", "pr.files"}

// ADR-002 amendment 12: the four read ops are on in the shipped baseline, as routine, reversible reads (the operator's policy PR).
func TestPRReadOpsShipOnAsRoutineReads(t *testing.T) {
	cat, base := mustDefault(t)
	eff := base.ForProject("acme-shop")
	for _, op := range prReadOps {
		e, ok := cat.Lookup(op)
		if !ok || e.Class != ClassRoutine || e.Reversibility != "reversible" || e.Surface != SurfaceOp {
			t.Errorf("%s: catalog entry %+v, want a routine, reversible op", op, e)
		}
		rule, ok := base.Ops[op]
		if !ok || !rule.Enabled || !eff.Enabled(op) {
			t.Errorf("%s: rule %+v enabled=%v; the baseline must carry a rule that is on", op, rule, eff.Enabled(op))
		}
		if rule.RatePerMinute < 1 || rule.RatePerHour < rule.RatePerMinute {
			t.Errorf("%s: %d per minute, %d per hour: each read op carries both caps", op, rule.RatePerMinute, rule.RatePerHour)
		}
		// No run profile may ever ask for them: the orchestrator token (and later a the dashboard client) only.
		for name, allow := range eff.Profiles {
			for _, a := range allow {
				if a == op {
					t.Errorf("profile %s lists %s", name, op)
				}
			}
		}
	}
	// The diff is the dearest read: it gets the smallest caps.
	for _, op := range []string{"pr.view", "pr.checks", "pr.files"} {
		if base.Ops["pr.diff"].RatePerMinute >= base.Ops[op].RatePerMinute || base.Ops["pr.diff"].RatePerHour >= base.Ops[op].RatePerHour {
			t.Errorf("pr.diff caps %+v are not below %s caps %+v", base.Ops["pr.diff"], op, base.Ops[op])
		}
	}
}

// A project file cannot lift a cap; it can lower a cap or turn a read op off for the project (it can never turn one on).
func TestPRReadOpsProjectFileOnlyNarrows(t *testing.T) {
	cat, base := mustDefault(t)
	off, err := base.LoadProject("acme-shop", []byte("project: acme-shop\nops:\n  pr.view: { enabled: false }\n"), cat)
	if err != nil {
		t.Fatal(err)
	}
	if off.Enabled("pr.view") || !off.Enabled("pr.diff") {
		t.Errorf("a project file turned pr.view off: pr.view enabled=%v, pr.diff enabled=%v", off.Enabled("pr.view"), off.Enabled("pr.diff"))
	}
	if _, err := base.LoadProject("acme-shop", []byte("project: acme-shop\nops:\n  pr.diff: { rate_per_hour: 9999 }\n"), cat); err == nil {
		t.Error("a project file lifted the hourly cap of pr.diff")
	}
	// A project may lower both caps (the ops stay on: the baseline decides that).
	narrow, err := base.LoadProject("acme-shop", []byte("project: acme-shop\nops:\n  pr.diff: { rate_per_minute: 2, rate_per_hour: 10 }\n"), cat)
	if err != nil {
		t.Fatal(err)
	}
	if narrow.Rate("pr.diff") != 2 || narrow.RateHour("pr.diff") != 10 || !narrow.Enabled("pr.diff") {
		t.Errorf("narrowed pr.diff: %d per minute, %d per hour, enabled=%v", narrow.Rate("pr.diff"), narrow.RateHour("pr.diff"), narrow.Enabled("pr.diff"))
	}
}
