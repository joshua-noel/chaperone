package policy

import (
	"strings"
	"testing"
)

func linearProject(t *testing.T, block string) (*Effective, error) {
	t.Helper()
	cat, base, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	return base.LoadProject("acme-shop", []byte("project: acme-shop\n"+block), cat)
}

func TestLinearBlockLoads(t *testing.T) {
	eff, err := linearProject(t, `
linear:
  team: SHOP
  label: claude
  states:
    - Handed to engineering
    - In Progress
    - Blocked
    - Completed
`)
	if err != nil {
		t.Fatal(err)
	}
	l := eff.Linear
	if l == nil || l.Team != "SHOP" || l.Label != "claude" || len(l.States) != 4 {
		t.Fatalf("block: %+v", l)
	}
	if s, ok := l.StateAllowed("blocked"); !ok || s != "Blocked" {
		t.Errorf("StateAllowed(blocked) = %q %v", s, ok)
	}
	if _, ok := l.StateAllowed("Done"); ok {
		t.Error("an unlisted state is allowed")
	}
	// The block adds data and changes no op's enablement: the baseline alone decides.
	cat, base := mustDefault(t)
	plain, err := base.LoadProject("acme-shop", []byte("project: acme-shop\n"), cat)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"intake.list", "intake.comment", "intake.move", "intake.states"} {
		if eff.Enabled(op) != plain.Enabled(op) {
			t.Errorf("%s: the linear block changed its enablement", op)
		}
	}
	// No block: nil, and the adapters refuse the project.
	if eff, err := linearProject(t, ""); err != nil || eff.Linear != nil {
		t.Errorf("no block: %v %v", eff.Linear, err)
	}
}

func TestLinearBlockWithNoStatesIsValid(t *testing.T) {
	// The shipped placeholder: the operator has not confirmed the state names yet.
	eff, err := linearProject(t, "linear:\n  team: SHOP\n  label: claude\n  states: []\n")
	if err != nil || eff.Linear == nil || len(eff.Linear.States) != 0 {
		t.Fatalf("%v %+v", err, eff)
	}
}

func TestLinearBlockIsValidated(t *testing.T) {
	long := strings.Repeat("a", LinearMaxState+1)
	for name, c := range map[string]struct{ block, want string }{
		"no team":                {"linear:\n  label: claude\n", "team"},
		"lower-case team":        {"linear:\n  team: ops\n  label: claude\n", "team"},
		"team name, not key":     {"linear:\n  team: Operations\n  label: claude\n", "team"},
		"engineering mirror key": {"linear:\n  team: ENG\n  label: claude\n", "Engineering"},
		"no label":               {"linear:\n  team: SHOP\n", "label"},
		"label with spaces":      {"linear:\n  team: SHOP\n  label: \" claude\"\n", "label"},
		"label control char":     {"linear:\n  team: SHOP\n  label: \"cla\\x07ude\"\n", "control"},
		"blank state":            {"linear:\n  team: SHOP\n  label: claude\n  states: [\"\"]\n", "states"},
		"state too long":         {"linear:\n  team: SHOP\n  label: claude\n  states: [" + long + "]\n", "states"},
		"duplicate state":        {"linear:\n  team: SHOP\n  label: claude\n  states: [Blocked, blocked]\n", "twice"},
		"too many states":        {"linear:\n  team: SHOP\n  label: claude\n  states: [" + strings.TrimSuffix(strings.Repeat("s,", LinearMaxStates+1), ",") + "]\n", "at most"},
		"two teams":              {"linear:\n  team: SHOP\n  team: HR\n  label: claude\n", ""},
		"unknown key":            {"linear:\n  team: SHOP\n  label: claude\n  remove_label: true\n", ""},
		"a second label":         {"linear:\n  team: SHOP\n  label: claude\n  labels: [a]\n", ""},
	} {
		_, err := linearProject(t, c.block)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), "linear") && c.want != "" || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestIntakeOpsShipOnAndOutsideEveryProfile(t *testing.T) {
	cat, base, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	eff := base.ForProject("acme-shop")
	for _, op := range []string{"intake.list", "intake.comment", "intake.move", "intake.states"} {
		e, ok := cat.Lookup(op)
		if !ok || e.Class != ClassRoutine {
			t.Errorf("%s: catalog entry %+v", op, e)
		}
		if !eff.Enabled(op) {
			t.Errorf("%s is off in the shipped baseline (on since the policy PR of 31 Oct 2026)", op)
		}
		if eff.Rate(op) < 1 {
			t.Errorf("%s has no rate", op)
		}
		for name, allow := range eff.Profiles {
			for _, a := range allow {
				if a == op {
					t.Errorf("profile %s lists %s: a run could ask", name, op)
				}
			}
		}
	}
}
