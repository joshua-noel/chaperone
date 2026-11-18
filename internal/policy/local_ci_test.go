package policy

import (
	"strings"
	"testing"
)

// ADR-002 amendment 10: the `pr.local_ci` block and the ci.report op.

func TestProjectLocalCIBlock(t *testing.T) {
	cat, base := mustDefault(t)
	load := func(body string) (*Effective, error) {
		return base.LoadProject("chaperone", []byte("project: chaperone\npr:\n  repo: joshua-noel/chaperone\n  base: main\n"+body), cat)
	}

	eff, err := load("  local_ci:\n    mode: also\n")
	if err != nil {
		t.Fatal(err)
	}
	if l := eff.PR.LocalCI; l == nil || l.Mode != LocalCIAlso || l.Check != DefaultLocalCICheck {
		t.Errorf("also, default name: %+v", eff.PR.LocalCI)
	}
	eff, err = load("  local_ci:\n    mode: instead\n    check: room-ci\n")
	if err != nil {
		t.Fatal(err)
	}
	if l := eff.PR.LocalCI; l == nil || l.Mode != LocalCIInstead || l.Check != "room-ci" {
		t.Errorf("instead, named: %+v", eff.PR.LocalCI)
	}
	plain, err := base.LoadProject("chaperone", []byte("project: chaperone\npr:\n  repo: joshua-noel/chaperone\n  base: main\n"), cat)
	if err != nil {
		t.Fatal(err)
	}
	if eff.Enabled("ci.report") != plain.Enabled("ci.report") {
		t.Error("a local_ci block must not change whether ci.report is on; only the baseline does")
	}
	none, err := load("")
	if err != nil || none.PR.LocalCI != nil {
		t.Errorf("no local_ci block must stay nil: %+v, %v", none.PR.LocalCI, err)
	}

	for name, body := range map[string]string{
		"no mode":              "  local_ci:\n    check: local-ci\n",
		"unknown mode":         "  local_ci:\n    mode: replace\n",
		"unknown key":          "  local_ci:\n    mode: also\n    app_id: 15368\n",
		"check is verify":      "  local_ci:\n    mode: instead\n    check: verify\n",
		"check is an extra":    "  extra_checks: [lint]\n  local_ci:\n    mode: also\n    check: lint\n",
		"check with a newline": "  local_ci:\n    mode: also\n    check: \"a\\nb\"\n",
		"check too long":       "  local_ci:\n    mode: also\n    check: " + strings.Repeat("x", 65) + "\n",
		"check with spaces":    "  local_ci:\n    mode: also\n    check: \" local-ci\"\n",
	} {
		if _, err := load(body); err == nil {
			t.Errorf("%s: want refusal", name)
		}
	}
	// A local_ci block without a pr: block around it is not a key at all.
	if _, err := base.LoadProject("chaperone", []byte("project: chaperone\nlocal_ci:\n  mode: also\n"), cat); err == nil {
		t.Error("local_ci outside pr: must be refused")
	}
}

func TestCIReportIsOnAndOrchestratorOnly(t *testing.T) {
	cat, base := mustDefault(t)
	e, ok := cat.Lookup("ci.report")
	if !ok || e.Class != ClassRoutine || e.Reversibility != "reversible" || e.Surface != SurfaceOp {
		t.Fatalf("catalog entry: %+v %v", e, ok)
	}
	eff := base.ForProject("chaperone")
	if !eff.Enabled("ci.report") {
		t.Error("ci.report is on in the baseline (operator sign-off, 31 Oct 2026); it works only for a project with a pr.local_ci block")
	}
	// A project file can narrow it: switch it off for that project.
	if off, err := base.LoadProject("chaperone", []byte("project: chaperone\nops:\n  ci.report: { enabled: false }\n"), cat); err != nil || off.Enabled("ci.report") {
		t.Errorf("a project file must be able to switch ci.report off: %v", err)
	}
	// No profile's ceiling holds it: a run never reports a result, neither a ci run nor an agent's.
	for name := range base.Profiles {
		ceiling, _ := eff.ProfileCeiling(name)
		for _, op := range ceiling {
			if op == "ci.report" {
				t.Errorf("profile %s may ask for ci.report", name)
			}
		}
	}
	if ceiling, ok := eff.ProfileCeiling("ci"); !ok || len(ceiling) != 0 {
		t.Errorf("ci profile ceiling = %v, %v; a ci run asks for no op", ceiling, ok)
	}
}
