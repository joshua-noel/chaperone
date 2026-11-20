package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustDefault(t *testing.T) (*Catalog, *Pack) {
	t.Helper()
	cat, base, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	return cat, base
}

// shippedEnabled is every op the shipped baseline turns on. Enabling an op is a
// policy PR, and this list is the tripwire for that PR: add the op here.
var shippedEnabled = map[string]bool{
	"pr.merge":    true, // L1-10; the adapter refuses a project with no `pr:` block
	"pr.update":   true, // L1-10; same
	"pr.open":     true, // L1-09; a run opens a PR from its own branch; the adapter refuses any other head
	"branch.push": true, // L1-09; the git proxy admits one push to the task branch, nothing else
	// The error watcher's orchestrator token only, no profile lists them, the adapter needs the label source:error-watcher
	"issue.open":    true,
	"issue.comment": true,
	"issue.reopen":  true,
	// ADR-002 amendment 10; the orchestrator's token only; it works only for a project whose `pr:` block has `local_ci`
	"ci.report": true,
	// The orchestrator's token only; each needs the project's `linear:` block and the vault's Linear secrets
	"intake.list":    true,
	"intake.comment": true,
	"intake.move":    true,
	"intake.states":  true,
	// ADR-002 amendment 12; read-only; the orchestrator's token only; each works only for a project whose `pr:` block names the repository
	"pr.view":   true,
	"pr.diff":   true,
	"pr.checks": true,
	"pr.files":  true,
}

func TestOnlyShippedOpsEnabledByDefault(t *testing.T) {
	cat, base := mustDefault(t)
	eff := base.ForProject("acme-shop")
	for _, op := range cat.Ops() {
		if eff.Enabled(op) != shippedEnabled[op] {
			t.Errorf("%s: enabled=%v in the shipped baseline, want %v; enabling is a policy PR and this test is the tripwire for that PR (update shippedEnabled there)", op, eff.Enabled(op), shippedEnabled[op])
		}
	}
	if eff.PR != nil {
		t.Error("the baseline has no pr: block; only a project file can have one")
	}
	// Every op of the catalog has a baseline rule, so "disabled" is explicit.
	for _, op := range cat.Ops() {
		if _, ok := base.Ops[op]; !ok {
			t.Errorf("no baseline rule for %s", op)
		}
	}
}

func TestClassesAndCriticalOps(t *testing.T) {
	cat, _ := mustDefault(t)
	want := map[string]Class{
		"pr.open": ClassRoutine, "branch.push": ClassRoutine, "health": ClassRoutine, "logs": ClassRoutine,
		"pr.merge": ClassGated, "keys.issue": ClassHigh,
		"deploy": ClassHigh, "mail.send": ClassHigh, "drive.share": ClassHigh, "data.apply": ClassHigh,
		"repo.settings": ClassCritical, "secrets.write": ClassCritical, "host.scripts.refresh": ClassCritical,
	}
	for op, class := range want {
		e, ok := cat.Lookup(op)
		if !ok || e.Class != class {
			t.Errorf("%s: class %q, want %q", op, e.Class, class)
		}
	}
	if !ClassHigh.NeedsApproval() || !ClassCritical.NeedsApproval() || ClassRoutine.NeedsApproval() || ClassGated.NeedsApproval() {
		t.Error("NeedsApproval is wrong")
	}
}

func TestCatalogRefusesDemotedCriticalOp(t *testing.T) {
	src := `version: 1
ops:
  secrets.write:
    class: high
    reversibility: compensable
    surface: op
    summary: x
    usage: y
`
	if _, err := LoadCatalog([]byte(src)); err == nil || !strings.Contains(err.Error(), "critical") {
		t.Fatalf("want critical error, got %v", err)
	}
	src = strings.Replace(src, "secrets.write", "secrets.rotate", 1)
	if _, err := LoadCatalog([]byte(src)); err == nil {
		t.Fatal("any secrets.* op must be critical")
	}
}

// enabledBase is a baseline with pr.merge and health on, to test narrowing.
func enabledBase(t *testing.T) (*Catalog, *Pack) {
	t.Helper()
	cat, base := mustDefault(t)
	src := string(BaselineBytes())
	src = strings.Replace(src, "health:               { enabled: false", "health:               { enabled: true", 1)
	p, err := LoadBaseline([]byte(src), cat)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Ops["pr.merge"].Enabled || !p.Ops["health"].Enabled || base.Ops["health"].Enabled {
		t.Fatal("test baseline was not built")
	}
	return cat, p
}

func TestProjectNarrowsOnly(t *testing.T) {
	cat, base := enabledBase(t)
	good := `project: acme-shop
ops:
  pr.merge: { enabled: false }
  health: { rate_per_minute: 2 }
limits:
  thrash: { threshold: 2, window_seconds: 600 }
  pending: { per_run: 1 }
profiles:
  code: [pr.open]
`
	eff, err := base.LoadProject("acme-shop", []byte(good), cat)
	if err != nil {
		t.Fatal(err)
	}
	if eff.Enabled("pr.merge") || !eff.Enabled("health") || eff.Rate("health") != 2 {
		t.Errorf("narrowing not applied: %+v", eff.Ops["pr.merge"])
	}
	if eff.Limits.Thrash.Threshold != 2 || eff.Limits.Thrash.WindowSeconds != 600 || eff.Limits.Pending.PerRun != 1 {
		t.Errorf("limits not narrowed: %+v", eff.Limits)
	}
	if got, _ := eff.ProfileCeiling("code"); len(got) != 1 || got[0] != "pr.open" {
		t.Errorf("profile not narrowed: %v", got)
	}
	if eff.Version == base.ForProject("acme-shop").Version {
		t.Error("a project file must change policy_version")
	}
	if len(eff.Version) > 64 {
		t.Errorf("policy_version %q is longer than 64", eff.Version)
	}

	bad := map[string]string{
		"enable an op the baseline has off": "ops:\n  deploy: { enabled: true }\n",
		"raise a rate":                      "ops:\n  health: { rate_per_minute: 99 }\n",
		"raise an hourly cap":               "ops:\n  issue.open: { rate_per_hour: 21 }\n",
		"raise a cap":                       "limits:\n  pending: { total: 99 }\n",
		"raise the thrash threshold":        "limits:\n  thrash: { threshold: 9 }\n",
		"shorten the thrash window":         "limits:\n  thrash: { window_seconds: 10 }\n",
		"gain a profile op":                 "profiles:\n  docs: [pr.merge]\n",
		"unknown op":                        "ops:\n  nuke: { enabled: false }\n",
		"unknown key":                       "extra: 1\n",
		"unknown profile":                   "profiles:\n  wizard: [health]\n",
	}
	for name, body := range bad {
		if _, err := base.LoadProject("acme-shop", []byte("project: acme-shop\n"+body), cat); err == nil {
			t.Errorf("%s: want refusal", name)
		}
	}
	if _, err := base.LoadProject("acme-shop", []byte("project: other-shop\n"), cat); err == nil {
		t.Error("project name mismatch must be refused")
	}
	if _, err := base.LoadProject("acme-shop", []byte("project: acme-shop\n---\nproject: acme-shop\n"), cat); err == nil {
		t.Error("second YAML document must be refused")
	}
}

func TestPolicyVersionChangesWithBytes(t *testing.T) {
	cat, base := mustDefault(t)
	v1 := base.ForProject("acme-shop").Version
	changed := strings.Replace(string(BaselineBytes()), "per_run: 2", "per_run: 3", 1)
	p2, err := LoadBaseline([]byte(changed), cat)
	if err != nil {
		t.Fatal(err)
	}
	if p2.ForProject("acme-shop").Version == v1 {
		t.Error("same label, different bytes: version must differ")
	}
	if !strings.HasPrefix(v1, "baseline-2026.10.1+") {
		t.Errorf("version %q does not start with the label", v1)
	}
}

func TestEngineReloadsAndFailsClosed(t *testing.T) {
	cat, base := enabledBase(t)
	dir := t.TempDir()
	eng := NewEngine(cat, base, dir)
	clock := time.Unix(1_800_000_000, 0)
	eng.now = func() time.Time { return clock }

	v0 := eng.For("acme-shop").Version // no file: baseline
	if !eng.For("acme-shop").Enabled("health") {
		t.Fatal("baseline health should be enabled")
	}
	path := filepath.Join(dir, "acme-shop.yaml")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		clock = clock.Add(2 * time.Second)
	}
	write("project: acme-shop\nops:\n  health: { enabled: false }\n")
	eff := eng.For("acme-shop")
	if eff.Enabled("health") || eff.Version == v0 {
		t.Errorf("file not picked up: %+v", eff)
	}
	write("project: acme-shop\nops:\n  health: { enabled: true }\n  deploy: { enabled: true }\n")
	eff = eng.For("acme-shop")
	if eff.Invalid == nil || eff.Enabled("health") || eff.Enabled("pr.merge") {
		t.Errorf("an invalid file must disable every op of the project: %+v", eff)
	}
	if !strings.HasSuffix(eff.Version, "+invalid") {
		t.Errorf("version %q", eff.Version)
	}
	// Another project is unaffected.
	if !eng.For("other-shop").Enabled("health") {
		t.Error("other project lost the baseline")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(2 * time.Second)
	if eff = eng.For("acme-shop"); eff.Invalid != nil || !eff.Enabled("health") {
		t.Errorf("removing the file returns the baseline: %+v", eff)
	}
}

func TestProjectPRBlock(t *testing.T) {
	cat, base := mustDefault(t)
	good := `project: storefront
pr:
  repo: example-org/storefront
  base: feat/d1-private-pilot
  extra_checks: [lint]
  tiers:
    high: ["db/**"]
    low: ["notes/**"]
`
	eff, err := base.LoadProject("storefront", []byte(good), cat)
	if err != nil {
		t.Fatal(err)
	}
	if eff.PR == nil || eff.PR.Repo != "example-org/storefront" || eff.PR.Base != "feat/d1-private-pilot" || len(eff.PR.ExtraChecks) != 1 ||
		len(eff.PR.Tiers.High) != 1 || len(eff.PR.Tiers.Low) != 1 || len(eff.PR.Tiers.Medium) != 0 {
		t.Errorf("pr block not read: %+v", eff.PR)
	}
	if !eff.Enabled("pr.merge") {
		t.Error("a pr: block must not change which ops are enabled")
	}
	none, err := base.LoadProject("storefront", []byte("project: storefront\n"), cat)
	if err != nil || none.PR != nil {
		t.Errorf("no pr: block must stay nil: %+v, %v", none, err)
	}
	for name, body := range map[string]string{
		"no repo":      "pr:\n  base: main\n",
		"bad repo":     "pr:\n  repo: just-a-name\n  base: main\n",
		"no base":      "pr:\n  repo: o/r\n  extra_checks: [lint]\n",
		"base spaces":  "pr:\n  repo: o/r\n  base: a b\n",
		"empty check":  "pr:\n  repo: o/r\n  base: main\n  extra_checks: [\"\"]\n",
		"unknown key":  "pr:\n  repo: o/r\n  base: main\n  merge_method: rebase\n",
		"unknown tier": "pr:\n  repo: o/r\n  base: main\n  tiers:\n    critical: [\"x/**\"]\n",
	} {
		if _, err := base.LoadProject("storefront", []byte("project: storefront\n"+body), cat); err == nil {
			t.Errorf("%s: want refusal", name)
		}
	}
}

// TestShippedProjectFiles loads every policy/<project>.yaml of the repository
// the way chapd does, so a typo in one is caught before it is deployed.
func TestShippedProjectFiles(t *testing.T) {
	cat, base := mustDefault(t)
	dir := filepath.Join("..", "..", "policy")
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no project files in %s: %v", dir, err)
	}
	eng := NewEngine(cat, base, dir)
	for _, f := range files {
		project := strings.TrimSuffix(filepath.Base(f), ".yaml")
		eff := eng.For(project)
		if eff.Invalid != nil {
			t.Errorf("%s: %v", f, eff.Invalid)
		} else if eff.PR == nil || eff.PR.Base == "" {
			t.Errorf("%s: has no pr: block", f)
		}
	}
	if eff := eng.For("storefront"); eff.PR == nil || eff.PR.Base != "feat/d1-private-pilot" {
		t.Errorf("storefront pr block: %+v", eff.PR)
	}
}

func TestIssueOpsShipOnWithAnHourlyCap(t *testing.T) {
	cat, base := enabledBase(t)
	eff := base.ForProject("acme-shop")
	for _, op := range []string{"issue.open", "issue.comment", "issue.reopen"} {
		if !eff.Enabled(op) || eff.RateHour(op) != 20 || eff.Rate(op) < 1 {
			t.Errorf("%s: enabled=%v per minute=%d per hour=%d, want on with an hourly cap of 20", op, eff.Enabled(op), eff.Rate(op), eff.RateHour(op))
		}
		// No run profile may ask for them: only an orchestrator token does.
		for name, allow := range eff.Profiles {
			for _, a := range allow {
				if a == op {
					t.Errorf("profile %s lists %s", name, op)
				}
			}
		}
		if e, ok := cat.Lookup(op); !ok || e.Class != ClassRoutine {
			t.Errorf("%s: catalog entry %+v, want routine", op, e)
		}
	}
	if eff.RateHour("health") != 0 {
		t.Error("health has an hourly cap nobody asked for")
	}
	// A project file can lower an hourly cap, and add one where there is none; never lift one.
	narrow, err := base.LoadProject("acme-shop", []byte("project: acme-shop\nops:\n  issue.open: { rate_per_hour: 5 }\n  health: { rate_per_hour: 30 }\n"), cat)
	if err != nil {
		t.Fatal(err)
	}
	if narrow.RateHour("issue.open") != 5 || narrow.RateHour("health") != 30 || narrow.RateHour("issue.comment") != 20 {
		t.Errorf("hourly caps: %d %d %d", narrow.RateHour("issue.open"), narrow.RateHour("health"), narrow.RateHour("issue.comment"))
	}
	for name, body := range map[string]string{"lift": "issue.open: { rate_per_hour: 21 }", "zero": "issue.open: { rate_per_hour: 0 }", "negative": "health: { rate_per_hour: -1 }"} {
		if _, err := base.LoadProject("acme-shop", []byte("project: acme-shop\nops:\n  "+body+"\n"), cat); err == nil {
			t.Errorf("%s: want refusal", name)
		}
	}
	if _, err := LoadBaseline([]byte(strings.Replace(string(BaselineBytes()), "issue.open:           { enabled: true,  rate_per_minute: 6,  rate_per_hour: 20 }", "issue.open: { enabled: true, rate_per_minute: 6, rate_per_hour: -1 }", 1)), cat); err == nil {
		t.Error("a baseline with a negative hourly cap loaded")
	}
}
