package policy

import (
	"io/fs"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/connectors"
)

// The tests of the connector profiles that need no connector's fake service:
// C1 (the catalog is valid and its names match the op pattern) and C19 (the
// connector profiles, api/manual.yaml, the baseline pack and the `chap` usage
// agree). C2 (every op off until a policy PR) is
// TestOnlyShippedOpsEnabledByDefault in policy_test.go.

func loadProfiles(t *testing.T) map[string]*ConnectorProfile {
	t.Helper()
	files, err := fs.Glob(connectors.Files, "*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no connector profiles: %v", err)
	}
	out := map[string]*ConnectorProfile{}
	for _, f := range files {
		data, err := connectors.Files.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		p, err := LoadProfile(data)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if f != p.Connector+".yaml" {
			t.Errorf("%s holds the profile of %q: name the file after the connector", f, p.Connector)
		}
		out[p.Connector] = p
	}
	return out
}

// C1: every op name of the catalog matches the contract's pattern.
func TestC1CatalogNamesMatchTheOpPattern(t *testing.T) {
	cat, _ := mustDefault(t)
	for _, op := range cat.Ops() {
		if !ValidOpName(op) {
			t.Errorf("%s does not match ^[a-z][a-z0-9]*(\\.[a-z][a-z0-9]*)*$ (at most 64 characters)", op)
		}
	}
}

// unprofiledOps are the catalog ops no connector profile in connectors/ covers
// yet. The list only shrinks: an op that gains a profile must leave it, and a
// new op must have a profile (C19: "adding an op without a profile entry, or the
// reverse, fails CI").
var unprofiledOps = []string{
	"approvers.enroll", "data.apply", "deploy", "drive.share", "health", "host.scripts.refresh", "keys.extend", "keys.issue", "keys.request",
	"logs", "mail.send", "notion.write", "policy.activate", "secrets.write",
}

// C19: profile, catalog, baseline pack and chap usage agree.
func TestC19ProfilesTieToTheCatalogTheBaselineAndTheUsage(t *testing.T) {
	cat, base := mustDefault(t)
	profiles := loadProfiles(t)
	covered := map[string]bool{}
	for _, p := range profiles {
		for _, o := range p.Ops {
			covered[o.Name] = true
			e, ok := cat.Lookup(o.Name)
			if !ok {
				t.Errorf("%s: %s is in the profile but not in api/manual.yaml", p.Connector, o.Name)
				continue
			}
			if e.Class != o.Class || e.Reversibility != o.Reversibility || e.Surface != o.Surface {
				t.Errorf("%s: %s is %s/%s/%s in the profile and %s/%s/%s in api/manual.yaml", p.Connector, o.Name,
					o.Class, o.Reversibility, o.Surface, e.Class, e.Reversibility, e.Surface)
			}
			rule, ok := base.Ops[o.Name]
			switch {
			case !ok:
				t.Errorf("%s: %s has no rule in the baseline pack", p.Connector, o.Name)
			case rule.Enabled != o.EnabledDefault:
				t.Errorf("%s: %s is enabled_default %v in the profile and enabled %v in the baseline pack (a policy PR flips both)", p.Connector, o.Name, o.EnabledDefault, rule.Enabled)
			}
			switch {
			case o.Chap != "":
				if e.Usage != "chap "+o.Chap && !strings.HasPrefix(e.Usage, "chap "+o.Chap+" ") {
					t.Errorf("%s: %s has chap %q but its usage in api/manual.yaml is %q", p.Connector, o.Name, o.Chap, e.Usage)
				}
			case o.Surface == SurfaceOp && !strings.HasPrefix(e.Usage, "chap request op "):
				t.Errorf("%s: %s has no chap command in the profile and its usage is %q, not a `chap request op` line", p.Connector, o.Name, e.Usage)
			}
			// An orchestrator-only op is in no run profile's ceiling (a run can never hold it).
			if o.OrchestratorOnly {
				for name, ops := range base.Profiles {
					if slices.Contains(ops, o.Name) {
						t.Errorf("%s: %s is orchestrator-only but the baseline's %s profile lists it", p.Connector, o.Name, name)
					}
				}
			}
		}
	}
	// The reverse: a catalog op is profiled, or listed as not yet profiled.
	for _, op := range cat.Ops() {
		switch listed := slices.Contains(unprofiledOps, op); {
		case !covered[op] && !listed:
			t.Errorf("%s is in api/manual.yaml but no profile in connectors/ lists it (add it there, or to unprofiledOps)", op)
		case covered[op] && listed:
			t.Errorf("%s has a profile now: remove it from unprofiledOps", op)
		}
	}
	for _, op := range unprofiledOps {
		if _, ok := cat.Lookup(op); !ok {
			t.Errorf("unprofiledOps lists %s, which is not in api/manual.yaml", op)
		}
	}
}

// One name, one class, one reversibility, one surface and one default across
// every connector that implements it (the other half of C19).
func TestC19OneNameHasOneClassAcrossConnectors(t *testing.T) {
	type facts struct {
		by                  string
		class               Class
		reversibility, surf string
		enabled             bool
	}
	first := map[string]facts{}
	var names []string
	profiles := loadProfiles(t)
	for c := range profiles {
		names = append(names, c)
	}
	sort.Strings(names)
	for _, c := range names {
		for _, o := range profiles[c].Ops {
			f := facts{c, o.Class, o.Reversibility, o.Surface, o.EnabledDefault}
			if g, ok := first[o.Name]; !ok {
				first[o.Name] = f
			} else if g.class != f.class || g.reversibility != f.reversibility || g.surf != f.surf || g.enabled != f.enabled {
				t.Errorf("%s: %+v in %s and %+v in %s", o.Name, g, g.by, f, f.by)
			}
		}
	}
	if len(first) == 0 {
		t.Fatal("no ops")
	}
}

// A built name is frozen: it appears in signed tokens. The standard's name for the same capability is
// a mapping in the profile, never a second op, and never a name the catalog
// already uses for something else.
func TestLK48StandardNamesAreMappingsNotOps(t *testing.T) {
	cat, _ := mustDefault(t)
	profiles := loadProfiles(t)
	owner := map[string]string{}
	for _, p := range profiles {
		for _, o := range p.Ops {
			if o.StandardName == "" {
				continue
			}
			if _, ok := cat.Lookup(o.StandardName); ok {
				t.Errorf("%s: %s maps to %s, which is an op of the catalog; a mapping must not shadow an op", p.Connector, o.Name, o.StandardName)
			}
			if prev, dup := owner[o.StandardName]; dup {
				t.Errorf("%s is the standard name of both %s and %s", o.StandardName, prev, o.Name)
			}
			owner[o.StandardName] = o.Name
		}
	}
	// The GitHub read ops, as ADR-002 amendment 12 and the standard's overlay record them.
	gh := map[string]ProfileOp{}
	for _, o := range profiles["github"].Ops {
		gh[o.Name] = o
	}
	for name, want := range map[string]struct {
		std string
		ext bool
	}{"pr.view": {"pr.get", false}, "pr.checks": {"", false}, "pr.diff": {"", true}, "pr.files": {"", true}} {
		if got := gh[name]; got.StandardName != want.std || got.Extension != want.ext {
			t.Errorf("%s: standard_name %q extension %v, want %q %v", name, got.StandardName, got.Extension, want.std, want.ext)
		}
	}
	if owner["pr.get"] != "pr.view" {
		t.Errorf("pr.get maps to %q, want pr.view", owner["pr.get"])
	}
	if !slices.Contains(profiles["github"].StandardNotBuilt, "pr.list") {
		t.Error("pr.list is the standard's and is not built: the profile must say so")
	}
}

// The security review's P1 as a profile rule: every Linear issue op names
// `intake_label_excluded`, and no intake op can be held by a key.
func TestLinearProfileCarriesTheIntakeExclusion(t *testing.T) {
	p := loadProfiles(t)["linear"]
	if p == nil {
		t.Fatal("no linear profile")
	}
	seen := 0
	for _, o := range p.Ops {
		switch {
		case strings.HasPrefix(o.Name, "issue."):
			seen++
			if !slices.Contains(o.Conditions, "intake_label_excluded") {
				t.Errorf("%s does not list intake_label_excluded", o.Name)
			}
			if o.OrchestratorOnly {
				t.Errorf("%s is the key-facing family; it must not be orchestrator-only", o.Name)
			}
		case strings.HasPrefix(o.Name, "intake."):
			if !o.OrchestratorOnly {
				t.Errorf("%s must be orchestrator-only (a run can never hold it)", o.Name)
			}
			if slices.Contains(o.Conditions, "intake_label_excluded") {
				t.Errorf("%s is the operator board itself; it cannot exclude it", o.Name)
			}
		}
	}
	if seen != 6 {
		t.Errorf("%d issue ops in the Linear profile, want 6 (get, list, comment, label, move, link)", seen)
	}
	// issue.open and issue.update wait for the operator's yes: not in the catalog, not in the profile ops.
	cat, _ := mustDefault(t)
	for _, n := range p.StandardNotBuilt {
		for _, o := range p.Ops {
			if o.Name == n {
				t.Errorf("%s is both built and in standard_not_built", n)
			}
		}
	}
	if _, ok := cat.Lookup("issue.update"); ok {
		t.Error("issue.update is in the catalog: it waits for the operator's yes ")
	}
}

func TestLoadProfileRefusesMistakes(t *testing.T) {
	good := `profile_version: 1
connector: acme
standard: v1.1
ops:
  - {name: thing.get, class: routine, reversibility: reversible, surface: op, unit: repo, enabled_default: false}
`
	if _, err := LoadProfile([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct{ from, to string }{
		"bad version":         {"profile_version: 1", "profile_version: 2"},
		"bad connector":       {"connector: acme", "connector: Acme"},
		"digit-first id":      {"connector: acme", "connector: 1password"},
		"no standard":         {"standard: v1.1\n", ""},
		"unknown key":         {"enabled_default: false", "enabled_default: false, enabled: true"},
		"bad op name":         {"thing.get", "thing_get"},
		"op name too long":    {"thing.get", strings.Repeat("a", 65)},
		"bad class":           {"class: routine", "class: safe"},
		"bad reversibility":   {"reversibility: reversible", "reversibility: undoable"},
		"bad surface":         {"surface: op", "surface: api"},
		"no unit":             {", unit: repo", ""},
		"own standard name":   {"enabled_default: false", "enabled_default: false, standard_name: thing.get"},
		"alias and extension": {"enabled_default: false", "enabled_default: false, standard_name: thing.read, extension: true"},
		"bad condition":       {"enabled_default: false", "enabled_default: false, conditions: [Not-Snake]"},
		"repeated condition":  {"enabled_default: false", "enabled_default: false, conditions: [a, a]"},
		"duplicate op":        {"ops:\n", "ops:\n  - {name: thing.get, class: routine, reversibility: reversible, surface: op, unit: repo}\n"},
		"no ops":              {"ops:\n  - {name: thing.get, class: routine, reversibility: reversible, surface: op, unit: repo, enabled_default: false}\n", "ops: []\n"},
		"bad not-built name":  {"ops:", "standard_not_built: [Not.Valid]\nops:"},
	} {
		if _, err := LoadProfile([]byte(strings.Replace(good, c.from, c.to, 1))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
