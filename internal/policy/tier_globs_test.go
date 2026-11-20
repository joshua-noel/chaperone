package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const storefrontPR = "project: storefront\npr:\n  repo: example-org/storefront\n  base: main\n  tiers:\n"

// A project tier glob that can never match a plain path turns off pr.merge and pr.update for that project only. The
// file still loads, so every other op of the project keeps working. The block says why, and names the file, the
// project, the tier and the glob.
func TestBadTierGlobTurnsOffTheMergeBlockOnly(t *testing.T) {
	cat, base := mustDefault(t)
	for name, tiers := range map[string]string{
		"an accent in high":     "    high: [\"docs/caf\u00e9/**\"]\n",
		"another script in low": "    low: [\"docs/\u65e5\u672c\u8a9e/**\"]\n",
		"a tilde in medium":     "    medium: [\"web/a~1/**\"]\n",
		"a hash":                "    low: [\"docs/a#b.md\"]\n",
		"a backslash":           "    high: ['docs\\\\a']\n",
		"bad syntax":            "    high: [\"[x\"]\n",
		"a reversed range":      "    low: [\"docs/[z-a]/**\"]\n",
		"a trailing slash":      "    low: [\"docs/\"]\n",
	} {
		eff, err := base.LoadProject("storefront", []byte(storefrontPR+tiers), cat)
		if err != nil {
			t.Errorf("%s: the file must still load: %v", name, err)
			continue
		}
		if eff.Invalid != nil {
			t.Errorf("%s: the whole project is invalid: %v", name, eff.Invalid)
		}
		if eff.PR == nil || eff.PR.Invalid == nil {
			t.Errorf("%s: the pr block is not marked unusable", name)
		}
	}

	eff, err := base.LoadProject("storefront", []byte(storefrontPR+"    low: [\"docs/caf\u00e9/**\"]\n"), cat)
	if err != nil {
		t.Fatal(err)
	}
	msg := eff.PR.Invalid.Error()
	for _, want := range []string{"storefront.yaml", "project storefront", "tiers.low", "docs/caf\u00e9/**", "pr.merge and pr.update are off"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message does not hold %q: %s", want, msg)
		}
	}
	// The rest of the project is as without the glob: every op the baseline turns on stays on.
	plain, err := base.LoadProject("storefront", []byte(storefrontPR), cat)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"issue.open", "issue.comment", "issue.reopen", "branch.push", "pr.open", "pr.view", "pr.diff", "pr.checks", "pr.files", "ci.report"} {
		if !eff.Enabled(op) || eff.Enabled(op) != plain.Enabled(op) {
			t.Errorf("%s: enabled=%v, without the glob %v", op, eff.Enabled(op), plain.Enabled(op))
		}
	}
	if eff.PR.Repo != "example-org/storefront" || eff.PR.Base != "main" {
		t.Errorf("the pr block lost its repo or base: %+v", eff.PR)
	}
	// Plain globs are fine.
	good, err := base.LoadProject("storefront", []byte(storefrontPR+"    high: [\"docs/**\", \"**/*.sh\"]\n    medium: [\"Docs/Getting Started/**\", \"app/?slug?/**\"]\n    low: [\"web/src/[a-c]*/**\", \"web/[^a]?.md\"]\n"), cat)
	if err != nil || good.PR.Invalid != nil {
		t.Errorf("plain globs refused: %v, %v", err, good)
	}
	// A file that is wrong in another way is still invalid as a whole.
	if _, err := base.LoadProject("storefront", []byte(storefrontPR+"    top: [x]\n"), cat); err == nil {
		t.Error("an unknown key must still refuse the file")
	}
}

// The engine follows the convention for a project file: it reads the file, the project stays usable, and a changed
// file is picked up on the next read, so fixing the glob turns the merge ops back on without a restart.
func TestEngineTurnsMergeOffAndBackOn(t *testing.T) {
	cat, base := mustDefault(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "storefront.yaml")
	bad := storefrontPR + "    low: [\"docs/caf\u00e9/**\"]\n"
	if err := os.WriteFile(file, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	eng := NewEngine(cat, base, dir)
	eng.now = func() time.Time { return now }

	eff := eng.For("storefront")
	if eff.Invalid != nil {
		t.Fatalf("the project must stay valid: %v", eff.Invalid)
	}
	if eff.PR == nil || eff.PR.Invalid == nil || !strings.Contains(eff.PR.Invalid.Error(), "storefront.yaml") {
		t.Fatalf("the pr block is not off: %+v", eff.PR)
	}
	for _, op := range []string{"issue.open", "branch.push", "pr.open", "pr.view"} {
		if !eff.Enabled(op) {
			t.Errorf("%s is off for the project", op)
		}
	}

	problems := eng.Problems()
	if len(problems) != 1 || problems[0].Project != "storefront" || problems[0].File != "storefront.yaml" || problems[0].Block != "pr" || problems[0].Err == nil {
		t.Errorf("Problems = %+v", problems)
	}

	good := strings.Replace(bad, "docs/caf\u00e9/**", "docs/**", 1)
	if err := os.WriteFile(file, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	now = now.Add(5 * time.Second)
	if eff := eng.For("storefront"); eff.Invalid != nil || eff.PR == nil || eff.PR.Invalid != nil {
		t.Errorf("the fixed file is still off: %+v %v", eff.PR, eff.Invalid)
	}
	if p := eng.Problems(); len(p) != 0 {
		t.Errorf("Problems after the fix = %+v", p)
	}
}

// An invalid project file is still a problem for the whole project, and Problems says so.
func TestProblemsReportsAnInvalidFile(t *testing.T) {
	cat, base := mustDefault(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "storefront.yaml"), []byte(storefrontPR+"    top: [x]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := NewEngine(cat, base, dir).Problems()
	if len(p) != 1 || p[0].Block != "" || p[0].File != "storefront.yaml" || !strings.Contains(p[0].Err.Error(), "storefront.yaml") {
		t.Errorf("Problems = %+v", p)
	}
	if got := NewEngine(cat, base, "").Problems(); got != nil {
		t.Errorf("no policy folder: %+v", got)
	}
}
