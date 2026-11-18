package ops_test

import (
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/ops"
)

func TestClassifyPath(t *testing.T) {
	cases := []struct {
		path string
		want ops.PRTier
	}{
		// low: docs and tests
		{"docs/factory/notes.md", ops.TierLow},
		{"README.md", ops.TierLow},
		{"internal/app/app_test.go", ops.TierLow},
		{"web/src/button.test.tsx", ops.TierLow},
		{"web/src/button.spec.ts", ops.TierLow},
		{"tests/e2e/login.ts", ops.TierLow},
		{"internal/x/testdata/golden.json", ops.TierLow},
		// medium: other code
		{"internal/app/app.go", ops.TierMedium},
		{"web/src/button.tsx", ops.TierMedium},
		{"web/src/styles.css", ops.TierMedium},
		{"web/public/logo.png", ops.TierMedium},
		// high: workflows, migrations, host scripts, auth, payment, deploy
		{".github/workflows/ci.yml", ops.TierHigh},
		{".github/CODEOWNERS", ops.TierHigh},
		{"supabase/migrations/0042_add.sql", ops.TierHigh},
		{"scripts/pilot-host/pilot.sh", ops.TierHigh},
		{"docs/howto/restore.ps1", ops.TierHigh}, // a script in docs is still a script
		{"web/src/auth/session.ts", ops.TierHigh},
		{"web/src/payments/checkout.ts", ops.TierHigh},
		{"web/src/billing.ts", ops.TierHigh},
		{"deploy/pilot.yml", ops.TierHigh},
		{"Dockerfile", ops.TierHigh},
		{"docker-compose.yml", ops.TierHigh},
		{"package.json", ops.TierHigh},
		{"go.mod", ops.TierHigh},
		{"AGENTS.md", ops.TierHigh}, // markdown, but a rule file
		{"test/redteam/rt01_merge_on_red_test.go", ops.TierHigh},
		{".env.production", ops.TierHigh},
		// high: cannot classify
		{"tools/blob.xyz", ops.TierHigh},
		{"Makefile", ops.TierHigh},
		{"noextension", ops.TierHigh},
		// high: not a plain relative path
		{"", ops.TierHigh},
		{"/etc/passwd", ops.TierHigh},
		{"docs/../.github/workflows/ci.yml", ops.TierHigh},
		{`docs\..\x.md`, ops.TierHigh},
		{"docs//x.md", ops.TierHigh},
		{"docs/x.md\x00.go", ops.TierHigh},
		// case does not hide a path
		{".GitHub/Workflows/CI.yml", ops.TierHigh},
		{"Docs/Guide.MD", ops.TierLow},
		{"Supabase/Migrations/1.SQL", ops.TierHigh},
	}
	var g ops.PRTierGlobs
	for _, c := range cases {
		if got := g.ClassifyPath(c.path); got != c.want {
			t.Errorf("%q: %s, want %s", c.path, got, c.want)
		}
	}
}

func TestClassifyPRTakesTheHighestTier(t *testing.T) {
	var g ops.PRTierGlobs
	r := g.Classify([]ops.PRFile{{Path: "docs/a.md"}, {Path: "internal/a.go"}, {Path: "docs/b.md"}})
	if r.Tier != ops.TierMedium || len(r.Paths) != 1 || r.Paths[0] != "internal/a.go" || r.Unclassified {
		t.Fatalf("%+v", r)
	}
	r = g.Classify([]ops.PRFile{{Path: "docs/a.md"}, {Path: "x.weird"}})
	if r.Tier != ops.TierHigh || !r.Unclassified {
		t.Fatalf("%+v", r)
	}
	r = g.Classify(nil)
	if r.Tier != ops.TierHigh || !r.Unclassified {
		t.Fatalf("an empty file list cannot be classified: %+v", r)
	}
	// A rule-based high is not "unclassified".
	r = g.Classify([]ops.PRFile{{Path: ".github/workflows/ci.yml"}})
	if r.Tier != ops.TierHigh || r.Unclassified {
		t.Fatalf("%+v", r)
	}
	// Both sides of a rename count.
	r = g.Classify([]ops.PRFile{{Path: "docs/ci.md", PreviousPath: ".github/workflows/ci.yml"}})
	if r.Tier != ops.TierHigh {
		t.Fatalf("%+v", r)
	}
	// Long lists are summarised.
	var files []ops.PRFile
	for i := range 25 {
		files = append(files, ops.PRFile{Path: "internal/p" + strings.Repeat("x", i) + "/a.go"})
	}
	r = g.Classify(files)
	if len(r.Paths) != 10 || r.More != 15 {
		t.Fatalf("paths=%d more=%d", len(r.Paths), r.More)
	}
}

// A project may raise paths and flag more paths low, but a baseline-high path
// stays high whatever the project says.
func TestProjectGlobsNeverLowerBaselineHigh(t *testing.T) {
	g := ops.PRTierGlobs{Low: []string{".github/**", "supabase/**", "web/**"}, Medium: []string{"docs/**"}}
	if got := g.ClassifyPath(".github/workflows/ci.yml"); got != ops.TierHigh {
		t.Fatalf("workflow: %s", got)
	}
	if got := g.ClassifyPath("supabase/migrations/1.sql"); got != ops.TierHigh {
		t.Fatalf("migration: %s", got)
	}
	if got := g.ClassifyPath("web/src/a.ts"); got != ops.TierLow {
		t.Fatalf("project low: %s", got)
	}
	if got := g.ClassifyPath("docs/a.md"); got != ops.TierMedium {
		t.Fatalf("project can raise docs: %s", got)
	}
	g = ops.PRTierGlobs{High: []string{"internal/ledger/**"}}
	if got := g.ClassifyPath("internal/ledger/ledger_test.go"); got != ops.TierHigh {
		t.Fatalf("project high beats the test glob: %s", got)
	}
}

func TestTierGlobValidation(t *testing.T) {
	for _, bad := range []string{"", "/abs/**", `a\b`, "[x", "a/[/b"} {
		if err := (ops.PRTierGlobs{High: []string{bad}}).Validate(); err == nil {
			t.Errorf("glob %q accepted", bad)
		}
	}
	ok := ops.PRTierGlobs{High: []string{"a/**/b.go", "**/*.sh"}, Low: []string{"docs/**"}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestManifestsAreAtLeastMedium(t *testing.T) {
	var g ops.PRTierGlobs
	for _, p := range []string{
		"requirements.txt", "api/requirements-dev.txt", "constraints.txt", "pyproject.toml", "svc/pyproject.toml",
		"uv.lock", "package.json", "web/package.json", "pnpm-lock.yaml", "go.mod", "go.sum",
	} {
		if got := g.ClassifyPath(p); got == ops.TierLow {
			t.Errorf("%q is low", p)
		}
	}
	if got := g.ClassifyPath("notes.txt"); got != ops.TierLow {
		t.Errorf("notes.txt: %s", got)
	}
}

func TestClassifyDeletedOrSkippedTestsIsMedium(t *testing.T) {
	var g ops.PRTierGlobs
	skip := func(line string) ops.PRFile {
		return ops.PRFile{Path: "a_test.go", Changes: 1, Patch: "@@ -1 +1 @@\n context\n" + line}
	}
	for name, f := range map[string]ops.PRFile{
		"deleted":         {Path: "web/a.test.ts", Status: "removed", Changes: 9},
		"moved out":       {Path: "docs/a.md", PreviousPath: "tests/a.py", Status: "renamed"},
		"t.Skip":          skip("+\tt.Skip(\"x\")"),
		"t.SkipNow":       skip("+\tt.SkipNow()"),
		"it.skip":         skip("+it.skip('x', () => {})"),
		"describe.skip":   skip("+describe.skip('x', () => {"),
		"xdescribe":       skip("+xdescribe('x', () => {"),
		"it.only":         skip("+it.only('x', () => {"),
		"pytest skip":     skip("+@pytest.mark.skip"),
		"pytest.skip()":   skip("+    pytest.skip('x')"),
		"skipif":          skip("+@pytest.mark.skipif(True, reason='x')"),
		"unittest.skip":   skip("+@unittest.skip('x')"),
		"xfail":           skip("+@pytest.mark.xfail"),
		"JUnit Disabled":  skip("+@Disabled"),
		"Rust ignore":     skip("+#[ignore]"),
		"diff not sent":   {Path: "e2e/a.spec.ts", Changes: 1700},
		"upper-case path": {Path: "WEB/A.TEST.TS", Status: "removed"},
	} {
		r := g.Classify([]ops.PRFile{f})
		if r.Tier != ops.TierMedium || !r.TestsWeakened || len(r.Paths) == 0 {
			t.Errorf("%s: %+v", name, r)
		}
	}
	for name, f := range map[string]ops.PRFile{
		"a test added":         {Path: "a_test.go", Status: "added", Changes: 2, Patch: "@@ -0,0 +1,2 @@\n+func TestA(t *testing.T) {\n+}"},
		"a skip removed":       {Path: "a_test.go", Changes: 1, Patch: "@@ -1 +0,0 @@\n-\tt.Skip(\"x\")"},
		"the +++ header":       {Path: "a_test.go", Changes: 1, Patch: "+++ skip(b/a_test.go)"},
		"a doc that says skip": {Path: "docs/a.md", Changes: 1, Patch: "+use t.Skip(\"x\") sparingly"},
		"a test word":          {Path: "a_test.go", Changes: 1, Patch: "@@ -1 +1 @@\n+\t// skipped nothing"},
		"no change, no diff":   {Path: "a_test.go", Status: "renamed"},
	} {
		if r := g.Classify([]ops.PRFile{f}); r.Tier != ops.TierLow || r.TestsWeakened {
			t.Errorf("%s: %+v", name, r)
		}
	}
	// Weakening raises a low PR only; a high PR stays high and keeps its paths.
	r := g.Classify([]ops.PRFile{{Path: "a_test.go", Status: "removed"}, {Path: ".github/workflows/ci.yml"}})
	if r.Tier != ops.TierHigh || len(r.Paths) != 1 {
		t.Errorf("%+v", r)
	}
	// With a medium path in the PR the deleted test is listed too.
	r = g.Classify([]ops.PRFile{{Path: "a.go"}, {Path: "a_test.go", Status: "removed"}})
	if r.Tier != ops.TierMedium || len(r.Paths) != 2 {
		t.Errorf("%+v", r)
	}
}
