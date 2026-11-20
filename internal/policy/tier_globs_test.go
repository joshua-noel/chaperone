package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A project tier glob that no plain path can match would silently do nothing, so the project file is refused when it
// loads. The refusal names the project, the tier and the glob.
func TestProjectTierGlobThatCanNeverMatchIsRefusedAtLoad(t *testing.T) {
	cat, base := mustDefault(t)
	load := func(tiers string) (*Effective, error) {
		return base.LoadProject("storefront", []byte("project: storefront\npr:\n  repo: example-org/storefront\n  base: main\n  tiers:\n"+tiers), cat)
	}
	for name, tiers := range map[string]string{
		"an accent in high":     "    high: [\"docs/caf\u00e9/**\"]\n",
		"another script in low": "    low: [\"docs/\u65e5\u672c\u8a9e/**\"]\n",
		"a tilde in medium":     "    medium: [\"web/a~1/**\"]\n",
		"a hash":                "    low: [\"docs/a#b.md\"]\n",
		"a backslash":           "    high: ['docs\\\\a']\n",
		"bad syntax":            "    high: [\"[x\"]\n",
	} {
		if _, err := load(tiers); err == nil {
			t.Errorf("%s: want a refusal at load", name)
		}
	}
	_, err := load("    low: [\"docs/caf\u00e9/**\"]\n")
	if err == nil || !strings.Contains(err.Error(), "storefront") || !strings.Contains(err.Error(), "tiers.low") || !strings.Contains(err.Error(), "docs/caf\u00e9/**") {
		t.Errorf("the refusal must name the project, the tier and the glob: %v", err)
	}
	if _, err := load("    high: [\"docs/**\", \"**/*.sh\"]\n    medium: [\"Docs/Getting Started/**\"]\n    low: [\"web/src/**\"]\n"); err != nil {
		t.Errorf("plain globs refused: %v", err)
	}
}

// The engine follows the existing convention for an invalid project file: the daemon still starts, every op of that
// project is refused (Invalid is set), the error names the file, the project and the glob, and fixing the file
// restores the project without a restart.
func TestEngineRefusesAProjectWithAnUnmatchableTierGlob(t *testing.T) {
	cat, base := mustDefault(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "storefront.yaml")
	bad := "project: storefront\npr:\n  repo: example-org/storefront\n  base: main\n  tiers:\n    low: [\"docs/caf\u00e9/**\"]\n"
	if err := os.WriteFile(file, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	eng := NewEngine(cat, base, dir)
	eng.now = func() time.Time { return now }
	eff := eng.For("storefront")
	if eff.Invalid == nil {
		t.Fatal("a project file with an unmatchable tier glob must be invalid")
	}
	for _, want := range []string{"storefront.yaml", "project storefront", "tiers.low", "docs/caf\u00e9/**"} {
		if !strings.Contains(eff.Invalid.Error(), want) {
			t.Errorf("the error does not hold %q: %v", want, eff.Invalid)
		}
	}
	if eff.Enabled("pr.merge") {
		t.Error("an invalid project must have every op refused")
	}
	// Fixed: the next read (the engine re-reads a changed file) loads it.
	good := strings.Replace(bad, "docs/caf\u00e9/**", "docs/**", 1)
	if err := os.WriteFile(file, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	now = now.Add(5 * time.Second)
	if eff := eng.For("storefront"); eff.Invalid != nil {
		t.Errorf("the fixed file is still invalid: %v", eff.Invalid)
	}
}
