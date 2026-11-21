package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// chapd says at start, once and at Warn, that a project file has a tier glob that cannot be used: pr.merge and
// pr.update are off for that project, its other ops work. It starts either way.
func TestStartWarnsOnceAboutAnUnusableTierGlob(t *testing.T) {
	dir := t.TempDir()
	db, keys := filepath.Join(dir, "state.db"), writeKeys(t, dir)
	policyDir := filepath.Join(dir, "policy")
	if err := os.MkdirAll(policyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := "project: storefront\npr:\n  repo: example-org/storefront\n  base: main\n  tiers:\n    low: [\"docs/caf\u00e9/**\"]\n"
	if err := os.WriteFile(filepath.Join(policyDir, "storefront.yaml"), []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	log := &syncBuf{}
	app, err := Build(context.Background(), Config{DBPath: db, KeysPath: keys, Instance: "test", PolicyDir: policyDir,
		Log: slog.New(slog.NewTextHandler(log, nil))})
	if err != nil {
		t.Fatal(err) // a bad glob must not stop chapd from starting
	}
	app.Close()
	out := log.String()
	if n := strings.Count(out, "unusable pr block"); n != 1 {
		t.Fatalf("the start-up log says it %d times, want once:\n%s", n, out)
	}
	for _, want := range []string{"level=WARN", "project=storefront", "file=storefront.yaml", "pr.merge and pr.update are off", "tiers.low", "docs/caf"} {
		if !strings.Contains(out, want) {
			t.Errorf("the warning does not hold %q:\n%s", want, out)
		}
	}
}

// chapd says at start, once and at Warn, that a project file has an unusable linear.issues block: the Linear issue
// operations are off for that project, the intake and the other ops work. It starts either way.
func TestStartWarnsOnceAboutAnUnusableLinearIssuesBlock(t *testing.T) {
	dir := t.TempDir()
	db, keys := filepath.Join(dir, "state.db"), writeKeys(t, dir)
	policyDir := filepath.Join(dir, "policy")
	if err := os.MkdirAll(policyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := "project: storefront\nlinear:\n  team: SHOP\n  label: claude\n  issues:\n    team: SHOP\n    label: agent\n"
	if err := os.WriteFile(filepath.Join(policyDir, "storefront.yaml"), []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	log := &syncBuf{}
	app, err := Build(context.Background(), Config{DBPath: db, KeysPath: keys, Instance: "test", PolicyDir: policyDir,
		Log: slog.New(slog.NewTextHandler(log, nil))})
	if err != nil {
		t.Fatal(err) // a bad block must not stop chapd from starting
	}
	app.Close()
	out := log.String()
	if n := strings.Count(out, "unusable linear.issues block"); n != 1 {
		t.Fatalf("the start-up log says it %d times, want once:\n%s", n, out)
	}
	for _, want := range []string{"level=WARN", "project=storefront", "file=storefront.yaml", "Linear issue operations", "issues.team"} {
		if !strings.Contains(out, want) {
			t.Errorf("the warning does not hold %q:\n%s", want, out)
		}
	}
}
