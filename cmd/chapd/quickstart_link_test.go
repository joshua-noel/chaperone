package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The quickstart makes its first-run files (the marker, the policy, run-keys.json, the empty state.db) with
// createExclusive. A link at the final path must be refused and nothing written through it, whatever the link is:
// one whose target does not exist (which a plain create-new follows on Windows), one to an existing file, one to a
// folder, and a junction. A kind the machine cannot make is SKIPPED with the reason, never passed; each that runs
// logs which kind it made.
func TestQuickstartFirstRunFileIsNotMadeThroughALink(t *testing.T) {
	for _, c := range []struct {
		name     string
		junction bool
		setup    func(t *testing.T, dir string) (target string)
		check    func(t *testing.T, target string)
	}{
		{"symbolic link to a path that does not exist", false,
			func(t *testing.T, dir string) string { return filepath.Join(dir, "nowhere") },
			func(t *testing.T, target string) {
				if _, err := os.Lstat(target); err == nil {
					t.Error("a file was created at the link's target")
				}
			}},
		{"symbolic link to an existing file", false,
			func(t *testing.T, dir string) string {
				p := filepath.Join(dir, "theirs")
				if err := os.WriteFile(p, []byte("theirs"), 0o644); err != nil {
					t.Fatal(err)
				}
				return p
			},
			func(t *testing.T, target string) {
				if got, _ := os.ReadFile(target); string(got) != "theirs" {
					t.Errorf("the target was written through: %q", got)
				}
			}},
		{"symbolic link to a folder", false,
			func(t *testing.T, dir string) string { return mkFolder(t, dir) },
			func(t *testing.T, target string) { folderEmpty(t, target) }},
		{"junction to a folder", true,
			func(t *testing.T, dir string) string { return mkFolder(t, dir) },
			func(t *testing.T, target string) { folderEmpty(t, target) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			target := c.setup(t, dir)
			link := filepath.Join(dir, "state.db")
			if err := makeTestLink(c.junction, target, link); err != nil {
				t.Skipf("cannot make a %s on this machine (%v): this case was NOT run", c.name, err)
			}
			t.Logf("made a %s at the path (GOOS=%s)", c.name, runtime.GOOS)
			if err := createExclusive(link, []byte("secret")); err == nil {
				t.Error("createExclusive wrote through or replaced the link")
			} else {
				t.Logf("refused: %v", err)
			}
			c.check(t, target)
			if _, err := os.Lstat(link); err != nil {
				t.Errorf("the link itself is gone: %v", err)
			}
		})
	}
}

func mkFolder(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "folder")
	if err := os.Mkdir(p, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func folderEmpty(t *testing.T, p string) {
	t.Helper()
	if ents, _ := os.ReadDir(p); len(ents) != 0 {
		t.Errorf("%d entries were made in the folder the link points at", len(ents))
	}
}
