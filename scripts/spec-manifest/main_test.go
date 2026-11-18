package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range map[string]string{
		"schemas/a.schema.json": "{}\n",
		"vectors/v0.json":       "{\"a\":1}\n",
		"VERSION":               "v0.1.0\n",
	} {
		p := filepath.Join(root, filepath.FromSlash(dataDir), filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestSealThenCheck(t *testing.T) {
	root := tree(t)
	var out, errb bytes.Buffer
	if code := run([]string{"-root", root, "-check"}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "out of date") {
		t.Fatalf("check before sealing: code %d, %q", code, errb.String())
	}
	if code := run([]string{"-root", root}, &out, &errb); code != 0 {
		t.Fatalf("seal: code %d, %q", code, errb.String())
	}
	m, _ := os.ReadFile(filepath.Join(root, filepath.FromSlash(dataDir), "MANIFEST"))
	lines := strings.Split(strings.TrimSpace(string(m)), "\n")
	if len(lines) != 3 || !strings.HasSuffix(lines[0], "  VERSION") || !strings.HasSuffix(lines[2], "  vectors/v0.json") {
		t.Fatalf("MANIFEST = %q", m)
	}
	errb.Reset()
	if code := run([]string{"-root", root, "-check"}, &out, &errb); code != 0 {
		t.Fatalf("check after sealing: code %d, %q", code, errb.String())
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(dataDir), "vectors/v0.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"-root", root, "-check"}, &out, &errb); code != 1 {
		t.Fatalf("check after an edit: code %d", code)
	}
}
