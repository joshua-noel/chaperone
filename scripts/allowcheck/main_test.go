package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const goMod = `module github.com/joshua-noel/chaperone

go 1.26.10

require github.com/single/one v1.0.0

require (
	example.com/direct v1.2.3
	example.com/indirect v0.1.0 // indirect
)

// require example.com/commented v1.0.0
`

func TestRequiredModules(t *testing.T) {
	got, err := requiredModules(strings.NewReader(goMod))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"github.com/single/one", "example.com/direct", "example.com/indirect"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestAllowedModulesRejectsExtraColumns(t *testing.T) {
	if _, err := allowedModules(strings.NewReader("example.com/a v1.0.0\n")); err == nil {
		t.Fatal("want an error for a version column")
	}
}

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	gm := write(t, dir, "go.mod", goMod)

	full := write(t, dir, "full.allow", "# header\ngithub.com/single/one # why\nexample.com/direct\nexample.com/indirect\n")
	var out, errb bytes.Buffer
	if code := run(gm, full, &out, &errb); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}

	// A module that is required but not allowlisted fails the check and is named.
	short := write(t, dir, "short.allow", "github.com/single/one\nexample.com/direct\n")
	out.Reset()
	errb.Reset()
	if code := run(gm, short, &out, &errb); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "example.com/indirect") {
		t.Fatalf("stderr %q does not name the missing module", errb.String())
	}

	errb.Reset()
	if code := run(filepath.Join(dir, "missing.mod"), full, &out, &errb); code != 2 {
		t.Fatalf("exit %d, want 2 for a missing go.mod", code)
	}
}
