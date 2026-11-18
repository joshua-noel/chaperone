package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"version"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	if !strings.HasPrefix(out.String(), "chap-host ") {
		t.Fatalf("stdout %q does not start with the binary name", out.String())
	}
	if errb.Len() != 0 {
		t.Fatalf("stderr %q, want empty", errb.String())
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{nil, {"bogus"}, {"version", "extra"}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 2 {
			t.Errorf("args %q: exit %d, want 2", args, code)
		}
		if out.Len() != 0 || errb.Len() == 0 {
			t.Errorf("args %q: stdout %q, stderr %q", args, out.String(), errb.String())
		}
	}
}

func TestRunCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"run", "-config", filepath.Join(t.TempDir(), "absent.json")}, &out, &errb); code != 1 {
		t.Fatalf("missing config: exit %d, stderr %q", code, errb.String())
	}
	if out.Len() != 0 || errb.Len() == 0 {
		t.Fatalf("stdout %q, stderr %q", out.String(), errb.String())
	}
}
