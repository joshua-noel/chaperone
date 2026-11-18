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
	if !strings.HasPrefix(out.String(), "chapd ") {
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

func TestEnrollUsage(t *testing.T) {
	for _, args := range [][]string{{"enroll", "-bogus"}, {"enroll", "extra"}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 2 {
			t.Errorf("args %q: exit %d, want 2", args, code)
		}
		if out.Len() != 0 || !strings.Contains(errb.String(), "usage: chapd enroll") {
			t.Errorf("args %q: stdout %q, stderr %q", args, out.String(), errb.String())
		}
	}
}

func TestEnrollCheckWithoutApprover(t *testing.T) {
	var out, errb bytes.Buffer
	db := filepath.Join(t.TempDir(), "state.db")
	if code := run([]string{"enroll", "-check", "-db", db}, &out, &errb); code != 1 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	if !strings.Contains(errb.String(), "no approver is enrolled") {
		t.Fatalf("stderr %q", errb.String())
	}
}

func TestEnrollScratchExcludesDB(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"enroll", "-scratch", "-db", "x.db"}, &out, &errb); code != 2 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
}
