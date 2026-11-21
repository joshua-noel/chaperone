//go:build windows

package main

import (
	"os/exec"
	"strings"
	"testing"
)

func icaclsOut(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("icacls", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("icacls %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// openFolder makes everything created in dir readable by Everyone, as a shared repository folder or %TEMP% may be.
func openFolder(t *testing.T, dir string) { icaclsOut(t, dir, "/grant", "*S-1-1-0:(OI)(CI)R") }

// ownerOnlyProblem says what is wrong with the access to path, or "" when exactly one entry, full control for the
// current user, none inherited, holds it.
func ownerOnlyProblem(t *testing.T, path string) string {
	t.Helper()
	out := icaclsOut(t, path)
	who, err := exec.Command("whoami").Output()
	if err != nil {
		t.Fatal(err)
	}
	user := strings.ToLower(strings.TrimSpace(string(who)))
	switch {
	case strings.Count(out, ":(") != 1:
		return "not exactly one access entry:\n" + out
	case strings.Contains(out, "(I)"):
		return "access is inherited from the folder:\n" + out
	case !strings.Contains(strings.ToLower(out), user+":(f)"):
		return "the one entry is not full control for " + user + ":\n" + out
	}
	return ""
}
