//go:build !windows

package main

import (
	"os"
	"testing"
)

// openFolder makes the folder wide open, as a shared repository folder or /tmp may be.
func openFolder(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
}

// ownerOnlyProblem says what is wrong with the mode of path, or "" when it is a plain file with mode 0600.
func ownerOnlyProblem(t *testing.T, path string) string {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 {
		return "mode " + st.Mode().String() + ", want -rw-------"
	}
	return ""
}
