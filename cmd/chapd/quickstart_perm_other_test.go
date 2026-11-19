//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// checkPrivateFile fails unless only the owner can read the file: mode 0600 (writePrivate's call path:
// restrictToCurrentUser sets it, and the temporary file it renames was created 0600).
func checkPrivateFile(t *testing.T, path string) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("%s has mode %v, want -rw-------", path, st.Mode().Perm())
	}
	// Nothing else is left in the folder by the write: no temporary copy of the token.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if len(e.Name()) > 5 && e.Name()[:5] == ".orch" {
			t.Errorf("temporary token file %s left behind", e.Name())
		}
	}
}
