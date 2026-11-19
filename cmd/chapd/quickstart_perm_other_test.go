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

// makeWorldWritable lets every user write path.
func makeWorldWritable(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
}

// A folder or file another user owns is refused, not taken over: chmod alone would not be a reason on every system.
func TestOwnerIsCheckedOnUnix(t *testing.T) {
	own := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(own, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ownedByCurrentUser(own); err != nil {
		t.Errorf("own file: %v", err)
	}
	if err := checkTrusted(own); err != nil {
		t.Errorf("own 0600 file: %v", err)
	}
	if os.Getuid() != 0 { // "/" belongs to root
		if err := ownedByCurrentUser("/"); err == nil {
			t.Error("a folder owned by root was taken as owned by this user")
		}
		if err := restrictDirToCurrentUser("/"); err == nil {
			t.Error("restrictDirToCurrentUser accepted a folder this user does not own")
		}
		if err := checkTrusted("/"); err == nil {
			t.Error("checkTrusted accepted a folder owned by root")
		}
	}
	makeWorldWritable(t, own)
	if err := checkTrusted(own); err == nil {
		t.Error("a world-writable file was trusted")
	}
	link := filepath.Join(filepath.Dir(own), "link")
	if err := os.Symlink(own, link); err == nil {
		if err := checkTrusted(link); err == nil {
			t.Error("a link was trusted")
		}
	}
}
