//go:build !windows

package main

import (
	"fmt"
	"os"
)

// elevated is true off Windows: there the file mode below is the whole story,
// and tests run here.
func elevated() bool { return true }

// restrictToCurrentUser sets mode 0600 (the file was created 0600 already).
func restrictToCurrentUser(path string) error { return os.Chmod(path, 0o600) }

// restrictDirToCurrentUser sets mode 0700 and reads it back. Chmod fails on a
// folder somebody else owns, so a folder this user does not own is refused.
func restrictDirToCurrentUser(path string) error {
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.Mode().Perm() != 0o700 {
		return fmt.Errorf("%s has mode %v after chmod 0700", path, st.Mode().Perm())
	}
	return nil
}
