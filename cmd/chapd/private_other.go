//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

// elevated is true off Windows: there the file mode below is the whole story,
// and tests run here.
func elevated() bool { return true }

// restrictToCurrentUser sets mode 0600 (the file was created 0600 already).
func restrictToCurrentUser(path string) error { return os.Chmod(path, 0o600) }

// ownedByCurrentUser fails unless the current user owns path. It is checked
// before anything is changed: chmod would also fail on a folder somebody else
// owns (unless this is root), but a folder another user owns can be changed by
// that user whatever its mode is, so it is never taken as private.
func ownedByCurrentUser(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read the owner of %s on this system", path)
	}
	if int(sys.Uid) != os.Getuid() {
		return fmt.Errorf("%s is owned by user %d, not by the current user (%d)", path, sys.Uid, os.Getuid())
	}
	return nil
}

// restrictDirToCurrentUser sets mode 0700 on a folder the current user owns and reads it back.
func restrictDirToCurrentUser(path string) error {
	if err := ownedByCurrentUser(path); err != nil {
		return err
	}
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

// checkTrusted decides whether a file or folder that already exists may be trusted: the current
// user owns it, it is not a link to somewhere else, and neither group nor others can write it.
func checkTrusted(path string) error {
	if err := ownedByCurrentUser(path); err != nil {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a link", path)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s can be changed by other users (mode %v)", path, st.Mode().Perm())
	}
	return nil
}
