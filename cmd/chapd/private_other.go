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

func statOf(path string) (os.FileInfo, *syscall.Stat_t, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, nil, fmt.Errorf("cannot read the owner of %s on this system", path)
	}
	return st, sys, nil
}

// ownedByCurrentUser fails unless the current user owns path. A folder another user owns can be
// changed by that user whatever its mode is, so it is never taken as private.
func ownedByCurrentUser(path string) error {
	_, sys, err := statOf(path)
	if err != nil {
		return err
	}
	if int(sys.Uid) != os.Getuid() {
		return fmt.Errorf("%s is owned by user %d, not by the current user (%d)", path, sys.Uid, os.Getuid())
	}
	return nil
}

// createPrivateDir makes a NEW folder with mode 0700: os.Mkdir fails if the path exists, so nothing of
// anybody else's can be in it or hold it open. The owner and mode are read back.
func createPrivateDir(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil {
		return err
	}
	if err := verifyPrivateDir(path); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

// verifyPrivateDir fails unless path is a real folder (not a link) owned by the current user that group
// and others cannot reach.
func verifyPrivateDir(path string) error {
	st, _, err := statOf(path)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a plain folder", path)
	}
	if err := ownedByCurrentUser(path); err != nil {
		return err
	}
	if p := st.Mode().Perm(); p&0o077 != 0 || p&0o700 != 0o700 {
		return fmt.Errorf("%s has mode %v, want -rwx------", path, p)
	}
	return nil
}

// ancestorSafe decides whether a folder ABOVE the quickstart folder may stay as it is. It must be owned
// by the current user or root, and group and others must not be able to write in it unless the sticky
// bit is set (as on /tmp). Otherwise another user could rename the quickstart folder away after it is made
// and put their own in its place.
func ancestorSafe(path string) error {
	st, sys, err := statOf(path)
	if err != nil {
		return err
	}
	if sys.Uid != 0 && int(sys.Uid) != os.Getuid() {
		return fmt.Errorf("%s is owned by user %d, neither you nor root", path, sys.Uid)
	}
	if st.Mode().Perm()&0o022 != 0 && st.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("%s (mode %v) can be written by group or others, who could then rename your folder away; run: chmod go-w %s", path, st.Mode().Perm(), path)
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
