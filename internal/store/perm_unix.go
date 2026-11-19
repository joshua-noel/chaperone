//go:build unix

package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// dbFileMode is the mode of the database and of its -wal and -shm files: the
// owner only. The database holds the ledger, the vault index and the run
// state, and SQLite creates files with 0666 minus the umask, which is 0644 on
// a normal system.
const dbFileMode = 0o600

// prepareDBFile creates the database file with mode 0600 if it is missing and
// tightens it if it exists, before SQLite opens it. SQLite gives the -wal and
// -shm files the mode of the main file when it creates them, so doing this
// first means they are never created readable by others. fchmod on the open
// descriptor ignores the umask and follows no second path lookup.
func prepareDBFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, dbFileMode)
	if err != nil {
		return fmt.Errorf("store: create %s: %w", path, err)
	}
	if err := f.Chmod(dbFileMode); err != nil {
		_ = f.Close()
		return fmt.Errorf("store: restrict %s to its owner: %w", path, err)
	}
	return f.Close()
}

// restrictSidecars sets the -wal and -shm files, which exist once WAL mode is
// on, to 0600. It covers files left by an earlier run with a wider mode; a
// file that is not there is fine.
func restrictSidecars(path string) error {
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Chmod(path+suffix, dbFileMode); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("store: restrict %s to its owner: %w", path+suffix, err)
		}
	}
	return nil
}
