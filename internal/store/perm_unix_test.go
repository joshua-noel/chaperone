//go:build unix

package store

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// modeOf returns the permission bits of path, or fails the test.
func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("%s: %v", filepath.Base(path), err)
	}
	return fi.Mode().Perm()
}

func checkOwnerOnly(t *testing.T, db string) {
	t.Helper()
	for _, p := range []string{db, db + "-wal", db + "-shm"} {
		if m := modeOf(t, p); m != 0o600 {
			t.Errorf("%s has mode %#o, want 0600", filepath.Base(p), m)
		}
	}
}

// Not parallel: the umask is process-wide.
func TestDatabaseFilesAreOwnerOnly(t *testing.T) {
	for _, umask := range []int{0o022, 0o000} {
		old := syscall.Umask(umask)
		path := filepath.Join(t.TempDir(), "state.db")
		d, err := Open(context.Background(), path)
		syscall.Umask(old)
		if err != nil {
			t.Fatal(err)
		}
		// A write makes SQLite use the log and the shared-memory file.
		if _, err := d.SQL().Exec(`CREATE TABLE t (x INTEGER)`); err != nil {
			t.Fatal(err)
		}
		if _, err := d.SQL().Exec(`INSERT INTO t VALUES (1)`); err != nil {
			t.Fatal(err)
		}
		checkOwnerOnly(t, path)
		d.Close()
	}
}

// A database made by an older version with mode 0644, and its leftover -wal
// and -shm files, are tightened at the next start.
func TestOpenTightensAnExistingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	d, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.SQL().Exec(`CREATE TABLE t (x INTEGER)`); err != nil {
		t.Fatal(err)
	}
	// Keep this connection open so -wal and -shm stay on disk, then widen all three.
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	d2, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	defer d.Close()
	checkOwnerOnly(t, path)
}
