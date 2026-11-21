package store

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A symbolic link at the database path is refused and nothing is created through it: a dangling one would have the
// file it points at created, one to a file would have that file opened and changed. A machine that cannot make a
// symbolic link SKIPS the test, with the reason.
func TestOpenRefusesALinkAtTheDatabasePath(t *testing.T) {
	for name, withTarget := range map[string]bool{"a symbolic link to a path that does not exist": false, "a symbolic link to an existing file": true} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			target, link := filepath.Join(dir, "target.db"), filepath.Join(dir, "state.db")
			if withTarget {
				if err := os.WriteFile(target, []byte("not a database"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(target, link); err != nil {
				t.Skipf("cannot make a symbolic link on this machine (%v): this case was NOT run", err)
			}
			t.Logf("made %s at the path (GOOS=%s)", name, runtime.GOOS)
			if db, err := Open(context.Background(), link); err == nil {
				db.Close()
				t.Fatal("Open went through the link")
			} else {
				t.Logf("refused: %v", err)
			}
			if st, err := os.Stat(target); withTarget {
				if err != nil || st.Size() != int64(len("not a database")) {
					t.Errorf("the target was changed: %v %v", st, err)
				}
			} else if err == nil {
				t.Error("a file was created at the link's target")
			}
		})
	}
}
