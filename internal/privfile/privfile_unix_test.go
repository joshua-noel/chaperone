//go:build !windows

package privfile

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The file is mode 0600 whatever the umask says: with a umask of 0 a mode that was left to the umask would be wide
// open.
func TestCreateIsMode0600(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	path := filepath.Join(t.TempDir(), "key")
	f, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 || !st.Mode().IsRegular() {
		t.Errorf("mode %v, want -rw-------", st.Mode())
	}
}
