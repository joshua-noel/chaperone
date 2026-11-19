package vault

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// newPTY returns the slave side of a new pseudo-terminal: a real terminal for
// the descriptor checks.
func newPTY(t *testing.T) *os.File {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no /dev/ptmx: %v", err)
	}
	t.Cleanup(func() { m.Close() })
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Skipf("unlockpt: %v", err)
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Skipf("ptsname: %v", err)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("open pty: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestFDPassphraseRefusesATerminal(t *testing.T) {
	s := newPTY(t)
	if !isTerminal(s) {
		t.Fatal("isTerminal says a pty is not a terminal")
	}
	// As standard input.
	old := os.Stdin
	os.Stdin = s
	t.Cleanup(func() { os.Stdin = old })
	_, err := FDPassphrase(0)
	if err == nil || !strings.Contains(err.Error(), "is a terminal") || !strings.Contains(err.Error(), "drop the descriptor flag") {
		t.Errorf("a terminal on descriptor 0: %v", err)
	}
	// As another descriptor, and the terminal is left open.
	fd := int(s.Fd())
	if fd >= 3 {
		if _, err := FDPassphrase(fd); err == nil || !strings.Contains(err.Error(), "is a terminal") {
			t.Errorf("a terminal on descriptor %d: %v", fd, err)
		}
		if _, err := s.Stat(); err != nil {
			t.Errorf("refusing closed the terminal: %v", err)
		}
	}
}
