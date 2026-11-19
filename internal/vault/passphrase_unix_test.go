//go:build unix

package vault

import (
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A descriptor number the process owns, other than 0: only a pipe or FIFO is
// taken, and the original descriptor is never closed.
func TestFDPassphraseOnARealDescriptor(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	fd := int(r.Fd())
	if fd < 3 {
		t.Skipf("pipe got descriptor %d", fd)
	}
	s, err := FDPassphrase(fd)
	if err != nil {
		t.Fatal(err)
	}
	go func() { io.WriteString(w, testPassphrase+"\nignored\n"); w.Close() }()
	got, err := s.Passphrase(false)
	if err != nil || string(got) != testPassphrase {
		t.Fatalf("got %q, %v", got, err)
	}
	// The source read a duplicate and closed it; our descriptor is still open.
	if _, err := r.Stat(); err != nil {
		t.Errorf("the original descriptor was closed: %v", err)
	}
}

// A descriptor the program opened itself (a log file, the database) is not a
// pipe: refused, and left open and usable.
func TestFDPassphraseRefusesADescriptorTheProcessOwns(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	io.WriteString(f, testPassphrase+"\n")
	f.Seek(0, io.SeekStart)
	fd := int(f.Fd())
	if fd < 3 {
		t.Skipf("file got descriptor %d", fd)
	}
	if _, err := FDPassphrase(fd); err == nil || !strings.Contains(err.Error(), "not a pipe or FIFO") {
		t.Errorf("a regular file on descriptor %d: %v", fd, err)
	}
	if _, err := f.WriteString("still usable\n"); err != nil {
		t.Errorf("refusing the descriptor closed it: %v", err)
	}
	// Not open at all.
	if _, err := FDPassphrase(987654); err == nil {
		t.Error("a descriptor that is not open was accepted")
	}
}

// Every signal that ends a prompt restores the terminal, delivered for real.
func TestTerminalPassphraseSignalsRestoreEcho(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGINT} {
		ft := newFakeTerminal()
		old := openTerminal
		openTerminal = func() (terminal, error) { return ft, nil }
		res := make(chan error, 1)
		go func() { _, err := TerminalPassphrase().Passphrase(false); res <- err }()
		deadline := time.After(5 * time.Second)
		for !strings.Contains(ft.shown(), "passphrase") {
			select {
			case <-deadline:
				t.Fatalf("%v: no prompt", sig)
			case <-time.After(time.Millisecond):
			}
		}
		if err := syscall.Kill(os.Getpid(), sig); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-res:
			if err != errInterrupted {
				t.Errorf("%v: got %v", sig, err)
			}
		case <-deadline:
			t.Fatalf("%v: the prompt ignored the signal", sig)
		}
		ft.mu.Lock()
		on, restored := ft.echoOn, ft.restored
		ft.mu.Unlock()
		if !on || restored != 1 {
			t.Errorf("%v: echo left off", sig)
		}
		ft.feed.Close()
		openTerminal = old
	}
}
