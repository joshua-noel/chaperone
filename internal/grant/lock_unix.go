//go:build unix

package grant

import (
	"fmt"
	"os"
	"syscall"
)

// processLock is an exclusive flock on a lock file, released by Close or by
// the process dying.
type processLock struct{ f *os.File }

func lockProcess(path string) (*processLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another chap-host holds %s: %w", path, err)
	}
	return &processLock{f: f}, nil
}

func (l *processLock) Close() error { return l.f.Close() }
