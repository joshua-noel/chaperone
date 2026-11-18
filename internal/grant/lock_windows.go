package grant

import (
	"fmt"
	"syscall"
)

// processLock is an exclusive open of a lock file: a second open fails with a
// sharing violation until Close, or until the process dies.
type processLock struct{ h syscall.Handle }

func lockProcess(path string) (*processLock, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil,
		syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, fmt.Errorf("another chap-host holds %s: %w", path, err)
	}
	return &processLock{h: h}, nil
}

func (l *processLock) Close() error { return syscall.CloseHandle(l.h) }
