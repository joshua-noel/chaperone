//go:build windows

package loopback

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// soExclusiveAddrUse is SO_EXCLUSIVEADDRUSE, ~SO_REUSEADDR: a socket that holds
// the address and that no other socket may share, whatever options it sets.
const soExclusiveAddrUse = -5

func exclusive(_, _ string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, soExclusiveAddrUse, 1)
	}); err != nil {
		return err
	}
	return serr
}
