//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package vault

import "golang.org/x/sys/unix"

const (
	ioctlGetTermios = unix.TIOCGETA
	ioctlSetTermios = unix.TIOCSETA
)
