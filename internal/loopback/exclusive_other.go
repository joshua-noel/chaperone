//go:build !windows

package loopback

import "syscall"

func exclusive(_, _ string, _ syscall.RawConn) error { return nil }
