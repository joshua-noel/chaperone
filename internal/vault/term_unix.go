//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package vault

import (
	"os"

	"golang.org/x/sys/unix"
)

// ttyTerminal is /dev/tty, the controlling terminal. Using it instead of
// standard input leaves standard input for data, and fails when there is no
// terminal rather than reading a passphrase from whatever stdin is.
type ttyTerminal struct{ f *os.File }

func init() {
	openTerminal = func() (terminal, error) {
		f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			return nil, errNoTerminal
		}
		return ttyTerminal{f}, nil
	}
}

func (t ttyTerminal) Read(p []byte) (int, error)  { return t.f.Read(p) }
func (t ttyTerminal) Write(p []byte) (int, error) { return t.f.Write(p) }
func (t ttyTerminal) Close() error                { return t.f.Close() }

func (t ttyTerminal) disableEcho() (func(), error) {
	fd := int(t.f.Fd())
	old, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		return nil, err
	}
	raw := *old
	raw.Lflag &^= unix.ECHO | unix.ECHONL
	if err := unix.IoctlSetTermios(fd, ioctlSetTermios, &raw); err != nil {
		return nil, err
	}
	return func() { _ = unix.IoctlSetTermios(fd, ioctlSetTermios, old) }, nil
}
