//go:build !windows

package privfile

import (
	"os"
	"syscall"
)

const createFlags = os.O_CREATE | os.O_EXCL | syscall.O_NOFOLLOW

// Create makes a NEW file at path, readable and writable by the current user only (mode 0600), and opens it for
// writing. It fails if anything exists at path: O_EXCL also refuses a symbolic link there (a dangling one too), so
// a file somebody else planted, or a link to a file of yours, is never opened or followed.
func Create(path string) (*os.File, error) { return os.OpenFile(path, os.O_WRONLY|createFlags, 0o600) }

// CreateReadWrite is Create for a file the caller also reads back (it is opened for reading and writing).
func CreateReadWrite(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|createFlags, 0o600)
}
