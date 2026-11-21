//go:build !windows

package privfile

import "os"

// Create makes a NEW file at path, readable and writable by the current user only (mode 0600), and opens it for
// writing. It fails if anything exists at path: O_EXCL also refuses a symbolic link there (a dangling one too), so
// a file somebody else planted, or a link to a file of yours, is never opened or followed.
func Create(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}
