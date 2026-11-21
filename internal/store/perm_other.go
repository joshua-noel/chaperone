//go:build !unix

package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// File modes mean nothing on Windows: access to the folder is set by its ACL (the install script gives it to the
// service account only). The database is not pre-created here, because SQLite makes it and the account that opens it
// first (the service, or an administrator running `chapd orch`) must not lock the other out of it.
//
// What this does check is that the path is not a link: a symbolic link at the path (a dangling one would have SQLite
// create the file it points at) or a junction is refused, as the Unix build refuses it with O_NOFOLLOW. The check and
// SQLite's open are two steps, so a link planted between them is not caught; the folder's ACL is what keeps others out.
func prepareDBFile(path string) error {
	st, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("store: %w", err)
	case !st.Mode().IsRegular():
		return fmt.Errorf("store: %s is not a plain file (it is a link, a folder or a device); refusing to open a database there", path)
	}
	return nil
}

func restrictSidecars(string) error { return nil }
