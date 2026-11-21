//go:build !windows

package privfile

import (
	"errors"
	"os"
)

func makeLink(kind linkKind, target, link string) error {
	if kind == junctionToDir {
		return errors.New("junctions exist only on Windows")
	}
	return os.Symlink(target, link)
}
