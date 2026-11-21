//go:build windows

package privfile

import (
	"fmt"
	"os"
	"os/exec"
)

// makeLink makes a symbolic link (which needs the privilege, or developer mode, and fails without it) or a junction
// (which needs neither, and points at a folder).
func makeLink(kind linkKind, target, link string) error {
	if kind == junctionToDir {
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
			return fmt.Errorf("mklink /J: %v: %s", err, out)
		}
		return nil
	}
	return os.Symlink(target, link)
}
