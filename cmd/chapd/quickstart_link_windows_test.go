//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
)

// makeTestLink makes a symbolic link (which needs the privilege, or developer mode) or a junction (which needs
// neither).
func makeTestLink(junction bool, target, link string) error {
	if junction {
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
			return fmt.Errorf("mklink /J: %v: %s", err, out)
		}
		return nil
	}
	return os.Symlink(target, link)
}
