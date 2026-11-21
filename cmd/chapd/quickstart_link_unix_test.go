//go:build !windows

package main

import (
	"errors"
	"os"
)

func makeTestLink(junction bool, target, link string) error {
	if junction {
		return errors.New("junctions exist only on Windows")
	}
	return os.Symlink(target, link)
}
