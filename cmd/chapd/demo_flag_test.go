//go:build !demo

package main

import (
	"bytes"
	"testing"
)

// The shipped build has no demo flag, in `chapd run` or in the service.
func TestShippedBuildHasNoDemoFlag(t *testing.T) {
	for _, name := range []string{"chapd run", "chapd svc"} {
		var errb bytes.Buffer
		if _, code := parseRunFlags(name, []string{"-dev-fake-github", "x.json"}, &errb, name == "chapd run"); code != 2 {
			t.Errorf("%s accepted -dev-fake-github (exit %d)", name, code)
		}
	}
}
