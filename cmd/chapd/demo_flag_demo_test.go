//go:build demo

package main

import (
	"bytes"
	"testing"
)

// Even the demo build gives the flag to `chapd run` only, never to the service.
func TestDemoFlagNotOnService(t *testing.T) {
	var errb bytes.Buffer
	if _, code := parseRunFlags("chapd svc", []string{"-dev-fake-github", "x.json"}, &errb, false); code != 2 {
		t.Errorf("chapd svc accepted -dev-fake-github (exit %d)", code)
	}
}
