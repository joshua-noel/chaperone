package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Redirected stderr (a file, the null device, the test runner's pipe) is not
// a terminal, so a script's `2>/dev/null` can never use up the one-time banner.
func TestIsTerminalFalseWhenRedirected(t *testing.T) {
	file, err := os.Create(filepath.Join(t.TempDir(), "err.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	for name, f := range map[string]*os.File{"file": file, "null device": null, "pipe": w} {
		if isTerminal(f) {
			t.Errorf("%s reported as a terminal", name)
		}
	}
}
