package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// isTerminal reports whether f is a console. GetConsoleMode fails on a pipe,
// a file and NUL, which is what a script's redirected stderr is.
func isTerminal(f *os.File) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(f.Fd()), &mode) == nil
}
