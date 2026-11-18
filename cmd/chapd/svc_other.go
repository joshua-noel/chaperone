//go:build !windows

package main

import (
	"fmt"
	"io"
)

func svcCmd(_ []string, _, stderr io.Writer) int {
	fmt.Fprintln(stderr, "chapd svc: the service host exists on Windows only; use `chapd run`")
	return 2
}
