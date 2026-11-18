//go:build !windows && !linux

package main

import "os"

// isTerminal is false where chap is not built for (windows and linux are the
// targets): no banner is better than a banner in a pipe.
func isTerminal(*os.File) bool { return false }
