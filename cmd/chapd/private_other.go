//go:build !windows

package main

import "os"

// elevated is true off Windows: there the file mode below is the whole story,
// and tests run here.
func elevated() bool { return true }

// restrictToCurrentUser sets mode 0600 (the file was created 0600 already).
func restrictToCurrentUser(path string) error { return os.Chmod(path, 0o600) }
