//go:build !unix

package vault

import "os"

// toolTrusted: file ownership is not checked off Unix. Only Windows reaches
// this, and it uses no external tool (DPAPI is a system call).
func toolTrusted(_, _ os.FileInfo) bool { return true }
