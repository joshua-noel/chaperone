//go:build unix

package vault

import (
	"os"
	"testing"
)

// The system's own tools are what the rule is for: on a normal system /bin/sh
// and its folder are root-owned and writable by nobody else.
func TestToolTrustAcceptsASystemTool(t *testing.T) {
	for _, p := range []string{"/bin/sh", "/usr/bin/env"} {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		dir := p[:len(p)-len(fi.Name())-1]
		di, err := os.Stat(dir)
		if err != nil {
			continue
		}
		if !toolTrusted(fi, di) {
			t.Skipf("%s is not root-owned here (a container or a package store?)", p)
		}
		return
	}
	t.Skip("no system tool to look at")
}
