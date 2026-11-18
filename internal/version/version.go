// Package version reports the build identity shared by chapd, chap and chap-host.
package version

import (
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
)

// Version and Commit are set at link time:
//
//	-ldflags "-X github.com/joshua-noel/chaperone/internal/version.Version=v0.1.0
//	          -X github.com/joshua-noel/chaperone/internal/version.Commit=<sha>"
//
// Unset values read as "dev" and, for Commit, as the VCS revision the Go
// toolchain stamped into the binary (empty outside a git checkout).
var (
	Version = "dev"
	Commit  = ""
)

// Info is one binary's build identity.
type Info struct {
	Binary  string
	Version string
	Commit  string
	GoOS    string
	GoArch  string
	Go      string
}

// Current returns the identity of the running binary named binary.
func Current(binary string) Info {
	commit := Commit
	if commit == "" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" {
					commit = s.Value
				}
			}
		}
	}
	return Info{
		Binary:  binary,
		Version: Version,
		Commit:  commit,
		GoOS:    runtime.GOOS,
		GoArch:  runtime.GOARCH,
		Go:      runtime.Version(),
	}
}

// String formats the identity on one line:
// "chap dev (commit 0123456789ab) linux/amd64 go1.26.10".
func (i Info) String() string {
	commit := i.Commit
	if len(commit) > 12 {
		commit = commit[:12]
	}
	if commit == "" {
		commit = "unknown"
	}
	return fmt.Sprintf("%s %s (commit %s) %s/%s %s", i.Binary, i.Version, commit, i.GoOS, i.GoArch, i.Go)
}

// Fprint writes the identity of binary followed by a newline to w.
func Fprint(w io.Writer, binary string) error {
	_, err := fmt.Fprintln(w, Current(binary))
	return err
}
