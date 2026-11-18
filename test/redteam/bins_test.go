package redteam

// The real `chap` and `chapd` binaries, built once per test run from this
// checkout, for the tests that must see what a person or an agent sees: the
// bytes on stdout and stderr, and the files the commands leave behind.

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

type binaries struct{ chap, chapd string }

var (
	binOnce sync.Once
	binDir  string
	binSet  binaries
	binErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if binDir != "" {
		os.RemoveAll(binDir)
	}
	os.Exit(code)
}

func goTool() string {
	p := filepath.Join(runtime.GOROOT(), "bin", "go")
	if runtime.GOOS == "windows" {
		p += ".exe"
	}
	if _, err := os.Stat(p); err == nil {
		return p
	}
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	return p
}

func buildBinaries(t *testing.T) binaries {
	t.Helper()
	binOnce.Do(func() {
		binDir, binErr = os.MkdirTemp("", "redteam-bin-")
		if binErr != nil {
			return
		}
		ext := ""
		if runtime.GOOS == "windows" {
			ext = ".exe"
		}
		binSet = binaries{chap: filepath.Join(binDir, "chap"+ext), chapd: filepath.Join(binDir, "chapd"+ext)}
		for pkg, out := range map[string]string{"github.com/joshua-noel/chaperone/cmd/chap": binSet.chap, "github.com/joshua-noel/chaperone/cmd/chapd": binSet.chapd} {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			b, err := exec.CommandContext(ctx, goTool(), "build", "-o", out, pkg).CombinedOutput()
			cancel()
			if err != nil {
				binErr = &buildError{pkg: pkg, out: string(b), err: err}
				return
			}
		}
	})
	if binErr != nil {
		t.Fatalf("building the binaries: %v", binErr)
	}
	return binSet
}

type buildError struct {
	pkg, out string
	err      error
}

func (e *buildError) Error() string { return "go build " + e.pkg + ": " + e.err.Error() + "\n" + e.out }

// runBin runs a binary with extra environment and returns stdout and stderr.
func runBin(t *testing.T, bin string, env []string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), env...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err = cmd.Run()
	return so.String(), se.String(), err
}
