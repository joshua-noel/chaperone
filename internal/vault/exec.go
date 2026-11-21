package vault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// commandRunner is the one place the vault starts another program. It exists
// so the keychain wrappers can be tested with a fake and so the rules for
// running a secret-handling tool live in one spot:
//
//   - a secret goes to the tool on standard input and comes back on standard
//     output. It is never an argument and never an environment variable,
//     because other processes of the same user can read both;
//   - the program is an absolute path chosen by this package, never looked up
//     through PATH at the moment of use;
//   - the output buffers are allocated once at a fixed size, so no earlier
//     copy of a secret is left behind by a growing buffer, and the caller
//     zeroes them.
type commandRunner interface {
	// Run starts the program at path with args and stdin, waits for it and
	// returns what it wrote. A program that ran and exited non-zero is not an
	// error: it is a result with a non-zero exit code. err is for a program
	// that did not start, timed out, or wrote too much.
	Run(ctx context.Context, path string, args []string, stdin []byte) (cmdResult, error)
}

type cmdResult struct {
	stdout, stderr []byte
	exit           int
}

// wipe zeroes both buffers. The caller of Run MUST call it when done.
func (r cmdResult) wipe() {
	clear(r.stdout)
	clear(r.stderr)
}

const (
	maxToolStdout = 16 << 10
	maxToolStderr = 4 << 10
	// toolTimeout covers a keychain that has to ask the user to unlock it.
	toolTimeout = 2 * time.Minute
)

// toolWaitDelay is how long Run waits, after the tool has exited or was
// killed at the timeout, for its output pipes to close. A tool that left a
// child holding them would otherwise block Run for as long as the child lives.
const toolWaitDelay = 5 * time.Second

// execRunner is the real [commandRunner]. The zero value uses the default
// limits; tests shorten them.
type execRunner struct {
	timeout, waitDelay time.Duration
}

func (r execRunner) Run(ctx context.Context, path string, args []string, stdin []byte) (cmdResult, error) {
	if r.timeout == 0 {
		r.timeout = toolTimeout
	}
	if r.waitDelay == 0 {
		r.waitDelay = toolWaitDelay
	}
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	out := newFixedBuffer(maxToolStdout)
	errb := newFixedBuffer(maxToolStderr)
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.Stdout = out
	cmd.Stderr = errb
	cmd.WaitDelay = r.waitDelay
	err := cmd.Run()
	res := cmdResult{stdout: out.buf, stderr: errb.buf}
	var ee *exec.ExitError
	switch {
	case err != nil && ctx.Err() != nil:
		// Checked first: a tool killed at the timeout also reports an
		// ExitError, which must not be taken for a normal failure.
		res.wipe()
		return cmdResult{}, fmt.Errorf("%s did not finish in %s", filepath.Base(path), r.timeout)
	case err == nil:
	case errors.Is(err, exec.ErrWaitDelay):
		res.wipe()
		return cmdResult{}, fmt.Errorf("%s left a process holding its output open", filepath.Base(path))
	case errors.As(err, &ee):
		res.exit = ee.ExitCode()
		if res.exit == 0 { // killed by a signal
			res.exit = -1
		}
	default:
		res.wipe()
		return cmdResult{}, fmt.Errorf("start %s: %w", filepath.Base(path), err)
	}
	if out.overflow {
		res.wipe()
		return cmdResult{}, fmt.Errorf("%s wrote more than %d bytes", filepath.Base(path), maxToolStdout)
	}
	return res, nil
}

// fixedBuffer is an io.Writer over one allocation. Output past the capacity
// is dropped and flagged: growing the slice would leave a stale copy of a
// secret that nobody can zero.
type fixedBuffer struct {
	buf      []byte
	overflow bool
}

func newFixedBuffer(n int) *fixedBuffer { return &fixedBuffer{buf: make([]byte, 0, n)} }

var _ io.Writer = (*fixedBuffer)(nil)

func (b *fixedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if room := cap(b.buf) - len(b.buf); n > room {
		b.overflow = true
		p = p[:room]
	}
	b.buf = append(b.buf, p...)
	// Report all of it as written so the child is not killed by a broken pipe;
	// the overflow flag makes the result an error.
	return n, nil
}

// findTool returns the absolute path of the first regular, executable file
// called name in dirs that [toolTrusted] accepts. The directories are fixed by
// the caller, not read from PATH: a program that another process of the same
// user could put on PATH would receive the secret.
func findTool(name string, dirs []string) (string, error) {
	return findToolWith(name, dirs, toolTrusted)
}

// findToolWith is findTool with the trust rule given, for tests.
func findToolWith(name string, dirs []string, trusted func(file, dir os.FileInfo) bool) (string, error) {
	var skipped []string
	for _, d := range dirs {
		p := filepath.Join(d, name)
		st, err := os.Stat(p)
		if err != nil || !st.Mode().IsRegular() || (runtime.GOOS != "windows" && st.Mode().Perm()&0o111 == 0) {
			continue
		}
		dst, err := os.Stat(d)
		if err != nil || !trusted(st, dst) {
			skipped = append(skipped, p)
			continue
		}
		return p, nil
	}
	if len(skipped) > 0 {
		return "", fmt.Errorf("%s found at %v but not trusted: the file and its folder must be owned by root and writable by nobody else", name, skipped)
	}
	return "", fmt.Errorf("%s not found in %v", name, dirs)
}
