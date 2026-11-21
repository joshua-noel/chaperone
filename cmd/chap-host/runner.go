package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/joshua-noel/chaperone/internal/grant"
	"github.com/joshua-noel/chaperone/internal/privfile"
)

// Refusal codes the runner adds to the grant package's.
const (
	CodeBusy          = "HOST_BUSY"
	CodeNotConfigured = "RUNBOOK_NOT_CONFIGURED"
	CodeScriptRead    = "SCRIPT_UNREADABLE"
	CodeStaging       = "STAGING_FAILED"
	CodeStart         = "START_FAILED"

	maxScriptBytes = 1 << 20
	waitDelay      = 10 * time.Second
)

// Runner turns a grant into one run of one allowlisted runbook, or into a
// refusal. It has no entry point that takes a command, an argument or a path
// from its caller: the only input is the grant's wire string.
type Runner struct {
	verifier *grant.Verifier
	runbooks map[string]Runbook
	tempRoot string
	log      *slog.Logger
	busy     sync.Mutex // one runbook at a time
}

// NewRunner builds a runner. runbooks must match the grant allowlist exactly.
// tempRoot is the private directory for script copies; it belongs to the
// helper, and whatever a crashed run left in it is deleted here.
func NewRunner(v *grant.Verifier, runbooks map[string]Runbook, tempRoot string, log *slog.Logger) (*Runner, error) {
	if err := checkRunbooks(runbooks); err != nil {
		return nil, err
	}
	if err := os.RemoveAll(tempRoot); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(tempRoot, 0o700); err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Runner{verifier: v, runbooks: runbooks, tempRoot: tempRoot, log: log}, nil
}

// Outcome is what happened to one presented grant.
type Outcome struct {
	Result
	Grant *grant.Grant // nil when the grant did not verify
}

func refused(code string) Outcome { return Outcome{Result: Result{Status: "refused", Code: code}} }

// Run verifies token and, only if every check passes, runs the runbook with
// its output (redacted) written to out. The checks, in order: busy; signature,
// schema, lifetime, clock, nonce (grant.Verifier); runbook configured; the
// script on disk hashes to script_sha256; the private copy hashes to it too.
// A grant that passed the nonce check is spent whatever happens afterwards.
func (r *Runner) Run(ctx context.Context, token string, out io.Writer) Outcome {
	if !r.busy.TryLock() {
		return refused(CodeBusy)
	}
	defer r.busy.Unlock()

	g, err := r.verifier.Verify(token)
	if err != nil {
		r.log.Warn("grant refused", "code", grant.CodeOf(err), "detail", err.Error())
		return refused(grant.CodeOf(err))
	}
	fail := func(code string, err error) Outcome {
		r.log.Warn("grant refused", "grant", g.Runbook, "requester", g.Requester(), "code", code, "detail", err.Error())
		o := refused(code)
		o.Grant = g
		return o
	}

	rb := r.runbooks[g.Runbook] // present: Verify only returns allowlisted names, NewRunner checked the table
	if rb.Source == "" {
		return fail(CodeNotConfigured, errors.New("no script path in the config"))
	}
	script, err := readScript(rb.Source)
	if err != nil {
		return fail(CodeScriptRead, err)
	}
	if !grant.SameHash(grant.HashBytes(script), g.ScriptSHA256) {
		return fail(grant.ErrScript.Code, errors.New("script on disk does not match script_sha256"))
	}

	dir, err := os.MkdirTemp(r.tempRoot, "run-")
	if err != nil {
		return fail(CodeStaging, err)
	}
	defer os.RemoveAll(dir)
	copyPath := filepath.Join(dir, "script")
	stdin, err := stageCopy(copyPath, script, g.ScriptSHA256)
	if err != nil {
		return fail(CodeStaging, err)
	}
	defer stdin.Close()

	spec, _ := grant.Lookup(g.Runbook)
	argv := rb.Argv(spec.Ordered(g.Args))
	r.log.Info("running", "runbook", g.Runbook, "requester", g.Requester(), "op_hash", g.OpHash, "script_sha256", g.ScriptSHA256)

	runCtx, cancel := context.WithTimeout(ctx, rb.Timeout)
	defer cancel()
	red := newLineRedactor(out)
	cmd := exec.CommandContext(runCtx, argv[0], argv[1:]...)
	cmd.Stdin = stdin
	cmd.Stdout, cmd.Stderr = red, red // one writer: one pipe, order kept
	cmd.Env = childEnv(rb.Env)
	cmd.Dir = dir
	cmd.WaitDelay = waitDelay
	err = cmd.Run()
	_ = red.Close()

	res := Outcome{Grant: g}
	switch {
	case err == nil:
		res.Status = "succeeded"
	case errors.Is(runCtx.Err(), context.DeadlineExceeded):
		res.Status, res.ExitCode = "timeout", -1
	default:
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.Status, res.ExitCode = "failed", ee.ExitCode()
		} else {
			res.Status, res.Code, res.ExitCode = "refused", CodeStart, -1
			r.log.Warn("could not start", "runbook", g.Runbook, "detail", err.Error())
		}
	}
	r.log.Info("finished", "runbook", g.Runbook, "status", res.Status, "exit", res.ExitCode)
	return res
}

// readScript reads a regular file of at most maxScriptBytes.
func readScript(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxScriptBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxScriptBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxScriptBytes)
	}
	return b, nil
}

// stageCopy writes the verified bytes to a new private file, reads the file
// back and checks its hash, and returns it open for reading from the start.
// What runs is what was hashed: the launcher reads this file, not the source.
func stageCopy(path string, script []byte, want string) (*os.File, error) {
	f, err := privfile.CreateReadWrite(path) // new, private, and never through a link planted at the path
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(script); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	back, err := io.ReadAll(io.LimitReader(f, maxScriptBytes+1))
	if err == nil && !grant.SameHash(grant.HashBytes(back), want) {
		err = errors.New("private copy does not match script_sha256")
	}
	if err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// childEnv is the child's whole environment: a short list of system variables
// copied from ours, plus extra. The helper's own environment may hold things a
// script must not see.
func childEnv(extra []string) []string {
	keep := []string{
		"SystemRoot", "SystemDrive", "windir", "ComSpec", "PATH", "PATHEXT",
		"USERPROFILE", "LOCALAPPDATA", "APPDATA", "TEMP", "TMP", "USERNAME",
		"HOME", "TMPDIR", "LANG",
	}
	env := make([]string, 0, len(keep)+len(extra))
	for _, k := range keep {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return append(env, extra...)
}
