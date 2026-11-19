package vault

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
)

// call is one program start recorded by a fake runner.
type call struct {
	path  string
	args  []string
	stdin string
}

// fakeTool is a commandRunner that behaves like the macOS `security` tool or
// `secret-tool` for the commands the wrappers use, with an in-memory store.
// It records every call so tests can check where a secret travelled.
type fakeTool struct {
	kind string // "security" or "secret-tool"

	mu    sync.Mutex
	items map[string]string // id -> stored value
	calls []call

	failRun    error  // Run returns this error (program missing, timeout)
	failPut    int    // non-zero: store commands exit with this code
	failGet    int    // non-zero: read commands exit with this code
	echoStdin  bool   // failing commands echo their standard input on stderr
	corrupt    bool   // store commands succeed but store nothing
	stderrText string // stderr of a failing command
}

func newFakeSecurity() *fakeTool   { return &fakeTool{kind: "security", items: map[string]string{}} }
func newFakeSecretTool() *fakeTool { return &fakeTool{kind: "secret-tool", items: map[string]string{}} }

func (f *fakeTool) Run(_ context.Context, path string, args []string, stdin []byte) (cmdResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{path, append([]string(nil), args...), string(stdin)})
	if f.failRun != nil {
		return cmdResult{}, f.failRun
	}
	fail := func(code int) (cmdResult, error) {
		msg := f.stderrText
		if f.echoStdin {
			msg += string(stdin)
		}
		return cmdResult{stderr: []byte(msg), exit: code}, nil
	}
	if f.kind == "security" {
		return f.security(args, stdin, fail)
	}
	return f.secretTool(args, stdin, fail)
}

func flagValue(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func (f *fakeTool) security(args []string, stdin []byte, fail func(int) (cmdResult, error)) (cmdResult, error) {
	switch {
	case len(args) == 1 && args[0] == "-i":
		fields := strings.Fields(string(stdin))
		if len(fields) == 0 || fields[0] != "add-generic-password" {
			return fail(1)
		}
		if f.failPut != 0 {
			return fail(f.failPut)
		}
		if !f.corrupt {
			f.items[flagValue(fields, "-a")] = flagValue(fields, "-w")
		}
		return cmdResult{}, nil
	case len(args) > 0 && args[0] == "find-generic-password":
		if f.failGet != 0 {
			return fail(f.failGet)
		}
		v, ok := f.items[flagValue(args, "-a")]
		if !ok {
			return fail(44)
		}
		return cmdResult{stdout: []byte(v + "\n")}, nil
	case len(args) > 0 && args[0] == "delete-generic-password":
		delete(f.items, flagValue(args, "-a"))
		return cmdResult{}, nil
	}
	return fail(2)
}

func (f *fakeTool) secretTool(args []string, stdin []byte, fail func(int) (cmdResult, error)) (cmdResult, error) {
	if len(args) == 0 {
		return fail(2)
	}
	id := flagValue(args, "id")
	switch args[0] {
	case "store":
		if f.failPut != 0 {
			return fail(f.failPut)
		}
		if !f.corrupt {
			f.items[id] = string(stdin)
		}
		return cmdResult{}, nil
	case "lookup":
		if f.failGet != 0 {
			return fail(f.failGet)
		}
		v, ok := f.items[id]
		if !ok {
			return fail(1)
		}
		return cmdResult{stdout: []byte(v)}, nil // secret-tool adds no newline off a tty
	case "clear":
		delete(f.items, id)
		return cmdResult{}, nil
	}
	return fail(2)
}

// noSecretOnCommandLine fails the test if any recorded call passed the key
// (raw, or in hex) as an argument, or carried it anywhere but standard input.
func (f *fakeTool) noSecretOnCommandLine(t *testing.T, secret []byte) {
	t.Helper()
	hexForm := hexOf(secret)
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		for _, a := range c.args {
			if strings.Contains(a, string(secret)) || strings.Contains(a, hexForm) {
				t.Errorf("%s %v: the key is in an argument", c.path, c.args)
			}
		}
	}
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

func newKeychainWrapper(f *fakeTool) KeyWrapper {
	return storeWrapper{name: KeychainName, store: keychainStore{run: f, tool: "/usr/bin/security"}}
}

func newSecretServiceWrapper(f *fakeTool) KeyWrapper {
	return storeWrapper{name: SecretServiceName, store: secretServiceStore{run: f, tool: "/usr/bin/secret-tool"}}
}

// staticPassphrase is a PassphraseSource with a fixed answer that counts asks.
type staticPassphrase struct {
	mu       sync.Mutex
	pass     string
	err      error
	asked    int
	confirms []bool
	forgot   int
}

func (s *staticPassphrase) Passphrase(confirm bool) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asked++
	s.confirms = append(s.confirms, confirm)
	if s.err != nil {
		return nil, s.err
	}
	return []byte(s.pass), nil
}

func (s *staticPassphrase) Forget() { s.mu.Lock(); s.forgot++; s.mu.Unlock() }

const testPassphrase = "correct horse battery staple"

// testWorkFactor keeps scrypt fast in tests; production uses 18.
const testWorkFactor = 10

func newTestPassphraseWrapper(pass string) (*passphraseWrapper, *staticPassphrase) {
	src := &staticPassphrase{pass: pass}
	return newPassphraseWrapper(src, testWorkFactor), src
}

var errBoom = errors.New("boom")

func contains(b []byte, s string) bool { return bytes.Contains(b, []byte(s)) }
