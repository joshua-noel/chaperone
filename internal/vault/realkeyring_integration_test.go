package vault

// Shared parts of the opt-in tests that run the key wrappers against the real
// operating-system tools (`security` on macOS, `secret-tool` on Linux).
//
// Every test that touches a real keyring is skipped unless its environment
// variable is set to 1, so `go test ./...` on a developer machine never writes
// to the user's keychain or keyring:
//
//	CHAPERONE_TEST_REAL_KEYCHAIN=1        macOS: keychain-macos wrapper (keychain_macos_integration_test.go)
//	CHAPERONE_TEST_REAL_SECRET_SERVICE=1  Linux: secret-service wrapper (secretservice_integration_test.go)
//
// CI sets them in .github/workflows/keyring.yml, on a throwaway keychain and a
// private session keyring. The tests only compare keys. A key is never
// printed, logged or put in a failure message.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// requireRealKeyring skips the test unless envVar is "1" and the system is
// goos.
func requireRealKeyring(t *testing.T, envVar, goos, what string) {
	t.Helper()
	if os.Getenv(envVar) != "1" {
		t.Skipf("set %s=1 to run against the real %s (opt-in: it writes to, and deletes from, the current user's keyring)", envVar, what)
	}
	if runtime.GOOS != goos {
		t.Skipf("%s needs %s; this is %s", envVar, goos, runtime.GOOS)
	}
}

// recordedCall is one run of the tool: the arguments, never the standard input.
type recordedCall struct {
	args []string
	exit int
	err  error
}

// recordingRunner runs the real tool and remembers each call's argument list,
// so a test can say what the wrapper itself put on the command line.
type recordingRunner struct {
	inner commandRunner
	mu    sync.Mutex
	calls []recordedCall
}

func newRecordingRunner() *recordingRunner {
	// A keychain can ask the user to unlock it; on a CI runner nobody answers,
	// so fail well before the production limit of two minutes.
	return &recordingRunner{inner: execRunner{timeout: 45 * time.Second}}
}

func (r *recordingRunner) Run(ctx context.Context, path string, args []string, stdin []byte) (cmdResult, error) {
	res, err := r.inner.Run(ctx, path, args, stdin)
	r.mu.Lock()
	r.calls = append(r.calls, recordedCall{args: append([]string(nil), args...), exit: res.exit, err: err})
	r.mu.Unlock()
	return res, err
}

// forbidInArgs fails the test if any recorded argument holds needle.
func (r *recordingRunner) forbidInArgs(t *testing.T, needle string) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, c := range r.calls {
		for _, a := range c.args {
			if strings.Contains(a, needle) {
				t.Errorf("call %d (%s): the key is in the tool's argument list", i, c.args[0])
			}
		}
	}
}

// logCalls writes what was run: the first argument (the tool's command) and
// the exit code. It is for the person reading a CI log.
func (r *recordingRunner) logCalls(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, c := range r.calls {
		verb := "(none)"
		if len(c.args) > 0 {
			verb = c.args[0]
		}
		t.Logf("tool call %d: %s, exit %d, did not start: %v", i, verb, c.exit, c.err != nil)
	}
}

// platformFor builds a wrapper the way [NewWrapper] does, on the real system
// and the real trust check, but with the recording runner.
func platformFor(rec *recordingRunner) platform {
	return platform{goos: runtime.GOOS, run: rec, find: findTool}
}

// randomKey returns 32 random bytes and the lower-case hex the stores hold.
func randomKey(t *testing.T) (key []byte, hexValue string) {
	t.Helper()
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key, hex.EncodeToString(key)
}

// refID returns the id inside a reference made by Wrap.
func refID(t *testing.T, blob []byte) string {
	t.Helper()
	parts := strings.Split(string(blob), "\n")
	if len(parts) != 4 || !isHexID([]byte(parts[2])) {
		t.Fatalf("Wrap returned something that is not a key reference (%d bytes)", len(blob))
	}
	return parts[2]
}

// removeAfter deletes the item under id when the test ends, whatever happened.
func removeAfter(t *testing.T, st secretStore, id string) {
	t.Helper()
	t.Cleanup(func() { _ = st.remove(context.Background(), id) })
}

// removeVaultItemsAfter deletes, when the test ends, every item that the key
// files in dir refer to. Call it before the vault is created: it reads the
// files only at the end.
func removeVaultItemsAfter(t *testing.T, st secretStore, w storeWrapper, dir string) {
	t.Helper()
	t.Cleanup(func() {
		for _, name := range []string{identityFile, fpKeyFile} {
			b, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				continue
			}
			if id, err := w.parseRef(b); err == nil {
				_ = st.remove(context.Background(), id)
			}
		}
	})
}

// --- the process list ---

// psHas reports whether needle is in the command line of any process now.
func psHas(needle string) (bool, error) {
	out, err := psList()
	if err != nil {
		return false, err
	}
	return bytes.Contains(out, []byte(needle)), nil
}

// psArgs is the exact ps command used on every system: all processes (-ax),
// no width limit (-ww), the command line only (-o command=). Both the BSD ps of
// macOS and the procps ps of Linux take it.
var psArgs = []string{"-axww", "-o", "command="}

func psList() ([]byte, error) {
	return exec.Command("ps", psArgs...).Output()
}

// describePS is what the next run needs to see when the control check fails:
// the command, how many lines came back, the first lines, and every line that
// could be the control process. It holds no key (it runs before any is made).
func describePS(marker string) string {
	out, err := psList()
	var b strings.Builder
	fmt.Fprintf(&b, "command: ps %s\nerror: %v\nbytes: %d\n", strings.Join(psArgs, " "), err, len(out))
	lines := strings.Split(string(out), "\n")
	fmt.Fprintf(&b, "lines: %d\nfirst lines:\n", len(lines))
	clip := func(s string) string {
		if len(s) > 200 {
			return s[:200] + "..."
		}
		return s
	}
	for i, l := range lines {
		if i >= 8 {
			break
		}
		fmt.Fprintf(&b, "  %s\n", clip(l))
	}
	b.WriteString("lines naming the control process or its sleep:\n")
	for _, l := range lines {
		if strings.Contains(l, marker) || strings.Contains(l, "chaperone-ps-control") || strings.Contains(l, "sleep") {
			fmt.Fprintf(&b, "  %s\n", clip(l))
		}
	}
	return b.String()
}

// requirePSSeesArguments proves, with a process whose command line holds a
// marker, that `ps` here can see arguments. Without that, an empty answer
// would prove nothing.
func requirePSSeesArguments(t *testing.T) {
	t.Helper()
	marker := "chaperone-ps-control-" + randomHex(t, 8)
	// The marker is $0 of a shell that stays a shell. The script must not end
	// in a single command: a shell may then exec that command in its own place
	// (macOS does), the process becomes `sleep 20`, and the marker is gone from
	// its command line.
	c := exec.Command("sh", "-c", "sleep 20; true", marker)
	if err := c.Start(); err != nil {
		t.Fatalf("start the ps control process: %v", err)
	}
	defer func() { _ = c.Process.Kill(); _ = c.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		has, err := psHas(marker)
		if err != nil {
			t.Fatalf("ps: %v", err)
		}
		if has {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("ps did not show the command line of a control process: the process-list check cannot work on this system\ncontrol command: sh -c %q %s\n%s",
				"sleep 20; true", marker, describePS(marker))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// psWatch samples the process list in a loop while a call runs, and notes
// whether needle ever appeared in any command line. A call that is quicker than
// one `ps` is not caught; the argument-list record of [recordingRunner] is the
// exact check, and this is the check that looks from outside.
type psWatch struct {
	stopCh  chan struct{}
	wg      sync.WaitGroup
	samples atomic.Int64
	seen    atomic.Bool
	psErr   atomic.Value // error
}

// watchProcessList starts sampling for needle. Call stop when done.
func watchProcessList(needle string) *psWatch {
	w := &psWatch{stopCh: make(chan struct{})}
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		for {
			select {
			case <-w.stopCh:
				return
			default:
			}
			has, err := psHas(needle)
			if err != nil {
				w.psErr.Store(err)
				return
			}
			w.samples.Add(1)
			if has {
				w.seen.Store(true)
			}
		}
	}()
	return w
}

// stop ends the sampling and fails the test if the needle was ever seen.
func (w *psWatch) stop(t *testing.T) {
	t.Helper()
	close(w.stopCh)
	w.wg.Wait()
	if err, _ := w.psErr.Load().(error); err != nil {
		t.Fatalf("ps: %v", err)
	}
	t.Logf("process list sampled %d times during the call", w.samples.Load())
	if w.seen.Load() {
		t.Error("the key was visible in the process list while the tool ran")
	}
}

// --- scenarios that are the same on both systems ---

// realWrapRoundTrip wraps a random key with w, unwraps it, compares, and
// checks that the key was neither on a command line nor in the reference. It
// returns the id of the item, which is also scheduled for deletion.
func realWrapRoundTrip(t *testing.T, w KeyWrapper, st secretStore, rec *recordingRunner) (key []byte, value, id string) {
	t.Helper()
	requirePSSeesArguments(t)
	key, value = randomKey(t)
	t.Cleanup(func() { clear(key) })

	watch := watchProcessList(value[:24])
	blob, err := w.Wrap(key)
	if err != nil {
		watch.stop(t)
		t.Fatalf("Wrap: %v", err)
	}
	id = refID(t, blob)
	removeAfter(t, st, id)

	got, err := w.Unwrap(blob)
	watch.stop(t)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	defer clear(got)
	if !bytes.Equal(got, key) {
		t.Fatalf("Unwrap returned %d bytes that differ from the %d-byte key that was wrapped", len(got), len(key))
	}
	if bytes.Contains(blob, []byte(value)) || bytes.Contains(blob, key) {
		t.Error("the reference blob contains the key")
	}
	rec.forbidInArgs(t, value[:24])
	return key, value, id
}

// realVaultRoundTrip runs a whole vault on the real wrapper: Init, Import, Use,
// close, open again, Use. It deletes the two keys the vault stored.
func realVaultRoundTrip(t *testing.T, w storeWrapper, st secretStore) {
	t.Helper()
	cfg := newConfig(t, w)
	removeVaultItemsAfter(t, st, w, cfg.KeyDir)
	ctx := context.Background()
	if err := Init(ctx, cfg, func(string) error { return nil }); err != nil {
		t.Fatalf("Init: %v", err)
	}
	secret := []byte("chaperone-ci-vault-secret-" + randomHex(t, 12))
	check := func(v *Vault) {
		t.Helper()
		err := v.Use(ctx, "ci-secret", func(s []byte) error {
			if !bytes.Equal(s, secret) {
				return errors.New("the secret read back differs from the one imported")
			}
			return nil
		})
		if err != nil {
			t.Fatalf("Use: %v", err)
		}
	}
	v, err := Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := v.Import(ctx, Meta{ID: "ci-secret", Kind: "test", Owner: "ci"}, append([]byte(nil), secret...)); err != nil {
		v.Close()
		t.Fatalf("Import: %v", err)
	}
	check(v)
	v.Close()

	// A second open unwraps both keys again from the keyring.
	v2, err := Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open (second time): %v", err)
	}
	defer v2.Close()
	check(v2)
}
