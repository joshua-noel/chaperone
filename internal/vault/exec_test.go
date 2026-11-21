package vault

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestMain lets this test binary stand in for an external tool: run with
// VAULT_TEST_TOOL set, it behaves as the tool named there.
func TestMain(m *testing.M) {
	switch os.Getenv("VAULT_TEST_TOOL") {
	case "":
		os.Exit(m.Run())
	case "cat": // standard input to standard output, nothing else
		var buf bytes.Buffer
		buf.ReadFrom(os.Stdin)
		os.Stdout.Write(buf.Bytes())
	case "exit3":
		os.Stderr.WriteString("failing on purpose")
		os.Exit(3)
	case "flood":
		os.Stdout.Write(bytes.Repeat([]byte("x"), maxToolStdout+10))
	case "hang":
		time.Sleep(time.Minute)
	case "orphan": // exits at once but leaves a child holding standard output
		c := exec.Command(os.Args[0])
		c.Env = append(os.Environ(), "VAULT_TEST_TOOL=sleep3")
		c.Stdout = os.Stdout
		_ = c.Start()
	case "sleep3":
		time.Sleep(3 * time.Second)
	case "fakesecurity":
		fakeSecurityMain()
	}
	os.Exit(0)
}

func runSelf(t *testing.T, tool string, args []string, stdin []byte) (cmdResult, error) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAULT_TEST_TOOL", tool)
	return execRunner{}.Run(context.Background(), self, args, stdin)
}

func TestExecRunnerPassesStdinAndReadsStdout(t *testing.T) {
	res, err := runSelf(t, "cat", nil, []byte("secret-on-stdin"))
	if err != nil {
		t.Fatal(err)
	}
	defer res.wipe()
	if res.exit != 0 || string(res.stdout) != "secret-on-stdin" {
		t.Errorf("exit %d stdout %q", res.exit, res.stdout)
	}
}

func TestExecRunnerExitCodeIsAResultNotAnError(t *testing.T) {
	res, err := runSelf(t, "exit3", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.exit != 3 || string(res.stderr) != "failing on purpose" {
		t.Errorf("exit %d stderr %q", res.exit, res.stderr)
	}
}

func TestExecRunnerRefusesTooMuchOutput(t *testing.T) {
	if _, err := runSelf(t, "flood", nil, nil); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("got %v", err)
	}
}

func TestExecRunnerMissingProgram(t *testing.T) {
	_, err := execRunner{}.Run(context.Background(), "/no/such/tool", nil, nil)
	if err == nil {
		t.Fatal("started a program that does not exist")
	}
	if strings.Contains(err.Error(), "exit") {
		t.Errorf("a start failure reported as an exit: %v", err)
	}
}

func TestFixedBufferNeverGrows(t *testing.T) {
	b := newFixedBuffer(8)
	first := &b.buf[:1][0]
	n, err := b.Write([]byte("0123456789"))
	if n != 10 || err != nil {
		t.Errorf("Write reported %d, %v; a short count would break the pipe", n, err)
	}
	if !b.overflow || len(b.buf) != 8 || cap(b.buf) != 8 {
		t.Errorf("len %d cap %d overflow %v", len(b.buf), cap(b.buf), b.overflow)
	}
	if &b.buf[0] != first {
		t.Error("the buffer moved: a stale copy of the output would remain")
	}
}

func TestFindToolSearchesOnlyTheGivenDirectories(t *testing.T) {
	dir := t.TempDir()
	name := "fake-secret-tool"
	file := name
	if runtime.GOOS == "windows" {
		file += ".exe"
	}
	path := dir + string(os.PathSeparator) + file
	if err := os.WriteFile(path, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := findToolWith(file, []string{"/nowhere", dir}, anyTool); err != nil || got != path {
		t.Errorf("got %q, %v", got, err)
	}
	if _, err := findToolWith(file, []string{"/nowhere"}, anyTool); err == nil {
		t.Error("found a tool outside the directories")
	}
	// A tool on PATH is not found: PATH is not consulted.
	t.Setenv("PATH", dir)
	if _, err := findToolWith(file, []string{"/nowhere"}, anyTool); err == nil {
		t.Error("consulted PATH")
	}
	if _, err := findToolWith("", []string{dir}, anyTool); err == nil {
		t.Error("a directory was returned as a tool")
	}
	if runtime.GOOS != "windows" {
		noexec := dir + "/plain"
		if err := os.WriteFile(noexec, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := findToolWith("plain", []string{dir}, anyTool); err == nil {
			t.Error("a file without the execute bit was returned")
		}
	}
}

func anyTool(_, _ os.FileInfo) bool { return true }

func TestExecRunnerTimeoutIsATimeoutNotAnExit(t *testing.T) {
	self, _ := os.Executable()
	t.Setenv("VAULT_TEST_TOOL", "hang")
	start := time.Now()
	res, err := execRunner{timeout: 300 * time.Millisecond, waitDelay: time.Second}.Run(context.Background(), self, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "did not finish") {
		t.Fatalf("a tool that hangs gave %+v, %v", res, err)
	}
	if res.exit != 0 || res.stdout != nil {
		t.Errorf("a result came back with the timeout: %+v", res)
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("took %s", time.Since(start))
	}
}

func TestExecRunnerDoesNotWaitForAnOrphanHoldingTheOutput(t *testing.T) {
	self, _ := os.Executable()
	t.Setenv("VAULT_TEST_TOOL", "orphan")
	start := time.Now()
	_, err := execRunner{timeout: time.Minute, waitDelay: 300 * time.Millisecond}.Run(context.Background(), self, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "holding its output") {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) > 2500*time.Millisecond { // the orphan lives 3 s
		t.Errorf("waited %s for the orphan", time.Since(start))
	}
}

// fakeSecurityMain is a stand-in for /usr/bin/security that really runs as a
// separate process: it logs its argument list and environment, and keeps
// items in files, so a test can look at what an outside observer could see.
func fakeSecurityMain() {
	dir := os.Getenv("VAULT_TEST_DIR")
	log, _ := os.OpenFile(filepath.Join(dir, "observed.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	fmt.Fprintf(log, "ARGV %q\n", os.Args[1:])
	for _, e := range os.Environ() {
		fmt.Fprintf(log, "ENV %s\n", e)
	}
	log.Close()
	in, _ := io.ReadAll(os.Stdin)
	args := os.Args[1:]
	switch {
	case len(args) == 1 && args[0] == "-i":
		f := strings.Fields(string(in))
		os.WriteFile(filepath.Join(dir, "item-"+flagValue(f, "-a")), []byte(flagValue(f, "-w")), 0o600)
	case len(args) > 0 && args[0] == "find-generic-password":
		b, err := os.ReadFile(filepath.Join(dir, "item-"+flagValue(args, "-a")))
		if err != nil {
			os.Exit(44)
		}
		os.Stdout.Write(append(b, '\n'))
	}
}

// TestKeychainKeyNeverReachesAnObserver runs the macOS wrapper over the real
// execRunner and a real child process, and checks what that process was given:
// the key is on its standard input and nowhere else.
func TestKeychainKeyNeverReachesAnObserver(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	t.Setenv("VAULT_TEST_TOOL", "fakesecurity")
	t.Setenv("VAULT_TEST_DIR", dir)
	w := storeWrapper{name: KeychainName, store: keychainStore{run: execRunner{}, tool: self}}
	plain := []byte("AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ")
	blob, err := w.Wrap(plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := w.Unwrap(blob)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("round trip: %v", err)
	}
	logged, err := os.ReadFile(filepath.Join(dir, "observed.log"))
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{string(plain), hexOf(plain), hexOf(plain)[:24], "AGE-SECRET-KEY"} {
		if bytes.Contains(logged, []byte(leak)) {
			t.Errorf("the key (%.12s...) was visible to the process in its arguments or environment:\n%s", leak, logged)
		}
	}
	if !bytes.Contains(logged, []byte(`ARGV ["-i"]`)) || !bytes.Contains(logged, []byte("find-generic-password")) {
		t.Errorf("the tool was not run as expected:\n%s", logged)
	}
	stored, err := os.ReadFile(filepath.Join(dir, "item-"+strings.Split(string(blob), "\n")[2]))
	if err != nil || string(stored) != hexOf(plain) {
		t.Errorf("the key did not arrive on standard input: %q, %v", stored, err)
	}
}

func TestToolTrustRefusesWhatOthersCouldSwap(t *testing.T) {
	trustedNever := func(_, _ os.FileInfo) bool { return false }
	dir := t.TempDir()
	path := filepath.Join(dir, "tool.exe")
	if err := os.WriteFile(path, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := findToolWith("tool.exe", []string{dir}, trustedNever)
	if err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Errorf("an untrusted tool was returned or the error is unclear: %v", err)
	}
	if runtime.GOOS == "windows" {
		return // ownership is not checked on Windows, which uses no tool
	}
	fi, _ := os.Stat(path)
	di, _ := os.Stat(dir)
	if os.Getuid() != 0 && toolTrusted(fi, di) {
		t.Error("a file owned by an ordinary user was trusted")
	}
	// Group-writable is refused whoever owns it.
	if err := os.Chmod(path, 0o775); err != nil {
		t.Fatal(err)
	}
	fi, _ = os.Stat(path)
	if toolTrusted(fi, di) {
		t.Error("a group-writable tool was trusted")
	}
}
