package vault

import (
	"bytes"
	"context"
	"os"
	"runtime"
	"strings"
	"testing"
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
	if got, err := findTool(file, []string{"/nowhere", dir}); err != nil || got != path {
		t.Errorf("got %q, %v", got, err)
	}
	if _, err := findTool(file, []string{"/nowhere"}); err == nil {
		t.Error("found a tool outside the directories")
	}
	// A tool on PATH is not found: PATH is not consulted.
	t.Setenv("PATH", dir)
	if _, err := findTool(file, []string{"/nowhere"}); err == nil {
		t.Error("consulted PATH")
	}
	if _, err := findTool("", []string{dir}); err == nil {
		t.Error("a directory was returned as a tool")
	}
	if runtime.GOOS != "windows" {
		noexec := dir + "/plain"
		if err := os.WriteFile(noexec, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := findTool("plain", []string{dir}); err == nil {
			t.Error("a file without the execute bit was returned")
		}
	}
}
