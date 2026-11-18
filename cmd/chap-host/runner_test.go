package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/grant"
)

func TestRunsScratchRunbook(t *testing.T) {
	s := newScratch(t, "echo hello", 30*time.Second)
	o, out := s.run(s.token(s.grantFor("deploy")))
	if o.Status != "succeeded" || o.ExitCode != 0 || o.Grant == nil {
		t.Fatalf("outcome %+v\n%s", o.Result, s.logBuf)
	}
	if want := "ran: hello | args=" + testSHA + "\n"; out != want {
		t.Fatalf("output %q, want %q", out, want)
	}
	if s.launched.Load() != 1 {
		t.Fatalf("launched %d times", s.launched.Load())
	}

	o, out = s.run(s.token(s.grantFor("logs.pilot")))
	if o.Status != "succeeded" || !strings.Contains(out, "args=web") {
		t.Fatalf("logs.pilot: %+v %q", o.Result, out)
	}
}

func TestPrivateCopyIsCleanedUp(t *testing.T) {
	s := newScratch(t, "echo x", 30*time.Second)
	if o, _ := s.run(s.token(s.grantFor("deploy"))); o.Status != "succeeded" {
		t.Fatalf("%+v", o.Result)
	}
	left, _ := os.ReadDir(s.tempRoot)
	if len(left) != 0 {
		t.Fatalf("private copies left behind: %v", left)
	}
}

func TestNoGrantRefused(t *testing.T) {
	s := newScratch(t, "echo should-not-run", 30*time.Second)
	for name, tok := range map[string]string{
		"empty":   "",
		"garbage": "rm -rf /",
		"json":    `{"runbook":"deploy","args":{"sha":"` + testSHA + `"}}`,
		"shell":   "lg1.cm0gLXJmIC8.AAAA",
	} {
		o, out := s.run(tok)
		if o.Status != "refused" || o.Code != "GRANT_MALFORMED" || out != "" {
			t.Errorf("%s: %+v %q", name, o.Result, out)
		}
	}
	if s.launched.Load() != 0 {
		t.Fatal("something was launched without a grant")
	}
}

func TestWrongKeyRefused(t *testing.T) {
	s := newScratch(t, "echo should-not-run", 30*time.Second)
	other := newScratch(t, "echo should-not-run", 30*time.Second)
	o, out := s.run(other.token(s.grantFor("deploy")))
	if o.Status != "refused" || o.Code != "GRANT_SIGNATURE" || out != "" || s.launched.Load() != 0 {
		t.Fatalf("%+v %q launched=%d", o.Result, out, s.launched.Load())
	}
}

func TestReplayRefused(t *testing.T) {
	s := newScratch(t, "echo once", 30*time.Second)
	tok := s.token(s.grantFor("deploy"))
	if o, _ := s.run(tok); o.Status != "succeeded" {
		t.Fatalf("first run: %+v", o.Result)
	}
	for i := 0; i < 3; i++ {
		o, out := s.run(tok)
		if o.Status != "refused" || o.Code != "GRANT_REPLAYED" || out != "" {
			t.Fatalf("replay %d: %+v %q", i, o.Result, out)
		}
	}
	if s.launched.Load() != 1 {
		t.Fatalf("launched %d times, want 1", s.launched.Load())
	}
}

func TestExpiredRefused(t *testing.T) {
	s := newScratch(t, "echo late", 30*time.Second)
	g := s.grantFor("deploy")
	g.IssuedAt, g.ExpiresAt = time.Now().Add(-6*time.Minute).Unix(), time.Now().Add(-time.Minute).Unix()
	o, out := s.run(s.token(g))
	if o.Status != "refused" || o.Code != "GRANT_EXPIRED" || out != "" || s.launched.Load() != 0 {
		t.Fatalf("%+v %q", o.Result, out)
	}
}

func TestWrongScriptHashRefused(t *testing.T) {
	s := newScratch(t, "echo original", 30*time.Second)
	tok := s.token(s.grantFor("deploy"))
	s.writeScript("deploy", "echo tampered") // the file changes after the grant was signed
	o, out := s.run(tok)
	if o.Status != "refused" || o.Code != "GRANT_SCRIPT_MISMATCH" || out != "" || s.launched.Load() != 0 {
		t.Fatalf("%+v %q launched=%d", o.Result, out, s.launched.Load())
	}
	// A grant for a hash that matches no file at all.
	g := s.grantFor("deploy")
	g.ScriptSHA256 = grant.HashBytes([]byte("some other script"))
	o, _ = s.run(s.token(g))
	if o.Code != "GRANT_SCRIPT_MISMATCH" || s.launched.Load() != 0 {
		t.Fatalf("%+v", o.Result)
	}
	// The spent grant stays spent, even though it never ran.
	o, _ = s.run(tok)
	if o.Code != "GRANT_REPLAYED" {
		t.Fatalf("wrong-hash grant was not spent: %+v", o.Result)
	}
}

func TestScriptProblemsRefused(t *testing.T) {
	s := newScratch(t, "echo x", 30*time.Second)
	dirAsScript := filepath.Join(s.dir, "adir")
	if err := os.Mkdir(dirAsScript, 0o700); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(s.dir, "big.sh")
	if err := os.WriteFile(big, make([]byte, maxScriptBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, src := range map[string]string{
		"missing":   filepath.Join(s.dir, "nope.sh"),
		"directory": dirAsScript,
		"too large": big,
		"not set":   "",
	} {
		r := s.build(map[string]string{"deploy": src})
		s.runner = r
		o, _ := s.run(s.token(s.grantFor("deploy")))
		want := CodeScriptRead
		if src == "" {
			want = CodeNotConfigured
		}
		if o.Status != "refused" || o.Code != want {
			t.Errorf("%s: %+v, want %s", name, o.Result, want)
		}
	}
	if s.launched.Load() != 0 {
		t.Fatal("launched despite an unusable script")
	}
}

func TestFailureAndTimeout(t *testing.T) {
	s := newScratch(t, "fail", 30*time.Second)
	o, out := s.run(s.token(s.grantFor("deploy")))
	if o.Status != "failed" || o.ExitCode != 3 || !strings.Contains(out, "about to fail") {
		t.Fatalf("%+v %q", o.Result, out)
	}

	s = newScratch(t, "sleep", 300*time.Millisecond)
	start := time.Now()
	o, _ = s.run(s.token(s.grantFor("deploy")))
	if o.Status != "timeout" || time.Since(start) > 20*time.Second {
		t.Fatalf("%+v after %v", o.Result, time.Since(start))
	}
}

func TestBusyDoesNotSpendGrant(t *testing.T) {
	flag := filepath.Join(t.TempDir(), "go")
	s := newScratch(t, "block "+flag, 30*time.Second)
	first := s.token(s.grantFor("deploy"))
	second := s.token(s.grantFor("deploy"))

	done := make(chan Outcome, 1)
	started := make(chan struct{})
	go func() {
		var w startedWriter
		w.ch = started
		done <- s.runner.Run(context.Background(), first, &w)
	}()
	select {
	case <-started:
	case <-time.After(20 * time.Second):
		t.Fatal("first run did not start")
	}
	o, _ := s.run(second)
	if o.Status != "refused" || o.Code != CodeBusy {
		t.Fatalf("second grant while busy: %+v", o.Result)
	}
	if err := os.WriteFile(flag, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if o := <-done; o.Status != "succeeded" {
		t.Fatalf("first: %+v", o.Result)
	}
	if o, _ := s.run(second); o.Status != "succeeded" {
		t.Fatalf("a grant refused as busy must stay usable: %+v", o.Result)
	}
}

type startedWriter struct {
	ch   chan struct{}
	once bool
}

func (w *startedWriter) Write(p []byte) (int, error) {
	if !w.once {
		w.once = true
		close(w.ch)
	}
	return len(p), nil
}

func TestChildEnvironmentIsMinimal(t *testing.T) {
	t.Setenv("GH_TOKEN", "ghp_canary_must_not_reach_the_script")
	s := newScratch(t, "env", 30*time.Second)
	o, out := s.run(s.token(s.grantFor("deploy")))
	if o.Status != "succeeded" || !strings.Contains(out, "gh_var_present=false") || strings.Contains(out, "canary") {
		t.Fatalf("%+v %q", o.Result, out)
	}
}

func TestOutputIsRedacted(t *testing.T) {
	s := newScratch(t, "secrets", 30*time.Second)
	o, out := s.run(s.token(s.grantFor("deploy")))
	if o.Status != "succeeded" {
		t.Fatalf("%+v", o.Result)
	}
	for _, canary := range []string{"ghp_A1A1", "hunter2", "s3cretpw", "b3BlbnNzaC1rZXk", "BEGIN OPENSSH"} {
		if strings.Contains(out, canary) {
			t.Errorf("canary %q reached the output:\n%s", canary, out)
		}
	}
	if !strings.Contains(out, "done") {
		t.Errorf("redaction swallowed ordinary output:\n%s", out)
	}
}

func TestNewRunnerChecksTable(t *testing.T) {
	v, _ := grant.NewVerifier(make([]byte, 32), grant.NewMemoryNonces())
	argv := func([]string) []string { return []string{"x"} }
	ok := func() map[string]Runbook {
		return map[string]Runbook{
			"deploy":     {Timeout: time.Second, Argv: argv},
			"logs.pilot": {Timeout: time.Second, Argv: argv},
		}
	}
	if _, err := NewRunner(v, ok(), t.TempDir(), nil); err != nil {
		t.Fatal(err)
	}
	extra := ok()
	extra["shell"] = Runbook{Timeout: time.Second, Argv: argv}
	missing := ok()
	delete(missing, "logs.pilot")
	noArgv := ok()
	noArgv["deploy"] = Runbook{Timeout: time.Second}
	for name, table := range map[string]map[string]Runbook{"extra": extra, "missing": missing, "incomplete": noArgv} {
		if _, err := NewRunner(v, table, t.TempDir(), nil); err == nil {
			t.Errorf("%s table accepted", name)
		}
	}
}

func TestProductionRunbookArgv(t *testing.T) {
	t.Setenv("SystemRoot", `C:\Windows`)
	table := builtinRunbooks(map[string]string{"deploy": "/x/pilot.sh"})
	if err := checkRunbooks(table); err != nil {
		t.Fatal(err)
	}
	if table["deploy"].Source != "/x/pilot.sh" || table["logs.pilot"].Source != "" {
		t.Fatalf("sources: %+v", table)
	}
	got := table["deploy"].Argv([]string{testSHA})
	want := []string{
		filepath.Join(`C:\Windows`, "System32", "wsl.exe"), "-d", "sm-pilot", "-u", "pilot", "--exec",
		"bash", "-lc", wslStage, "chap-host", "deploy", testSHA,
	}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("deploy argv\n got %q\nwant %q", got, want)
	}
	logs := table["logs.pilot"].Argv([]string{"worker"})
	if logs[len(logs)-2] != "logs" || logs[len(logs)-1] != "worker" {
		t.Fatalf("logs argv %q", logs)
	}
	if strings.ContainsAny(wslStage, `"`+"`") {
		t.Fatal("the stub must not need double quotes: wsl.exe re-parses the command line")
	}
}
