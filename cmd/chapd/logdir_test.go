package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewLoggerWritesRotatedFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	var console bytes.Buffer
	log, closeLog, err := newLogger(dir, &console)
	if err != nil {
		t.Fatal(err)
	}
	log.Info("hello", "k", "v")
	closeLog()
	b, err := os.ReadFile(filepath.Join(dir, "chapd.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "msg=hello") || !strings.Contains(console.String(), "msg=hello") {
		t.Fatalf("file %q console %q", b, console.String())
	}
}

func TestNewLoggerWithoutDirMakesNoFile(t *testing.T) {
	var console bytes.Buffer
	log, closeLog, err := newLogger("", &console)
	if err != nil {
		t.Fatal(err)
	}
	defer closeLog()
	log.Info("hello")
	if !strings.Contains(console.String(), "msg=hello") {
		t.Fatalf("console %q", console.String())
	}
}

func TestRunFlagsAcceptLogDir(t *testing.T) {
	var stderr bytes.Buffer
	cfg, code := parseRunFlags("chapd run", []string{"-db", filepath.Join(t.TempDir(), "s.db"), "-log-dir", `D:\x\logs`}, &stderr, true)
	if code != 0 || cfg.LogDir != `D:\x\logs` {
		t.Fatalf("code %d dir %q: %s", code, cfg.LogDir, stderr.String())
	}
}
