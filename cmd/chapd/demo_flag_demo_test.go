//go:build demo

package main

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
)

// Even the demo build gives the flag to `chapd run` only, never to the service.
func TestDemoFlagNotOnService(t *testing.T) {
	var errb bytes.Buffer
	if _, code := parseRunFlags("chapd svc", []string{"-dev-fake-github", "x.json"}, &errb, false); code != 2 {
		t.Errorf("chapd svc accepted -dev-fake-github (exit %d)", code)
	}
}

// -dev-enroll issues a first-passkey address on whatever database it is given, so it is refused unless the fake
// GitHub is on and the database is not the real install's.
func TestDevEnrollIsForScratchDatabasesOnly(t *testing.T) {
	scratch := filepath.Join(t.TempDir(), "state.db")
	fake, err := newFakeGitHub(fakeGitHubOptions{Owner: "o", Repo: "r", Base: "main"})
	if err != nil {
		t.Fatal(err)
	}
	defer fake.Close()

	if err := checkDemoEnroll(Config{DBPath: scratch}); err == nil {
		t.Error("-dev-enroll without -dev-fake-github was accepted")
	}
	if err := checkDemoEnroll(Config{DBPath: "", github: fake.Client}); err == nil {
		t.Error("-dev-enroll without a database path was accepted")
	}
	if err := checkDemoEnroll(Config{DBPath: defaultDB, github: fake.Client}); err == nil {
		t.Error("-dev-enroll on the default (real) database was accepted")
	}
	if err := checkDemoEnroll(Config{DBPath: scratch, github: fake.Client}); err != nil {
		t.Errorf("a scratch database with the fake GitHub: %v", err)
	}
	// The real install's folder, found by identity too.
	real := t.TempDir()
	old := realInstallDir
	realInstallDir = func() string { return real }
	defer func() { realInstallDir = old }()
	if err := checkDemoEnroll(Config{DBPath: filepath.Join(real, "state.db"), github: fake.Client}); err == nil {
		t.Error("-dev-enroll on a database in the real install's folder was accepted")
	}

	// Through the flag: it is parsed, and the refusal comes before anything is issued (the App has no database).
	var errb bytes.Buffer
	cfg, code := parseRunFlags("chapd run", []string{"-db", scratch, "-dev-enroll"}, &errb, true)
	if code != 0 || cfg.afterBuild == nil {
		t.Fatalf("exit %d, afterBuild %v: %s", code, cfg.afterBuild != nil, errb.String())
	}
	if err := cfg.afterBuild(context.Background(), &App{cfg: cfg}); err == nil {
		t.Error("-dev-enroll alone ran")
	}
}
