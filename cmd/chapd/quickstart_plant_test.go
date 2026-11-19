package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const attackerKeys = "ATTACKER KEYS"

func emptyFolder(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "qs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The window between "the folder is empty" and "the folder is private": another user plants run-keys.json with an
// entry of its own that the later lock does not remove. It must be refused, never loaded.
func TestQuickstartRefusesAFileAPlantedBeforeTheLock(t *testing.T) {
	for _, openIt := range []bool{false, true} {
		dir := emptyFolder(t)
		if _, st, err := checkQuickstartDir(dir); err != nil || st != nil {
			t.Fatal(st, err) // the check says: new or empty
		}
		planted := filepath.Join(dir, "run-keys.json")
		if err := os.WriteFile(planted, []byte(attackerKeys), 0o644); err != nil {
			t.Fatal(err)
		}
		if openIt {
			makeWorldWritable(t, planted) // an entry on the file itself, which locking the folder does not remove
		}
		_, err := prepareQuickstartFolder(dir, nil, "127.0.0.1:55437", time.Now())
		if err == nil || !strings.Contains(err.Error(), "run-keys.json") {
			t.Fatalf("openIt=%v: a planted run-keys.json was accepted: %v", openIt, err)
		}
		if b, _ := os.ReadFile(planted); string(b) != attackerKeys {
			t.Errorf("the planted file was changed: %q", b)
		}
		if _, err := os.Stat(filepath.Join(dir, quickstartMarker)); err == nil {
			t.Error("a marker was written into a folder somebody else wrote in")
		}
	}
}

// The same through the whole command: the file appears after the check and the bind; nothing is built, loaded or printed.
func TestQuickstartRunRefusesAFilePlantedAfterTheCheck(t *testing.T) {
	dir := emptyFolder(t)
	quickstartAfterCheck = func() {
		p := filepath.Join(dir, "run-keys.json")
		if err := os.WriteFile(p, []byte(attackerKeys), 0o644); err != nil {
			t.Error(err)
			return
		}
		makeWorldWritable(t, p)
	}
	defer func() { quickstartAfterCheck = nil }()
	var out bytes.Buffer
	err := runQuickstart(context.Background(), quickstartOptions{Dir: dir, Addr: qsFreeAddr(t), Playground: true}, &out)
	if err == nil || !strings.Contains(err.Error(), "run-keys.json") {
		t.Fatalf("runQuickstart went on with a planted key set: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("it printed:\n%s", out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "state.db")); err == nil {
		t.Error("a database was made: chapd was built")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "run-keys.json")); string(b) != attackerKeys {
		t.Error("the planted file was replaced or used")
	}
}

// A reused folder: every file about to be trusted must be the user's alone.
func TestQuickstartRefusesOpenOrForeignFilesInAReusedFolder(t *testing.T) {
	for _, name := range []string{"run-keys.json", "state.db", "policy/playground.yaml", quickstartMarker, quickstartTokenFile, "logs/chapd.log", "policy", "logs"} {
		dir := emptyFolder(t)
		if _, err := prepareQuickstartFolder(dir, nil, "127.0.0.1:55438", time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := writePrivate(filepath.Join(dir, quickstartTokenFile), []byte("chap_orch_x\n")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "logs", "chapd.log"), []byte("log\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		st, err := readQuickstartState(dir)
		if err != nil {
			t.Fatal(err)
		}
		// Untouched, the folder is accepted again (the log file made by hand is inside the user's own folder).
		if _, err := prepareQuickstartFolder(dir, st, "", time.Now()); err != nil {
			t.Fatalf("%s: a good folder was refused: %v", name, err)
		}
		makeWorldWritable(t, filepath.Join(dir, filepath.FromSlash(name)))
		_, err = prepareQuickstartFolder(dir, st, "", time.Now())
		if err == nil || !strings.Contains(err.Error(), "will not use") || !strings.Contains(err.Error(), filepath.Base(name)) {
			t.Errorf("%s opened to everyone was accepted: %v", name, err)
		}
	}
}

// A marker that changed between the read and the lock is refused.
func TestQuickstartRefusesAMarkerThatChanged(t *testing.T) {
	dir := emptyFolder(t)
	if _, err := prepareQuickstartFolder(dir, nil, "127.0.0.1:55439", time.Now()); err != nil {
		t.Fatal(err)
	}
	st, err := readQuickstartState(dir)
	if err != nil {
		t.Fatal(err)
	}
	other := *st
	other.Addr = "127.0.0.1:55440"
	if _, err := prepareQuickstartFolder(dir, &other, "", time.Now()); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Errorf("a changed marker was accepted: %v", err)
	}
}

// Files made on a first run are made exclusively: an existing one is an error, not an input.
func TestCreateExclusiveRefusesAnExistingFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := createExclusive(p, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := createExclusive(p, []byte("two")); err == nil {
		t.Error("an existing file was overwritten or reused")
	}
	if b, _ := os.ReadFile(p); string(b) != "one" {
		t.Errorf("file holds %q", b)
	}
}

// A reused folder with a file missing at the check makes it exclusively: one that appears in between is refused.
func TestQuickstartReuseCreatesMissingFilesExclusively(t *testing.T) {
	dir := emptyFolder(t)
	if _, err := prepareQuickstartFolder(dir, nil, "127.0.0.1:55441", time.Now()); err != nil {
		t.Fatal(err)
	}
	st, err := readQuickstartState(dir)
	if err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(dir, "run-keys.json")
	if err := os.Remove(keys); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareQuickstartFolder(dir, st, "", time.Now()); err != nil {
		t.Fatalf("a missing key set is made again: %v", err)
	}
	if b, _ := os.ReadFile(keys); !bytes.Contains(b, []byte(`"kid"`)) {
		t.Errorf("run-keys.json: %q", b)
	}
}
