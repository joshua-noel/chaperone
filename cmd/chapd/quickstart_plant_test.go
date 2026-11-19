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

// newPath is a folder path inside the allowed temp root that does not exist yet: a first run makes it.
func newPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(qsTemp(t), "qs")
}

// madeAndPrepared is a folder of a first run and its marker.
func madeAndPrepared(t *testing.T, addr string) (string, *quickstartState) {
	t.Helper()
	dir := newPath(t)
	if _, err := prepareQuickstartFolder(dir, nil, addr, time.Now()); err != nil {
		t.Fatal(err)
	}
	st, err := readQuickstartState(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, st
}

// The window between "the folder does not exist" and "the first run makes it": another user makes it first and puts a
// run-keys.json in it. A first run never uses a folder that exists, so the planted key set is never loaded.
func TestQuickstartRefusesAFolderPlantedBeforeTheFirstRunMakesIt(t *testing.T) {
	for _, openIt := range []bool{false, true} {
		dir := newPath(t)
		if _, st, err := checkQuickstartDir(dir); err != nil || st != nil {
			t.Fatal(st, err) // the check says: new
		}
		plant := func() {
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Error(err)
				return
			}
			p := filepath.Join(dir, "run-keys.json")
			if err := os.WriteFile(p, []byte(attackerKeys), 0o644); err != nil {
				t.Error(err)
				return
			}
			if openIt {
				makeWorldWritable(t, p)
			}
		}
		plant()
		_, err := prepareQuickstartFolder(dir, nil, "127.0.0.1:55437", time.Now())
		if err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("openIt=%v: a folder made by somebody else was used: %v", openIt, err)
		}
		if b, _ := os.ReadFile(filepath.Join(dir, "run-keys.json")); string(b) != attackerKeys {
			t.Errorf("the planted file was changed: %q", b)
		}
		if _, err := os.Stat(filepath.Join(dir, quickstartMarker)); err == nil {
			t.Error("a marker was written into a folder somebody else made")
		}
	}
}

// The same through the whole command, with the folder appearing after the check and the bind: nothing is built, loaded or printed.
func TestQuickstartRunRefusesAFolderMadeAfterTheCheck(t *testing.T) {
	dir := newPath(t)
	quickstartAfterCheck = func() {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Error(err)
			return
		}
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
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("runQuickstart went on with a folder it did not make: %v", err)
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

// A reused folder: every entry about to be trusted must be the user's alone.
func TestQuickstartRefusesOpenOrForeignFilesInAReusedFolder(t *testing.T) {
	for _, name := range []string{"run-keys.json", "state.db", "policy/playground.yaml", quickstartMarker, quickstartTokenFile, "logs/chapd.log",
		"policy", "logs", "state.db-journal", "state.db-wal", "state.db-shm"} {
		dir, st := madeAndPrepared(t, "127.0.0.1:55438")
		if err := writePrivate(filepath.Join(dir, quickstartTokenFile), []byte("chap_orch_x\n")); err != nil {
			t.Fatal(err)
		}
		for _, extra := range []string{"logs/chapd.log", "state.db-journal", "state.db-wal", "state.db-shm"} {
			if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(extra)), []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		// Untouched, the folder is accepted again (everything in it is the user's own and closed).
		if _, err := prepareQuickstartFolder(dir, st, "", time.Now()); err != nil {
			t.Fatalf("%s: a good folder was refused: %v", name, err)
		}
		makeWorldWritable(t, filepath.Join(dir, filepath.FromSlash(name)))
		_, err := prepareQuickstartFolder(dir, st, "", time.Now())
		if err == nil || !strings.Contains(err.Error(), "will not use") || !strings.Contains(err.Error(), filepath.Base(name)) {
			t.Errorf("%s opened to everyone was accepted: %v", name, err)
		}
	}
}

// Reviewer's experiment (c): SQLite opens a rollback journal it finds next to the database and writes its pages into it. A
// state.db-journal planted by somebody else must be refused, and so must any other entry the quickstart does not make.
func TestQuickstartRefusesAPlantedJournalAndUnknownEntries(t *testing.T) {
	for _, name := range []string{"state.db-journal", "evil.txt", "run-keys.json.bak", ".hidden", "other.db"} {
		dir, st := madeAndPrepared(t, "127.0.0.1:55445")
		planted := filepath.Join(dir, name)
		if err := os.WriteFile(planted, []byte("EVIL JOURNAL"), 0o644); err != nil {
			t.Fatal(err)
		}
		if name != "state.db-journal" { // a journal is a known name: it is refused by the owner/permission check, below
			_, err := prepareQuickstartFolder(dir, st, "", time.Now())
			if err == nil || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "did not make") {
				t.Errorf("%s: an unknown entry was accepted: %v", name, err)
			}
			continue
		}
		makeWorldWritable(t, planted) // stand-in for a file owned by another user: closed to nobody
		_, err := prepareQuickstartFolder(dir, st, "", time.Now())
		if err == nil || !strings.Contains(err.Error(), "will not use") || !strings.Contains(err.Error(), "state.db-journal") {
			t.Errorf("a planted journal was accepted: %v", err)
		}
		if b, _ := os.ReadFile(planted); string(b) != "EVIL JOURNAL" {
			t.Error("the planted journal was consumed")
		}
	}
}

// A marker that changed between the read and the use is refused.
func TestQuickstartRefusesAMarkerThatChanged(t *testing.T) {
	dir, st := madeAndPrepared(t, "127.0.0.1:55439")
	other := *st
	other.Addr = "127.0.0.1:55440"
	if _, err := prepareQuickstartFolder(dir, &other, "", time.Now()); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Errorf("a changed marker was accepted: %v", err)
	}
}

// Files made on a first run are made exclusively: an existing one is an error, not an input.
func TestCreateExclusiveRefusesAnExistingFile(t *testing.T) {
	p := filepath.Join(qsTemp(t), "f")
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

// A reused folder with a file missing at the check makes it exclusively.
func TestQuickstartReuseCreatesMissingFilesExclusively(t *testing.T) {
	dir, st := madeAndPrepared(t, "127.0.0.1:55441")
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

// Reviewer's experiment (b), the identity half: the folder is renamed away after chapd has opened its files, and another
// put in its place. Whatever the parent check missed, the path no longer leads to the folder that was prepared, so
// nothing is printed or served. (Windows refuses to rename a folder that holds open files, which is protection of its
// own; the test then has nothing to swap.)
func TestQuickstartRefusesAFolderSwappedAfterBuild(t *testing.T) {
	dir := newPath(t)
	swapped := false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	quickstartAfterBuild = func() {
		away := dir + ".away"
		if err := os.Rename(dir, away); err != nil {
			cancel() // nothing to swap here: stop instead of serving
			return
		}
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Error(err)
			return
		}
		swapped = true
	}
	defer func() { quickstartAfterBuild = nil }()
	var out bytes.Buffer
	err := runQuickstart(ctx, quickstartOptions{Dir: dir, Addr: qsFreeAddr(t), Playground: true}, &out)
	if !swapped {
		t.Skip("the folder cannot be renamed while chapd holds its files open on this system")
	}
	if err == nil || !strings.Contains(err.Error(), "no longer the folder") {
		t.Fatalf("a swapped folder was not refused: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("it printed:\n%s", out.String())
	}
}

// The identity check passes for the folder itself.
func TestQuickstartFolderIdentityHolds(t *testing.T) {
	f, err := prepareQuickstartFolder(newPath(t), nil, "127.0.0.1:55446", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.stillTheSameFolder(); err != nil {
		t.Fatal(err)
	}
}

// A folder renamed away and replaced is found. The check is called ONCE, after the swap: on Windows os.Stat reads the file ID
// lazily, so a Stat-based check that had been called before would have cached nothing and compared the replacement with
// itself. The identity is taken from an open handle at record time and at check time. No file of the folder is open here,
// so the rename works on Windows too.
func TestQuickstartFolderIdentityFindsASwap(t *testing.T) {
	dir := newPath(t)
	f, err := prepareQuickstartFolder(dir, nil, "127.0.0.1:55447", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dir, dir+".away"); err != nil {
		t.Fatalf("cannot rename the prepared folder: %v", err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := f.stillTheSameFolder(); err == nil || !strings.Contains(err.Error(), "no longer the folder") {
		t.Errorf("a replaced folder passed the identity check: %v", err)
	}
}

// A parent that did not exist at the ancestor check, and that another user makes before ours is made, is caught: the
// ancestors are checked again once every one of them exists, and before anything is written.
func TestQuickstartChecksAParentMadeInTheGap(t *testing.T) {
	base := qsTemp(t)
	parent := filepath.Join(base, "newparent")
	dir := filepath.Join(parent, "qs")
	prepareGapHook = func() {
		if err := os.Mkdir(parent, 0o755); err != nil {
			t.Error(err)
			return
		}
		makeWorldWritable(t, parent) // a folder somebody else made, open to others
	}
	defer func() { prepareGapHook = nil }()
	if _, err := prepareQuickstartFolder(dir, nil, "127.0.0.1:55448", time.Now()); err == nil {
		t.Fatal("a parent made by somebody else in the gap was accepted")
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("the quickstart folder was left in the foreign parent")
	}
	// The same, with a parent that is fine: no refusal.
	prepareGapHook = func() {
		if err := os.Mkdir(filepath.Join(base, "okparent"), 0o700); err != nil {
			t.Error(err)
		}
	}
	if _, err := prepareQuickstartFolder(filepath.Join(base, "okparent", "qs"), nil, "127.0.0.1:55448", time.Now()); err != nil {
		t.Errorf("a harmless parent made in the gap: %v", err)
	}
}
