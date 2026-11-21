package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

// linkOrJunction makes link lead to target: a symlink, or on Windows without the privilege a junction.
func linkOrJunction(t *testing.T, link, target string) {
	t.Helper()
	if err := os.Symlink(target, link); err == nil {
		return
	}
	if runtime.GOOS != "windows" {
		t.Skip("no symlinks here")
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("no symlinks or junctions here: %v %s", err, out)
	}
}

// rootAndOutside makes a root (the only allowed one besides home) and a sibling folder outside it.
func rootAndOutside(t *testing.T) (root, outside string) {
	t.Helper()
	base := qsTemp(t)
	root, outside = filepath.Join(base, "root"), filepath.Join(base, "outside")
	for _, d := range []string{root, outside} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	old := quickstartTestRoots
	quickstartTestRoots = []string{root}
	t.Cleanup(func() { quickstartTestRoots = old })
	return root, outside
}

func mustBeEmpty(t *testing.T, dir, what string) {
	t.Helper()
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Errorf("%s: %s is not empty: %v %v", what, dir, entries, err)
	}
}

// A link in the path the caller gives that leads OUT of the root. The rule: a link is followed once, up front, and the
// resolved path must lie inside the root (on Windows a junction is not followed and is refused as a link). Either way it
// is refused, and nothing is made anywhere, the link's target included.
func TestQuickstartRefusesALinkInTheGivenPathThatLeadsOut(t *testing.T) {
	root, outside := rootAndOutside(t)
	if home, err := os.UserHomeDir(); err == nil && runtime.GOOS != "windows" && within(outside, home) {
		t.Skipf("the temp folder %s is inside the home folder %s, so the \"outside\" folder is inside the allowed root and a symlink to it is rightly accepted", outside, home)
	}
	link := filepath.Join(root, "lnk")
	linkOrJunction(t, link, outside)
	dir := filepath.Join(link, "deeper", "qs")
	if _, _, err := checkQuickstartDir(dir); err == nil {
		t.Error("check accepted a link that leads out")
	}
	if _, err := prepareQuickstartFolder(dir, nil, "127.0.0.1:55453", time.Now()); err == nil {
		t.Error("prepare accepted a link that leads out")
	}
	mustBeEmpty(t, outside, "the link's target")
	if entries, _ := os.ReadDir(root); len(entries) != 1 || entries[0].Name() != "lnk" {
		t.Errorf("the root holds %v", entries)
	}
}

// A parent replaced by a link to a folder outside the root AFTER the path was resolved and checked (the gap hook runs
// there). What is then made is made through the link; the path no longer resolves to itself, so it is refused and what
// was made is taken back: nothing is left outside.
func TestQuickstartRefusesAParentSwappedForALinkAfterTheCheck(t *testing.T) {
	root, outside := rootAndOutside(t)
	parent := filepath.Join(root, "parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "qs")
	swapped := false
	prepareGapHook = func() {
		if err := os.Rename(parent, parent+".away"); err != nil {
			t.Error(err)
			return
		}
		linkOrJunction(t, parent, outside)
		swapped = true
	}
	defer func() { prepareGapHook = nil }()
	_, err := prepareQuickstartFolder(dir, nil, "127.0.0.1:55454", time.Now())
	if !swapped {
		t.Skip("the parent could not be swapped here")
	}
	if err == nil {
		t.Fatal("a parent swapped for a link in the gap was accepted")
	}
	mustBeEmpty(t, outside, "the folder outside the root")
	if _, err := os.Stat(filepath.Join(parent+".away", "qs")); err == nil {
		t.Error("something was made in the real parent after it was moved away")
	}
}

// ONE path: prepare resolves once, and the folder it returns, derives its files from, records and prints is the resolved one.
func TestQuickstartPrepareUsesTheResolvedPathThroughout(t *testing.T) {
	root, _ := rootAndOutside(t)
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	f, err := prepareQuickstartFolder(filepath.Join(link, "qs"), nil, "127.0.0.1:55455", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(real)
	want = filepath.Join(want, "qs")
	for name, got := range map[string]string{"Dir": f.Dir, "DB": filepath.Dir(f.DB), "Keys": filepath.Dir(f.Keys), "PolicyDir": filepath.Dir(f.PolicyDir),
		"TokenFile": filepath.Dir(f.TokenFile), "LogDir": filepath.Dir(f.LogDir)} {
		if !samePath(got, want) {
			t.Errorf("%s is under %s, want %s", name, got, want)
		}
	}
	if err := f.stillTheSameFolder(); err != nil {
		t.Error(err)
	}
	if _, err := os.Stat(filepath.Join(real, "qs", quickstartMarker)); err != nil {
		t.Errorf("the folder is not where the link leads: %v", err)
	}
}

// Clean-up must not follow a link. If a part of the path is swapped for a link between making the folders and taking them
// back, removing by path would delete a same-named empty folder (or unlink a same-named file) somewhere else. Each folder
// is removed only if the path still leads to the recorded folder, only with a directory-only call, and clean-up stops at
// the first mismatch.
func TestRemoveCreatedDoesNotFollowASwappedPath(t *testing.T) {
	for _, what := range []string{"folder", "file"} {
		root, outside := rootAndOutside(t)
		dir := filepath.Join(root, "a", "b")
		created, err := makePrivateTree(dir)
		if err != nil || len(created) != 2 {
			t.Fatal(created, err)
		}
		if err := os.Rename(filepath.Join(root, "a"), filepath.Join(root, "a.away")); err != nil {
			t.Fatal(err)
		}
		linkOrJunction(t, filepath.Join(root, "a"), outside)
		victim := filepath.Join(outside, "b") // same name as the folder that was made, behind the link
		if what == "folder" {
			if err := os.Mkdir(victim, 0o700); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(victim, []byte("mine"), 0o600); err != nil {
			t.Fatal(err)
		}
		removeCreated(created)
		if _, err := os.Lstat(victim); err != nil {
			t.Errorf("%s: clean-up through the swapped path removed %s", what, victim)
		}
		if _, err := os.Stat(filepath.Join(root, "a.away", "b")); err != nil {
			t.Errorf("%s: clean-up went on after a mismatch and removed the real folder: %v", what, err)
		}
	}
}

// Untouched, clean-up takes back everything that was made, innermost first.
func TestRemoveCreatedTakesBackWhatWasMade(t *testing.T) {
	root, _ := rootAndOutside(t)
	created, err := makePrivateTree(filepath.Join(root, "a", "b", "c"))
	if err != nil || len(created) != 3 {
		t.Fatal(created, err)
	}
	removeCreated(created)
	if entries, _ := os.ReadDir(root); len(entries) != 0 {
		t.Errorf("left behind: %v", entries)
	}
	// A folder that is not empty is not removed (and then nothing outside it is touched).
	created, err = makePrivateTree(filepath.Join(root, "x", "y"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "x", "y", "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	removeCreated(created)
	if _, err := os.Stat(filepath.Join(root, "x", "y", "f")); err != nil {
		t.Errorf("a non-empty folder was removed: %v", err)
	}
}

// confirmCreated compares the folder the path leads to with the identity recorded when the folder was made, not with itself.
func TestConfirmCreatedComparesWithTheRecordedIdentity(t *testing.T) {
	root, _ := rootAndOutside(t)
	_, dir, err := resolveFolderPath(filepath.Join(root, "p", "qs")) // confirmCreated, like prepare, is given the resolved path
	if err != nil {
		t.Fatal(err)
	}
	created, err := makePrivateTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := confirmCreated(dir, created[len(created)-1]); err != nil {
		t.Fatalf("the folder that was made: %v", err)
	}
	other, err := recordMade(filepath.Dir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := confirmCreated(dir, other); err == nil || !strings.Contains(err.Error(), "not the folder that was made") {
		t.Errorf("a different folder's identity was accepted: %v", err)
	}
	// The folder itself swapped for another after it was recorded.
	if err := os.Rename(dir, dir+".away"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := confirmCreated(dir, created[len(created)-1]); err == nil {
		t.Error("a folder swapped after it was made was accepted")
	}
}
