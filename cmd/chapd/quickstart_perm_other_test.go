//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// checkPrivateFile fails unless only the owner can read the file: mode 0600 (writePrivate's call path:
// restrictToCurrentUser sets it, and the temporary file it renames was created 0600).
func checkPrivateFile(t *testing.T, path string) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("%s has mode %v, want -rw-------", path, st.Mode().Perm())
	}
	// Nothing else is left in the folder by the write: no temporary copy of the token.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if len(e.Name()) > 5 && e.Name()[:5] == ".orch" {
			t.Errorf("temporary token file %s left behind", e.Name())
		}
	}
}

// makeWorldWritable lets every user write path. It ADDS the write bits, so a folder keeps its execute bit
// (a folder at 0666 cannot be entered, and the test's temp folder could not be cleaned up).
func makeWorldWritable(t *testing.T, path string) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, st.Mode().Perm()|0o022); err != nil {
		t.Fatal(err)
	}
}

// A folder or file another user owns is refused, not taken over.
func TestOwnerIsCheckedOnUnix(t *testing.T) {
	own := filepath.Join(qsTemp(t), "f")
	if err := os.WriteFile(own, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ownedByCurrentUser(own); err != nil {
		t.Errorf("own file: %v", err)
	}
	if err := checkTrusted(own); err != nil {
		t.Errorf("own 0600 file: %v", err)
	}
	if os.Getuid() != 0 { // "/" belongs to root
		if err := ownedByCurrentUser("/"); err == nil {
			t.Error("a folder owned by root was taken as owned by this user")
		}
		if err := verifyPrivateDir("/"); err == nil {
			t.Error("verifyPrivateDir accepted a folder this user does not own")
		}
		if err := checkTrusted("/"); err == nil {
			t.Error("checkTrusted accepted a folder owned by root")
		}
		// As an ANCESTOR, root's folders are fine when others cannot write in them.
		if err := ancestorSafe("/"); err != nil {
			t.Errorf("/ as an ancestor: %v", err)
		}
	}
	makeWorldWritable(t, own)
	if err := checkTrusted(own); err == nil {
		t.Error("a world-writable file was trusted")
	}
	link := filepath.Join(filepath.Dir(own), "link")
	if err := os.Symlink(own, link); err == nil {
		if err := checkTrusted(link); err == nil {
			t.Error("a link was trusted")
		}
	}
}

// The folder is made 0700 by the quickstart itself, also under a loose umask; files start at 0600. A folder that already
// exists is refused, whatever its mode, and left as it was.
func TestQuickstartMakesItsFolderPrivate(t *testing.T) {
	base, base2, base3 := qsTemp(t), qsTemp(t), qsTemp(t) // made before the umask is loosened
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	dir := filepath.Join(base, "qs")
	if _, err := prepareQuickstartFolder(dir, nil, "127.0.0.1:55434", time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".", "policy", "logs", "run-keys.json", quickstartMarker, "policy/playground.yaml", "state.db"} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s has mode %v under umask 000", name, st.Mode().Perm())
		}
	}
	// Missing parents are made private too.
	deep := filepath.Join(base2, "a", "b", "qs")
	if _, err := prepareQuickstartFolder(deep, nil, "127.0.0.1:55434", time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{filepath.Dir(filepath.Dir(deep)), filepath.Dir(deep), deep} {
		if st, err := os.Stat(d); err != nil || st.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v %v", d, st, err)
		}
	}
	loose := filepath.Join(base3, "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareQuickstartFolder(loose, nil, "127.0.0.1:55434", time.Now()); err == nil {
		t.Error("an existing folder was used")
	}
	if st, _ := os.Stat(loose); st.Mode().Perm() != 0o755 {
		t.Errorf("the existing folder was changed to %v", st.Mode().Perm())
	}
}

// Another user who can write in the PARENT can rename the quickstart folder away after it is made and put their own in
// its place: in 11 of 12 runs the whole folder was swapped, and chapd wrote its database and token into it. A parent
// that group or others can write in, without the sticky bit, is refused before anything is made. (Same-user stand-in:
// a second account is not available, but renaming in a non-sticky writable folder is plain Unix behaviour.)
func TestQuickstartRefusesAParentOthersCanWriteIn(t *testing.T) {
	base := qsTemp(t)
	parent := filepath.Join(base, "parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o777, 0o770 | 0o020, 0o722} {
		if err := os.Chmod(parent, mode); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(parent, "qs")
		if _, _, err := checkQuickstartDir(dir); err == nil || !strings.Contains(err.Error(), "chmod go-w") {
			t.Errorf("parent %v: check: %v", mode, err)
		}
		if _, err := prepareQuickstartFolder(dir, nil, "127.0.0.1:55442", time.Now()); err == nil {
			t.Errorf("parent %v: prepare went on", mode)
		}
		var out strings.Builder
		if err := runQuickstart(t.Context(), quickstartOptions{Dir: dir, Addr: qsFreeAddr(t), Playground: true}, &out); err == nil || out.Len() != 0 {
			t.Errorf("parent %v: runQuickstart: %v", mode, err)
		}
		if _, err := os.Stat(dir); err == nil {
			t.Errorf("parent %v: the folder was made", mode)
		}
	}
	// A sticky bit (as on /tmp) means others cannot rename OUR entries, so it is accepted; so is a parent that is only readable.
	for _, mode := range []os.FileMode{0o777 | os.ModeSticky, 0o755, 0o700} {
		if err := os.Chmod(parent, mode); err != nil {
			t.Fatal(err)
		}
		if _, _, err := checkQuickstartDir(filepath.Join(parent, "qs")); err != nil {
			t.Errorf("parent %v: %v", mode, err)
		}
	}
	// An ancestor higher up counts too, not only the parent.
	high := filepath.Join(base, "high")
	if err := os.MkdirAll(filepath.Join(high, "mid"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(high, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, _, err := checkQuickstartDir(filepath.Join(high, "mid", "qs")); err == nil {
		t.Error("a writable grandparent was accepted")
	}
}

// On macOS the temp folder is reached through a link (/var -> /private/var) and a home may be too (a home on another volume,
// /home -> /System/Volumes/Data/home). A folder is inside a root when it is, once BOTH are resolved. The tests below build the shape under a temp
// folder: a root reached through a symlink, a folder given through the link, and the same given through the real path.
func TestQuickstartRootsAndFoldersMayBeReachedThroughLinks(t *testing.T) {
	base := qsTemp(t)
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	old := quickstartTestRoots
	defer func() { quickstartTestRoots = old }()
	for _, root := range []string{link, real} {
		quickstartTestRoots = []string{root}
		for _, via := range []string{link, real} {
			dir := filepath.Join(via, "deeper", "qs")
			// The check, and the preparation called directly with the path as written.
			if _, _, err := checkQuickstartDir(dir); err != nil {
				t.Errorf("root %s, folder via %s: check: %v", root, via, err)
			}
			if _, err := prepareQuickstartFolder(dir, nil, "127.0.0.1:55450", time.Now()); err != nil {
				t.Errorf("root %s, folder via %s: prepare: %v", root, via, err)
			}
			_ = os.RemoveAll(filepath.Join(real, "deeper"))
		}
	}
}

// The production rule, with a HOME that is a symlink: a user whose home is reached through a link is not refused, and
// nothing outside that home is accepted because of it.
func TestQuickstartAHomeReachedThroughALink(t *testing.T) {
	base := qsTemp(t)
	realHome := filepath.Join(base, "volume", "u")
	outside := filepath.Join(base, "volume", "other")
	for _, d := range []string{realHome, outside} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	linkHome := filepath.Join(base, "home-link")
	if err := os.Symlink(realHome, linkHome); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	old := quickstartTestRoots
	quickstartTestRoots = nil // production: the home folder alone
	defer func() { quickstartTestRoots = old }()
	t.Setenv("HOME", linkHome)
	if h, _ := os.UserHomeDir(); h != linkHome {
		t.Skipf("home is %s here", h)
	}

	for _, dir := range []string{
		filepath.Join(linkHome, ".config", "qs"), // as the user writes it
		filepath.Join(realHome, ".config", "qs"), // by its real path
		filepath.Join(linkHome, "a", "b", "qs"),  // missing parents, made inside the real home
	} {
		if _, _, err := checkQuickstartDir(dir); err != nil {
			t.Errorf("%s inside a home reached through a link was refused: %v", dir, err)
		}
		if _, err := prepareQuickstartFolder(dir, nil, "127.0.0.1:55451", time.Now()); err != nil {
			t.Errorf("%s: prepare: %v", dir, err)
		}
		_ = os.RemoveAll(filepath.Join(realHome, ".config"))
		_ = os.RemoveAll(filepath.Join(realHome, "a"))
	}
	// Not loosened: a sibling of the home, by either route, and a link in home that leads out, are refused.
	escape := filepath.Join(realHome, "escape")
	if err := os.Symlink(outside, escape); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{
		filepath.Join(outside, "qs"), filepath.Join(escape, "qs"), filepath.Join(linkHome, "escape", "qs"),
	} {
		if _, _, err := checkQuickstartDir(dir); err == nil || !strings.Contains(err.Error(), "outside your home folder") {
			t.Errorf("%s was not refused as outside home: %v", dir, err)
		}
		if _, err := prepareQuickstartFolder(dir, nil, "127.0.0.1:55452", time.Now()); err == nil {
			t.Errorf("%s: prepare went on", dir)
		}
	}
}
