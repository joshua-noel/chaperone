package privfile

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Create refuses to replace anything: an existing file is left as it was.
func TestCreateRefusesAnExistingFileAndLeavesItAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if f, err := Create(path); err == nil {
		f.Close()
		t.Fatal("Create replaced an existing file")
	}
	if got, _ := os.ReadFile(path); string(got) != "mine" {
		t.Errorf("the existing file was changed: %q", got)
	}
}

// Create writes what it is given, once, to a file that did not exist.
func TestCreateWritesANewFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	f, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("secret"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "secret" {
		t.Errorf("read back: %q %v", got, err)
	}
}

// linkKind is a kind of link a test puts at the final path of the file it wants made.
type linkKind string

const (
	danglingLink  linkKind = "symbolic link to a path that does not exist"
	linkToFile    linkKind = "symbolic link to an existing file"
	linkToFolder  linkKind = "symbolic link to a folder"
	junctionToDir linkKind = "junction to a folder"
)

var allLinkKinds = []linkKind{danglingLink, linkToFile, linkToFolder, junctionToDir}

// linkFixture is a link at path, and what it points at: target is a path that must be left as it is.
type linkFixture struct {
	kind   linkKind
	path   string // where the link is
	target string // what it points at
}

// makeLinkFixture puts a link of the kind in a new folder. When the machine cannot make that kind (a Windows user
// without the symbolic-link privilege, a junction on Unix) the test is SKIPPED with the reason, never passed. When it
// runs it logs which kind of link it made.
func makeLinkFixture(t *testing.T, kind linkKind) linkFixture {
	t.Helper()
	dir := t.TempDir()
	f := linkFixture{kind: kind, path: filepath.Join(dir, "link")}
	switch kind {
	case danglingLink:
		f.target = filepath.Join(dir, "nowhere")
	case linkToFile:
		f.target = filepath.Join(dir, "theirs")
		if err := os.WriteFile(f.target, []byte("theirs"), 0o644); err != nil {
			t.Fatal(err)
		}
	case linkToFolder, junctionToDir:
		f.target = filepath.Join(dir, "folder")
		if err := os.Mkdir(f.target, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := makeLink(kind, f.target, f.path); err != nil {
		t.Skipf("cannot make a %s on this machine (%v): this case was NOT run", kind, err)
	}
	t.Logf("made a %s at the path (GOOS=%s)", kind, runtime.GOOS)
	return f
}

// untouched fails the test if what the link points at was created, written to or filled.
func (f linkFixture) untouched(t *testing.T) {
	t.Helper()
	switch f.kind {
	case danglingLink:
		if _, err := os.Lstat(f.target); err == nil {
			t.Errorf("%s: a file was created at the link's target", f.kind)
		}
	case linkToFile:
		if got, _ := os.ReadFile(f.target); string(got) != "theirs" {
			t.Errorf("%s: the target was written through: %q", f.kind, got)
		}
	case linkToFolder, junctionToDir:
		if ents, _ := os.ReadDir(f.target); len(ents) != 0 {
			t.Errorf("%s: %d entries were made in the folder the link points at", f.kind, len(ents))
		}
	}
	if _, err := os.Lstat(f.path); err != nil {
		t.Errorf("%s: the link itself is gone: %v", f.kind, err)
	}
}

// A link at the final path is refused, and nothing is written through it: to a path that does not exist (a dangling
// link, which CREATE_NEW follows on Windows if it is the only flag), to an existing file, to a folder, and a junction.
func TestCreateDoesNotFollowALink(t *testing.T) {
	for _, kind := range allLinkKinds {
		t.Run(string(kind), func(t *testing.T) {
			for name, create := range map[string]func(string) (*os.File, error){"Create": Create, "CreateReadWrite": CreateReadWrite} {
				f := makeLinkFixture(t, kind)
				file, err := create(f.path)
				if err == nil {
					file.Close()
					t.Errorf("%s followed or replaced a %s", name, kind)
				} else {
					t.Logf("%s refused the %s: %v", name, kind, err)
				}
				f.untouched(t)
			}
		})
	}
}

// CreateTemp is Create on a random name, so a link cannot be waiting there, and its file is new and private.
func TestCreateTempMakesNewFiles(t *testing.T) {
	dir := t.TempDir()
	seen := map[string]bool{}
	for range 5 {
		f, err := CreateTemp(dir, ".tok-*.tmp")
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		name := filepath.Base(f.Name())
		if seen[name] || !strings.HasPrefix(name, ".tok-") || !strings.HasSuffix(name, ".tmp") {
			t.Errorf("temp name %q (seen %v)", name, seen)
		}
		seen[name] = true
	}
}

// A probe, not a check: what a PLAIN os.OpenFile(O_CREATE|O_EXCL) does at a link on the machine it runs on. It never
// fails for either answer; it says what happened, one line each, so a CI log shows whether plain O_EXCL is safe on
// that system. (privfile.Create does not depend on the answer.) Run with -v.
func TestProbePlainExclusiveCreateAtALink(t *testing.T) {
	for _, kind := range allLinkKinds {
		t.Run(string(kind), func(t *testing.T) {
			f := makeLinkFixture(t, kind)
			file, err := os.OpenFile(f.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				t.Logf("PLAIN O_EXCL through a %s on %s: refused: %v", kind, runtime.GOOS, err)
				return
			}
			_, werr := file.WriteString("probe")
			file.Close()
			switch kind {
			case danglingLink:
				if _, serr := os.Stat(f.target); serr == nil {
					t.Logf("PLAIN O_EXCL through a %s on %s: created the target (write error: %v)", kind, runtime.GOOS, werr)
					return
				}
			case linkToFile:
				if got, _ := os.ReadFile(f.target); string(got) == "probe" {
					t.Logf("PLAIN O_EXCL through a %s on %s: wrote into the existing target", kind, runtime.GOOS)
					return
				}
			}
			t.Logf("PLAIN O_EXCL through a %s on %s: succeeded, but the target is unchanged (the link was replaced or opened as itself)", kind, runtime.GOOS)
		})
	}
}
