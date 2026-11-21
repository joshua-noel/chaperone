package privfile

import (
	"os"
	"path/filepath"
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

// A link at the path is refused, and nothing is written through it: not to a file that exists, and not to a path
// that does not (a dangling link).
func TestCreateDoesNotFollowALink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("theirs"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, to := range map[string]string{"to-a-file": target, "dangling": filepath.Join(dir, "nowhere")} {
		link := filepath.Join(dir, name)
		if err := os.Symlink(to, link); err != nil {
			t.Skipf("cannot make a symbolic link here (%v)", err)
		}
		if f, err := Create(link); err == nil {
			f.Close()
			t.Errorf("%s: Create followed or replaced the link", name)
		}
	}
	if got, _ := os.ReadFile(target); string(got) != "theirs" {
		t.Errorf("the link target was written through: %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "nowhere")); err == nil {
		t.Error("a file was created through the dangling link")
	}
}
