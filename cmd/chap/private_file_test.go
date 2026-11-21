package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The key file that `chap key claim --out`, `chap agent enrol` and `chap dev-token --out` write is private to the
// user from the moment it exists, on every system: mode 0600, and on Windows (where the mode means nothing) a
// protected access list for the user alone. The folder here is open to everybody, which is what a shared repository
// folder or the temp folder can be, so a file that took its folder's access would be open too.
func TestKeyFilesArePrivateFromCreation(t *testing.T) {
	dir := t.TempDir()
	openFolder(t, dir)
	path := filepath.Join(dir, "chap.key")

	if err := createPrivateFile(path, []byte("chap_key_one")); err != nil {
		t.Fatal(err)
	}
	if p := ownerOnlyProblem(t, path); p != "" {
		t.Errorf("createPrivateFile: %s", p)
	}

	// The rotation (`chap agent enrol` over its own key file): the new file is private too, the old one is replaced,
	// and no temporary file is left.
	if err := replacePrivateFile(path, []byte("chap_key_two")); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != "chap_key_two" {
		t.Errorf("the key file holds %q", got)
	}
	if p := ownerOnlyProblem(t, path); p != "" {
		t.Errorf("replacePrivateFile: %s", p)
	}
	if _, err := os.Stat(path + ".new"); err == nil {
		t.Error("the temporary file was left behind")
	}

	// Nothing is overwritten.
	if err := createPrivateFile(path, []byte("chap_key_three")); err == nil {
		t.Error("createPrivateFile replaced an existing file")
	}
	if got, _ := os.ReadFile(path); string(got) != "chap_key_two" {
		t.Errorf("an existing key file was changed: %q", got)
	}
}

// A link at the path is refused, and nothing is written through it.
func TestKeyFileIsNotWrittenThroughALink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "theirs")
	if err := os.WriteFile(target, []byte("theirs"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "chap.key")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot make a symbolic link here (%v)", err)
	}
	if err := createPrivateFile(link, []byte("chap_key_x")); err == nil {
		t.Error("createPrivateFile wrote through a link")
	}
	if got, _ := os.ReadFile(target); string(got) != "theirs" {
		t.Errorf("the link target was changed: %q", got)
	}
}
