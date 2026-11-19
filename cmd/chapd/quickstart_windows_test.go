//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// checkPrivateFile fails unless the file's DACL is protected (nothing inherited) and holds exactly one entry:
// the current user. That is what restrictToCurrentUser, called by writePrivate, sets.
func checkPrivateFile(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("%s inherits permissions from its folder", path)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if acl == nil || acl.AceCount != 1 {
		t.Fatalf("%s: DACL has %v entries, want exactly 1", path, acl)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(acl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
		t.Errorf("the entry is not an allow entry (type %d)", ace.Header.AceType)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if !windows.EqualSid((*windows.SID)(unsafe.Pointer(&ace.SidStart)), user.User.Sid) {
		t.Errorf("%s: the entry is for another user than %s", path, user.User.Sid)
	}
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

// onlyTheUserCanUse fails unless every entry in the DACL of path is an allow entry for the current user, and there is
// at least one.
func onlyTheUserCanUse(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		t.Fatalf("%s: no DACL entries (%v)", path, err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	for i := range uint32(acl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !windows.EqualSid((*windows.SID)(unsafe.Pointer(&ace.SidStart)), user.User.Sid) {
			t.Errorf("%s: entry %d is for somebody else, or not an allow entry", path, i)
		}
	}
}

// A quickstart folder is private to the user whatever its parent allows, which matters for a --dir outside the profile:
// the folder gets a protected ACL, and what is made in it inherits it. The parent here (the test's temp folder) has
// entries for others, as such a parent would.
func TestQuickstartFolderACLOnWindows(t *testing.T) {
	parent := t.TempDir()
	if err := verifyUserOnlyDACL(parent, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT); err == nil {
		t.Fatal("the test's parent folder already looks private; the check below proves nothing")
	}
	dir := filepath.Join(parent, "qs")
	if err := os.MkdirAll(dir, 0o755); err != nil { // an empty folder the user made, with the parent's permissions
		t.Fatal(err)
	}
	if _, err := prepareQuickstartFolder(dir, nil, "127.0.0.1:55436", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := verifyUserOnlyDACL(dir, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT); err != nil { // owner included
		t.Fatal(err)
	}
	// Everything the quickstart makes, and a file made later, carries only the user's entry.
	later := filepath.Join(dir, "later.txt")
	if err := os.WriteFile(later, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{later, filepath.Join(dir, "state.db"), filepath.Join(dir, quickstartMarker), filepath.Join(dir, "run-keys.json"),
		filepath.Join(dir, "policy"), filepath.Join(dir, "policy", "playground.yaml"), filepath.Join(dir, "logs")} {
		onlyTheUserCanUse(t, p)
		if err := checkTrusted(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	// A second start keeps it so.
	st, err := readQuickstartState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareQuickstartFolder(dir, st, "", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := verifyUserOnlyDACL(dir, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT); err != nil {
		t.Fatal(err)
	}
}

// A folder is private only if its OWNER is the current user: an owner can always rewrite the permission list.
// C:\Windows is owned by the system, not by the user; reading is all this does.
func TestOwnerOfAFolderIsChecked(t *testing.T) {
	win := os.Getenv("SystemRoot")
	if win == "" {
		t.Skip("no SystemRoot")
	}
	if err := ownedByCurrentUser(win); err == nil {
		t.Errorf("%s was taken as owned by the current user", win)
	}
	if err := verifyUserOnlyDACL(win, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT); err == nil || !strings.Contains(err.Error(), "owned by") {
		t.Errorf("verifyUserOnlyDACL accepted a folder somebody else owns: %v", err)
	}
	if err := checkTrusted(win); err == nil {
		t.Errorf("checkTrusted accepted %s", win)
	}
	own := filepath.Join(t.TempDir(), "mine")
	if err := os.Mkdir(own, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ownedByCurrentUser(own); err != nil {
		t.Errorf("a folder this user made: %v", err)
	}
	// After the lock the owner is read back as the current user.
	if err := restrictDirToCurrentUser(own); err != nil {
		t.Fatal(err)
	}
	if err := ownedByCurrentUser(own); err != nil {
		t.Error(err)
	}
}

// makeWorldWritable gives Everyone full control of path through an explicit entry, the way a user
// with write access to the folder could (an entry set on the file itself, which a later change to the folder keeps).
func makeWorldWritable(t *testing.T, path string) {
	t.Helper()
	if out, err := exec.Command("icacls", path, "/grant", "*S-1-1-0:F").CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v %s", err, out)
	}
}
