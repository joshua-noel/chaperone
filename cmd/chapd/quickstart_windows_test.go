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

// A quickstart folder is made private by the quickstart itself, from the instant it exists, whatever its parent
// allows: owner = the user, a protected ACL with the user's entries alone, inherited by what is made in it. The
// parent here (the test's temp folder) has entries for others, as a parent would.
func TestQuickstartFolderACLOnWindows(t *testing.T) {
	parent := qsTemp(t)
	if err := verifyUserOnlyDACL(parent, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT); err == nil {
		t.Fatal("the test's parent folder already looks private; the check below proves nothing")
	}
	dir := filepath.Join(parent, "qs")
	if _, err := prepareQuickstartFolder(dir, nil, "127.0.0.1:55436", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := verifyPrivateDir(dir); err != nil { // owner included
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(dir, "state.db"), filepath.Join(dir, quickstartMarker), filepath.Join(dir, "run-keys.json"),
		filepath.Join(dir, "policy"), filepath.Join(dir, "policy", "playground.yaml"), filepath.Join(dir, "logs")} {
		onlyTheUserCanUse(t, p)
		if err := checkTrusted(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	// A second start reuses it.
	st, err := readQuickstartState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareQuickstartFolder(dir, st, "", time.Now()); err != nil {
		t.Fatal(err)
	}
	// A file made later inherits the user's entry only; but it is not something the quickstart made, so a later start refuses it.
	later := filepath.Join(dir, "later.txt")
	if err := os.WriteFile(later, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	onlyTheUserCanUse(t, later)
	if _, err := prepareQuickstartFolder(dir, st, "", time.Now()); err == nil || !strings.Contains(err.Error(), "later.txt") {
		t.Errorf("an unknown entry was accepted: %v", err)
	}
}

// Reviewer's experiment (a): a handle with WRITE_DAC opened on a pre-existing folder BEFORE the run keeps that right after
// any lock. Now impossible by construction: a pre-existing folder is refused, untouched, and a first run only makes its
// own folder.
func TestQuickstartRefusesAFolderThatExistedBeforeTheRun(t *testing.T) {
	dir := filepath.Join(qsTemp(t), "qs")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p, _ := windows.UTF16PtrFromString(dir)
	h, err := windows.CreateFile(p, windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	before, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := checkQuickstartDir(dir); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("check: %v", err)
	}
	if _, err := prepareQuickstartFolder(dir, nil, "127.0.0.1:55443", time.Now()); err == nil {
		t.Error("prepare used a folder that existed, with a WRITE_DAC handle open on it")
	}
	var out strings.Builder
	if err := runQuickstart(t.Context(), quickstartOptions{Dir: dir, Addr: qsFreeAddr(t), Playground: true}, &out); err == nil || out.Len() != 0 {
		t.Errorf("runQuickstart: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("something was written into the existing folder: %v", entries)
	}
	after, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if before.String() != after.String() {
		t.Errorf("the existing folder's permissions were changed:\n%s\n%s", before, after)
	}
}

// A first run makes its folder with CreateDirectory and a descriptor that is already private: it fails if the folder is there,
// and what it makes (and what is made inside it) carries the user's entries alone.
func TestCreatePrivateDirIsAtomic(t *testing.T) {
	parent := qsTemp(t)
	dir := filepath.Join(parent, "new")
	if err := createPrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := verifyPrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := createPrivateDir(dir); err == nil {
		t.Error("createPrivateDir succeeded on a folder that exists")
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	onlyTheUserCanUse(t, sub)
	// A folder with parent-inherited entries is NOT private.
	loose := filepath.Join(parent, "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifyPrivateDir(loose); err == nil {
		t.Error("a folder that inherits its parent's permissions was accepted as private")
	}
}

// The parent must not let others rename the folder away or take it: no entry for anybody but the user, SYSTEM and
// Administrators may give the right to add to it, delete in it, or change its permissions or owner.
func TestQuickstartRefusesAParentOthersCanChangeOnWindows(t *testing.T) {
	base := qsTemp(t)
	if err := ancestorSafe(base); err != nil {
		t.Fatalf("an ordinary temp folder was refused as an ancestor: %v", err)
	}
	for _, grant := range []string{"*S-1-1-0:(F)", "*S-1-1-0:(M)", "*S-1-5-11:(M)", "*S-1-5-32-545:(W)", "*S-1-1-0:(DC)", "*S-1-1-0:(WDAC)"} {
		parent := filepath.Join(base, "p-"+strings.NewReplacer("*", "", ":", "-", "(", "", ")", "").Replace(grant))
		if err := os.Mkdir(parent, 0o755); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("icacls", parent, "/grant", grant).CombinedOutput(); err != nil {
			t.Fatalf("icacls %s: %v %s", grant, err, out)
		}
		dir := filepath.Join(parent, "qs")
		if _, _, err := checkQuickstartDir(dir); err == nil || !strings.Contains(err.Error(), "lets") {
			t.Errorf("parent granting %s: check: %v", grant, err)
		}
		if _, err := prepareQuickstartFolder(dir, nil, "127.0.0.1:55444", time.Now()); err == nil {
			t.Errorf("parent granting %s: prepare went on", grant)
		}
		if _, err := os.Stat(dir); err == nil {
			t.Errorf("parent granting %s: the folder was made", grant)
		}
	}
	// Read and execute for everyone is harmless.
	ro := filepath.Join(base, "readable")
	if err := os.Mkdir(ro, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("icacls", ro, "/grant", "*S-1-1-0:(RX)").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if _, _, err := checkQuickstartDir(filepath.Join(ro, "qs")); err != nil {
		t.Errorf("a parent others can only read: %v", err)
	}
	// A higher ancestor counts too.
	high := filepath.Join(base, "high")
	if err := os.MkdirAll(filepath.Join(high, "mid"), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("icacls", high, "/grant", "*S-1-1-0:(F)").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if _, _, err := checkQuickstartDir(filepath.Join(high, "mid", "qs")); err == nil {
		t.Error("a writable grandparent was accepted")
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
	own := filepath.Join(qsTemp(t), "mine")
	if err := createPrivateDir(own); err != nil {
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

// Only the principals an ordinary profile folder lists are trusted on a folder above ours: the user, SYSTEM, Administrators,
// CREATOR OWNER and TrustedInstaller itself. Other service SIDs (S-1-5-80-*) are per-service and are not.
func TestOnlyTheNamedPrincipalsAreTrustedOnAnAncestor(t *testing.T) {
	user, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	for sid, want := range map[string]bool{
		"S-1-5-18": true, "S-1-5-32-544": true, "S-1-3-0": true, trustedInstallerSID: true,
		"S-1-5-80-0": false, "S-1-5-80-1": false, "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478465": false,
		"S-1-1-0": false, "S-1-5-11": false, "S-1-5-32-545": false,
	} {
		s, err := windows.StringToSid(sid)
		if err != nil {
			t.Fatal(err)
		}
		if got := trustedPrincipal(s, user); got != want {
			t.Errorf("trustedPrincipal(%s) = %v, want %v", sid, got, want)
		}
	}
	if !trustedPrincipal(user, user) {
		t.Error("the current user is not trusted")
	}
	// On a real folder: an entry for another service SID that lets it change things is refused.
	parent := filepath.Join(qsTemp(t), "svc")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("icacls", parent, "/grant", "*S-1-5-80-0:(M)").CombinedOutput(); err != nil {
		t.Skipf("icacls cannot grant to S-1-5-80-0 here: %v %s", err, out)
	}
	if err := ancestorSafe(parent); err == nil || !strings.Contains(err.Error(), "S-1-5-80-0") {
		t.Errorf("a folder that lets S-1-5-80-0 modify it was accepted as an ancestor: %v", err)
	}
}

// Deny entries only narrow access and are skipped; an entry of any other type is not understood and is refused.
func TestAncestorEntryTypes(t *testing.T) {
	for typ, want := range map[byte]string{
		windows.ACCESS_ALLOWED_ACE_TYPE: "allow", windows.ACCESS_DENIED_ACE_TYPE: "deny",
		2:    "other",                // system audit
		5:    "other",                // access allowed, object
		6:    "other",                // access denied, object
		9:    "other",                // access allowed, callback
		0x11: "other", 0x12: "other", // mandatory label, resource attribute
	} {
		if got := ancestorACEKind(typ); got != want {
			t.Errorf("ancestorACEKind(%d) = %q, want %q", typ, got, want)
		}
	}
}
