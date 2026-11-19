//go:build windows

package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// elevated reports whether this process runs with an elevated token. `chapd orch`
// refuses to touch the real database otherwise: the state folder's ACL (ADR-003)
// already keeps a normal user out, and this makes the refusal explicit.
func elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// restrictToCurrentUser replaces the DACL of path with one ACE: full control
// for the invoking user and nobody else, with inheritance cut (ADR-007 item 5:
// "an ACL granting only that user"). Administrators can still take ownership;
// that is Windows, and an administrator can read the process anyway.
func restrictToCurrentUser(path string) error {
	return setUserOnlyDACL(path, windows.NO_INHERITANCE)
}

// restrictDirToCurrentUser is restrictToCurrentUser for a folder: the one ACE is
// inherited by every file and folder made in it later, and the folder takes
// no permission from its parent. It reads the ACL back and fails unless it is
// exactly that, so a quickstart folder outside the user's profile is private too.
func restrictDirToCurrentUser(path string) error {
	if err := setUserOnlyDACL(path, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT); err != nil {
		return err
	}
	return verifyUserOnlyDACL(path, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
}

func setUserOnlyDACL(path string, inheritance uint32) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("read the current user: %w", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
		},
	}}, nil)
	if err != nil {
		return fmt.Errorf("build the ACL: %w", err)
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

// verifyUserOnlyDACL reads the DACL of path back: it must be protected (nothing
// inherited), and every entry must be an allow entry for the current user alone.
// For a folder, Windows writes the "this folder" entry and an inherit-only entry
// (OI)(CI)(IO) for the contents; both are accepted, one entry alone with
// (OI)(CI) too. Whatever it holds, it must apply to the folder itself and, when
// inheritance is asked for, to files and subfolders created in it.
func verifyUserOnlyDACL(path string, inheritance uint32) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read the ACL of %s: %w", path, err)
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%s still inherits permissions from its parent folder", path)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return fmt.Errorf("read the ACL of %s: %v", path, err)
	}
	if acl.AceCount < 1 || acl.AceCount > 2 {
		return fmt.Errorf("%s has %d access entries, want only the current user's", path, acl.AceCount)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	var onFolder, inherits bool
	for i := range uint32(acl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			!windows.EqualSid((*windows.SID)(unsafe.Pointer(&ace.SidStart)), user.User.Sid) {
			return fmt.Errorf("an access entry of %s is not an allow entry for the current user", path)
		}
		flags := uint32(ace.Header.AceFlags)
		if flags&windows.INHERIT_ONLY_ACE == 0 {
			onFolder = true
		}
		if flags&windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT == windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT {
			inherits = true
		}
	}
	if !onFolder || (inheritance == windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT && !inherits) {
		return fmt.Errorf("the access entries of %s do not give the current user the folder and what is made in it", path)
	}
	return nil
}
