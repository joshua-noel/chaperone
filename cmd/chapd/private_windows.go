//go:build windows

package main

import (
	"errors"
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
	return setUserOnlyDACL(path, windows.NO_INHERITANCE, false)
}

// restrictDirToCurrentUser is restrictToCurrentUser for a folder: the entries are
// inherited by every file and folder made in it later, the folder takes no
// permission from its parent, and its OWNER is set to the current user (an owner
// can always rewrite the permission list, so a folder another user owns is never
// private). It reads owner and ACL back and fails unless they are exactly that.
// If the owner cannot be set the folder is refused.
func restrictDirToCurrentUser(path string) error {
	if err := setUserOnlyDACL(path, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT, true); err != nil {
		return err
	}
	return verifyUserOnlyDACL(path, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
}

func currentUserSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read the current user: %w", err)
	}
	return user.User.Sid, nil
}

func setUserOnlyDACL(path string, inheritance uint32, setOwner bool) error {
	sid, err := currentUserSID()
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, nil)
	if err != nil {
		return fmt.Errorf("build the ACL: %w", err)
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	var owner *windows.SID
	if setOwner {
		info |= windows.OWNER_SECURITY_INFORMATION
		owner = sid
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, owner, nil, acl, nil)
}

// ownerTrusted reports whether sd's owner is the current user, or, for an elevated process, the Administrators group, which owns what such a process creates.
func ownerTrusted(sd *windows.SECURITY_DESCRIPTOR) error {
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("read the owner: %v", err)
	}
	user, err := currentUserSID()
	if err != nil {
		return err
	}
	if windows.EqualSid(owner, user) {
		return nil
	}
	// An elevated process creates objects owned by the Administrators group.
	if windows.GetCurrentProcessToken().IsElevated() {
		if admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid); err == nil && windows.EqualSid(owner, admins) {
			return nil
		}
	}
	return fmt.Errorf("it is owned by %s, not by the current user", owner)
}

// onlyUserEntries checks the DACL of sd: it exists (a missing DACL grants everyone everything),
// and every entry is an allow entry for the current user. It returns whether one applies to the
// object itself and whether one is inherited by what is made inside.
func onlyUserEntries(sd *windows.SECURITY_DESCRIPTOR) (onObject, inherits bool, err error) {
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return false, false, fmt.Errorf("it has no permission list (%v)", err)
	}
	if acl.AceCount < 1 || acl.AceCount > 2 {
		return false, false, fmt.Errorf("it has %d access entries, want only the current user's", acl.AceCount)
	}
	user, err := currentUserSID()
	if err != nil {
		return false, false, err
	}
	for i := range uint32(acl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return false, false, err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			!windows.EqualSid((*windows.SID)(unsafe.Pointer(&ace.SidStart)), user) {
			return false, false, errors.New("an access entry is not an allow entry for the current user")
		}
		flags := uint32(ace.Header.AceFlags)
		if flags&windows.INHERIT_ONLY_ACE == 0 {
			onObject = true
		}
		if flags&windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT == windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT {
			inherits = true
		}
	}
	return onObject, inherits, nil
}

func securityOf(path string) (*windows.SECURITY_DESCRIPTOR, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, fmt.Errorf("read the owner and permissions of %s: %w", path, err)
	}
	return sd, nil
}

// verifyUserOnlyDACL reads owner and DACL of a folder back: the owner is the current user, the DACL is
// protected (nothing inherited), and every entry is an allow entry for the current user. Windows writes
// the "this folder" entry and an inherit-only (OI)(CI)(IO) entry for the contents; both are accepted,
// as is one entry with (OI)(CI). It must apply to the folder and, when asked, to what is made in it.
func verifyUserOnlyDACL(path string, inheritance uint32) error {
	sd, err := securityOf(path)
	if err != nil {
		return err
	}
	if err := ownerTrusted(sd); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%s still inherits permissions from its parent folder", path)
	}
	onFolder, inherits, err := onlyUserEntries(sd)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if !onFolder || (inheritance == windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT && !inherits) {
		return fmt.Errorf("the access entries of %s do not give the current user the folder and what is made in it", path)
	}
	return nil
}

// ownedByCurrentUser fails unless the current user owns path (see ownerTrusted).
func ownedByCurrentUser(path string) error {
	sd, err := securityOf(path)
	if err != nil {
		return err
	}
	if err := ownerTrusted(sd); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// checkTrusted decides whether a file or folder that already exists may be trusted: the current user
// owns it and only the current user has access to it. A file another user planted fails the first test;
// one that was made readable or writable by others (an Everyone entry, a NULL permission list) the second.
func checkTrusted(path string) error {
	sd, err := securityOf(path)
	if err != nil {
		return err
	}
	if err := ownerTrusted(sd); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if _, _, err := onlyUserEntries(sd); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
