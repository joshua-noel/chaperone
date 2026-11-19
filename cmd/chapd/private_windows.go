//go:build windows

package main

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
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
	sid, err := currentUserSID()
	if err != nil {
		return err
	}
	acl, err := userOnlyACL(sid, windows.NO_INHERITANCE)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

func currentUserSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read the current user: %w", err)
	}
	return user.User.Sid, nil
}

func userOnlyACL(sid *windows.SID, inheritance uint32) (*windows.ACL, error) {
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
		return nil, fmt.Errorf("build the ACL: %w", err)
	}
	return acl, nil
}

// createPrivateDir makes a NEW folder that is private from the instant it exists: CreateDirectory is given a
// security descriptor that already names the current user as owner and holds the protected, user-only DACL
// with object and container inheritance. It fails if the folder exists. So no handle can have been opened on it
// under looser permissions (Windows checks access when a handle is opened, and a handle opened with WRITE_DAC
// before a later lock keeps that right), and nobody else owns it. The result is read back.
func createPrivateDir(path string) error {
	sid, err := currentUserSID()
	if err != nil {
		return err
	}
	acl, err := userOnlyACL(sid, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
	if err != nil {
		return err
	}
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return err
	}
	if err := sd.SetOwner(sid, false); err != nil {
		return fmt.Errorf("set the owner: %w", err)
	}
	if err := sd.SetDACL(acl, true, false); err != nil {
		return err
	}
	if err := sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	err = windows.CreateDirectory(p, sa)
	runtime.KeepAlive(acl)
	runtime.KeepAlive(sd)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if err := verifyPrivateDir(path); err != nil {
		_ = windows.RemoveDirectory(p)
		return err
	}
	return nil
}

// verifyPrivateDir reads owner and ACL of a folder this program made: see verifyUserOnlyDACL.
func verifyPrivateDir(path string) error {
	return verifyUserOnlyDACL(path, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
}

// Access rights that let a principal swap, rewrite or take a folder: add entries (rename a folder in),
// delete children, delete the folder, change its permissions or owner, or any generic write or all.
const riskyFolderRights = 0x2 | 0x4 | 0x40 | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL

// trustedPrincipal reports whether sid is the current user, SYSTEM, the Administrators group, the
// service installer, or CREATOR OWNER: the principals an ordinary profile folder lists.
func trustedPrincipal(sid *windows.SID, user *windows.SID) bool {
	return windows.EqualSid(sid, user) || sid.IsWellKnown(windows.WinLocalSystemSid) ||
		sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.IsWellKnown(windows.WinCreatorOwnerSid) ||
		strings.HasPrefix(sid.String(), "S-1-5-80-")
}

// ancestorSafe decides whether a folder ABOVE the quickstart folder may stay as it is: nobody but the
// user, SYSTEM and Administrators may own it or hold, through an entry that applies to the folder itself,
// a right to add to it, delete in it or from it, or change its permissions or owner. Otherwise they could
// rename the quickstart folder away after it is made and put their own in its place.
func ancestorSafe(path string) error {
	sd, err := securityOf(path)
	if err != nil {
		return err
	}
	user, err := currentUserSID()
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !trustedPrincipal(owner, user) {
		return fmt.Errorf("%s is owned by somebody other than you, SYSTEM or Administrators", path)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return fmt.Errorf("%s has no permission list (everyone has full control): %v", path, err)
	}
	for i := range uint32(acl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || uint32(ace.Header.AceFlags)&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !trustedPrincipal(sid, user) && uint32(ace.Mask)&riskyFolderRights != 0 {
			return fmt.Errorf("%s lets %s add to it, delete from it or change its permissions (rights 0x%x)", path, sid, uint32(ace.Mask))
		}
	}
	return nil
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
