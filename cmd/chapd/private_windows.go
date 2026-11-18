//go:build windows

package main

import (
	"fmt"

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
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("read the current user: %w", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
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
