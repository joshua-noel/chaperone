//go:build windows

package privfile

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CurrentUserSID returns the SID of the user this process runs as.
func CurrentUserSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read the current user: %w", err)
	}
	return user.User.Sid, nil
}

// UserOnlyACL builds an access list with one entry: full control for sid, with the given inheritance flags.
func UserOnlyACL(sid *windows.SID, inheritance uint32) (*windows.ACL, error) {
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

// Descriptor is a security descriptor that names the current user as owner and holds the protected, user-only
// access list (nothing is inherited from the folder). Hand Attributes to the call that creates the file or folder,
// and call Release after it returns, so the descriptor outlives the call.
type Descriptor struct {
	sd  *windows.SECURITY_DESCRIPTOR
	acl *windows.ACL
	sa  windows.SecurityAttributes
}

// NewDescriptor builds the descriptor. inheritance is windows.NO_INHERITANCE for a file, and
// windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT for a folder whose contents are private too.
func NewDescriptor(inheritance uint32) (*Descriptor, error) {
	sid, err := CurrentUserSID()
	if err != nil {
		return nil, err
	}
	acl, err := UserOnlyACL(sid, inheritance)
	if err != nil {
		return nil, err
	}
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, err
	}
	if err := sd.SetOwner(sid, false); err != nil {
		return nil, fmt.Errorf("set the owner: %w", err)
	}
	if err := sd.SetDACL(acl, true, false); err != nil {
		return nil, err
	}
	if err := sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
		return nil, err
	}
	d := &Descriptor{sd: sd, acl: acl}
	d.sa.SecurityDescriptor = sd
	d.sa.Length = uint32(unsafe.Sizeof(d.sa))
	return d, nil
}

// Attributes is the SECURITY_ATTRIBUTES to pass to CreateFile or CreateDirectory.
func (d *Descriptor) Attributes() *windows.SecurityAttributes { return &d.sa }

// Release keeps the descriptor and its access list alive until the create call is over.
func (d *Descriptor) Release() { runtime.KeepAlive(d) }

// Create makes a NEW file at path and opens it for writing. The file is created with the protected, user-only
// access list in the same call (CREATE_NEW), so it is never readable by anybody else, not even for an instant, and
// whatever the folder's own access list says is not inherited. It fails if anything exists at path, a link
// included. The caller's own handle is the only one: it is opened with no sharing for write.
func Create(path string) (*os.File, error) {
	d, err := NewDescriptor(windows.NO_INHERITANCE)
	if err != nil {
		return nil, err
	}
	defer d.Release()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE|windows.DELETE, windows.FILE_SHARE_READ, d.Attributes(), windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "create", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}
