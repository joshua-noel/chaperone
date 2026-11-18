//go:build windows

package vault

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dpapiFlags is CRYPTPROTECT_UI_FORBIDDEN only. The scope is the calling
// user because CRYPTPROTECT_LOCAL_MACHINE (0x4) is absent, and a test asserts
// it stays absent.
const dpapiFlags = windows.CRYPTPROTECT_UI_FORBIDDEN

type dpapiUser struct{ entropy []byte }

func newDPAPIUser(entropy []byte) KeyWrapper { return dpapiUser{entropy: entropy} }

func (dpapiUser) Name() string { return DPAPIName }

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func (w dpapiUser) Wrap(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("vault: dpapi-user: nothing to wrap")
	}
	desc, err := windows.UTF16PtrFromString("chaperone vault key")
	if err != nil {
		return nil, err
	}
	var out windows.DataBlob
	if err := windows.CryptProtectData(blob(plaintext), desc, blob(w.entropy), 0, nil, dpapiFlags, &out); err != nil {
		return nil, fmt.Errorf("vault: dpapi-user: CryptProtectData: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func (w dpapiUser) Unwrap(wrapped []byte) ([]byte, error) {
	if len(wrapped) == 0 {
		return nil, errors.New("vault: dpapi-user: empty blob")
	}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blob(wrapped), nil, blob(w.entropy), 0, nil, dpapiFlags, &out); err != nil {
		return nil, fmt.Errorf("vault: dpapi-user: CryptUnprotectData: %w", err)
	}
	// DPAPI allocated the plaintext with LocalAlloc: copy it out, then wipe
	// and free the original.
	src := unsafe.Slice(out.Data, out.Size)
	plain := append([]byte(nil), src...)
	clear(src)
	windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return plain, nil
}
