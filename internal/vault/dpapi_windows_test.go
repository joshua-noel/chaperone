//go:build windows

package vault

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestDPAPIRoundTrip(t *testing.T) {
	w := NewDPAPI()
	if w.Name() != "dpapi-user" {
		t.Errorf("name %q", w.Name())
	}
	plain := []byte("AGE-SECRET-KEY-1-not-a-real-key-just-test-bytes")
	blob, err := w.Wrap(plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, plain) || bytes.Contains(blob, plain[:12]) {
		t.Error("wrapped blob holds the plaintext")
	}
	got, err := w.Unwrap(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Error("round trip changed the bytes")
	}
	// Two wraps of the same input differ (DPAPI salts every blob).
	blob2, _ := w.Wrap(plain)
	if bytes.Equal(blob, blob2) {
		t.Error("identical blobs for identical input")
	}
}

func TestDPAPIRefusals(t *testing.T) {
	w := NewDPAPI()
	if _, err := w.Wrap(nil); err == nil {
		t.Error("empty plaintext wrapped")
	}
	if _, err := w.Unwrap(nil); err == nil {
		t.Error("empty blob unwrapped")
	}
	blob, err := w.Wrap([]byte("some secret bytes"))
	if err != nil {
		t.Fatal(err)
	}
	// Our entropy is part of the key: another entropy cannot unwrap.
	if _, err := newDPAPIUser([]byte("someone else")).Unwrap(blob); err == nil {
		t.Error("a different entropy unwrapped the blob")
	}
	// A flipped byte is detected.
	bad := append([]byte(nil), blob...)
	bad[len(bad)-1] ^= 1
	if _, err := w.Unwrap(bad); err == nil {
		t.Error("a corrupted blob unwrapped")
	}
	if _, err := w.Unwrap([]byte("garbage")); err == nil {
		t.Error("garbage unwrapped")
	}
}

// TestDPAPIScopeIsUser pins the flags: machine scope would let any local user
// decrypt (ADR-003), so the constant must not carry it.
func TestDPAPIScopeIsUser(t *testing.T) {
	if dpapiFlags&windows.CRYPTPROTECT_LOCAL_MACHINE != 0 {
		t.Fatal("CRYPTPROTECT_LOCAL_MACHINE is set: any user on the PC could decrypt")
	}
	if dpapiFlags&windows.CRYPTPROTECT_UI_FORBIDDEN == 0 {
		t.Error("UI_FORBIDDEN missing: a service could hang on a prompt")
	}
}

// TestDPAPIWrongAccount is the wrong-account acceptance check. It needs two
// Windows users, and creating the second needs an administrator, so it is a
// documented manual check (package comment in vault.go):
//
//	account A: CHAP_VAULT_DPAPI_WRITE=<shared path>  go test -run TestDPAPIWrongAccount ./internal/vault
//	account B: CHAP_VAULT_DPAPI_READ=<same path>     go test -run TestDPAPIWrongAccount ./internal/vault
//
// A writes a blob and unwraps it (control). B must fail to unwrap it.
func TestDPAPIWrongAccount(t *testing.T) {
	writePath, readPath := os.Getenv("CHAP_VAULT_DPAPI_WRITE"), os.Getenv("CHAP_VAULT_DPAPI_READ")
	if writePath == "" && readPath == "" {
		t.Skip("MANUAL CHECK: needs a second Windows account. As account A set CHAP_VAULT_DPAPI_WRITE=<path>, " +
			"as account B set CHAP_VAULT_DPAPI_READ=<same path>, run this test in each; B must pass. See the package comment in vault.go.")
	}
	w := NewDPAPI()
	marker := []byte("chaperone-wrong-account-check")
	if writePath != "" {
		blob, err := w.Wrap(marker)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(writePath, blob, 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := w.Unwrap(blob)
		if err != nil || !bytes.Equal(got, marker) {
			t.Fatalf("control: the writing account cannot unwrap its own blob: %v", err)
		}
		t.Logf("wrote %s; now run the read half as the other account", writePath)
	}
	if readPath != "" {
		blob, err := os.ReadFile(readPath)
		if err != nil {
			t.Fatal(err)
		}
		got, err := w.Unwrap(blob)
		if err == nil {
			t.Fatalf("WRONG ACCOUNT DECRYPTED the blob (%q): the wrapper is not user-scoped", got)
		}
		if strings.Contains(err.Error(), string(marker)) {
			t.Error("error holds plaintext")
		}
	}
}
