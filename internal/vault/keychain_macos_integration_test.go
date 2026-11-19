package vault

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// TestRealKeychainMacOS runs the keychain-macos wrapper on the real
// /usr/bin/security. It is the check ADR-003 amendment 6 lists as "not run on
// a Mac yet".
//
//	CHAPERONE_TEST_REAL_KEYCHAIN=1 go test -count=1 -run RealKeychainMacOS -v ./internal/vault
//
// Which keychain it uses: the wrapper does not name one. `security` stores in
// the user's default keychain, so the test writes there. On a CI runner the
// workflow first makes a throwaway keychain and makes it the default; on a
// developer Mac the login keychain is used. Every item the test makes is
// deleted at the end, by its id; items are labelled chaperone-vault-key under
// the service chaperone-vault, so a leftover is easy to find.
//
// What it checks: Wrap, Unwrap and compare; that the key was on no command line
// (the arguments the wrapper passed, and the real process list during the
// calls); that `security -w` prints the value with a line end that the wrapper
// removes; what happens when the item is gone; a whole vault on the wrapper.
func TestRealKeychainMacOS(t *testing.T) {
	requireRealKeyring(t, "CHAPERONE_TEST_REAL_KEYCHAIN", "darwin", "macOS keychain")

	rec := newRecordingRunner()
	p := platformFor(rec)
	kw, err := p.wrapper(KeychainName, WrapperOptions{})
	if err != nil {
		t.Fatalf("the wrapper could not be built (is /usr/bin/security trusted?): %v", err)
	}
	w := kw.(storeWrapper)
	st := w.store.(keychainStore)
	defer rec.logCalls(t)

	t.Run("wrap, unwrap, compare, no key on a command line", func(t *testing.T) {
		_, _, _ = realWrapRoundTrip(t, w, st, rec)
	})

	t.Run("the tool's own output", func(t *testing.T) {
		_, value, id := realWrapRoundTrip(t, w, st, rec)
		got, err := st.get(context.Background(), id)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		defer clear(got)
		// `security find-generic-password -w` ends its output with a newline.
		// The wrapper removes it; record whether the tool really adds one.
		t.Logf("security printed a trailing newline: %v", bytes.HasSuffix(got, []byte("\n")))
		if string(bytes.TrimRight(got, "\r\n")) != value {
			t.Errorf("the stored value is not the value that was put (%d bytes read)", len(got))
		}
	})

	t.Run("the item is deleted", func(t *testing.T) {
		_, value, id := realWrapRoundTrip(t, w, st, rec)
		blob := []byte(refMagic + "\n" + KeychainName + "\n" + id + "\n")
		if err := st.remove(context.Background(), id); err != nil {
			t.Fatalf("delete: %v", err)
		}
		out, err := w.Unwrap(blob)
		if err == nil {
			clear(out)
			t.Fatal("Unwrap succeeded after the item was deleted")
		}
		if strings.Contains(err.Error(), value) {
			t.Error("the error holds the key")
		}
		// The exit code the wrapper maps to its "not in this keychain" advice.
		if !strings.Contains(err.Error(), "not in this user's keychain") {
			t.Errorf("a deleted item did not give the not-found advice (exit 44 expected): %v", err)
		}
		t.Logf("error for a deleted item: %v", err)
	})

	t.Run("a whole vault", func(t *testing.T) {
		realVaultRoundTrip(t, w, st)
	})
}
