package vault

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestRealSecretServiceLinux runs the secret-service wrapper on the real
// `secret-tool` and a real Secret Service. It is the check ADR-003 amendment 6
// lists as "not run on a Linux desktop yet".
//
// It needs a session bus with an unlocked keyring on it. The CI workflow makes
// one (dbus-run-session and gnome-keyring-daemon, see keyring.yml). On a
// desktop, run it in your own session:
//
//	CHAPERONE_TEST_REAL_SECRET_SERVICE=1 go test -count=1 -run RealSecretService -v ./internal/vault
//
// Every item it makes is deleted at the end, by its id. Items carry the
// attribute service=chaperone-vault, so a leftover can be found with
// `secret-tool search service chaperone-vault`.
func TestRealSecretServiceLinux(t *testing.T) {
	requireRealKeyring(t, "CHAPERONE_TEST_REAL_SECRET_SERVICE", "linux", "Secret Service keyring")

	rec := newRecordingRunner()
	p := platformFor(rec)
	kw, err := p.wrapper(SecretServiceName, WrapperOptions{})
	if err != nil {
		t.Fatalf("the wrapper could not be built (is secret-tool in /usr/bin and root-owned?): %v", err)
	}
	w := kw.(storeWrapper)
	st := w.store.(secretServiceStore)
	defer rec.logCalls(t)

	t.Run("wrap, unwrap, compare, no key on a command line", func(t *testing.T) {
		_, _, _ = realWrapRoundTrip(t, w, st, rec)
	})

	t.Run("lookup returns the value with no trailing newline", func(t *testing.T) {
		_, value, id := realWrapRoundTrip(t, w, st, rec)
		got, err := st.get(context.Background(), id)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		defer clear(got)
		if bytes.HasSuffix(got, []byte("\n")) {
			t.Error("secret-tool lookup ended its output with a newline")
		}
		if string(got) != value {
			t.Errorf("secret-tool lookup returned %d bytes that differ from the %d-byte value that was stored", len(got), len(value))
		}
	})

	t.Run("the item is deleted", func(t *testing.T) {
		_, value, id := realWrapRoundTrip(t, w, st, rec)
		blob := []byte(refMagic + "\n" + SecretServiceName + "\n" + id + "\n")
		if err := st.remove(context.Background(), id); err != nil {
			t.Fatalf("clear: %v", err)
		}
		out, err := w.Unwrap(blob)
		if err == nil {
			clear(out)
			t.Fatal("Unwrap succeeded after the item was deleted")
		}
		if strings.Contains(err.Error(), value) {
			t.Error("the error holds the key")
		}
		t.Logf("error for a deleted item: %v", err)
	})

	t.Run("a whole vault", func(t *testing.T) {
		realVaultRoundTrip(t, w, st)
	})

	// Last: it changes the environment for the rest of the test (restored by
	// t.Setenv when the subtest ends).
	t.Run("no session bus gives a clear error that names the passphrase wrapper", func(t *testing.T) {
		for _, k := range []string{"DBUS_SESSION_BUS_ADDRESS", "DISPLAY", "WAYLAND_DISPLAY"} {
			t.Setenv(k, "") // registers the restore
			os.Unsetenv(k)
		}
		t.Setenv("XDG_RUNTIME_DIR", t.TempDir()) // no /run/user/UID/bus to find

		key, value := randomKey(t)
		start := time.Now()
		blob, err := w.Wrap(key)
		if err == nil {
			// It worked without a bus: something else answered. Clean up the
			// item before failing.
			removeAfter(t, st, refID(t, blob))
			t.Fatal("Wrap succeeded with no session bus")
		}
		if strings.Contains(err.Error(), value) {
			t.Error("the error holds the key")
		}
		if !strings.Contains(err.Error(), PassphraseName) {
			t.Errorf("the error does not name the %s wrapper: %v", PassphraseName, err)
		}
		if time.Since(start) > 30*time.Second {
			t.Errorf("failing took %s", time.Since(start))
		}
		t.Logf("error with no session bus: %v", err)
	})
}
