package vault

import (
	"bytes"
	"strings"
	"testing"
)

// storeCases runs a test against both operating-system stores, each over its
// fake tool.
func storeCases(t *testing.T, fn func(t *testing.T, name string, f *fakeTool, w KeyWrapper)) {
	t.Helper()
	t.Run("keychain", func(t *testing.T) { f := newFakeSecurity(); fn(t, KeychainName, f, newKeychainWrapper(f)) })
	t.Run("secret-service", func(t *testing.T) { f := newFakeSecretTool(); fn(t, SecretServiceName, f, newSecretServiceWrapper(f)) })
}

func TestStoreWrapperRoundTripKeepsTheKeyOffTheCommandLine(t *testing.T) {
	storeCases(t, func(t *testing.T, name string, f *fakeTool, w KeyWrapper) {
		if w.Name() != name {
			t.Fatalf("name %q", w.Name())
		}
		plain := []byte("AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ")
		blob, err := w.Wrap(plain)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(blob, plain) || bytes.Contains(blob, []byte(hexOf(plain))) || bytes.Contains(blob, plain[:12]) {
			t.Error("the blob on disk holds key material")
		}
		got, err := w.Unwrap(blob)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, plain) {
			t.Error("round trip changed the key")
		}
		blob2, err := w.Wrap(plain)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(blob, blob2) {
			t.Error("two wraps share one reference")
		}
		f.noSecretOnCommandLine(t, plain)
		// The key did reach the tool, and on standard input only.
		var viaStdin bool
		for _, c := range f.calls {
			if strings.Contains(c.stdin, hexOf(plain)) {
				viaStdin = true
			}
		}
		if !viaStdin {
			t.Error("the key never reached the tool's standard input; the test proves nothing")
		}
	})
}

func TestStoreWrapperRefusesAReferenceItDidNotMake(t *testing.T) {
	storeCases(t, func(t *testing.T, name string, f *fakeTool, w KeyWrapper) {
		good, err := w.Wrap([]byte("a key worth keeping"))
		if err != nil {
			t.Fatal(err)
		}
		id := strings.Split(string(good), "\n")[2]
		bad := map[string]string{
			"empty":           "",
			"no newline":      refMagic,
			"other magic":     "something-else v1\n" + name + "\n" + id + "\n",
			"other wrapper":   refMagic + "\nother\n" + id + "\n",
			"upper-case id":   refMagic + "\n" + name + "\n" + strings.ToUpper(id) + "\n",
			"short id":        refMagic + "\n" + name + "\n" + id[:31] + "\n",
			"long id":         refMagic + "\n" + name + "\n" + id + "0\n",
			"option as id":    refMagic + "\n" + name + "\n-----------------a-b-c-d-e-f-0123\n",
			"shell as id":     refMagic + "\n" + name + "\n" + id[:20] + "; rm -rf /\n",
			"extra line":      string(good) + "more\n",
			"missing newline": strings.TrimSuffix(string(good), "\n"),
			"crlf":            strings.ReplaceAll(string(good), "\n", "\r\n"),
			"binary":          "\x00\x01\x02",
		}
		callsBefore := len(f.calls)
		for what, blob := range bad {
			if _, err := w.Unwrap([]byte(blob)); err == nil {
				t.Errorf("%s: accepted", what)
			}
		}
		if len(f.calls) != callsBefore {
			t.Error("a refused reference still started the tool")
		}
		if _, err := w.Unwrap(good); err != nil {
			t.Errorf("the good reference stopped working: %v", err)
		}
	})
}

func TestStoreWrapperOneStoresReferenceIsNotAnothers(t *testing.T) {
	f := newFakeSecurity()
	blob, err := newKeychainWrapper(f).Wrap([]byte("a key worth keeping"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newSecretServiceWrapper(newFakeSecretTool()).Unwrap(blob); err == nil {
		t.Error("the Secret Service wrapper accepted a keychain reference")
	}
}

func TestStoreWrapperLimits(t *testing.T) {
	storeCases(t, func(t *testing.T, _ string, f *fakeTool, w KeyWrapper) {
		if _, err := w.Wrap(nil); err == nil {
			t.Error("wrapped nothing")
		}
		if _, err := w.Wrap(make([]byte, maxStoredKey+1)); err == nil {
			t.Error("wrapped more than the limit")
		}
		if _, err := w.Wrap(bytes.Repeat([]byte{7}, maxStoredKey)); err != nil {
			t.Errorf("a key at the limit: %v", err)
		}
		if len(f.calls) == 0 {
			t.Fatal("nothing ran")
		}
		for _, c := range f.calls {
			if len(c.stdin) > 4000 {
				t.Errorf("a command line of %d bytes exceeds what security -i reads", len(c.stdin))
			}
		}
	})
}

func TestStoreWrapperFailsClosed(t *testing.T) {
	plain := []byte("a key that must never appear in an error")
	secretHex := hexOf(plain)
	for name, mod := range map[string]func(*fakeTool){
		"store exits non-zero":                     func(f *fakeTool) { f.failPut = 1 },
		"store echoes its input in the error":      func(f *fakeTool) { f.failPut = 1; f.echoStdin = true },
		"tool cannot start":                        func(f *fakeTool) { f.failRun = errBoom },
		"store reports success but stores nothing": func(f *fakeTool) { f.corrupt = true },
		"read exits non-zero":                      func(f *fakeTool) { f.failGet = 1 },
	} {
		storeCases(t, func(t *testing.T, _ string, f *fakeTool, w KeyWrapper) {
			mod(f)
			blob, err := w.Wrap(plain)
			if err == nil {
				t.Fatalf("%s: Wrap succeeded (%q)", name, blob)
			}
			if blob != nil {
				t.Errorf("%s: a blob came back with the error", name)
			}
			for _, leak := range []string{string(plain), secretHex} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("%s: the error text holds the key: %v", name, err)
				}
			}
			if len(f.items) != 0 {
				t.Errorf("%s: a key was left in the store", name)
			}
		})
	}
}

func TestStoreWrapperUnwrapFailures(t *testing.T) {
	storeCases(t, func(t *testing.T, _ string, f *fakeTool, w KeyWrapper) {
		blob, err := w.Wrap([]byte("a key worth keeping"))
		if err != nil {
			t.Fatal(err)
		}
		// The item is gone (another user, another machine).
		saved := f.items
		f.items = map[string]string{}
		if out, err := w.Unwrap(blob); err == nil || out != nil {
			t.Errorf("a missing item unwrapped: %v", err)
		}
		// The item holds junk.
		for id := range saved {
			f.items[id] = "not hex at all"
		}
		if out, err := w.Unwrap(blob); err == nil || out != nil || !strings.Contains(err.Error(), "damaged") {
			t.Errorf("junk unwrapped: %v", err)
		}
		for id := range saved {
			f.items[id] = ""
		}
		if _, err := w.Unwrap(blob); err == nil {
			t.Error("an empty value unwrapped")
		}
		f.items = saved
		f.failRun = errBoom
		if _, err := w.Unwrap(blob); err == nil {
			t.Error("unwrapped with the tool gone")
		}
	})
}

func TestKeychainCommandShapes(t *testing.T) {
	f := newFakeSecurity()
	w := newKeychainWrapper(f)
	plain := []byte("0123456789abcdef")
	blob, err := w.Wrap(plain)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Split(string(blob), "\n")[2]
	if _, err := w.Unwrap(blob); err != nil {
		t.Fatal(err)
	}
	put, get := f.calls[0], f.calls[1]
	if put.path != "/usr/bin/security" || len(put.args) != 1 || put.args[0] != "-i" {
		t.Errorf("store ran %s %v; want security -i", put.path, put.args)
	}
	want := "add-generic-password -s chaperone-vault -a " + id + " -l chaperone-vault-key -w " + hexOf(plain) + "\n"
	if put.stdin != want {
		t.Errorf("store input %q, want %q", put.stdin, want)
	}
	wantGet := []string{"find-generic-password", "-s", "chaperone-vault", "-a", id, "-w"}
	if strings.Join(get.args, " ") != strings.Join(wantGet, " ") || get.stdin != "" {
		t.Errorf("read ran %v with input %q", get.args, get.stdin)
	}
	for _, c := range f.calls {
		for _, a := range c.args {
			if a == "-p" || a == "-w" && c.args[0] != "find-generic-password" {
				t.Errorf("insecure option in %v", c.args)
			}
		}
	}
}

func TestKeychainItemNotFoundExplainsItself(t *testing.T) {
	f := newFakeSecurity()
	w := newKeychainWrapper(f)
	blob, _ := w.Wrap([]byte("a key worth keeping"))
	f.items = map[string]string{}
	_, err := w.Unwrap(blob)
	if err == nil || !strings.Contains(err.Error(), "not in this user's keychain") || !strings.Contains(err.Error(), "recover") {
		t.Errorf("got %v", err)
	}
}

func TestSecretServiceCommandShapes(t *testing.T) {
	f := newFakeSecretTool()
	w := newSecretServiceWrapper(f)
	plain := []byte("0123456789abcdef")
	blob, err := w.Wrap(plain)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Split(string(blob), "\n")[2]
	if _, err := w.Unwrap(blob); err != nil {
		t.Fatal(err)
	}
	store, lookup := f.calls[0], f.calls[1]
	if got := strings.Join(store.args, " "); got != "store --label=chaperone-vault-key service chaperone-vault id "+id {
		t.Errorf("store args %q", got)
	}
	if store.stdin != hexOf(plain) {
		t.Errorf("store input %q", store.stdin)
	}
	if got := strings.Join(lookup.args, " "); got != "lookup service chaperone-vault id "+id || lookup.stdin != "" {
		t.Errorf("lookup args %q input %q", got, lookup.stdin)
	}
}

func TestStoreWrapperErrorsNameTheWayOut(t *testing.T) {
	f := newFakeSecretTool()
	f.failPut = 1
	f.stderrText = "secret-tool: Cannot autolaunch D-Bus without X11 $DISPLAY\n"
	_, err := newSecretServiceWrapper(f).Wrap([]byte("a key worth keeping"))
	if err == nil || !strings.Contains(err.Error(), "D-Bus") || !strings.Contains(err.Error(), PassphraseName) {
		t.Errorf("got %v", err)
	}
	f2 := newFakeSecurity()
	f2.failGet = 36
	f2.stderrText = "security: User interaction is not allowed.\n"
	_, err = newKeychainWrapper(f2).Wrap([]byte("a key worth keeping"))
	if err == nil || !strings.Contains(err.Error(), "User interaction") {
		// Wrap stores first; the failure shows on the read back.
		t.Errorf("got %v", err)
	}
}

func TestToolErrorCleansItsText(t *testing.T) {
	err := toolError("w", "tool", "read", cmdResult{stderr: []byte("line one\nline\x1b[31m two " + strings.Repeat("x", 500)), exit: 3}, "")
	s := err.Error()
	if strings.ContainsAny(s, "\n\x1b") || len(s) > 400 {
		t.Errorf("unclean error: %q", s)
	}
}
