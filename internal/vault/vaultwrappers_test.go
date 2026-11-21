package vault

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests run the whole vault, not just a wrapper, on the macOS, Linux and
// passphrase wrappers. The wrapper-agnostic suite (eachWrapper) covers the
// rest.

func TestVaultOnTheKeychainKeepsKeysOutOfTheKeyFolderAndTheCommandLine(t *testing.T) {
	ctx := context.Background()
	for name, f := range map[string]*fakeTool{"security": newFakeSecurity(), "secret-tool": newFakeSecretTool()} {
		t.Run(name, func(t *testing.T) {
			w := newKeychainWrapper(f)
			if name == "secret-tool" {
				w = newSecretServiceWrapper(f)
			}
			e, v := newEnv(t, w)
			if _, err := v.Import(ctx, Meta{ID: "k", Kind: "test", Owner: "t"}, []byte("a secret value of some length")); err != nil {
				t.Fatal(err)
			}
			if len(f.items) != 2 {
				t.Fatalf("%d items in the keychain, want 2 (identity, fingerprint key)", len(f.items))
			}
			for _, stored := range f.items {
				key, err := hex.DecodeString(stored)
				if err != nil {
					t.Fatal(err)
				}
				f.noSecretOnCommandLine(t, key)
				// Neither key file on disk holds the key.
				for _, file := range []string{identityFile, fpKeyFile} {
					b, err := os.ReadFile(filepath.Join(e.cfg.KeyDir, file))
					if err != nil {
						t.Fatal(err)
					}
					if bytes.Contains(b, key) || bytes.Contains(b, []byte(stored)) {
						t.Errorf("%s holds key material", file)
					}
					if len(b) > 200 {
						t.Errorf("%s is %d bytes: a reference, not a key", file, len(b))
					}
				}
			}
		})
	}
}

func TestVaultOpenedWithAnotherWrapperFailsClearly(t *testing.T) {
	ctx := context.Background()
	pass, _ := newTestPassphraseWrapper(testPassphrase)
	made := map[string]KeyWrapper{
		KeychainName:      newKeychainWrapper(newFakeSecurity()),
		SecretServiceName: newSecretServiceWrapper(newFakeSecretTool()),
		PassphraseName:    pass,
	}
	for from, wFrom := range made {
		e, v := newEnv(t, wFrom)
		v.Close()
		for to, wTo := range made {
			if from == to {
				continue
			}
			cfg := e.cfg
			cfg.Wrapper = wTo
			_, err := Open(ctx, cfg)
			if err == nil || !strings.Contains(err.Error(), from) || !strings.Contains(err.Error(), to) {
				t.Errorf("made with %s, opened with %s: %v", from, to, err)
			}
		}
	}
}

func TestVaultOnAPassphrase(t *testing.T) {
	ctx := context.Background()
	w, src := newTestPassphraseWrapper(testPassphrase)
	e, v := newEnv(t, w)
	if _, err := v.Import(ctx, Meta{ID: "k", Kind: "test", Owner: "t"}, []byte("a secret value of some length")); err != nil {
		t.Fatal(err)
	}
	v.Close()
	if w.pass != nil {
		t.Error("Init or Open left the passphrase in memory")
	}
	// Init asked once (twice at a terminal), and each Open asks once, however many keys it unwraps.
	if src.asked != 2 {
		t.Errorf("asked %d times for Init and one Open, want 2", src.asked)
	}

	wrong, _ := newTestPassphraseWrapper("not the passphrase at all")
	cfg := e.cfg
	cfg.Wrapper = wrong
	if _, err := Open(ctx, cfg); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("a wrong passphrase: %v", err)
	}

	right, _ := newTestPassphraseWrapper(testPassphrase)
	cfg.Wrapper = right
	v2, err := Open(ctx, cfg)
	if err != nil {
		t.Fatalf("the right passphrase: %v", err)
	}
	defer v2.Close()
	if err := v2.Use(ctx, "k", func(s []byte) error {
		if string(s) != "a secret value of some length" {
			t.Error("wrong value")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverAfterAForgottenPassphrase(t *testing.T) {
	ctx := context.Background()
	w, _ := newTestPassphraseWrapper(testPassphrase)
	e, v := newEnv(t, w)
	if _, err := v.Import(ctx, Meta{ID: "k", Kind: "test", Owner: "t"}, []byte("a secret value of some length")); err != nil {
		t.Fatal(err)
	}
	v.Close()

	// The operator no longer knows the passphrase: they type something else
	// when asked to open, then choose a new one.
	forgot, src := newTestPassphraseWrapper("a brand new passphrase")
	cfg := e.cfg
	cfg.Wrapper = forgot
	if _, err := Open(ctx, cfg); err == nil {
		t.Fatal("opened without the passphrase")
	}
	if _, err := Recover(ctx, cfg, e.recovery); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if forgot.pass != nil {
		t.Error("Recover left the passphrase in memory")
	}
	if src.forgot == 0 {
		t.Error("the source was not told to forget")
	}
	again, _ := newTestPassphraseWrapper("a brand new passphrase")
	cfg.Wrapper = again
	v2, err := Open(ctx, cfg)
	if err != nil {
		t.Fatalf("the new passphrase does not open the recovered vault: %v", err)
	}
	v2.Close()
	// The old passphrase no longer opens it.
	old, _ := newTestPassphraseWrapper(testPassphrase)
	cfg.Wrapper = old
	if _, err := Open(ctx, cfg); err == nil {
		t.Error("the old passphrase still opens the vault")
	}
}

func TestRecoverWhenTheKeychainItemsAreGone(t *testing.T) {
	ctx := context.Background()
	f := newFakeSecurity()
	e, v := newEnv(t, newKeychainWrapper(f))
	if _, err := v.Import(ctx, Meta{ID: "k", Kind: "test", Owner: "t"}, []byte("a secret value of some length")); err != nil {
		t.Fatal(err)
	}
	v.Close()

	// Another user on the same Mac, or a restored backup: the key folder is
	// there, the keychain items are not.
	other := newFakeSecurity()
	cfg := e.cfg
	cfg.Wrapper = newKeychainWrapper(other)
	if _, err := Open(ctx, cfg); err == nil || !strings.Contains(err.Error(), "keychain") {
		t.Fatalf("Open: %v", err)
	}
	if _, err := Recover(ctx, cfg, e.recovery); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	v2, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	v2.Close()
}

// Recover is the way to move a vault to another wrapper: it needs the offline
// recovery identity, and it records the new wrapper's name.
func TestRecoverMovesAVaultToAnotherWrapper(t *testing.T) {
	ctx := context.Background()
	e, v := newEnv(t, newKeychainWrapper(newFakeSecurity()))
	if _, err := v.Import(ctx, Meta{ID: "k", Kind: "test", Owner: "t"}, []byte("a secret value of some length")); err != nil {
		t.Fatal(err)
	}
	v.Close()

	pass, _ := newTestPassphraseWrapper(testPassphrase)
	cfg := e.cfg
	cfg.Wrapper = pass
	if _, err := Open(ctx, cfg); err == nil {
		t.Fatal("opened a keychain vault with the passphrase wrapper")
	}
	if _, err := Recover(ctx, cfg, e.recovery); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	pass2, _ := newTestPassphraseWrapper(testPassphrase)
	cfg.Wrapper = pass2
	v2, err := Open(ctx, cfg)
	if err != nil {
		t.Fatalf("the moved vault does not open with the new wrapper: %v", err)
	}
	defer v2.Close()
	cfg.Wrapper = newKeychainWrapper(newFakeSecurity())
	if _, err := Open(ctx, cfg); err == nil || !strings.Contains(err.Error(), PassphraseName) {
		t.Errorf("the old wrapper still opens it, or the error does not name the recorded one: %v", err)
	}
}
