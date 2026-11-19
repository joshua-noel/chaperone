package vault

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

// afterReset returns env's config as the rebuilt service account sees it: the
// same files and database, a wrapper that cannot unwrap the old key files.
func afterReset(t *testing.T, e env) Config {
	t.Helper()
	cfg := e.cfg
	cfg.Wrapper = newAESWrapper(t)
	return cfg
}

func TestRecoverRekeysEverySecret(t *testing.T) {
	ctx := context.Background()
	e, v := newEnv(t, newAESWrapper(t))
	values := map[string][]byte{
		"app-key":    []byte("-----BEGIN RSA PRIVATE KEY-----\nabcdefghijklmnop\n-----END RSA PRIVATE KEY-----\n"),
		"ntfy-topic": []byte("0123456789abcdef0123456789abcdef"),
	}
	oldFP := map[string]string{}
	for id, val := range values {
		info, err := v.Import(ctx, Meta{ID: id, Kind: "test", Owner: "recover_test"}, val)
		if err != nil {
			t.Fatal(err)
		}
		oldFP[id] = info.Fingerprint
	}
	v.Close()

	cfg := afterReset(t, e)
	if _, err := Open(ctx, cfg); err == nil {
		t.Fatal("the reset account opened the old vault")
	}
	n, err := Recover(ctx, cfg, e.recovery)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if n != len(values) {
		t.Fatalf("re-keyed %d secrets, want %d", n, len(values))
	}

	v2, err := Open(ctx, cfg)
	if err != nil {
		t.Fatalf("the new account cannot open the recovered vault: %v", err)
	}
	defer v2.Close()
	for id, want := range values {
		var got []byte
		if err := v2.Use(ctx, id, func(s []byte) error { got = append([]byte(nil), s...); return nil }); err != nil {
			t.Fatalf("Use %s: %v", id, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s changed value", id)
		}
		info, err := v2.Info(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if info.Fingerprint == oldFP[id] {
			t.Errorf("%s kept its old fingerprint, which was made with the lost key", id)
		}
		if info.Kind != "test" || info.Owner != "recover_test" || info.Created.IsZero() {
			t.Errorf("%s lost its metadata: %+v", id, info)
		}
	}

	// The offline identity is the same one and still opens the new files.
	recID, _ := age.ParseX25519Identity(e.recovery)
	for id, want := range values {
		b, err := os.ReadFile(filepath.Join(cfg.Dir, id+".age"))
		if err != nil {
			t.Fatal(err)
		}
		got, err := decryptWith(filepath.Join(cfg.Dir, id+".age"), recID)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("recovery identity cannot read the new %s file: %v", id, err)
		}
		if bytes.Contains(b, want) {
			t.Errorf("%s ciphertext holds the plaintext", id)
		}
	}
	var rec string
	if err := cfg.DB.SQL().QueryRow(`SELECT value FROM vault_meta WHERE key='recovery_recipient'`).Scan(&rec); err != nil || rec != recID.Recipient().String() {
		t.Errorf("recovery recipient changed: %q, %v", rec, err)
	}
	var stamp string
	if err := cfg.DB.SQL().QueryRow(`SELECT value FROM vault_meta WHERE key='recovered'`).Scan(&stamp); err != nil || stamp == "" {
		t.Errorf("no recovered stamp: %v", err)
	}

	// The dead key files were moved, not deleted.
	matches, _ := filepath.Glob(filepath.Join(cfg.KeyDir, "retired-*", "*.dpapi"))
	if len(matches) != 2 {
		t.Errorf("retired key files: %v", matches)
	}

	// Nothing is left to recover.
	if _, err := Recover(ctx, cfg, e.recovery); !errors.Is(err, ErrRecoveryNotNeeded) {
		t.Errorf("second Recover: %v, want ErrRecoveryNotNeeded", err)
	}
}

func TestRecoverRefusals(t *testing.T) {
	ctx := context.Background()
	e, v := newEnv(t, newAESWrapper(t))
	if _, err := v.Import(ctx, Meta{ID: "app-key", Kind: "test"}, []byte("a secret that is long enough")); err != nil {
		t.Fatal(err)
	}
	v.Close()
	cfg := afterReset(t, e)

	other, _ := age.GenerateX25519Identity()
	for name, ident := range map[string]string{
		"another identity": other.String(),
		"garbage":          "not an identity",
		"empty":            "",
	} {
		if _, err := Recover(ctx, cfg, ident); !errors.Is(err, ErrWrongRecoveryIdentity) {
			t.Errorf("%s: %v, want ErrWrongRecoveryIdentity", name, err)
		}
	}
	// Refused means unchanged: the old account still opens it.
	v, err := Open(ctx, e.cfg)
	if err != nil {
		t.Fatalf("a refused recovery changed the vault: %v", err)
	}
	v.Close()

	// A vault that opens is not re-keyed.
	if _, err := Recover(ctx, e.cfg, e.recovery); !errors.Is(err, ErrRecoveryNotNeeded) {
		t.Errorf("healthy vault: %v, want ErrRecoveryNotNeeded", err)
	}

	// No vault at all.
	if _, err := Recover(ctx, newConfig(t, newAESWrapper(t)), e.recovery); !errors.Is(err, ErrNotInitialized) {
		t.Errorf("no vault: %v, want ErrNotInitialized", err)
	}
}

func TestRecoverChangesNothingWhenAFileFails(t *testing.T) {
	ctx := context.Background()
	e, v := newEnv(t, newAESWrapper(t))
	for _, id := range []string{"aaa-one", "bbb-two"} {
		if _, err := v.Import(ctx, Meta{ID: id, Kind: "test"}, []byte("value of "+id+" long enough")); err != nil {
			t.Fatal(err)
		}
	}
	v.Close()
	cfg := afterReset(t, e)

	// The second secret's file is damaged; the first would re-key fine.
	bad := filepath.Join(cfg.Dir, "bbb-two.age")
	if err := os.WriteFile(bad, []byte("not an age file"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(cfg.Dir, "aaa-one.age"))
	idBefore, _ := os.ReadFile(filepath.Join(cfg.KeyDir, identityFile))

	_, err := Recover(ctx, cfg, e.recovery)
	if err == nil || !strings.Contains(err.Error(), "bbb-two") {
		t.Fatalf("Recover = %v, want an error naming bbb-two", err)
	}
	after, _ := os.ReadFile(filepath.Join(cfg.Dir, "aaa-one.age"))
	idAfter, _ := os.ReadFile(filepath.Join(cfg.KeyDir, identityFile))
	if !bytes.Equal(before, after) || !bytes.Equal(idBefore, idAfter) {
		t.Error("a failed recovery changed files")
	}
	if m, _ := filepath.Glob(filepath.Join(cfg.KeyDir, "retired-*")); len(m) != 0 {
		t.Errorf("a failed recovery retired keys: %v", m)
	}
	if m, _ := filepath.Glob(filepath.Join(cfg.Dir, ".tmp-*")); len(m) != 0 {
		t.Errorf("staged files left behind: %v", m)
	}
}

// A run that stopped after the key files were replaced but before the index
// was updated (the vault does not open) is repeated to completion.
func TestRecoverRepeatsAfterAnInterruptedRun(t *testing.T) {
	ctx := context.Background()
	e, v := newEnv(t, newAESWrapper(t))
	val := []byte("a secret that is long enough")
	if _, err := v.Import(ctx, Meta{ID: "app-key", Kind: "test"}, val); err != nil {
		t.Fatal(err)
	}
	v.Close()
	cfg := afterReset(t, e)

	// Simulate the interruption: new key files in place, index still old.
	w := cfg.Wrapper
	for _, name := range []string{identityFile, fpKeyFile} {
		blob, err := w.Wrap([]byte("0123456789abcdef0123456789abcdef"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cfg.KeyDir, name), blob, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Open(ctx, cfg); err == nil {
		t.Fatal("the half-recovered vault opens")
	}
	if _, err := Recover(ctx, cfg, e.recovery); err != nil {
		t.Fatalf("repeat: %v", err)
	}
	v2, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	if err := v2.Use(ctx, "app-key", func(s []byte) error {
		if !bytes.Equal(s, val) {
			t.Error("value changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// The wrapped-key folder may be missing altogether (moved aside while an
// installer rebuilt the account): Recover makes it again.
func TestRecoverWithTheKeyFolderGone(t *testing.T) {
	ctx := context.Background()
	e, v := newEnv(t, newAESWrapper(t))
	val := []byte("a secret that is long enough")
	if _, err := v.Import(ctx, Meta{ID: "app-key", Kind: "test"}, val); err != nil {
		t.Fatal(err)
	}
	v.Close()
	cfg := afterReset(t, e)
	if err := os.Rename(cfg.KeyDir, cfg.KeyDir+".lost"); err != nil {
		t.Fatal(err)
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

// A signal at the first (old-passphrase) prompt of `vault recover` stops
// recovery; it is not read as "the vault does not open, carry on".
func TestRecoverStopsWhenThePromptIsInterrupted(t *testing.T) {
	ctx := context.Background()
	w, _ := newTestPassphraseWrapper(testPassphrase)
	e, v := newEnv(t, w)
	if _, err := v.Import(ctx, Meta{ID: "k", Kind: "test", Owner: "t"}, []byte("a secret value of some length")); err != nil {
		t.Fatal(err)
	}
	v.Close()

	src := &staticPassphrase{err: errInterrupted}
	cfg := e.cfg
	cfg.Wrapper = newPassphraseWrapper(src, testWorkFactor)
	if _, err := Recover(ctx, cfg, e.recovery); !errors.Is(err, errInterrupted) {
		t.Fatalf("got %v", err)
	}
	if src.asked != 1 {
		t.Errorf("asked %d times; an interrupt must not lead to a second prompt", src.asked)
	}
	if m, _ := filepath.Glob(filepath.Join(cfg.KeyDir, "retired-*")); len(m) != 0 {
		t.Errorf("key files were retired: %v", m)
	}
	// Nothing changed: the old passphrase still opens the vault.
	cfg.Wrapper, _ = newTestPassphraseWrapper(testPassphrase)
	v2, err := Open(ctx, cfg)
	if err != nil {
		t.Fatalf("the vault no longer opens: %v", err)
	}
	v2.Close()
}
