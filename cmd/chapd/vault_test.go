package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/store"
	"github.com/joshua-noel/chaperone/internal/vault"
)

// aesWrap is a test key wrapper (DPAPI does not exist on Linux CI).
type aesWrap struct{ aead cipher.AEAD }

func (aesWrap) Name() string { return "test-aesgcm" }
func (w aesWrap) Wrap(p []byte) ([]byte, error) {
	n := make([]byte, w.aead.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return w.aead.Seal(n, n, p, nil), nil
}
func (w aesWrap) Unwrap(b []byte) ([]byte, error) {
	ns := w.aead.NonceSize()
	return w.aead.Open(nil, b[:ns], b[ns:], nil)
}

// useTestWrapper makes `chapd vault` use one AES wrapper for the whole test.
func useTestWrapper(t *testing.T) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		t.Fatal(err)
	}
	old := newWrapper
	newWrapper = func() vault.KeyWrapper { return aesWrap{g} }
	t.Cleanup(func() { newWrapper = old })
}

func writePEM(t *testing.T, dir string) (path string, pemBytes []byte, key *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	path = filepath.Join(dir, "app.private-key.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, pemBytes, key
}

func runVault(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(append([]string{"vault"}, args...), &out, &errb)
	return code, out.String(), errb.String()
}

func TestVaultImportAppKey(t *testing.T) {
	useTestWrapper(t)
	dir := t.TempDir()
	db := filepath.Join(dir, "state.db")
	if code, _, e := runVault(t, "init", "-db", db); code != 0 {
		t.Fatalf("init: exit %d: %s", code, e)
	}
	pemPath, pemBytes, key := writePEM(t, dir)

	code, out, errs := runVault(t, "import", "--name", "github-app-key", "--file", pemPath, "--delete", "-db", db)
	if code != 0 {
		t.Fatalf("import: exit %d: %s", code, errs)
	}
	if !strings.Contains(out, "imported github-app-key (github-app-key), fingerprint ") {
		t.Fatalf("stdout %q", out)
	}
	for _, s := range []string{out, errs} {
		if strings.Contains(s, "PRIVATE KEY") || strings.Contains(s, string(pemBytes[40:80])) {
			t.Fatalf("output leaks key material: %q", s)
		}
	}
	if _, err := os.Stat(pemPath); !os.IsNotExist(err) {
		t.Fatalf("--delete left the file behind: %v", err)
	}

	// The daemon's side: open the vault the way chapd run does, and sign through VaultKey.
	ctx := context.Background()
	d, err := store.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	v, err := vault.Open(ctx, vault.Config{
		Dir: filepath.Join(dir, "vault"), KeyDir: filepath.Join(dir, "vault-keys"), DB: d, Wrapper: newWrapper(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	ks, err := gh.NewVaultKey(v, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ks.AppKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(key) {
		t.Fatal("the vault returned a different key")
	}
	info, err := v.Info(ctx, "github-app-key")
	if err != nil || info.LastUsed.IsZero() {
		t.Fatalf("use not recorded: %+v, %v", info, err)
	}

	code, out, _ = runVault(t, "list", "-db", db)
	if code != 0 || !strings.Contains(out, "github-app-key") || strings.Contains(out, "PRIVATE KEY") {
		t.Fatalf("list: exit %d, %q", code, out)
	}
}

func TestVaultImportKeepsFileOnFailure(t *testing.T) {
	useTestWrapper(t)
	dir := t.TempDir()
	db := filepath.Join(dir, "state.db")
	if code, _, e := runVault(t, "init", "-db", db); code != 0 {
		t.Fatalf("init: exit %d: %s", code, e)
	}

	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("-----BEGIN RSA PRIVATE KEY-----\nnot a key at all, but long enough\n-----END RSA PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, e := runVault(t, "import", "--name", "github-app-key", "--file", bad, "--delete", "-db", db); code != 1 || !strings.Contains(e, "not a usable GitHub App key") {
		t.Fatalf("bad key: exit %d, %q", code, e)
	}
	if _, err := os.Stat(bad); err != nil {
		t.Fatal("a rejected key file was deleted")
	}

	good, _, _ := writePEM(t, dir)
	if code, _, e := runVault(t, "import", "--name", "github-app-key", "--file", good, "-db", db); code != 0 {
		t.Fatalf("first import: exit %d: %s", code, e)
	}
	if _, err := os.Stat(good); err != nil {
		t.Fatal("the file was deleted without --delete")
	}
	code, _, e := runVault(t, "import", "--name", "github-app-key", "--file", good, "--delete", "-db", db)
	if code != 1 || !strings.Contains(e, "already exists") {
		t.Fatalf("duplicate: exit %d, %q", code, e)
	}
	if _, err := os.Stat(good); err != nil {
		t.Fatal("a file whose import was refused was deleted")
	}
}

func TestVaultUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"bogus"},
		{"import", "--file", "x"},
		{"import", "--name", "x", "--file", "x"}, // no kind, not the app key
		{"list", "extra"},
	} {
		code, out, errs := runVault(t, args...)
		if code != 2 || out != "" || errs == "" {
			t.Errorf("args %q: exit %d, stdout %q, stderr %q", args, code, out, errs)
		}
	}
}

func TestShredFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s")
	if err := os.WriteFile(p, []byte("secret value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := shredFile(p, 12); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("file remains: %v", err)
	}
}
