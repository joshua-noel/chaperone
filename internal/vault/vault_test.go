package vault

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"

	"github.com/joshua-noel/chaperone/internal/redact"
	"github.com/joshua-noel/chaperone/internal/store"
)

// aesWrapper is a test KeyWrapper: AES-GCM under a random in-memory key. It
// lets the whole suite run on Linux CI, where DPAPI does not exist. Two
// instances cannot unwrap each other's blobs, like two accounts.
type aesWrapper struct{ aead cipher.AEAD }

func newAESWrapper(t testing.TB) aesWrapper {
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
	return aesWrapper{g}
}

func (aesWrapper) Name() string { return "test-aesgcm" }

func (w aesWrapper) Wrap(p []byte) ([]byte, error) {
	n := make([]byte, w.aead.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return w.aead.Seal(n, n, p, nil), nil
}

func (w aesWrapper) Unwrap(b []byte) ([]byte, error) {
	if len(b) < w.aead.NonceSize() {
		return nil, errors.New("short blob")
	}
	return w.aead.Open(nil, b[:w.aead.NonceSize()], b[w.aead.NonceSize():], nil)
}

// wrappers lists what the suite runs against: the AES fake, the macOS and
// Linux wrappers over fake tools, the passphrase wrapper at a cheap scrypt cost
// (all always), and the real DPAPI wrapper on Windows.
func wrappers(t *testing.T) map[string]KeyWrapper {
	pass, _ := newTestPassphraseWrapper(testPassphrase)
	m := map[string]KeyWrapper{
		"aesgcm":              newAESWrapper(t),
		"keychain-fake":       newKeychainWrapper(newFakeSecurity()),
		"secret-service-fake": newSecretServiceWrapper(newFakeSecretTool()),
		"passphrase":          pass,
	}
	if runtime.GOOS == "windows" {
		m["dpapi"] = NewDPAPI()
	}
	return m
}

func eachWrapper(t *testing.T, fn func(t *testing.T, w KeyWrapper)) {
	for name, w := range wrappers(t) {
		t.Run(name, func(t *testing.T) { fn(t, w) })
	}
}

type env struct {
	cfg      Config
	root     string
	recovery string // the recovery identity, as revealed by Init
}

func newConfig(t *testing.T, w KeyWrapper) Config {
	t.Helper()
	root := t.TempDir()
	db, err := store.Open(context.Background(), filepath.Join(root, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() }) // runs before TempDir removal
	return Config{
		Dir:      filepath.Join(root, "vault"),
		KeyDir:   filepath.Join(root, "keys"),
		DB:       db,
		Wrapper:  w,
		Registry: redact.NewRegistry(),
	}
}

func newEnv(t *testing.T, w KeyWrapper) (env, *Vault) {
	t.Helper()
	cfg := newConfig(t, w)
	var rec string
	if err := Init(context.Background(), cfg, func(id string) error { rec = id; return nil }); err != nil {
		t.Fatal(err)
	}
	v, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	return env{cfg: cfg, root: filepath.Dir(cfg.Dir), recovery: rec}, v
}

// ghsToken returns a 520-character ghs_ installation token built at run time.
func ghsToken(t *testing.T) []byte {
	t.Helper()
	raw := make([]byte, 600)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	b := base64.RawURLEncoding.EncodeToString(raw)
	tok := "ghs_1234567_eyJ" + b[:30] + "." + b[30:330] + "." + b[330:]
	return []byte(tok[:520])
}

func pemKey(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

var bg = context.Background()

func meta(id string) Meta { return Meta{ID: id, Kind: "test", Project: "p", Owner: "o"} }

func use(t *testing.T, v *Vault, id string) []byte {
	t.Helper()
	var got []byte
	if err := v.Use(bg, id, func(s []byte) error { got = append([]byte(nil), s...); return nil }); err != nil {
		t.Fatalf("Use(%s): %v", id, err)
	}
	return got
}

func TestRoundTrip(t *testing.T) {
	eachWrapper(t, func(t *testing.T, w KeyWrapper) {
		_, v := newEnv(t, w)
		secrets := map[string][]byte{
			"plain":     []byte("correct-horse-battery-staple"),
			"ghs-token": ghsToken(t),
			"app-key":   pemKey(t),
			"binary":    {0, 1, 2, 3, 4, 5, 6, 7, 8, 255, 254},
		}
		for id, val := range secrets {
			if _, err := v.Import(bg, meta(id), val); err != nil {
				t.Fatalf("Import %s: %v", id, err)
			}
		}
		for id, want := range secrets {
			if got := use(t, v, id); !bytes.Equal(got, want) {
				t.Errorf("%s: round trip changed the value", id)
			}
		}
		infos, err := v.List(bg)
		if err != nil || len(infos) != len(secrets) {
			t.Fatalf("List: %d, %v", len(infos), err)
		}
		for i := 1; i < len(infos); i++ {
			if infos[i-1].ID >= infos[i].ID {
				t.Error("List is not ordered by id")
			}
		}
	})
}

func TestUseRecordsLastUsedAndZeroesBuffer(t *testing.T) {
	eachWrapper(t, func(t *testing.T, w KeyWrapper) {
		_, v := newEnv(t, w)
		if _, err := v.Import(bg, meta("k"), []byte("a-secret-value")); err != nil {
			t.Fatal(err)
		}
		i, _ := v.Info(bg, "k")
		if !i.LastUsed.IsZero() || !i.Rotated.IsZero() || i.Created.IsZero() {
			t.Errorf("fresh info: %+v", i)
		}
		var held []byte
		err := v.Use(bg, "k", func(s []byte) error {
			if string(s) != "a-secret-value" {
				t.Errorf("closure got %q", s)
			}
			held = s
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(held) == 0 || !allZero(held[:cap(held)]) {
			t.Error("buffer was not zeroed after Use")
		}
		i, _ = v.Info(bg, "k")
		if i.LastUsed.IsZero() {
			t.Error("last_used not recorded")
		}
	})
}

func TestUseZeroesOnPanicAndError(t *testing.T) {
	_, v := newEnv(t, newAESWrapper(t))
	if _, err := v.Import(bg, meta("k"), []byte("a-secret-value")); err != nil {
		t.Fatal(err)
	}
	var held []byte
	func() {
		defer func() {
			if recover() == nil {
				t.Error("panic was swallowed")
			}
		}()
		_ = v.Use(bg, "k", func(s []byte) error { held = s; panic("boom") })
	}()
	if !allZero(held[:cap(held)]) {
		t.Error("buffer not zeroed after a panic")
	}
	held = nil
	_ = v.Use(bg, "k", func(s []byte) error { held = s; return errors.New("failed") })
	if !allZero(held[:cap(held)]) {
		t.Error("buffer not zeroed after an error")
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func TestRecoveryIdentityDecrypts(t *testing.T) {
	eachWrapper(t, func(t *testing.T, w KeyWrapper) {
		e, v := newEnv(t, w)
		val := pemKey(t)
		if _, err := v.Import(bg, meta("app-key"), val); err != nil {
			t.Fatal(err)
		}
		id, err := age.ParseX25519Identity(e.recovery)
		if err != nil {
			t.Fatalf("revealed recovery identity is not an age identity: %v", err)
		}
		f, err := os.Open(filepath.Join(e.cfg.Dir, "app-key.age"))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		r, err := age.Decrypt(f, id)
		if err != nil {
			t.Fatalf("recovery identity cannot decrypt: %v", err)
		}
		var got bytes.Buffer
		if _, err := got.ReadFrom(r); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Bytes(), val) {
			t.Error("recovery decrypt returned a different value")
		}

		// An unrelated identity must not.
		other, _ := age.GenerateX25519Identity()
		f2, _ := os.Open(filepath.Join(e.cfg.Dir, "app-key.age"))
		defer f2.Close()
		if _, err := age.Decrypt(f2, other); err == nil {
			t.Error("an unrelated identity decrypted the file")
		}
	})
}

func TestOnlyPublicHalfIsStored(t *testing.T) {
	eachWrapper(t, func(t *testing.T, w KeyWrapper) {
		e, v := newEnv(t, w)
		if _, err := v.Import(bg, meta("k"), []byte("a-secret-value")); err != nil {
			t.Fatal(err)
		}
		recID, _ := age.ParseX25519Identity(e.recovery)
		var rec string
		if err := e.cfg.DB.SQL().QueryRow(`SELECT value FROM vault_meta WHERE key='recovery_recipient'`).Scan(&rec); err != nil {
			t.Fatal(err)
		}
		if rec != recID.Recipient().String() {
			t.Error("stored recovery recipient is not the public half of the revealed identity")
		}
		v.Close()
		e.cfg.DB.Close() // checkpoint the WAL
		err := filepath.WalkDir(e.root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, _ := os.ReadFile(p)
			if bytes.Contains(b, []byte(e.recovery)) {
				t.Errorf("recovery identity found in %s", p)
			}
			if bytes.Contains(b, []byte("AGE-SECRET-KEY-")) {
				t.Errorf("a plaintext age identity is in %s", p)
			}
			if bytes.Contains(b, []byte("a-secret-value")) {
				t.Errorf("plaintext secret found in %s", p)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestRunInitPrintsOnce(t *testing.T) {
	cfg := newConfig(t, newAESWrapper(t))
	var out bytes.Buffer
	if err := RunInit(bg, cfg, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "AGE-SECRET-KEY-1") != 1 || !strings.Contains(out.String(), "age1") {
		t.Errorf("output: %s", out.String())
	}
	// A second init prints nothing secret.
	var again bytes.Buffer
	if err := RunInit(bg, cfg, &again); !errors.Is(err, ErrAlreadyInitialized) || again.Len() != 0 {
		t.Errorf("second init: %v, printed %d bytes", err, again.Len())
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("pipe closed") }

func TestInitAbortsWhenIdentityNotShown(t *testing.T) {
	cfg := newConfig(t, newAESWrapper(t))
	if err := RunInit(bg, cfg, failWriter{}); err == nil {
		t.Fatal("init succeeded although nobody saw the recovery identity")
	}
	for _, p := range []string{identityFile, fpKeyFile} {
		if _, err := os.Stat(filepath.Join(cfg.KeyDir, p)); err == nil {
			t.Errorf("%s was left behind", p)
		}
	}
	if _, err := Open(bg, cfg); !errors.Is(err, ErrNotInitialized) {
		t.Errorf("Open after aborted init: %v", err)
	}
	// And a retry works.
	if err := RunInit(bg, cfg, &bytes.Buffer{}); err != nil {
		t.Fatalf("retry: %v", err)
	}
}

func TestInitRefusesExistingVault(t *testing.T) {
	e, _ := newEnv(t, newAESWrapper(t))
	if err := Init(bg, e.cfg, func(string) error { return nil }); !errors.Is(err, ErrAlreadyInitialized) {
		t.Errorf("got %v", err)
	}
	// Identity file present but index lost: refuse rather than overwrite.
	cfg := newConfig(t, newAESWrapper(t))
	if err := os.MkdirAll(cfg.KeyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.KeyDir, identityFile), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Init(bg, cfg, func(string) error { return nil }); !errors.Is(err, ErrAlreadyInitialized) {
		t.Errorf("existing identity file: %v", err)
	}
}

func TestOpenRefusals(t *testing.T) {
	cfg := newConfig(t, newAESWrapper(t))
	if _, err := Open(bg, cfg); !errors.Is(err, ErrNotInitialized) {
		t.Errorf("before init: %v", err)
	}
	e, _ := newEnv(t, newAESWrapper(t))

	// Another account cannot unwrap: a different wrapper instance with the
	// same name stands in for it.
	other := e.cfg
	other.Wrapper = newAESWrapper(t)
	if _, err := Open(bg, other); err == nil {
		t.Error("a wrapper with another key opened the vault")
	}
	// A different wrapper type is refused by name.
	other.Wrapper = namedWrapper{aesWrapper: other.Wrapper.(aesWrapper), name: "other"}
	if _, err := Open(bg, other); err == nil || !strings.Contains(err.Error(), "key wrapper") {
		t.Errorf("wrapper mismatch: %v", err)
	}
	// A service identity swapped for another valid one is caught.
	idPath := filepath.Join(e.cfg.KeyDir, identityFile)
	fresh, _ := age.GenerateX25519Identity()
	blob, _ := e.cfg.Wrapper.Wrap([]byte(fresh.String()))
	if err := os.WriteFile(idPath, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(bg, e.cfg); !errors.Is(err, ErrIntegrity) {
		t.Errorf("swapped identity: %v", err)
	}
}

type namedWrapper struct {
	aesWrapper
	name string
}

func (n namedWrapper) Name() string { return n.name }

func TestFingerprints(t *testing.T) {
	_, v1 := newEnv(t, newAESWrapper(t))
	_, v2 := newEnv(t, newAESWrapper(t))
	val := []byte("guessable-password-1")
	i1, err := v1.Import(bg, meta("a"), val)
	if err != nil {
		t.Fatal(err)
	}
	i2, _ := v2.Import(bg, meta("a"), val)
	b64 := base64.StdEncoding.EncodeToString(val)
	sum := sha256.Sum256(val)
	for _, bad := range []string{string(val), b64, hex.EncodeToString(val), hex.EncodeToString(sum[:]), hex.EncodeToString(sum[:16])} {
		if strings.Contains(i1.Fingerprint, bad) {
			t.Errorf("fingerprint contains %q", bad)
		}
	}
	if i1.Fingerprint == hex.EncodeToString(sum[:16]) {
		t.Error("fingerprint is an unkeyed hash: a guessed value could be confirmed offline")
	}
	if i1.Fingerprint == i2.Fingerprint {
		t.Error("two vaults with different keys gave the same fingerprint")
	}
	if len(i1.Fingerprint) != 2*fpBytes {
		t.Errorf("fingerprint length %d", len(i1.Fingerprint))
	}
	// Stable inside one vault, and different values differ.
	j, _ := v1.Import(bg, meta("b"), val)
	k, _ := v1.Import(bg, meta("c"), []byte("guessable-password-2"))
	if j.Fingerprint != i1.Fingerprint || k.Fingerprint == i1.Fingerprint {
		t.Error("fingerprint is not a stable function of the value")
	}
	// The index stores nothing but the fingerprint.
	var all string
	rows, err := v1.cfg.DB.SQL().Query(`SELECT id||kind||project||owner||fingerprint||created FROM vault_secrets`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		all += s
	}
	if strings.Contains(all, string(val)) || strings.Contains(all, b64) {
		t.Error("index holds a value")
	}
}

func TestErrorsNeverContainSecrets(t *testing.T) {
	eachWrapper(t, func(t *testing.T, w KeyWrapper) {
		_, v := newEnv(t, w)
		val := ghsToken(t)
		if _, err := v.Import(bg, meta("tok"), val); err != nil {
			t.Fatal(err)
		}
		sv := string(val)
		leaky := []error{
			fmt.Errorf("GET https://api.github.com/x?token=%s: 401", sv),
			fmt.Errorf("post failed: %w", errors.New("Authorization: token "+sv)),
			errors.New("b64 " + base64.StdEncoding.EncodeToString(val)),
			errors.New("hex " + hex.EncodeToString(val)),
		}
		for _, in := range leaky {
			err := v.Use(bg, "tok", func([]byte) error { return in })
			if err == nil {
				t.Fatal("closure error lost")
			}
			if !errors.Is(err, ErrSecretInError) {
				t.Errorf("error not marked: %v", err)
			}
			for _, bad := range []string{sv, sv[:40], sv[len(sv)-40:], base64.StdEncoding.EncodeToString(val), hex.EncodeToString(val)} {
				if strings.Contains(err.Error(), bad) || strings.Contains(fmt.Sprintf("%+v %#v", err, err), bad) {
					t.Errorf("returned error holds the secret: %.80s", err)
				}
			}
			if errors.Unwrap(err) != nil {
				t.Error("masked error still wraps the original")
			}
		}
		// A clean error keeps its identity.
		sentinel := errors.New("upstream said no")
		if err := v.Use(bg, "tok", func([]byte) error { return sentinel }); !errors.Is(err, sentinel) || errors.Is(err, ErrSecretInError) {
			t.Errorf("clean error: %v", err)
		}
		// Other failures name the id, never a value.
		for _, err := range []error{
			func() error { _, e := v.Import(bg, meta("short"), []byte("abc")); return e }(),
			func() error { _, e := v.Import(bg, meta("tok"), val); return e }(),
			func() error { _, e := v.Rotate(bg, "missing", val); return e }(),
			v.Use(bg, "missing", func([]byte) error { return nil }),
			func() error { _, e := v.Import(bg, meta("../x"), val); return e }(),
		} {
			if err == nil {
				t.Fatal("expected an error")
			}
			if strings.Contains(err.Error(), sv[:30]) || strings.Contains(err.Error(), "abc") {
				t.Errorf("error holds a value: %v", err)
			}
		}
	})
}

func TestImportRotate(t *testing.T) {
	eachWrapper(t, func(t *testing.T, w KeyWrapper) {
		_, v := newEnv(t, w)
		old, nu := []byte("old-value-12345"), []byte("new-value-67890")
		first, err := v.Import(bg, meta("k"), old)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.Import(bg, meta("k"), nu); !errors.Is(err, ErrExists) {
			t.Errorf("duplicate import: %v", err)
		}
		if got := use(t, v, "k"); !bytes.Equal(got, old) {
			t.Error("a refused import changed the secret")
		}
		after, err := v.Rotate(bg, "k", nu)
		if err != nil {
			t.Fatal(err)
		}
		if after.Fingerprint == first.Fingerprint || after.Rotated.IsZero() || !after.Created.Equal(first.Created) {
			t.Errorf("rotate info: %+v vs %+v", after, first)
		}
		if got := use(t, v, "k"); !bytes.Equal(got, nu) {
			t.Error("rotation did not take effect")
		}
		if _, err := v.Rotate(bg, "ghost", nu); !errors.Is(err, ErrNotFound) {
			t.Errorf("rotate missing: %v", err)
		}
		// No temp files are left behind.
		ents, _ := os.ReadDir(v.cfg.Dir)
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), ".tmp-") {
				t.Errorf("leftover %s", e.Name())
			}
		}
	})
}

func TestInputValidation(t *testing.T) {
	_, v := newEnv(t, newAESWrapper(t))
	val := []byte("a-secret-value")
	for _, id := range []string{"", "A", "a.b", "a/b", `a\b`, "..", "-x", "con", "nul", "com1", "lpt9", "aux", strings.Repeat("a", 64), "a b", "é"} {
		if _, err := v.Import(bg, meta(id), val); !errors.Is(err, ErrInvalid) {
			t.Errorf("id %q: %v", id, err)
		}
	}
	for _, id := range []string{"a", "github-app-key", "google_refresh_mail", "0abc", strings.Repeat("a", 63)} {
		if err := ValidID(id); err != nil {
			t.Errorf("id %q: %v", id, err)
		}
	}
	if _, err := v.Import(bg, Meta{ID: "x", Kind: "Bad Kind"}, val); !errors.Is(err, ErrInvalid) {
		t.Errorf("kind: %v", err)
	}
	if _, err := v.Import(bg, Meta{ID: "x", Kind: "k", Owner: "a\nb"}, val); !errors.Is(err, ErrInvalid) {
		t.Errorf("owner: %v", err)
	}
	if _, err := v.Import(bg, meta("big"), make([]byte, MaxSecretSize+1)); !errors.Is(err, ErrInvalid) {
		t.Errorf("oversize: %v", err)
	}
	if err := v.Use(bg, "x", nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("nil fn: %v", err)
	}
	if _, err := v.Info(bg, "../etc"); !errors.Is(err, ErrInvalid) {
		t.Errorf("info traversal: %v", err)
	}
	cctx, cancel := context.WithCancel(bg)
	cancel()
	if err := v.Use(cctx, "x", func([]byte) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled bg: %v", err)
	}
}

func TestTamperedFilesAreNotUsed(t *testing.T) {
	eachWrapper(t, func(t *testing.T, w KeyWrapper) {
		e, v := newEnv(t, w)
		if _, err := v.Import(bg, meta("a"), []byte("real-value-aaaa")); err != nil {
			t.Fatal(err)
		}
		if _, err := v.Import(bg, meta("b"), []byte("real-value-bbbb")); err != nil {
			t.Fatal(err)
		}
		called := false
		fn := func([]byte) error { called = true; return nil }

		// 1. Swap b's file into a's slot: valid age file, wrong value.
		b, _ := os.ReadFile(filepath.Join(e.cfg.Dir, "b.age"))
		if err := os.WriteFile(filepath.Join(e.cfg.Dir, "a.age"), b, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := v.Use(bg, "a", fn); !errors.Is(err, ErrIntegrity) {
			t.Errorf("swapped file: %v", err)
		}
		// 2. Anyone can encrypt to the public recipient; the HMAC still stops it.
		var buf bytes.Buffer
		wr, _ := age.Encrypt(&buf, v.identity.Recipient())
		wr.Write([]byte("attacker-chosen-value"))
		wr.Close()
		if err := os.WriteFile(filepath.Join(e.cfg.Dir, "a.age"), buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := v.Use(bg, "a", fn); !errors.Is(err, ErrIntegrity) {
			t.Errorf("forged file: %v", err)
		}
		// 3. Truncated, 4. missing.
		if err := os.WriteFile(filepath.Join(e.cfg.Dir, "a.age"), b[:len(b)/2], 0o600); err != nil {
			t.Fatal(err)
		}
		if err := v.Use(bg, "a", fn); err == nil {
			t.Error("truncated file was used")
		}
		os.Remove(filepath.Join(e.cfg.Dir, "a.age"))
		if err := v.Use(bg, "a", fn); !errors.Is(err, ErrIntegrity) {
			t.Errorf("missing file: %v", err)
		}
		if called {
			t.Error("closure ran on a file that failed its checks")
		}
		// Rotation repairs.
		if _, err := v.Rotate(bg, "a", []byte("repaired-value-1")); err != nil {
			t.Fatal(err)
		}
		if got := use(t, v, "a"); string(got) != "repaired-value-1" {
			t.Error("rotation did not repair")
		}
	})
}

func TestRegistryIsFed(t *testing.T) {
	e, v := newEnv(t, newAESWrapper(t))
	tok, key := ghsToken(t), pemKey(t)
	if _, err := v.Import(bg, meta("tok"), tok); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Import(bg, meta("app-key"), key); err != nil {
		t.Fatal(err)
	}
	reg := v.Registry()
	if reg != e.cfg.Registry {
		t.Error("Registry() is not the configured registry")
	}
	out, res := reg.Redact("token=" + string(tok) + "\n" + string(key))
	if !res.Blocked() || strings.Contains(out, string(tok[:30])) || strings.Contains(out, "PRIVATE KEY") {
		t.Errorf("not masked: %.120q", out)
	}
	for _, h := range res.Hits {
		if h.Rule == "exact" && (h.SecretID != "tok" && h.SecretID != "app-key") {
			t.Errorf("unexpected hit %+v", h)
		}
	}

	// After a restart the registry starts empty: LoadRegistry refills it.
	e.cfg.Registry = redact.NewRegistry()
	v2, err := Open(bg, e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	if e.cfg.Registry.Len() != 0 {
		t.Fatal("Open must not decrypt anything")
	}
	if err := v2.LoadRegistry(bg); err != nil {
		t.Fatal(err)
	}
	if e.cfg.Registry.Len() != 2 {
		t.Errorf("registry has %d secrets, want 2", e.cfg.Registry.Len())
	}
	out, _ = e.cfg.Registry.Redact("x " + string(tok) + " y")
	if out != "x [REDACTED:tok] y" {
		t.Errorf("after reload: %q", out)
	}
	i, _ := v2.Info(bg, "tok")
	if !i.LastUsed.IsZero() {
		t.Error("LoadRegistry counted as a use")
	}

	// A private registry is made when none is configured.
	e.cfg.Registry = nil
	v3, err := Open(bg, e.cfg)
	if err != nil || v3.Registry() == nil {
		t.Fatalf("nil registry: %v", err)
	}
	v3.Close()
}

func TestRotateReplacesRegistryValue(t *testing.T) {
	_, v := newEnv(t, newAESWrapper(t))
	if _, err := v.Import(bg, meta("k"), []byte("old-value-12345")); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Rotate(bg, "k", []byte("new-value-67890")); err != nil {
		t.Fatal(err)
	}
	if out, _ := v.Registry().Redact("new-value-67890"); out != "[REDACTED:k]" {
		t.Errorf("new value not masked: %q", out)
	}
}

func TestConcurrentUseAndRotate(t *testing.T) {
	_, v := newEnv(t, newAESWrapper(t))
	if _, err := v.Import(bg, meta("k"), []byte("value-0000000000")); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 200)
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 15 {
				err := v.Use(bg, "k", func(s []byte) error {
					if !bytes.HasPrefix(s, []byte("value-")) {
						return errors.New("torn read")
					}
					return nil
				})
				if err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 15 {
			if _, err := v.Rotate(bg, "k", fmt.Appendf(nil, "value-%010d", i+1)); err != nil {
				errs <- err
			}
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestNoFunctionReturnsASecret is the "Use, never read" rule as a test: no
// exported function or method of this package returns []byte, string or a
// reader, except the KeyWrapper interface (internal, below the vault API).
func TestNoFunctionReturnsASecret(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	bad := func(e ast.Expr) bool {
		switch x := e.(type) {
		case *ast.Ident:
			return x.Name == "string"
		case *ast.ArrayType:
			id, ok := x.Elt.(*ast.Ident)
			return ok && (id.Name == "byte" || id.Name == "rune")
		case *ast.SelectorExpr:
			p, _ := x.X.(*ast.Ident)
			return p != nil && p.Name == "io" && strings.HasSuffix(x.Sel.Name, "Reader")
		}
		return false
	}
	n := 0
	for _, p := range pkgs {
		for name, f := range p.Files {
			ast.Inspect(f, func(node ast.Node) bool {
				fd, ok := node.(*ast.FuncDecl)
				if !ok || !fd.Name.IsExported() || fd.Type.Results == nil {
					return true
				}
				if fd.Recv != nil { // methods on unexported types are unreachable
					rt := fd.Recv.List[0].Type
					if s, ok := rt.(*ast.StarExpr); ok {
						rt = s.X
					}
					if id, ok := rt.(*ast.Ident); !ok || !id.IsExported() {
						return true
					}
				}
				n++
				for _, r := range fd.Type.Results.List {
					if bad(r.Type) {
						t.Errorf("%s: exported %s returns a string, []byte or reader", filepath.Base(name), fd.Name.Name)
					}
				}
				return true
			})
		}
	}
	if n < 10 {
		t.Fatalf("scanned only %d exported functions; the scan is broken", n)
	}
	// Methods on *Vault, by reflection, including the fields of Info.
	vt := reflect.TypeOf(&Vault{})
	for i := range vt.NumMethod() {
		m := vt.Method(i)
		for j := range m.Type.NumOut() {
			if k := m.Type.Out(j).Kind(); k == reflect.String || k == reflect.Slice {
				if m.Type.Out(j) != reflect.TypeOf([]Info(nil)) {
					t.Errorf("(*Vault).%s returns %s", m.Name, m.Type.Out(j))
				}
			}
		}
	}
	it := reflect.TypeOf(Info{})
	for i := range it.NumField() {
		if f := it.Field(i); f.Type.Kind() == reflect.Slice {
			t.Errorf("Info.%s is a slice", f.Name)
		}
	}
}
