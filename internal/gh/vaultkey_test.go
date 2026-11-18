package gh

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeSecrets struct {
	id    string
	value []byte
	err   error
	uses  int
	seen  []byte // the buffer handed to fn, to prove it is not retained by VaultKey
}

func (f *fakeSecrets) Use(_ context.Context, id string, fn func([]byte) error) error {
	f.uses++
	if f.err != nil {
		return f.err
	}
	if id != f.id {
		return errors.New("no such secret")
	}
	buf := append([]byte(nil), f.value...)
	f.seen = buf
	defer clear(buf)
	return fn(buf)
}

func TestVaultKey(t *testing.T) {
	key := testKey(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	f := &fakeSecrets{id: AppKeySecretID, value: pemBytes}
	vk, err := NewVaultKey(f, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := vk.AppKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(key) {
		t.Fatal("parsed key differs from the stored key")
	}
	// The vault zeroes its buffer after fn; the parsed key must not alias it.
	if got2, err := vk.AppKey(context.Background()); err != nil || !got2.Equal(key) {
		t.Fatalf("second call: %v", err)
	}
	if f.uses != 2 {
		t.Fatalf("Use called %d times, want 2", f.uses)
	}

	// A key source works in the real client path: the JWT signs with it.
	if _, err := appJWT(context.Background(), vk, "123", time.Now()); err != nil {
		t.Fatalf("appJWT over a vault key: %v", err)
	}
}

func TestVaultKeyErrors(t *testing.T) {
	if _, err := NewVaultKey(nil, ""); err == nil {
		t.Fatal("nil vault accepted")
	}

	notPEM := "-----this is not a key-----"
	f := &fakeSecrets{id: "k", value: []byte(notPEM)}
	vk, _ := NewVaultKey(f, "k")
	_, err := vk.AppKey(context.Background())
	if err == nil {
		t.Fatal("garbage secret parsed")
	}
	if strings.Contains(err.Error(), notPEM) {
		t.Fatalf("error leaks the secret: %v", err)
	}

	sentinel := errors.New("vault is locked")
	vk, _ = NewVaultKey(&fakeSecrets{err: sentinel}, "k")
	if _, err := vk.AppKey(context.Background()); !errors.Is(err, sentinel) {
		t.Fatalf("vault error not passed on: %v", err)
	}

	vk, _ = NewVaultKey(&fakeSecrets{id: "other"}, "k")
	if _, err := vk.AppKey(context.Background()); err == nil {
		t.Fatal("missing secret returned a key")
	}
}
