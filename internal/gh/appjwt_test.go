package gh

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestAppJWTShape(t *testing.T) {
	key := testKey(t)
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	jwt, err := appJWT(context.Background(), StaticKey{key}, "Iv1.abc", now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("want 3 parts, got %d", len(parts))
	}
	dec := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var hdr map[string]string
	if err := json.Unmarshal(dec(parts[0]), &hdr); err != nil || hdr["alg"] != "RS256" || hdr["typ"] != "JWT" {
		t.Fatalf("header %v err %v", hdr, err)
	}
	var claims struct {
		Iss string `json:"iss"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	if err := json.Unmarshal(dec(parts[1]), &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Iss != "Iv1.abc" {
		t.Errorf("iss = %q", claims.Iss)
	}
	if claims.Exp-claims.Iat != 600 {
		t.Errorf("lifetime = %ds, want 600", claims.Exp-claims.Iat)
	}
	if claims.Iat != now.Unix()-60 {
		t.Errorf("iat = %d, want now-60 = %d", claims.Iat, now.Unix()-60)
	}
	if claims.Exp > now.Unix()+600 {
		t.Errorf("exp is more than 10 minutes from now")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], dec(parts[2])); err != nil {
		t.Errorf("signature does not verify: %v", err)
	}
}

type failingKeys struct{}

func (failingKeys) AppKey(context.Context) (*rsa.PrivateKey, error) {
	return nil, errors.New("vault sealed")
}

func TestAppJWTKeySourceError(t *testing.T) {
	_, err := appJWT(context.Background(), failingKeys{}, "1", time.Now())
	if err == nil || !strings.Contains(err.Error(), "vault sealed") {
		t.Fatalf("err = %v", err)
	}
	if _, err := (StaticKey{}).AppKey(context.Background()); err == nil {
		t.Fatal("empty StaticKey must fail")
	}
}

func TestParsePrivateKeyPEM(t *testing.T) {
	key := testKey(t)
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	der8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der8})
	for name, in := range map[string][]byte{"pkcs1": pkcs1, "pkcs8": pkcs8} {
		got, err := ParsePrivateKeyPEM(in)
		if err != nil || !got.Equal(key) {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string][]byte{
		"not pem":   []byte("hello"),
		"bad body":  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("SECRET-LOOKING-BYTES")}),
		"wrong typ": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}}),
	}
	for name, in := range bad {
		_, err := ParsePrivateKeyPEM(in)
		if err == nil {
			t.Errorf("%s: want error", name)
		} else if strings.Contains(err.Error(), "SECRET-LOOKING") {
			t.Errorf("%s: error leaks key bytes: %v", name, err)
		}
	}
}
