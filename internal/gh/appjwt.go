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
	"fmt"
	"time"
)

// KeySource supplies the GitHub App private key. The vault implements it
// (L1-03); tests use [StaticKey]. The returned key is used for signing only and
// must not be retained by the caller beyond one call; implementations may hand
// back a fresh parse each time so the vault can drop its copy.
type KeySource interface {
	AppKey(ctx context.Context) (*rsa.PrivateKey, error)
}

// StaticKey is a KeySource over an in-memory key. For tests and for the live
// test; production uses the vault.
type StaticKey struct{ Key *rsa.PrivateKey }

// AppKey implements KeySource.
func (s StaticKey) AppKey(context.Context) (*rsa.PrivateKey, error) {
	if s.Key == nil {
		return nil, errors.New("gh: no app key")
	}
	return s.Key, nil
}

// ParsePrivateKeyPEM parses the .pem GitHub gives for an App (PKCS#1 "RSA
// PRIVATE KEY"; PKCS#8 "PRIVATE KEY" is accepted too). Vault-backed KeySources
// use it on the decrypted secret. The error never includes key bytes.
func ParsePrivateKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("gh: app key is not PEM")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("gh: app key: invalid PKCS#1 RSA key")
		}
		return k, nil
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("gh: app key: invalid PKCS#8 key")
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("gh: app key is not an RSA key")
		}
		return rk, nil
	default:
		return nil, fmt.Errorf("gh: app key: unsupported PEM block %q", block.Type)
	}
}

const (
	// jwtLifetime is the App JWT lifetime. GitHub accepts at most 10 minutes
	// from the time it receives the token.
	jwtLifetime = 10 * time.Minute
	// jwtBackdate covers clock drift: iat is set this far in the past, as
	// GitHub's docs recommend. exp = iat + jwtLifetime, so the token is never
	// valid for more than 10 minutes from "now" even with a fast clock.
	jwtBackdate = 60 * time.Second
)

// appJWT signs an App JWT: header {"alg":"RS256","typ":"JWT"}, claims iss, iat,
// exp. The result is a bearer credential for /app endpoints only; it is not
// cached, stored or logged.
func appJWT(ctx context.Context, ks KeySource, issuer string, now time.Time) (string, error) {
	key, err := ks.AppKey(ctx)
	if err != nil {
		return "", fmt.Errorf("gh: app key: %w", err)
	}
	if key == nil {
		return "", errors.New("gh: app key source returned no key")
	}
	iat := now.Add(-jwtBackdate).Unix()
	claims, err := json.Marshal(struct {
		Iss string `json:"iss"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}{issuer, iat, iat + int64(jwtLifetime/time.Second)})
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + enc.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("gh: sign app jwt: %w", err)
	}
	return signing + "." + enc.EncodeToString(sig), nil
}
