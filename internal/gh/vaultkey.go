package gh

import (
	"context"
	"crypto/rsa"
	"errors"
)

// AppKeySecretID is the vault id `chapd vault import --name github-app-key`
// stores the App's private key under.
const AppKeySecretID = "github-app-key"

// SecretUser is the part of the vault a [VaultKey] needs: run fn with the
// decrypted secret. *vault.Vault implements it; the interface keeps gh free of
// a vault import.
type SecretUser interface {
	Use(ctx context.Context, id string, fn func(secret []byte) error) error
}

// VaultKey is the production [KeySource]: the App's private key lives in the
// vault as a PEM and is decrypted and parsed for each call, inside the vault's
// Use closure, so the vault zeroes its copy as soon as the parse is done. Each
// call is recorded as a use of the secret in the vault index.
type VaultKey struct {
	secrets SecretUser
	id      string
}

// NewVaultKey returns a KeySource over secret id in secrets. An empty id means
// [AppKeySecretID].
func NewVaultKey(secrets SecretUser, id string) (*VaultKey, error) {
	if secrets == nil {
		return nil, errors.New("gh: vault key needs a vault")
	}
	if id == "" {
		id = AppKeySecretID
	}
	return &VaultKey{secrets: secrets, id: id}, nil
}

// AppKey implements KeySource. The returned key is a fresh parse; the error
// never contains key bytes (see [ParsePrivateKeyPEM]).
func (k *VaultKey) AppKey(ctx context.Context) (*rsa.PrivateKey, error) {
	var key *rsa.PrivateKey
	err := k.secrets.Use(ctx, k.id, func(secret []byte) error {
		var perr error
		key, perr = ParsePrivateKeyPEM(secret)
		return perr
	})
	if err != nil {
		return nil, err
	}
	return key, nil
}
