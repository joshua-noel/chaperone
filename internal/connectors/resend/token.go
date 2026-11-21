package resend

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/joshua-noel/chaperone/internal/vault"
)

// The vault secret of the connector. A vault id takes no dot. It is the ONLY secret
// the connector reads: a test records every id that is asked for.
const (
	// SecretSendKey is the vault id of the API key that sends mail. Make it in
	// Resend with the permission "Sending access" and the domain restricted to
	// the one domain the senders are on: see docs/runbooks/resend.md.
	SecretSendKey = "resend-api-key"
	// SecretKind is the kind the operator gives the secret in the console.
	SecretKind = "resend-api-key"

	// redactSendKey is the name of the key in the redaction registry.
	redactSendKey = "resend-api-key"
)

// Secrets is the part of *vault.Vault the connector uses.
type Secrets interface {
	Use(ctx context.Context, id string, fn func(secret []byte) error) error
}

var _ Secrets = (*vault.Vault)(nil)

// VaultCredential returns the function of a [ClientConfig] that reads the vault
// secret [SecretSendKey] on every call, trimmed of surrounding white space (a value
// pasted into the console may carry a newline). The key is held only for the call.
func VaultCredential(s Secrets) func(ctx context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var tok string
		err := s.Use(ctx, SecretSendKey, func(b []byte) error {
			tok = strings.TrimSpace(string(b))
			return nil
		})
		if errors.Is(err, vault.ErrNotFound) {
			return "", ErrNoSendKey
		}
		if err != nil {
			return "", fmt.Errorf("resend: read %s from the vault: %w", SecretSendKey, err)
		}
		if tok == "" {
			return "", ErrNoSendKey
		}
		return tok, nil
	}
}
