package resend

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/joshua-noel/chaperone/internal/vault"
)

// The vault secrets of the connector. A vault id takes no dot.
const (
	// SecretSendKey is the vault id of the API key that sends mail. Make it in
	// Resend with the permission "Sending access" and the domain restricted to
	// the one domain the senders are on: see docs/runbooks/resend.md.
	SecretSendKey = "resend-api-key"
	// SecretStatusKey is the vault id of the optional API key that reads one
	// email for mail.status. Resend gives a sending_access key no read, so this
	// key must have "Full access", which can do anything in the Resend account.
	// Leave it out unless the runbook's warning has been read: mail.status then
	// answers that it is not available.
	SecretStatusKey = "resend-status-key"
	// SecretKind is the kind the operator gives either secret in the console.
	SecretKind = "resend-api-key"

	// The names of the keys in the redaction registry.
	redactSendKey   = "resend-api-key"
	redactStatusKey = "resend-status-key"
)

// Secrets is the part of *vault.Vault the connector uses.
type Secrets interface {
	Use(ctx context.Context, id string, fn func(secret []byte) error) error
}

var _ Secrets = (*vault.Vault)(nil)

// VaultCredential returns the function of a [ClientConfig] that reads vault
// secret id on every call, trimmed of surrounding white space (a value pasted
// into the console may carry a newline). The key is held only for the call.
// missing is the error to return when the vault has no such secret.
func VaultCredential(s Secrets, id string) func(ctx context.Context) (string, error) {
	missing := ErrNoSendKey
	if id == SecretStatusKey {
		missing = ErrNoStatusKey
	}
	return func(ctx context.Context) (string, error) {
		var tok string
		err := s.Use(ctx, id, func(b []byte) error {
			tok = strings.TrimSpace(string(b))
			return nil
		})
		if errors.Is(err, vault.ErrNotFound) {
			return "", missing
		}
		if err != nil {
			return "", fmt.Errorf("resend: read %s from the vault: %w", id, err)
		}
		if tok == "" {
			return "", missing
		}
		return tok, nil
	}
}
