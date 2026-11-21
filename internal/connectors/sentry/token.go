package sentry

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/joshua-noel/chaperone/internal/vault"
)

// The vault secret of the connector. A vault id takes no dot.
const (
	// SecretToken is the vault id of the Sentry auth token.
	SecretToken = "sentry-auth-token"
	// SecretKind is the kind the operator gives the secret in the console.
	SecretKind = "sentry-auth-token"

	// Scopes are what the token needs, and no more. A token for the read
	// operations needs only event:read. In the Sentry page for an internal
	// integration they are "Issue & Event: Read" and "Issue & Event: Read &
	// Write". Nothing else is needed: no project, team, member, organisation or
	// release permission. docs/runbooks/sentry.md says how to make the token.
	ScopeRead  = "event:read"
	ScopeWrite = "event:write"

	// redactID is the name of the token in the redaction registry.
	redactID = "sentry-auth-token"
)

// ErrNotConnected means the vault holds no Sentry auth token.
var ErrNotConnected = errors.New("sentry: not connected; the vault has no sentry-auth-token (docs/runbooks/sentry.md)")

// Secrets is the part of *vault.Vault the connector uses.
type Secrets interface {
	Use(ctx context.Context, id string, fn func(secret []byte) error) error
}

var _ Secrets = (*vault.Vault)(nil)

// VaultCredential returns the credential function of a [ClientConfig]: it reads
// the auth token from the vault on every call, trimmed of surrounding white
// space (a value pasted into the console may carry a newline). The token is held
// only for the call.
func VaultCredential(s Secrets) func(ctx context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var tok string
		err := s.Use(ctx, SecretToken, func(b []byte) error {
			tok = strings.TrimSpace(string(b))
			return nil
		})
		if errors.Is(err, vault.ErrNotFound) {
			return "", ErrNotConnected
		}
		if err != nil {
			return "", fmt.Errorf("sentry: read %s from the vault: %w", SecretToken, err)
		}
		if tok == "" {
			return "", ErrNotConnected
		}
		return tok, nil
	}
}
