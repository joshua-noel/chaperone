package gh

import (
	"errors"
	"sync"
	"time"
)

// Token is an installation access token. It is opaque: the client never looks
// at its length, prefix or structure (GitHub's 2026 stateless tokens are about
// 520 characters, the old ones 40). Its value never appears in String, %v, %+v,
// %#v, JSON or text encodings. Only [Token.Reveal] returns it.
type Token struct {
	mu      sync.RWMutex
	value   []byte
	expires time.Time

	// Repositories is the list of repository names GitHub says the token
	// covers; Permissions the permissions it holds.
	Repositories []string
	Permissions  map[string]string
}

func newToken(value string, expires time.Time, repos []string, perms map[string]string) *Token {
	return &Token{value: []byte(value), expires: expires, Repositories: repos, Permissions: perms}
}

// ExpiresAt is when GitHub says the token stops working (one hour after minting).
func (t *Token) ExpiresAt() time.Time { return t.expires }

// Reveal returns the token value for an Authorization header. It returns ""
// after [Token.Wipe]. Callers must not log, store or return the result.
func (t *Token) Reveal() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return string(t.value)
}

// Wipe overwrites the in-memory value. It does not revoke the token at GitHub;
// use [Client.RevokeToken] first. Safe to call more than once.
func (t *Token) Wipe() {
	t.mu.Lock()
	defer t.mu.Unlock()
	clear(t.value)
	t.value = nil
}

// String implements fmt.Stringer without the secret.
func (t *Token) String() string { return "gh.Token(redacted)" }

// GoString implements fmt.GoStringer without the secret.
func (t *Token) GoString() string { return "gh.Token(redacted)" }

// MarshalText refuses to encode the secret; it emits a fixed marker.
func (t *Token) MarshalText() ([]byte, error) { return []byte("[redacted]"), nil }

// MarshalJSON emits a JSON string marker, never the value.
func (t *Token) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }

// bearer returns the secret for a request, failing for a nil, wiped or expired token.
func (t *Token) bearer(now time.Time) (string, error) {
	if t == nil {
		return "", errors.New("gh: nil token")
	}
	t.mu.RLock()
	v := string(t.value)
	t.mu.RUnlock()
	if v == "" {
		return "", ErrTokenWiped
	}
	if !t.expires.IsZero() && !now.Before(t.expires) {
		return "", ErrTokenExpired
	}
	return v, nil
}
