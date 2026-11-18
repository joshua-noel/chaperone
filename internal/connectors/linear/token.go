package linear

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/joshua-noel/chaperone/internal/redact"
	"github.com/joshua-noel/chaperone/internal/vault"
)

// The vault secrets of the connector. Vault ids take no dot, so the names the
// ticket calls linear.client_id and linear.client_secret are written with a
// dash.
const (
	SecretClientID     = "linear-client-id"
	SecretClientSecret = "linear-client-secret"
	// SecretKind is the kind the operator gives both secrets in the console.
	SecretKind = "linear-oauth-client"

	// Scopes are what the app asks for. Linear revokes every earlier token of an
	// app when it is asked for a different scope set, so the set is fixed.
	// `write` is the narrowest scope that can change an issue's state; there is no
	// state-only scope (docs: research/linear-operator-board.md).
	Scopes = "read,write"

	// redactID is the name of the access token in the redaction registry.
	redactID = "linear-access-token"
)

// Token timing.
const (
	// tokenSkew is how long before its end a token is replaced.
	tokenSkew = 2 * time.Minute
	// DefaultTokenMaxAge caps how long chapd keeps a token. Linear's client
	// credentials token lives 30 days; Linear's own advice is a new token per
	// run, so chapd keeps one for an hour at most.
	DefaultTokenMaxAge = time.Hour
)

// ErrNotConnected means the vault holds no client id or no client secret.
var ErrNotConnected = errors.New("linear: not connected; the vault has no linear-client-id and linear-client-secret (docs/runbooks/linear-intake.md)")

// Endpoints are the URLs the connector talks to. Tests point both at a fake.
type Endpoints struct {
	API   string // GraphQL endpoint
	Token string // OAuth token endpoint
}

// DefaultEndpoints returns Linear's production endpoints.
func DefaultEndpoints() Endpoints {
	return Endpoints{API: "https://api.linear.app/graphql", Token: "https://api.linear.app/oauth/token"}
}

// Validate refuses an endpoint that is not https, except plain http to a
// loopback address (the fake server of the tests): a bearer token or a client
// secret sent in clear to another host would be readable on the wire.
func (e Endpoints) Validate() error {
	for name, raw := range map[string]string{"api": e.API, "token": e.Token} {
		if raw == "" {
			return fmt.Errorf("linear: endpoint %s is not set", name)
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return fmt.Errorf("linear: endpoint %s is not a URL", name)
		}
		switch u.Scheme {
		case "https":
		case "http":
			if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
				return fmt.Errorf("linear: endpoint %s is plain http to a non-loopback host", name)
			}
		default:
			return fmt.Errorf("linear: endpoint %s has scheme %q", name, u.Scheme)
		}
	}
	return nil
}

// Secrets is the part of *vault.Vault the connector uses.
type Secrets interface {
	Use(ctx context.Context, id string, fn func(secret []byte) error) error
}

var _ Secrets = (*vault.Vault)(nil)

// TokenConfig builds a [TokenSource].
type TokenConfig struct {
	Secrets   Secrets
	Registry  *redact.Registry // each token is registered so output masks it; may be nil
	Endpoints Endpoints
	HTTP      *http.Client
	// MaxAge caps how long a token is kept; zero means [DefaultTokenMaxAge].
	MaxAge time.Duration
	Now    func() time.Time
}

// TokenError is Linear's refusal to give a token.
type TokenError struct {
	Status int
	Code   string // OAuth error code ("invalid_client")
	Text   string // Linear's description, clipped
}

func (e *TokenError) Error() string {
	return fmt.Sprintf("linear: token endpoint answered HTTP %d %s: %s", e.Status, e.Code, e.Text)
}

// TokenSource hands out a valid access token, minting a new one from the
// client credentials in the vault when none is held. It is safe for concurrent
// use; one mint runs at a time. The token is in memory only.
type TokenSource struct {
	cfg TokenConfig

	mu      sync.Mutex
	token   []byte
	expires time.Time
	mints   int
}

// NewTokenSource returns a TokenSource.
func NewTokenSource(cfg TokenConfig) (*TokenSource, error) {
	if cfg.Secrets == nil {
		return nil, errors.New("linear: the token source needs the vault")
	}
	if err := cfg.Endpoints.Validate(); err != nil {
		return nil, err
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = DefaultTokenMaxAge
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &TokenSource{cfg: cfg}, nil
}

// Token returns a valid access token. force replaces a held token (after Linear
// answered 401 for it).
func (s *TokenSource) Token(ctx context.Context, force bool) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !force && s.token != nil && s.cfg.Now().Before(s.expires) {
		return string(s.token), nil
	}
	s.drop()
	tok, life, err := s.mint(ctx)
	if err != nil {
		return "", err
	}
	if life > s.cfg.MaxAge {
		life = s.cfg.MaxAge
	}
	s.token, s.expires = []byte(tok), s.cfg.Now().Add(life)
	s.mints++
	if s.cfg.Registry != nil {
		// A token that cannot be registered would reach a log unmasked: refuse it.
		if err := s.cfg.Registry.Set(redactID, s.token); err != nil {
			s.drop()
			return "", fmt.Errorf("linear: register the token for redaction: %w", err)
		}
	}
	return tok, nil
}

// Invalidate forgets the held token.
func (s *TokenSource) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.drop()
}

// Mints is the number of tokens minted so far (tests and status).
func (s *TokenSource) Mints() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mints
}

func (s *TokenSource) drop() {
	clear(s.token)
	s.token = nil
	if s.cfg.Registry != nil {
		s.cfg.Registry.Remove(redactID)
	}
}

// mint reads the client credentials from the vault and asks for a token: the
// client_credentials grant, HTTP Basic authentication, the fixed scope set.
func (s *TokenSource) mint(ctx context.Context) (token string, life time.Duration, err error) {
	id, err := s.secret(ctx, SecretClientID)
	if err != nil {
		return "", 0, err
	}
	sec, err := s.secret(ctx, SecretClientSecret)
	if err != nil {
		return "", 0, err
	}
	defer clear(sec)

	form := url.Values{"grant_type": {"client_credentials"}, "scope": {Scopes}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.Endpoints.Token, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.SetBasicAuth(string(id), string(sec))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.cfg.HTTP.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("linear: token request: %w", stripURL(err))
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &e)
		return "", 0, &TokenError{Status: resp.StatusCode, Code: clip(e.Error, 60), Text: clip(e.Description, 200)}
	}
	if rerr != nil {
		return "", 0, fmt.Errorf("linear: read the token answer: %w", rerr)
	}
	var t struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &t); err != nil || t.AccessToken == "" {
		return "", 0, errors.New("linear: the token endpoint answered something that is not a token")
	}
	if t.TokenType != "" && !strings.EqualFold(t.TokenType, "bearer") {
		return "", 0, fmt.Errorf("linear: the token endpoint gave a %q token, not a bearer token", clip(t.TokenType, 20))
	}
	life = time.Duration(t.ExpiresIn)*time.Second - tokenSkew
	if t.ExpiresIn <= 0 || life <= 0 {
		life = s.cfg.MaxAge
	}
	return t.AccessToken, life, nil
}

// secret reads one vault secret, trimmed of surrounding white space (a value
// pasted into the console may carry a newline).
func (s *TokenSource) secret(ctx context.Context, id string) ([]byte, error) {
	var out []byte
	err := s.cfg.Secrets.Use(ctx, id, func(b []byte) error {
		out = []byte(strings.TrimSpace(string(b)))
		return nil
	})
	if errors.Is(err, vault.ErrNotFound) {
		return nil, ErrNotConnected
	}
	if err != nil {
		return nil, fmt.Errorf("linear: read %s from the vault: %w", id, err)
	}
	if len(out) == 0 {
		return nil, ErrNotConnected
	}
	return out, nil
}

func stripURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// clip shortens s to n bytes and replaces control characters.
func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n-3], "") + "..."
}
