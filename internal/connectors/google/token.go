package google

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/joshua-noel/chaperone/internal/redact"
	"github.com/joshua-noel/chaperone/internal/vault"
)

// Vault ids and kinds of the two secrets.
const (
	ClientSecretID = "google-client"
	TokenSecretID  = "google-token"
	clientKind     = "google-oauth-client"
	tokenKind      = "google-oauth-token"
	secretOwner    = "google"
)

// Alert keys. An alert is raised once when the state turns bad and again only
// after it was good in between.
const (
	AlertReauth   = "google-reauth"
	AlertExpiring = "google-refresh-expiring"
	AlertRefresh  = "google-refresh-failing"
)

// Defaults of the token source.
const (
	// accessSkew is how long before its expiry an access token is replaced.
	accessSkew = 2 * time.Minute
	// expiryWarn is how long before a known refresh-token expiry the alert fires.
	expiryWarn = 48 * time.Hour
	// refreshFailAlertAfter is the number of consecutive failed refreshes (not
	// invalid_grant) after which the alert fires.
	refreshFailAlertAfter = 3
)

// Secrets is the part of *vault.Vault the connector uses.
type Secrets interface {
	Use(ctx context.Context, id string, fn func(secret []byte) error) error
	Import(ctx context.Context, m vault.Meta, value []byte) (vault.Info, error)
	Rotate(ctx context.Context, id string, value []byte) (vault.Info, error)
	Info(ctx context.Context, id string) (vault.Info, error)
}

var _ Secrets = (*vault.Vault)(nil)

// Alerter raises an alert for the operator. It must not block for long and must
// not fail an op; the implementation logs its own errors.
type Alerter interface {
	RaiseGoogleAlert(ctx context.Context, key, text string)
}

// SaveClient stores the OAuth client in the vault (import, or rotate if one is
// already there).
func SaveClient(ctx context.Context, s Secrets, c ClientCreds) error {
	if err := c.valid(); err != nil {
		return err
	}
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return upsert(ctx, s, ClientSecretID, clientKind, b)
}

// SaveTokens stores a token set in the vault.
func SaveTokens(ctx context.Context, s Secrets, t *TokenSet) error {
	b, err := json.Marshal(t)
	if err != nil {
		return err
	}
	return upsert(ctx, s, TokenSecretID, tokenKind, b)
}

func upsert(ctx context.Context, s Secrets, id, kind string, value []byte) error {
	defer clear(value)
	_, err := s.Import(ctx, vault.Meta{ID: id, Kind: kind, Owner: secretOwner}, value)
	if errors.Is(err, vault.ErrExists) {
		_, err = s.Rotate(ctx, id, value)
	}
	if err != nil {
		return fmt.Errorf("google: store %s in the vault: %w", id, err)
	}
	return nil
}

// LoadClient reads the OAuth client from the vault. The secret may be the flat
// {client_id, client_secret} that [SaveClient] writes, or the JSON file Google
// Cloud downloads, imported unchanged through the console's Secrets screen.
func LoadClient(ctx context.Context, s Secrets) (ClientCreds, error) {
	var c ClientCreds
	err := s.Use(ctx, ClientSecretID, func(b []byte) error {
		if json.Unmarshal(b, &c) == nil && c.valid() == nil {
			return nil
		}
		var perr error
		c, perr = ParseClientJSON(b)
		return perr
	})
	if errors.Is(err, vault.ErrNotFound) {
		return ClientCreds{}, ErrNotConnected
	}
	if err != nil {
		return ClientCreds{}, err
	}
	return c, c.valid()
}

// ErrNotConnected: Google was never connected (no client or no token set in
// the vault).
var ErrNotConnected = errors.New("google: not connected; run `chapd connect google`")

// Status is what the connector knows about the connection, with no secret in it.
type Status struct {
	Connected bool
	Account   string
	Scopes    []string
	// AccessExpiry is when the cached access token ends; it is renewed on use.
	AccessExpiry time.Time
	// RefreshExpiry is when Google said the refresh token ends; zero if it
	// said nothing (a production app's token has no fixed end).
	RefreshExpiry time.Time
	ConnectedAt   time.Time
	// ReauthRequired is set when Google refused the refresh token.
	ReauthRequired bool
	LastRefresh    time.Time
	LastError      string
}

// Problem returns why the connection cannot be used right now, or "".
func (s Status) Problem(now time.Time) string {
	switch {
	case !s.Connected:
		return "Google is not connected; run `chapd connect google`"
	case s.ReauthRequired:
		return "Google no longer accepts the saved sign-in; run `chapd connect google` again"
	case !s.RefreshExpiry.IsZero() && !now.Before(s.RefreshExpiry):
		return "the saved Google sign-in has expired (the consent screen is probably still in Testing); run `chapd connect google` again"
	}
	return ""
}

// SourceConfig builds a [Source].
type SourceConfig struct {
	Secrets   Secrets
	Registry  *redact.Registry // registers each token so output masks it; may be nil
	Endpoints Endpoints
	HTTP      *http.Client
	Alert     Alerter // optional
	Now       func() time.Time
}

// Source hands out a valid access token, refreshing it with the refresh token
// from the vault and writing the new set back. It is safe for concurrent use;
// one refresh runs at a time.
type Source struct {
	cfg SourceConfig

	mu         sync.Mutex
	reauth     bool
	lastErr    string
	lastOK     time.Time
	failures   int
	alerted    map[string]bool
	lastStatus Status // from the last read of the vault
}

// NewSource returns a Source.
func NewSource(cfg SourceConfig) (*Source, error) {
	if cfg.Secrets == nil {
		return nil, errors.New("google: the token source needs the vault")
	}
	if err := cfg.Endpoints.Validate(); err != nil {
		return nil, err
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Source{cfg: cfg, alerted: map[string]bool{}}, nil
}

func (s *Source) load(ctx context.Context) (*TokenSet, error) {
	var t TokenSet
	err := s.cfg.Secrets.Use(ctx, TokenSecretID, func(b []byte) error { return json.Unmarshal(b, &t) })
	if errors.Is(err, vault.ErrNotFound) {
		return nil, ErrNotConnected
	}
	if err != nil {
		return nil, err
	}
	s.register(&t)
	return &t, nil
}

// register adds each token to the redaction registry, so that a log line or an
// op result that quotes one is masked even if it is not in Google's usual shape.
func (s *Source) register(t *TokenSet) {
	if s.cfg.Registry == nil {
		return
	}
	_ = s.cfg.Registry.Set("google-access-token", []byte(t.AccessToken))
	_ = s.cfg.Registry.Set("google-refresh-token", []byte(t.RefreshToken))
}

func (s *Source) save(ctx context.Context, t *TokenSet) error {
	if err := SaveTokens(ctx, s.cfg.Secrets, t); err != nil {
		return err
	}
	s.register(t)
	return nil
}

// Status reads the connection's state from the vault. It makes no network
// call.
func (s *Source) Status(ctx context.Context) Status {
	t, err := s.load(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{ReauthRequired: s.reauth, LastRefresh: s.lastOK, LastError: s.lastErr}
	if err == nil {
		st.Connected = true
		st.Account, st.Scopes = t.Account, slices.Clone(t.Scopes)
		st.AccessExpiry, st.RefreshExpiry, st.ConnectedAt = t.AccessExpiry, t.RefreshExpiry, t.ConnectedAt
	} else if !errors.Is(err, ErrNotConnected) {
		st.LastError = clipText(err.Error(), 200)
	}
	s.lastStatus = st
	return st
}

// Connected records a fresh sign-in: it clears every alarm state.
func (s *Source) Connected(ctx context.Context, t *TokenSet) error {
	if err := s.save(ctx, t); err != nil {
		return err
	}
	s.mu.Lock()
	s.reauth, s.lastErr, s.failures, s.lastOK = false, "", 0, s.cfg.Now()
	clear(s.alerted)
	s.mu.Unlock()
	return nil
}

// Token returns a valid access token and the account it belongs to. It
// refreshes first when the cached token ends within two minutes.
func (s *Source) Token(ctx context.Context) (access string, t *TokenSet, err error) {
	return s.token(ctx, false)
}

// Refresh forces a refresh now (after a 401, and from the monitor).
func (s *Source) Refresh(ctx context.Context) error {
	_, _, err := s.token(ctx, true)
	return err
}

func (s *Source) token(ctx context.Context, force bool) (string, *TokenSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.load(ctx)
	if err != nil {
		return "", nil, err
	}
	now := s.cfg.Now()
	s.warnExpiring(ctx, t, now)
	if p := (Status{Connected: true, RefreshExpiry: t.RefreshExpiry}).Problem(now); p != "" {
		s.alertOnce(ctx, AlertReauth, "Google sign-in has expired: run `chapd connect google`. Mail and Drive ops are refused until you do.")
		return "", nil, ErrReauthRequired
	}
	if !force && now.Add(accessSkew).Before(t.AccessExpiry) && t.AccessToken != "" {
		return t.AccessToken, t, nil
	}
	nt, err := s.refresh(ctx, t, now)
	if err != nil {
		return "", nil, err
	}
	return nt.AccessToken, nt, nil
}

func (s *Source) refresh(ctx context.Context, t *TokenSet, now time.Time) (*TokenSet, error) {
	c, err := LoadClient(ctx, s.cfg.Secrets)
	if err != nil {
		return nil, err
	}
	s.registerClient(c)
	var tr tokenResponse
	err = postForm(ctx, s.cfg.HTTP, s.cfg.Endpoints.Token, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {t.RefreshToken},
		"client_id":     {c.ClientID},
		"client_secret": {c.ClientSecret},
	}, &tr)
	if err != nil {
		var oe *oauthError
		if errors.As(err, &oe) && oe.Code == "invalid_grant" {
			s.reauth, s.lastErr = true, "Google refused the refresh token (invalid_grant)"
			s.alertOnce(ctx, AlertReauth, "Google refused the saved sign-in (revoked, expired or the password changed). Mail and Drive ops are refused until you run `chapd connect google`.")
			return nil, ErrReauthRequired
		}
		s.failures++
		s.lastErr = clipText(err.Error(), 200)
		if s.failures >= refreshFailAlertAfter {
			s.alertOnce(ctx, AlertRefresh, fmt.Sprintf("Google token refresh has failed %d times in a row: %s", s.failures, s.lastErr))
		}
		return nil, fmt.Errorf("google: refresh the access token: %w", err)
	}
	if tr.AccessToken == "" {
		s.failures++
		s.lastErr = "the token endpoint returned no access token"
		return nil, errors.New("google: " + s.lastErr)
	}
	nt := *t
	nt.AccessToken = tr.AccessToken
	nt.AccessExpiry = now.Add(time.Duration(tr.ExpiresIn) * time.Second).UTC()
	if tr.RefreshToken != "" { // Google may rotate it
		nt.RefreshToken = tr.RefreshToken
	}
	if tr.RefreshExpiresIn > 0 {
		nt.RefreshExpiry = now.Add(time.Duration(tr.RefreshExpiresIn) * time.Second).UTC()
	}
	if tr.Scope != "" {
		nt.Scopes = slices.Sorted(slices.Values(strings.Fields(tr.Scope)))
	}
	if err := s.save(ctx, &nt); err != nil {
		// The new access token is good but could not be kept: fail rather than
		// use a token the vault does not know (a lost rotated refresh token
		// would be a silent break at the next refresh).
		s.failures++
		s.lastErr = "the vault refused the refreshed token set"
		return nil, err
	}
	s.reauth, s.lastErr, s.failures, s.lastOK = false, "", 0, now
	delete(s.alerted, AlertReauth)
	delete(s.alerted, AlertRefresh)
	return &nt, nil
}

func (s *Source) registerClient(c ClientCreds) {
	if s.cfg.Registry != nil {
		_ = s.cfg.Registry.Set("google-client-secret", []byte(c.ClientSecret))
	}
}

// warnExpiring raises the expiry alert when Google told us the refresh token
// has a fixed end and that end is near.
func (s *Source) warnExpiring(ctx context.Context, t *TokenSet, now time.Time) {
	if t.RefreshExpiry.IsZero() || now.Add(expiryWarn).Before(t.RefreshExpiry) {
		return
	}
	s.alertOnce(ctx, AlertExpiring, fmt.Sprintf(
		"The Google sign-in ends %s (an app in Testing mode issues 7-day tokens). Set the consent screen to In production and run `chapd connect google`.",
		t.RefreshExpiry.UTC().Format(time.RFC3339)))
}

func (s *Source) alertOnce(ctx context.Context, key, text string) {
	if s.alerted[key] {
		return
	}
	s.alerted[key] = true
	if s.cfg.Alert != nil {
		s.cfg.Alert.RaiseGoogleAlert(ctx, key, text)
	}
}

// Monitor refreshes the token on a timer, so a revoked or expired sign-in is
// found within one period and alerted, not on the next time an agent asks to
// send mail.
type Monitor struct {
	Source *Source
	// Every is the period; zero means 6 hours.
	Every time.Duration
}

// Run blocks until ctx ends. It probes once at start. A probe does nothing
// when Google was never connected.
func (m Monitor) Run(ctx context.Context) {
	every := m.Every
	if every <= 0 {
		every = 6 * time.Hour
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		m.Probe(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Probe does one refresh. Its errors are alerts and Status, not return values.
func (m Monitor) Probe(ctx context.Context) {
	if err := m.Source.Refresh(ctx); err != nil && !errors.Is(err, ErrNotConnected) {
		// token() already raised the alert; the error stays in Status.
		m.Source.mu.Lock()
		if m.Source.lastErr == "" {
			m.Source.lastErr = clipText(err.Error(), 200)
		}
		m.Source.mu.Unlock()
	}
}

// RevokeSaved asks Google to revoke the saved refresh token (which ends the
// whole grant). The vault entry stays; the next refresh finds the grant gone,
// raises the reauth alert and every mail and Drive op is refused until a new
// sign-in.
func RevokeSaved(ctx context.Context, s Secrets, hc *http.Client, ep Endpoints) error {
	if err := ep.Validate(); err != nil {
		return err
	}
	var t TokenSet
	err := s.Use(ctx, TokenSecretID, func(b []byte) error { return json.Unmarshal(b, &t) })
	if errors.Is(err, vault.ErrNotFound) {
		return ErrNotConnected
	}
	if err != nil {
		return err
	}
	return Revoke(ctx, hc, ep, t.RefreshToken)
}
