package google

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// Scopes. gmail.send can only send; it cannot read mail. The drive scope is a
// restricted scope: see docs/runbooks/google.md for what that means at H5.
const (
	ScopeGmailSend = "https://www.googleapis.com/auth/gmail.send"
	ScopeDrive     = "https://www.googleapis.com/auth/drive"
	ScopeOpenID    = "openid"
	ScopeEmail     = "email"
)

// Endpoints are the URLs the connector talks to. The zero value is not usable;
// start from [DefaultEndpoints]. Tests point every field at a fake server.
type Endpoints struct {
	Auth   string // authorization endpoint (opened in the operator's browser)
	Token  string // token endpoint
	Revoke string // revocation endpoint
	Gmail  string // Gmail API origin
	Drive  string // Drive API origin
}

// DefaultEndpoints returns Google's production endpoints.
func DefaultEndpoints() Endpoints {
	return Endpoints{
		Auth:   "https://accounts.google.com/o/oauth2/v2/auth",
		Token:  "https://oauth2.googleapis.com/token",
		Revoke: "https://oauth2.googleapis.com/revoke",
		Gmail:  "https://gmail.googleapis.com",
		Drive:  "https://www.googleapis.com",
	}
}

// Validate refuses an endpoint that is not https, except plain http to a
// loopback address (the fake servers of the tests). A token sent to a
// plain-http host that is not the local machine would be readable on the wire.
func (e Endpoints) Validate() error {
	for name, raw := range map[string]string{"auth": e.Auth, "token": e.Token, "revoke": e.Revoke, "gmail": e.Gmail, "drive": e.Drive} {
		if raw == "" {
			return fmt.Errorf("google: endpoint %s is not set", name)
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return fmt.Errorf("google: endpoint %s is not a URL", name)
		}
		switch u.Scheme {
		case "https":
		case "http":
			if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
				return fmt.Errorf("google: endpoint %s is plain http to a non-loopback host", name)
			}
		default:
			return fmt.Errorf("google: endpoint %s has scheme %q", name, u.Scheme)
		}
	}
	return nil
}

// ClientCreds is the OAuth client of the Google Cloud project (type Desktop
// app). Google documents that a desktop client's secret is not confidential,
// but Chaperone keeps it in the vault like everything else.
type ClientCreds struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func (c ClientCreds) valid() error {
	if c.ClientID == "" || c.ClientSecret == "" {
		return errors.New("google: the OAuth client needs a client id and a client secret")
	}
	return nil
}

// ParseClientJSON reads the file Google Cloud offers as "Download JSON" for an
// OAuth client. Only the "installed" (Desktop app) type is accepted: a "web"
// client needs redirect URIs registered in advance and has different rules.
func ParseClientJSON(data []byte) (ClientCreds, error) {
	var f struct {
		Installed *ClientCreds    `json:"installed"`
		Web       json.RawMessage `json:"web"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return ClientCreds{}, errors.New("google: the client file is not JSON")
	}
	if f.Installed == nil {
		if len(f.Web) > 0 {
			return ClientCreds{}, errors.New(`google: this is a "Web application" client; create one of type "Desktop app"`)
		}
		return ClientCreds{}, errors.New(`google: the client file has no "installed" section`)
	}
	if err := f.Installed.valid(); err != nil {
		return ClientCreds{}, err
	}
	return *f.Installed, nil
}

// TokenSet is what the vault holds under [TokenSecretID]: one JSON document.
type TokenSet struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	AccessExpiry time.Time `json:"access_expiry"`
	// RefreshExpiry is set only when Google said the refresh token ends (an
	// app whose consent screen is still in "Testing": 7 days). Zero otherwise.
	RefreshExpiry time.Time `json:"refresh_expiry,omitzero"`
	Scopes        []string  `json:"scopes"`
	// Account is the verified e-mail address the operator signed in with.
	Account     string    `json:"account"`
	ConnectedAt time.Time `json:"connected_at"`
}

// HasScope reports whether Google granted scope.
func (t *TokenSet) HasScope(scope string) bool { return slices.Contains(t.Scopes, scope) }

// tokenResponse is the token endpoint's answer.
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshExpiresIn int64  `json:"refresh_token_expires_in"`
	Scope            string `json:"scope"`
	IDToken          string `json:"id_token"`
	TokenType        string `json:"token_type"`
	Error            string `json:"error"`
	ErrorDesc        string `json:"error_description"`
}

// oauthError is a refusal by the token endpoint. It carries Google's error
// code and description, never a token.
type oauthError struct {
	Status int
	Code   string
	Desc   string
}

func (e *oauthError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("google: token endpoint answered HTTP %d", e.Status)
	}
	return fmt.Sprintf("google: token endpoint refused: %s (%s)", clipText(e.Code, 60), clipText(e.Desc, 160))
}

// ErrReauthRequired means Google no longer accepts the refresh token (revoked,
// expired, or the account's password changed). The operator must sign in again.
var ErrReauthRequired = errors.New("google: the refresh token is no longer valid; run `chapd connect google` again")

// postForm posts a form to the token or revoke endpoint and decodes the JSON.
func postForm(ctx context.Context, hc *http.Client, endpoint string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("google: %s: %w", hostOf(endpoint), stripURL(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("google: read %s: %w", hostOf(endpoint), err)
	}
	if resp.StatusCode/100 != 2 {
		var e tokenResponse
		_ = json.Unmarshal(body, &e)
		return &oauthError{Status: resp.StatusCode, Code: e.Error, Desc: e.ErrorDesc}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("google: %s answered something that is not JSON", hostOf(endpoint))
	}
	return nil
}

// stripURL drops the request URL from a *url.Error: the URL of a token call
// can carry nothing secret (the secrets are in the form body), but an error
// that is logged should still be short.
func stripURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Host
	}
	return "?"
}

func clipText(s string, n int) string {
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

// ---- loopback + PKCE sign-in -----------------------------------------------

// ConnectConfig drives [Connect].
type ConnectConfig struct {
	Client    ClientCreds
	Scopes    []string // the API scopes wanted; openid and email are added
	Endpoints Endpoints
	HTTP      *http.Client
	// OpenURL shows the sign-in page to the operator (normally: print it and
	// try to open the browser). It must not block.
	OpenURL func(authURL string) error
	// Timeout bounds the wait for the browser. Zero means 5 minutes.
	Timeout time.Duration
	// ListenAddr is the loopback address to listen on; default "127.0.0.1:0".
	ListenAddr string
	Now        func() time.Time
}

// Connect runs the OAuth 2.0 authorization-code flow for an installed app
// (RFC 8252 section 7.3, loopback redirect) with PKCE S256 (RFC 7636): it
// listens on a random loopback port, hands the sign-in URL to OpenURL, waits
// for the redirect, checks `state`, and exchanges the code with the verifier.
//
// The result must hold a refresh token, every scope asked for, and a verified
// e-mail address; anything less is an error and nothing is stored (the caller
// stores the returned set).
func Connect(ctx context.Context, cfg ConnectConfig) (*TokenSet, error) {
	if cfg.OpenURL == nil {
		return nil, errors.New("google: connect needs OpenURL")
	}
	p, err := StartConnect(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer p.Close()
	if err := cfg.OpenURL(p.AuthURL); err != nil {
		return nil, fmt.Errorf("google: show the sign-in page: %w", err)
	}
	return p.Wait(ctx)
}

// Pending is a sign-in that has started: the loopback listener is up and
// AuthURL is the page the operator opens. A caller that serves its own screen
// (a console route) uses [StartConnect] and [Pending.Wait] directly.
type Pending struct {
	// AuthURL is the Google sign-in address.
	AuthURL string

	cfg      ConnectConfig
	hc       *http.Client
	now      func() time.Time
	verifier string
	redirect string
	got      chan callbackResult
	srv      *http.Server
	timeout  time.Duration
}

type callbackResult struct {
	code string
	err  error
}

// StartConnect starts the loopback listener and builds the sign-in address.
// The caller must call [Pending.Close] (Wait does not).
func StartConnect(ctx context.Context, cfg ConnectConfig) (*Pending, error) {
	if err := cfg.Client.valid(); err != nil {
		return nil, err
	}
	if err := cfg.Endpoints.Validate(); err != nil {
		return nil, err
	}
	if len(cfg.Scopes) == 0 {
		return nil, errors.New("google: connect needs at least one scope")
	}
	p := &Pending{cfg: cfg, hc: cfg.HTTP, now: cfg.Now, timeout: cfg.Timeout}
	if p.hc == nil {
		p.hc = &http.Client{Timeout: 30 * time.Second}
	}
	if p.now == nil {
		p.now = time.Now
	}
	if p.timeout <= 0 {
		p.timeout = 5 * time.Minute
	}
	addr := cfg.ListenAddr
	if addr == "" {
		addr = "127.0.0.1:0"
	}

	var err error
	if p.verifier, err = randomToken(48); err != nil { // 64 characters, within RFC 7636's 43..128
		return nil, err
	}
	state, err := randomToken(24)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(p.verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return nil, fmt.Errorf("google: listen for the redirect: %w", err)
	}
	if ip := ln.Addr().(*net.TCPAddr).IP; !ip.IsLoopback() {
		ln.Close()
		return nil, errors.New("google: the redirect listener must be on the loopback interface")
	}
	p.redirect = "http://" + ln.Addr().String() + "/callback"

	p.got = make(chan callbackResult, 1)
	var used atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		// DNS-rebinding and look-alike defence: only the exact loopback host.
		if r.Host != ln.Addr().String() || r.Method != http.MethodGet {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		q := r.URL.Query()
		if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 {
			http.Error(w, "unexpected state; this sign-in was not started by Chaperone", http.StatusBadRequest)
			return
		}
		if !used.CompareAndSwap(false, true) {
			http.Error(w, "already used", http.StatusGone)
			return
		}
		if e := q.Get("error"); e != "" {
			p.got <- callbackResult{err: fmt.Errorf("google: the sign-in was refused: %s", clipText(e, 60))}
			fmt.Fprintf(w, "<!doctype html><title>Chaperone</title><p>Sign-in refused: %s. You can close this tab.", html.EscapeString(clipText(e, 60)))
			return
		}
		code := q.Get("code")
		if code == "" {
			http.Error(w, "no code", http.StatusBadRequest)
			return
		}
		p.got <- callbackResult{code: code}
		fmt.Fprint(w, "<!doctype html><title>Chaperone</title><p>Chaperone is connected to Google. You can close this tab.")
	})
	p.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go p.srv.Serve(ln) //nolint:errcheck // ends with Shutdown

	scopes := append(slices.Clone(cfg.Scopes), ScopeOpenID, ScopeEmail)
	q := url.Values{
		"client_id":             {cfg.Client.ClientID},
		"redirect_uri":          {p.redirect},
		"response_type":         {"code"},
		"scope":                 {strings.Join(scopes, " ")},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
		"access_type":           {"offline"},
		// consent makes Google issue a refresh token even if the app was
		// authorised before.
		"prompt": {"consent"},
	}
	p.AuthURL = cfg.Endpoints.Auth + "?" + q.Encode()
	return p, nil
}

// Close stops the loopback listener.
func (p *Pending) Close() {
	sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = p.srv.Shutdown(sctx)
}

// Wait blocks until the browser comes back (or the timeout or ctx ends) and
// exchanges the code for tokens.
func (p *Pending) Wait(ctx context.Context) (*TokenSet, error) {
	var res callbackResult
	select {
	case res = <-p.got:
	case <-time.After(p.timeout):
		return nil, errors.New("google: timed out waiting for the sign-in in the browser")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if res.err != nil {
		return nil, res.err
	}
	var tr tokenResponse
	err := postForm(ctx, p.hc, p.cfg.Endpoints.Token, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {res.code},
		"client_id":     {p.cfg.Client.ClientID},
		"client_secret": {p.cfg.Client.ClientSecret},
		"redirect_uri":  {p.redirect},
		"code_verifier": {p.verifier},
	}, &tr)
	if err != nil {
		return nil, err
	}
	return tokensFromExchange(&tr, p.cfg.Scopes, p.now())
}

func tokensFromExchange(tr *tokenResponse, wanted []string, now time.Time) (*TokenSet, error) {
	if tr.AccessToken == "" || tr.RefreshToken == "" {
		return nil, errors.New("google: Google did not return a refresh token; remove Chaperone at https://myaccount.google.com/permissions and sign in again")
	}
	granted := strings.Fields(tr.Scope)
	var missing []string
	for _, s := range wanted {
		if !slices.Contains(granted, s) {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("google: these scopes were not granted (untick nothing on the consent page): %s", strings.Join(missing, ", "))
	}
	email, err := verifiedEmail(tr.IDToken)
	if err != nil {
		return nil, err
	}
	ts := &TokenSet{
		AccessToken: tr.AccessToken, RefreshToken: tr.RefreshToken,
		AccessExpiry: now.Add(time.Duration(tr.ExpiresIn) * time.Second).UTC(),
		Scopes:       slices.Sorted(slices.Values(granted)), Account: email, ConnectedAt: now.UTC(),
	}
	if tr.RefreshExpiresIn > 0 {
		ts.RefreshExpiry = now.Add(time.Duration(tr.RefreshExpiresIn) * time.Second).UTC()
	}
	return ts, nil
}

// verifiedEmail reads the e-mail claim of the ID token. The token came from
// Google's token endpoint over TLS in answer to our own request, so OpenID
// Connect Core 3.1.3.7 allows skipping the signature check; the claim is used
// only to name the account.
func verifiedEmail(idToken string) (string, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return "", errors.New("google: no ID token; the openid and email scopes were not granted")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("google: the ID token is malformed")
	}
	var c struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}
	if err := json.Unmarshal(raw, &c); err != nil || c.Email == "" {
		return "", errors.New("google: the ID token has no e-mail address")
	}
	if !c.Verified {
		return "", errors.New("google: the account's e-mail address is not verified")
	}
	return strings.ToLower(c.Email), nil
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("google: random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Revoke tells Google to forget a token (the refresh token revokes the grant).
// `chapd connect google -revoke` calls it; a failure is returned, not hidden.
func Revoke(ctx context.Context, hc *http.Client, ep Endpoints, token string) error {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return postForm(ctx, hc, ep.Revoke, url.Values{"token": {token}}, nil)
}
