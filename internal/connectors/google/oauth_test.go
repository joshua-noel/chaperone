package google

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/connectors/google/googletest"
)

func TestConnectLoopbackPKCE(t *testing.T) {
	r := newRig(t, false)
	var authURL string
	ts, err := Connect(context.Background(), ConnectConfig{
		Client: ClientCreds{ClientID: googletest.ClientID, ClientSecret: googletest.ClientSecret}, Scopes: []string{ScopeGmailSend},
		Endpoints: r.ep, Now: r.clock.Now, Timeout: 10 * time.Second,
		OpenURL: func(u string) error { authURL = u; return r.fake.Approve(u, nil) },
	})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(authURL)
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 || q.Get("state") == "" {
		t.Errorf("PKCE or state missing: %v", q)
	}
	if !strings.HasPrefix(q.Get("redirect_uri"), "http://127.0.0.1:") || q.Get("access_type") != "offline" {
		t.Errorf("redirect or offline access wrong: %v", q)
	}
	if got := strings.Fields(q.Get("scope")); !slices.Equal(got, []string{ScopeGmailSend, "openid", "email"}) {
		t.Errorf("scopes %v", got)
	}
	if ts.Account != "operator@example.com" || !ts.HasScope(ScopeGmailSend) || ts.RefreshToken == "" || ts.AccessToken == "" {
		t.Errorf("token set: %+v", ts)
	}
	if !ts.RefreshExpiry.IsZero() {
		t.Error("a production app's refresh token has no fixed end")
	}
	if !ts.AccessExpiry.Equal(r.clock.Now().Add(time.Hour)) {
		t.Errorf("access expiry %v", ts.AccessExpiry)
	}
}

func TestConnectRefusals(t *testing.T) {
	cc := ClientCreds{ClientID: googletest.ClientID, ClientSecret: googletest.ClientSecret}
	t.Run("a scope the operator unticked", func(t *testing.T) {
		r := newRig(t, false)
		_, err := Connect(context.Background(), ConnectConfig{Client: cc, Scopes: []string{ScopeGmailSend, ScopeDrive}, Endpoints: r.ep, Timeout: 5 * time.Second,
			OpenURL: func(u string) error {
				return r.fake.Approve(u, []string{ScopeGmailSend, "openid", "email"})
			}})
		if err == nil || !strings.Contains(err.Error(), ScopeDrive) {
			t.Fatalf("want a missing-scope error, got %v", err)
		}
	})
	t.Run("wrong client secret", func(t *testing.T) {
		r := newRig(t, false)
		bad := cc
		bad.ClientSecret = "GOCSPX-wrongwrongwrongwrong"
		_, err := Connect(context.Background(), ConnectConfig{Client: bad, Scopes: []string{ScopeGmailSend}, Endpoints: r.ep, Timeout: 5 * time.Second,
			OpenURL: func(u string) error { return r.fake.Approve(u, nil) }})
		if err == nil || !strings.Contains(err.Error(), "invalid_client") || strings.Contains(err.Error(), bad.ClientSecret) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a redirect with another state is refused and the flow goes on", func(t *testing.T) {
		r := newRig(t, false)
		ts, err := Connect(context.Background(), ConnectConfig{Client: cc, Scopes: []string{ScopeGmailSend}, Endpoints: r.ep, Timeout: 5 * time.Second,
			OpenURL: func(u string) error {
				q := mustQuery(t, u)
				resp, err := http.Get(q.Get("redirect_uri") + "?code=evil&state=guess")
				if err != nil {
					return err
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusBadRequest {
					t.Errorf("forged state answered %d", resp.StatusCode)
				}
				return r.fake.Approve(u, nil)
			}})
		if err != nil || ts == nil {
			t.Fatalf("the genuine redirect after a forged one must still work: %v", err)
		}
	})
	t.Run("a forged host header on the callback", func(t *testing.T) {
		r := newRig(t, false)
		_, err := Connect(context.Background(), ConnectConfig{Client: cc, Scopes: []string{ScopeGmailSend}, Endpoints: r.ep, Timeout: 300 * time.Millisecond,
			OpenURL: func(u string) error {
				q := mustQuery(t, u)
				req, _ := http.NewRequest("GET", q.Get("redirect_uri")+"?code=x&state="+q.Get("state"), nil)
				req.Host = "evil.example"
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					return err
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusNotFound {
					t.Errorf("rebinding host answered %d", resp.StatusCode)
				}
				return nil
			}})
		if err == nil {
			t.Fatal("a callback with a foreign Host must not complete the sign-in")
		}
	})
	t.Run("the user denies", func(t *testing.T) {
		r := newRig(t, false)
		_, err := Connect(context.Background(), ConnectConfig{Client: cc, Scopes: []string{ScopeGmailSend}, Endpoints: r.ep, Timeout: 5 * time.Second,
			OpenURL: func(u string) error {
				q := mustQuery(t, u)
				resp, err := http.Get(q.Get("redirect_uri") + "?error=access_denied&state=" + q.Get("state"))
				if err == nil {
					resp.Body.Close()
				}
				return err
			}})
		if err == nil || !strings.Contains(err.Error(), "access_denied") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("no refresh token or plain-http non-loopback endpoint", func(t *testing.T) {
		if _, err := tokensFromExchange(&tokenResponse{AccessToken: "ya29.x"}, nil, time.Now()); err == nil {
			t.Error("a response without a refresh token must be refused")
		}
		ep := DefaultEndpoints()
		ep.Token = "http://example.com/token"
		if err := ep.Validate(); err == nil {
			t.Error("a plain-http token endpoint on the internet must be refused")
		}
		if err := DefaultEndpoints().Validate(); err != nil {
			t.Error(err)
		}
	})
}

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

func TestParseClientJSON(t *testing.T) {
	c, err := ParseClientJSON([]byte(`{"installed":{"client_id":"a.apps.googleusercontent.com","client_secret":"GOCSPX-abcdefghij","redirect_uris":["http://localhost"]}}`))
	if err != nil || c.ClientID == "" || c.ClientSecret == "" {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := ParseClientJSON([]byte(`{"web":{"client_id":"a","client_secret":"b"}}`)); err == nil || !strings.Contains(err.Error(), "Desktop") {
		t.Errorf("a web client must be refused with a hint: %v", err)
	}
	if _, err := ParseClientJSON([]byte(`not json`)); err == nil {
		t.Error("garbage must be refused")
	}
}

func TestTokensLiveInTheVaultAndAreMasked(t *testing.T) {
	r := newRig(t, true)
	ctx := context.Background()
	info, err := r.vault.Info(ctx, TokenSecretID)
	if err != nil || info.Kind != "google-oauth-token" {
		t.Fatalf("%+v %v", info, err)
	}
	var ts TokenSet
	_ = r.src.cfg.Secrets.Use(ctx, TokenSecretID, func(b []byte) error { ts = TokenSet{}; return json.Unmarshal(b, &ts) })
	for _, secret := range []string{ts.AccessToken, ts.RefreshToken, googletest.ClientSecret} {
		out, res := r.reg.Redact("log line with " + secret + " inside")
		if !res.Blocked() || strings.Contains(out, secret) {
			t.Errorf("a quoted secret was not masked: %q", out)
		}
	}
}

func TestRefreshWritesBackAndKeepsAccount(t *testing.T) {
	r := newRig(t, true)
	ctx := context.Background()
	a1, _, err := r.src.Token(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a2, _, _ := r.src.Token(ctx)
	if a1 != a2 || r.fake.RefreshCalls() != 0 {
		t.Fatalf("a fresh token must be reused: refreshes=%d", r.fake.RefreshCalls())
	}
	r.clock.Advance(59 * time.Minute) // inside the two-minute skew
	a3, ts, err := r.src.Token(ctx)
	if err != nil || a3 == a1 || r.fake.RefreshCalls() != 1 {
		t.Fatalf("expected one refresh: %v %d", err, r.fake.RefreshCalls())
	}
	if ts.Account != "operator@example.com" || ts.RefreshToken == "" {
		t.Fatalf("%+v", ts)
	}
	st := r.src.Status(ctx)
	if !st.Connected || st.AccessExpiry.Before(r.clock.Now().Add(50*time.Minute)) {
		t.Errorf("the vault does not hold the refreshed set: %+v", st)
	}
	info, _ := r.vault.Info(ctx, TokenSecretID)
	if info.Rotated.IsZero() {
		t.Error("the refreshed set must be a vault rotation")
	}
}

func TestRevokedRefreshTokenAlertsAndFailsClosed(t *testing.T) {
	r := newRig(t, true)
	ctx := context.Background()
	r.fake.RevokeAll()
	r.clock.Advance(2 * time.Hour)
	_, _, err := r.src.Token(ctx)
	if !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("got %v", err)
	}
	if r.alerts.count(AlertReauth) != 1 {
		t.Fatalf("alerts: %v", r.alerts.keys)
	}
	// Asked again: still refused, and the alert is not repeated.
	_, _, _ = r.src.Token(ctx)
	if r.alerts.count(AlertReauth) != 1 {
		t.Errorf("the alert must fire once per outage: %v", r.alerts.keys)
	}
	st := r.src.Status(ctx)
	if !st.ReauthRequired || st.Problem(r.clock.Now()) == "" {
		t.Errorf("status must show the outage: %+v", st)
	}
	// The ops refuse with a message that says what to do, never a send attempt.
	_, err = r.gmail.Check(ctx, mailReq(okMail()))
	ref := wantRefusal(t, err, "OP_POLICY_REFUSED")
	if !strings.Contains(ref.Why, "connect google") {
		t.Errorf("the refusal must say how to fix it: %s", ref.Why)
	}
	// Signing in again clears it and re-arms the alert.
	r.fake.Email = "operator@example.com"
	r.connect(ScopeGmailSend, ScopeDrive)
	if _, err := r.gmail.Check(ctx, mailReq(okMail())); err != nil {
		t.Fatalf("after a new sign-in: %v", err)
	}
}

func TestMonitorFindsARevokedGrantWithoutAnyOp(t *testing.T) {
	r := newRig(t, true)
	r.fake.RevokeAll()
	Monitor{Source: r.src}.Probe(context.Background())
	if r.alerts.count(AlertReauth) != 1 {
		t.Fatalf("the monitor must raise the alert: %v", r.alerts.keys)
	}
	// A monitor on a never-connected vault is quiet.
	q := newRig(t, false)
	Monitor{Source: q.src}.Probe(context.Background())
	if len(q.alerts.keys) != 0 {
		t.Errorf("no connection, no alert: %v", q.alerts.keys)
	}
}

func TestTestingModeTokenExpiryIsAlertedBeforeItEnds(t *testing.T) {
	r := newRig(t, false)
	r.fake.TestingMode = true
	ts := r.connect(ScopeGmailSend)
	if ts.RefreshExpiry.IsZero() || !ts.RefreshExpiry.Equal(r.clock.Now().Add(604799*time.Second)) {
		t.Fatalf("Google's 7-day refresh_token_expires_in was not recorded: %v", ts.RefreshExpiry)
	}
	ctx := context.Background()
	if _, _, err := r.src.Token(ctx); err != nil || len(r.alerts.keys) != 0 {
		t.Fatalf("day 0: %v %v", err, r.alerts.keys)
	}
	r.clock.Advance(5 * 24 * time.Hour) // 2 days left: inside the 48 h warning
	if _, _, err := r.src.Token(ctx); err != nil {
		t.Fatal(err)
	}
	if r.alerts.count(AlertExpiring) != 1 {
		t.Fatalf("no expiry warning two days ahead: %v", r.alerts.keys)
	}
	r.clock.Advance(3 * 24 * time.Hour) // past the end
	if _, _, err := r.src.Token(ctx); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("an expired sign-in must fail closed, got %v", err)
	}
	if r.alerts.count(AlertReauth) != 1 {
		t.Errorf("expiry must raise the reauth alert: %v", r.alerts.keys)
	}
	if p := r.src.Status(ctx).Problem(r.clock.Now()); !strings.Contains(p, "Testing") {
		t.Errorf("the status must say why: %q", p)
	}
}

func TestNotConnected(t *testing.T) {
	r := newRig(t, false)
	_, err := r.gmail.Check(context.Background(), mailReq(okMail()))
	ref := wantRefusal(t, err, "OP_POLICY_REFUSED")
	if !strings.Contains(ref.Why, "not connected") {
		t.Error(ref.Why)
	}
	if _, err := LoadClient(context.Background(), newRig(t, false).vault); err != nil {
		t.Fatal(err)
	}
}

func TestLoadClientAcceptsGoogleDownloadAsIs(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	doc := `{"installed":{"client_id":"` + googletest.ClientID + `","client_secret":"` + googletest.ClientSecret + `","redirect_uris":["http://localhost"]}}`
	if _, err := r.vault.Rotate(ctx, ClientSecretID, []byte(doc)); err != nil {
		t.Fatal(err)
	}
	c, err := LoadClient(ctx, r.vault)
	if err != nil || c.ClientID != googletest.ClientID || c.ClientSecret != googletest.ClientSecret {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := r.vault.Rotate(ctx, ClientSecretID, []byte(`{"web":{"client_id":"a","client_secret":"bbbbbbbbb"}}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadClient(ctx, r.vault); err == nil {
		t.Fatal("a web client must not load")
	}
}
