package sentry

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/connectors/sentry/sentrytest"
	"github.com/joshua-noel/chaperone/internal/redact"
	"github.com/joshua-noel/chaperone/internal/vault"
)

func tokenOf(s string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return s, nil }
}

// The client sends only to a base URL the policy rule accepts: an https origin
// with an exact DNS host name. There is no exception for a test.
func TestTheClientSendsOnlyToAnExactHTTPSHost(t *testing.T) {
	var hits atomic.Int32
	hc, srv := sentrytest.Serve(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	c, err := NewClient(ClientConfig{Credential: tokenOf(testToken), HTTP: hc})
	if err != nil {
		t.Fatal(err)
	}
	for name, base := range map[string]string{
		"plain http":              "http://sentry.example.com",
		"plain http, loopback":    "http://" + srv.Listener.Addr().String(),
		"https to the loopback":   srv.URL,
		"a user name":             "https://user:pw@sentry.example.com",
		"a path":                  "https://sentry.example.com/sentry",
		"a trailing slash":        "https://sentry.example.com/",
		"a query":                 "https://sentry.example.com?x=1",
		"a fragment":              "https://sentry.example.com#x",
		"upper case":              "https://Sentry.Example.com",
		"an IPv4 address":         "https://192.0.2.7",
		"an IPv4 address, a port": "https://192.0.2.7:8443",
		"localhost":               "https://localhost",
		"a bracketed IPv6":        "https://[::1]",
		"a port above 65535":      "https://sentry.example.com:70000",
		"a space":                 "https://sentry.example.com ",
		"empty":                   "",
		"another scheme":          "ftp://sentry.example.com",
	} {
		_, err := c.GetIssue(context.Background(), Scope{BaseURL: base, Org: "acme"}, "1")
		if err == nil || !Definite(err) {
			t.Errorf("%s: %q: err %v, want a refusal before anything is sent", name, base, err)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("the server got %d requests for a base URL the rule refuses", hits.Load())
	}
	// The ones that are fine reach the server (which answers 200 with no body).
	for _, base := range []string{"https://sentry.io", "https://de.sentry.io", "https://sentry.example.com:8443"} {
		before := hits.Load()
		_, _ = c.GetIssue(context.Background(), Scope{BaseURL: base, Org: "acme"}, "1")
		if hits.Load() != before+1 {
			t.Errorf("%q did not reach the server", base)
		}
	}
}

// The org and the ids that go into a path are checked again by the client.
func TestTheClientChecksWhatGoesIntoAPath(t *testing.T) {
	c, _ := NewClient(ClientConfig{Credential: tokenOf(testToken)})
	s := Scope{BaseURL: "https://sentry.example.com", Org: "acme"}
	for _, bad := range []string{"", "0", "01", "12a", "../1", "1/comments", "1?x=1", "1 2", strings.Repeat("1", 19)} {
		if _, err := c.GetIssue(context.Background(), s, bad); err == nil || !Definite(err) {
			t.Errorf("issue id %q: %v", bad, err)
		}
	}
	for _, bad := range []string{"", "Acme", "a/b", "a b", "../x", "a?b"} {
		if _, err := c.GetIssue(context.Background(), Scope{BaseURL: s.BaseURL, Org: bad}, "1"); err == nil || !Definite(err) {
			t.Errorf("org %q: %v", bad, err)
		}
		if _, err := c.ListIssues(context.Background(), s, bad, ListParams{Status: "unresolved", Limit: 5}); err == nil || !Definite(err) {
			t.Errorf("project %q: %v", bad, err)
		}
	}
	if _, err := c.SetStatus(context.Background(), s, "1", "ignored"); err == nil || !Definite(err) {
		t.Errorf("a status the connector does not set: %v", err)
	}
}

// A client that was given an HTTP client still follows no redirect.
func TestAGivenHTTPClientStillFollowsNoRedirect(t *testing.T) {
	var hits atomic.Int32
	given, _ := sentrytest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			http.Redirect(w, r, "https://other.example.net/x", http.StatusFound)
		}
	}))
	c, _ := NewClient(ClientConfig{Credential: tokenOf(testToken), HTTP: given})
	_, err := c.GetIssue(context.Background(), Scope{BaseURL: "https://sentry.example.com", Org: "acme"}, "1")
	var se *ServiceError
	if !errors.As(err, &se) || se.Status != http.StatusFound || hits.Load() != 1 {
		t.Fatalf("err %v, server hits %d: the redirect was followed", err, hits.Load())
	}
	if given.CheckRedirect != nil {
		t.Error("the caller's HTTP client was changed")
	}
}

// Every error of the client is a fixed sentence: none holds the token, the
// address or text that Sentry wrote.
func TestClientErrorsAreFixedSentences(t *testing.T) {
	hc, srv := sentrytest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(r.Header.Get("Authorization") + " " + r.URL.String()))
	}))
	c, _ := NewClient(ClientConfig{Credential: tokenOf(testToken), HTTP: hc})
	s := Scope{BaseURL: "https://sentry.example.com", Org: "acme"}
	_, err := c.GetIssue(context.Background(), s, "77")
	if err == nil || strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "77") || strings.Contains(err.Error(), "sentry.example.com") {
		t.Errorf("error: %v", err)
	}
	// A server that is not there.
	srv.Close()
	_, err = c.GetIssue(context.Background(), s, "77")
	if err == nil || strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "77") || strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), "sentry.example.com") {
		t.Errorf("error: %v", err)
	}
	if !Definite(err) {
		t.Errorf("a refused connection never sent the request, so it is definite: %v", err)
	}
}

func TestARateLimitAnswerCarriesTheWaitAndIsDefinite(t *testing.T) {
	hc, _ := sentrytest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "12")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	c, _ := NewClient(ClientConfig{Credential: tokenOf(testToken), HTTP: hc})
	_, err := c.GetIssue(context.Background(), Scope{BaseURL: "https://sentry.example.com", Org: "acme"}, "1")
	var rl *RateLimitError
	if !errors.As(err, &rl) || rl.RetryAfter != 12*time.Second || !Definite(err) {
		t.Errorf("err %v", err)
	}
}

// A success that is not the JSON the client reads is not definite: for a write
// the change may have been made.
func TestAnUnreadableSuccessIsNotDefinite(t *testing.T) {
	hc, _ := sentrytest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>")) }))
	c, _ := NewClient(ClientConfig{Credential: tokenOf(testToken), HTTP: hc})
	_, err := c.SetStatus(context.Background(), Scope{BaseURL: "https://sentry.example.com", Org: "acme"}, "1", "resolved")
	if err == nil || Definite(err) {
		t.Errorf("err %v, definite %v", err, Definite(err))
	}
}

// The client registers the token with the redaction registry, so it is masked
// wherever it would appear.
func TestTheClientRegistersTheTokenForRedaction(t *testing.T) {
	e := newEnv(t, nil)
	mustSucceed(t, e.run(OpGet, issUnresolved, nil))
	out, res := e.reg.Redact("the log said " + testToken)
	if !res.Blocked() || strings.Contains(out, testToken) {
		t.Errorf("the token is not masked: %q", out)
	}
}

// ---- the vault ----------------------------------------------------------------

type fakeVault map[string][]byte

func (v fakeVault) Use(_ context.Context, id string, fn func([]byte) error) error {
	b, ok := v[id]
	if !ok {
		return vault.ErrNotFound
	}
	return fn(b)
}

func TestVaultCredentialReadsTheTokenEveryTimeAndTrimsIt(t *testing.T) {
	v := fakeVault{SecretToken: []byte("  first-token-0123456789\n")}
	cred := VaultCredential(v)
	if got, err := cred(context.Background()); err != nil || got != "first-token-0123456789" {
		t.Fatalf("got %q, %v", got, err)
	}
	v[SecretToken] = []byte("rotated-token-0123456789")
	if got, _ := cred(context.Background()); got != "rotated-token-0123456789" {
		t.Errorf("a rotated secret is not picked up: %q", got)
	}
	delete(v, SecretToken)
	if _, err := cred(context.Background()); !errors.Is(err, ErrNotConnected) {
		t.Errorf("no secret: %v", err)
	}
	v[SecretToken] = []byte(" \n")
	if _, err := cred(context.Background()); !errors.Is(err, ErrNotConnected) {
		t.Errorf("a blank secret: %v", err)
	}
}

// Not connected is a refusal the operator can read, and the request was never
// sent.
func TestNotConnectedIsARefusal(t *testing.T) {
	e := newEnv(t, nil)
	client, _ := NewClient(ClientConfig{Credential: VaultCredential(fakeVault{}), Registry: redact.NewRegistry(), HTTP: e.fake.HTTPClient()})
	ads, err := Adapters(Config{Client: client, Policy: rigPolicy(sentrytest.BaseURL)})
	if err != nil {
		t.Fatal(err)
	}
	q := e.req(OpResolve, issUnresolved, nil)
	_, err = ads[OpResolve].Check(context.Background(), q)
	r := wantRefusal(t, err, "OP_POLICY_REFUSED")
	if !strings.Contains(r.Why, "sentry-auth-token") {
		t.Errorf("refusal: %s", r.Why)
	}
	if n := len(e.fake.Requests()); n != 0 {
		t.Errorf("%d requests were sent without a token", n)
	}
}
