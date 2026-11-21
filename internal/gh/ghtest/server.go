// Package ghtest is a fake GitHub REST server for Chaperone's tests (L1-05; reused
// by L1-09 and L1-10). It models only what ADR-002 uses: installations, App JWT
// checks, installation tokens (narrowing, expiry, revoke), repositories with a
// commit graph, pull requests, check runs, compare, merge, update-branch,
// deployments, issues (open, comment, reopen), and injectable faults (rate limits, 5xx).
//
// What is modelled on purpose:
//
//   - A Free-plan repository has no branch protection, so by default the fake
//     merges a red or stale PR happily, exactly as GitHub does. That is what
//     lets L1-10 prove that Chaperone refuses first. [Repo.Protect] turns on a
//     Team-plan-style required check and "up to date" rule, so this package's
//     own tests can show every refusal GitHub itself can make.
//   - A merge request with `sha` that is not the PR head answers 409.
//   - A token that does not cover a repository gets 404, one that lacks a
//     permission 403 "Resource not accessible by integration", a revoked,
//     expired or unknown one 401 "Bad credentials".
//
// [INFERENCE] The status codes follow GitHub's REST docs; the exact `message`
// strings for 405 merge refusals are modelled from memory of GitHub's wording
// and are not asserted by the client, which relies on the status code only.
//
// Nothing here uses a real key: the App key is generated at first use.
package ghtest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	keyOnce sync.Once
	testKey *rsa.PrivateKey
)

// TestKey returns the process-wide RSA key the fake accepts as the App key.
// Generated at runtime, never written to disk.
func TestKey() *rsa.PrivateKey {
	keyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		testKey = k
	})
	return testKey
}

// TokenStyle selects the shape of minted tokens. Clients must treat both as opaque.
type TokenStyle int

const (
	// Stateless is the 2026 form: "ghs_<appid>_<jwt-like>", about 520 characters.
	Stateless TokenStyle = iota
	// Legacy is the old 40-character form.
	Legacy
)

// Request is one logged request. Authorization is never logged.
type Request struct {
	Method string
	Path   string // unescaped path
	Query  string
	Body   string
}

// Server is the fake. Create with [New].
type Server struct {
	t     testing.TB
	srv   *httptest.Server
	appID string

	mu       sync.Mutex
	now      time.Time
	seq      int64
	style    TokenStyle
	installs map[int64]*Installation
	tokens   map[string]*tokenRec
	log      []Request
	logMax   int // 0: keep every request
	bodyMax  int // 0: keep whole bodies
	faults   []*fault
	before   []*hook
	mintAll  bool
	web      manifestState // the app-manifest flow (manifest.go)
}

// New starts the fake on a loopback port and stops it when the test ends. The
// fake clock starts at 2026-10-24T12:00:00Z.
func New(t testing.TB) *Server {
	t.Helper()
	s := &Server{
		t:        t,
		appID:    "424242",
		now:      time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC),
		installs: map[int64]*Installation{},
		tokens:   map[string]*tokenRec{},
	}
	s.srv = httptest.NewServer(s.routes())
	t.Cleanup(s.srv.Close)
	return s
}

// Close stops the server early (a test of transport errors); New also closes it at cleanup.
func (s *Server) Close() { s.srv.Close() }

// URL is the base URL for gh.Config.BaseURL.
func (s *Server) URL() string { return s.srv.URL }

// AppID is the iss the fake expects in the App JWT.
func (s *Server) AppID() string { return s.appID }

// Key is the App key the fake verifies JWTs against (see [TestKey]).
func (s *Server) Key() *rsa.PrivateKey { return TestKey() }

// Now is the fake clock; pass it as gh.Config.Now.
func (s *Server) Now() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.now
}

// Advance moves the fake clock forward (token expiry, JWT expiry).
func (s *Server) Advance(d time.Duration) {
	s.mu.Lock()
	s.now = s.now.Add(d)
	s.mu.Unlock()
}

// SkipIDs moves the id counter forward by n, before anything is created. Commit
// SHAs come from that counter, so a caller that runs the fake outside a test
// (the quickstart playground) gets SHAs that differ from run to run and no
// operation of an earlier run matches one of this run.
func (s *Server) SkipIDs(n int64) {
	s.mu.Lock()
	s.seq += n
	s.mu.Unlock()
}

// SetTokenStyle picks the token shape for later mints.
func (s *Server) SetTokenStyle(st TokenStyle) {
	s.mu.Lock()
	s.style = st
	s.mu.Unlock()
}

// MintAnswersAll makes the next mint ignore the narrowing and answer with a token
// for every repository and permission of the installation, as GitHub does when a
// request omits them. It models a server that does not honour the request, so a
// client must detect it.
func (s *Server) MintAnswersAll() {
	s.mu.Lock()
	s.mintAll = true
	s.mu.Unlock()
}

// Requests returns a copy of the request log.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.log...)
}

// Count counts logged requests with the method and a path containing sub.
func (s *Server) Count(method, sub string) int {
	n := 0
	for _, r := range s.Requests() {
		if r.Method == method && strings.Contains(r.Path, sub) {
			n++
		}
	}
	return n
}

// TokenRevoked reports whether a token value has been revoked through the API.
func (s *Server) TokenRevoked(value string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	tr := s.tokens[value]
	return tr != nil && tr.revoked
}

// LiveTokens counts minted tokens that are neither revoked nor expired.
func (s *Server) LiveTokens() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, tr := range s.tokens {
		if !tr.revoked && s.now.Before(tr.expires) {
			n++
		}
	}
	return n
}

// Fault answers matching requests with a canned refusal instead of handling them.
type Fault struct {
	Status  int
	Message string
	Header  http.Header
	// Times is how many requests the fault applies to; 0 means every request
	// until [Server.ClearFaults].
	Times int
}

type fault struct {
	method, sub string
	f           Fault
	used        int
}

// Inject adds a fault for requests with the method and a path containing sub.
func (s *Server) Inject(method, sub string, f Fault) {
	s.mu.Lock()
	s.faults = append(s.faults, &fault{method: method, sub: sub, f: f})
	s.mu.Unlock()
}

// ClearFaults removes every fault.
func (s *Server) ClearFaults() {
	s.mu.Lock()
	s.faults = nil
	s.mu.Unlock()
}

// PrimaryRateLimit is the 403 GitHub sends when the hourly limit is used up.
func (s *Server) PrimaryRateLimit(resetIn time.Duration) Fault {
	h := http.Header{}
	h.Set("X-RateLimit-Limit", "5000")
	h.Set("X-RateLimit-Remaining", "0")
	h.Set("X-RateLimit-Resource", "core")
	h.Set("X-RateLimit-Reset", strconv.FormatInt(s.Now().Add(resetIn).Unix(), 10))
	return Fault{Status: 403, Message: "API rate limit exceeded for installation ID 1.", Header: h}
}

// SecondaryRateLimit is the 403 with Retry-After GitHub sends for abusive request rates.
func SecondaryRateLimit(retryAfter time.Duration) Fault {
	h := http.Header{}
	h.Set("Retry-After", strconv.Itoa(int(retryAfter/time.Second)))
	return Fault{Status: 403, Header: h,
		Message: "You have exceeded a secondary rate limit. Please wait a few minutes before you try again."}
}

// TooManyRequests is a 429 with Retry-After.
func TooManyRequests(retryAfter time.Duration) Fault {
	h := http.Header{}
	h.Set("Retry-After", strconv.Itoa(int(retryAfter/time.Second)))
	return Fault{Status: 429, Header: h, Message: "Too many requests."}
}

// Unavailable is a 503.
func Unavailable() Fault { return Fault{Status: 503, Message: "Service Unavailable"} }

type hook struct {
	method, sub string
	fn          func()
}

// Before runs fn once, just before the next request with the method and a path
// containing sub is handled. Use it to move a PR head between a client's read
// and its merge. fn must not call t.Fatal (it runs on a server goroutine).
func (s *Server) Before(method, sub string, fn func()) {
	s.mu.Lock()
	s.before = append(s.before, &hook{method, sub, fn})
	s.mu.Unlock()
}

// ---- tokens and installations ----

// Installation is an App installation on one account.
type Installation struct {
	ID      int64
	Account string
	// Granted are the permissions the App holds on this installation.
	Granted map[string]string
	s       *Server
	repos   map[string]*Repo
	app     *App // the App made through the manifest flow that this belongs to; nil: the fake's own App
}

// AddInstallation registers an installation of the App on account with the
// permissions the App was granted (for example contents:write).
func (s *Server) AddInstallation(id int64, account string, granted map[string]string) *Installation {
	in := &Installation{ID: id, Account: account, Granted: granted, s: s, repos: map[string]*Repo{}}
	s.mu.Lock()
	s.installs[id] = in
	s.mu.Unlock()
	return in
}

type tokenRec struct {
	install *Installation
	repos   map[string]bool
	perms   map[string]string
	expires time.Time
	revoked bool
}

func permLevel(s string) int {
	switch s {
	case "read":
		return 1
	case "write":
		return 2
	case "admin":
		return 3
	}
	return 0
}

func (s *Server) newTokenValue() string {
	buf := make([]byte, 400)
	_, _ = rand.Read(buf)
	if s.style == Legacy {
		const alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		b := make([]byte, 36)
		for i := range b {
			b[i] = alnum[int(buf[i])%len(alnum)]
		}
		return "ghs_" + string(b)
	}
	return "ghs_" + s.appID + "_" + base64.RawURLEncoding.EncodeToString(buf)
}

// verifyJWT checks the App JWT the way GitHub does (RS256, iss, exp within 10
// minutes of now, iat not in the future). Returns "" if good, else GitHub's message.
func (s *Server) verifyJWT(authz string) string {
	_, msg := s.verifyApp(authz)
	return msg
}

// verifyApp is verifyJWT that also says which App signed: nil for the fake's own
// App ([OwnAppID], signed with [TestKey]), else an App made through the manifest
// flow (see [Server.Apps]), found by its numeric id or its client id in `iss`.
func (s *Server) verifyApp(authz string) (*App, string) {
	const undecodable = "A JSON web token could not be decoded"
	tok, ok := strings.CutPrefix(authz, "Bearer ")
	if !ok {
		return nil, undecodable
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, undecodable
	}
	sig, err1 := base64.RawURLEncoding.DecodeString(parts[2])
	hdr, err2 := base64.RawURLEncoding.DecodeString(parts[0])
	claimsRaw, err3 := base64.RawURLEncoding.DecodeString(parts[1])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, undecodable
	}
	var h struct{ Alg string }
	if json.Unmarshal(hdr, &h) != nil || h.Alg != "RS256" {
		return nil, undecodable
	}
	var c struct {
		Iss json.RawMessage `json:"iss"`
		Iat int64           `json:"iat"`
		Exp int64           `json:"exp"`
	}
	if json.Unmarshal(claimsRaw, &c) != nil {
		return nil, undecodable
	}
	iss := strings.Trim(string(c.Iss), `"`)
	pub, app := &TestKey().PublicKey, (*App)(nil)
	if iss != s.appID {
		if app = s.appByIss(iss); app == nil {
			return nil, undecodable
		}
		pub = &app.key.PublicKey
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig) != nil {
		return nil, undecodable
	}
	s.mu.Lock()
	now := s.now.Unix()
	s.mu.Unlock()
	switch {
	case c.Iat > now:
		return nil, "'Issued at' claim ('iat') must be an Integer representing the time that the assertion was issued"
	case c.Exp <= now:
		return nil, "'Expiration time' claim ('exp') must be a numeric value representing the future time at which the assertion expires"
	case c.Exp > now+600:
		return nil, "'Expiration time' claim ('exp') is too far in the future"
	}
	return app, ""
}

func bearer(r *http.Request) string {
	a := r.Header.Get("Authorization")
	if v, ok := strings.CutPrefix(a, "token "); ok {
		return "Bearer " + v
	}
	return a
}

// tokenFor resolves the installation token of a request; "" message means ok.
func (s *Server) tokenFor(r *http.Request) (*tokenRec, string, string) {
	v, ok := strings.CutPrefix(bearer(r), "Bearer ")
	s.mu.Lock()
	defer s.mu.Unlock()
	tr := s.tokens[v]
	if !ok || tr == nil || tr.revoked || !s.now.Before(tr.expires) {
		return nil, "", "Bad credentials"
	}
	return tr, v, ""
}

func (s *Server) fail(t testing.TB, format string, a ...any) {
	t.Helper()
	t.Errorf("ghtest: "+format, a...)
}

func jsonOut(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func refuse(w http.ResponseWriter, status int, msg string) {
	jsonOut(w, status, map[string]any{"message": msg, "documentation_url": "https://docs.github.com/rest"})
}

func (s *Server) nextID() int64 {
	s.seq++
	return s.seq
}

func hexSHA(n int64, salt string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s/%d", salt, n)))
	return fmt.Sprintf("%x", sum[:20])
}

// CapLog bounds the request log: at most maxEntries requests are kept (the
// oldest are dropped) and each body is cut to maxBody bytes. Without it the log
// keeps every request whole, which suits a test and not a long-running fake (the
// quickstart playground, whose loopback port any local process can call).
// Count and Requests then see only what is kept.
func (s *Server) CapLog(maxEntries, maxBody int) {
	s.mu.Lock()
	s.logMax, s.bodyMax = maxEntries, maxBody
	s.mu.Unlock()
}

// record appends to the log under s.mu, honouring CapLog. The body is cut before it
// becomes a string, so the log keeps a copy of at most bodyMax bytes and not the
// whole request body (a substring of a large string would keep all of it alive).
func (s *Server) record(method, path, query string, body []byte) {
	if s.bodyMax > 0 && len(body) > s.bodyMax {
		body = body[:s.bodyMax]
	}
	s.log = append(s.log, Request{Method: method, Path: path, Query: query, Body: string(body)})
	if s.logMax > 0 && len(s.log) > s.logMax {
		n := copy(s.log, s.log[len(s.log)-s.logMax:])
		clear(s.log[n:]) // drop the references the old tail still holds
		s.log = s.log[:n]
	}
}
