// Package googletest is a fake Google for the connector's tests: an OAuth
// authorization and token endpoint (PKCE S256 checked), the Gmail send call and
// the Drive file and permission calls. It never talks to the network. Tests
// build the connector's Endpoints from [Server.URL]:
//
//	Auth: URL+"/auth", Token: URL+"/token", Revoke: URL+"/revoke", Gmail: URL, Drive: URL
//
// (The package does not import the connector, so the connector's own tests can
// import it without a cycle.)
package googletest

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Fixed credentials of the fake OAuth client.
const (
	ClientID     = "123456789-fake.apps.googleusercontent.com"
	ClientSecret = "GOCSPX-fakefakefakefakefakefake"
)

// SendMode says what the Gmail send call does.
type SendMode int

const (
	SendOK         SendMode = iota
	SendReject              // 403 before sending anything
	SendServerErr           // 503 after the message was accepted: outcome unknown
	SendDropAnswer          // the message is accepted, then the connection is cut
)

// Mail is one message the fake Gmail accepted.
type Mail struct {
	Raw   []byte // the decoded `raw` field, byte for byte
	Token string // the bearer token the call carried
}

// File is a Drive file the fake holds.
type File struct {
	ID, Name, MimeType string
	Trashed            bool
	CanShare           bool
}

// Permission is one permission the fake Drive created.
type Permission struct {
	FileID, Email, Role string
	Notify              bool
	Type                string
}

type codeInfo struct {
	challenge, redirect string
	scopes              []string
}

type refreshInfo struct {
	scopes  []string
	revoked bool
}

// Server is the fake. Fields behind mu are reached through methods.
type Server struct {
	*httptest.Server
	// Email is the account the fake signs in as. Set before use.
	Email string
	// TestingMode makes the token endpoint say the refresh token ends in 7
	// days, as it does for an app whose consent screen is in Testing.
	TestingMode bool
	// Now is the fake's clock; nil means time.Now.
	Now func() time.Time

	mu       sync.Mutex
	codes    map[string]codeInfo
	refresh  map[string]*refreshInfo
	access   map[string]time.Time
	seq      int
	mail     []Mail
	files    map[string]*File
	perms    []Permission
	sendMode SendMode
	tokenHit int
	// RefreshCalls counts refresh_token grants.
	refreshCalls int
	// authedBy holds the scopes of each access token.
	scopesOf map[string][]string
}

// New starts a fake and stops it with the test.
func New(t testing.TB) *Server {
	t.Helper()
	s := &Server{
		Email: "operator@example.com", codes: map[string]codeInfo{}, refresh: map[string]*refreshInfo{},
		access: map[string]time.Time{}, files: map[string]*File{}, scopesOf: map[string][]string{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth", s.auth)
	mux.HandleFunc("POST /token", s.token)
	mux.HandleFunc("POST /revoke", s.revoke)
	mux.HandleFunc("POST /gmail/v1/users/me/messages/send", s.send)
	mux.HandleFunc("GET /drive/v3/files/{id}", s.getFile)
	mux.HandleFunc("POST /drive/v3/files/{id}/permissions", s.createPerm)
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) next(prefix string, n int) string {
	s.seq++
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s%d-%s", prefix, s.seq, base64.RawURLEncoding.EncodeToString(b))
}

// ---- OAuth ----

// auth is the sign-in page: it only checks the request is well formed and
// answers 200. Tests call [Server.Approve] to play the browser.
func (s *Server) auth(w http.ResponseWriter, r *http.Request) {
	if _, err := s.checkAuth(r.URL.Query()); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Fprint(w, "sign in")
}

func (s *Server) checkAuth(q url.Values) (codeInfo, error) {
	switch {
	case q.Get("client_id") != ClientID:
		return codeInfo{}, fmt.Errorf("unknown client")
	case q.Get("response_type") != "code":
		return codeInfo{}, fmt.Errorf("response_type must be code")
	case q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43:
		return codeInfo{}, fmt.Errorf("PKCE S256 is required")
	case q.Get("state") == "":
		return codeInfo{}, fmt.Errorf("state is required")
	case !strings.HasPrefix(q.Get("redirect_uri"), "http://127.0.0.1:"):
		return codeInfo{}, fmt.Errorf("redirect_uri must be a loopback address")
	case q.Get("access_type") != "offline":
		return codeInfo{}, fmt.Errorf("access_type must be offline")
	}
	return codeInfo{challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri"), scopes: strings.Fields(q.Get("scope"))}, nil
}

// Approve plays the operator's browser: it checks the sign-in URL, then follows
// the redirect with a fresh code and the same state. Pass grant to limit the
// scopes the operator "ticks"; nil grants all asked.
func (s *Server) Approve(authURL string, grant []string) error {
	u, err := url.Parse(authURL)
	if err != nil {
		return err
	}
	q := u.Query()
	ci, err := s.checkAuth(q)
	if err != nil {
		return err
	}
	if grant != nil {
		ci.scopes = grant
	}
	s.mu.Lock()
	code := s.next("4/0fake-", 24)
	s.codes[code] = ci
	s.mu.Unlock()
	resp, err := http.Get(ci.redirect + "?" + url.Values{"code": {code}, "state": {q.Get("state")}}.Encode())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("the redirect answered %d", resp.StatusCode)
	}
	return nil
}

func oauthErr(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthErr(w, 400, "invalid_request", "bad form")
		return
	}
	f := r.PostForm
	if f.Get("client_id") != ClientID || f.Get("client_secret") != ClientSecret {
		oauthErr(w, 401, "invalid_client", "The OAuth client was not found.")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokenHit++
	resp := map[string]any{"token_type": "Bearer"}
	switch f.Get("grant_type") {
	case "authorization_code":
		ci, ok := s.codes[f.Get("code")]
		delete(s.codes, f.Get("code")) // single use
		if !ok {
			oauthErr(w, 400, "invalid_grant", "Bad Request")
			return
		}
		sum := sha256.Sum256([]byte(f.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != ci.challenge || f.Get("redirect_uri") != ci.redirect {
			oauthErr(w, 400, "invalid_grant", "Bad Request")
			return
		}
		rt := s.next("1//0fake-refresh-", 32)
		s.refresh[rt] = &refreshInfo{scopes: ci.scopes}
		resp["refresh_token"] = rt
		resp["scope"] = strings.Join(ci.scopes, " ")
		if s.TestingMode {
			resp["refresh_token_expires_in"] = 604799
		}
		if has(ci.scopes, "openid") && has(ci.scopes, "email") {
			resp["id_token"] = idToken(s.Email, true)
		}
		s.mintAccess(resp, ci.scopes)
	case "refresh_token":
		s.refreshCalls++
		ri, ok := s.refresh[f.Get("refresh_token")]
		if !ok || ri.revoked {
			oauthErr(w, 400, "invalid_grant", "Token has been expired or revoked.")
			return
		}
		s.mintAccess(resp, ri.scopes)
		resp["scope"] = strings.Join(ri.scopes, " ")
	default:
		oauthErr(w, 400, "unsupported_grant_type", "")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) mintAccess(resp map[string]any, scopes []string) {
	at := s.next("ya29.fake-access-", 24)
	s.access[at] = s.now().Add(time.Hour)
	s.scopesOf[at] = scopes
	resp["access_token"] = at
	resp["expires_in"] = 3600
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	s.mu.Lock()
	defer s.mu.Unlock()
	if ri, ok := s.refresh[r.PostForm.Get("token")]; ok {
		ri.revoked = true
	}
	w.WriteHeader(200)
}

func idToken(email string, verified bool) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(map[string]string{"alg": "RS256"}) + "." + enc(map[string]any{"email": email, "email_verified": verified, "iss": "https://accounts.google.com"}) + ".c2ln"
}

func has(l []string, s string) bool {
	for _, e := range l {
		if e == s {
			return true
		}
	}
	return false
}

// ---- test knobs ----

// RevokeAll makes every refresh token answer invalid_grant, as after the user
// removes the app, or when a Testing-mode token passes its 7 days.
func (s *Server) RevokeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ri := range s.refresh {
		ri.revoked = true
	}
}

// ExpireAccess makes every issued access token answer 401.
func (s *Server) ExpireAccess() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.access {
		s.access[k] = time.Unix(0, 0)
	}
}

// SetSendMode chooses what the Gmail send call does.
func (s *Server) SetSendMode(m SendMode) {
	s.mu.Lock()
	s.sendMode = m
	s.mu.Unlock()
}

// AddFile puts a Drive file on the fake.
func (s *Server) AddFile(f File) {
	s.mu.Lock()
	cp := f
	s.files[f.ID] = &cp
	s.mu.Unlock()
}

// Sent returns the messages Gmail accepted.
func (s *Server) Sent() []Mail {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Mail(nil), s.mail...)
}

// Permissions returns the permissions Drive created.
func (s *Server) Permissions() []Permission {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Permission(nil), s.perms...)
}

// RefreshCalls is the number of refresh_token grants served.
func (s *Server) RefreshCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshCalls
}

// ---- APIs ----

// bearer checks the Authorization header; it answers 401 itself when the token
// is unknown or expired and returns false.
func (s *Server) bearer(w http.ResponseWriter, r *http.Request, scope string) (string, bool) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.mu.Lock()
	exp, ok := s.access[tok]
	scopes := s.scopesOf[tok]
	s.mu.Unlock()
	if !ok || !s.now().Before(exp) {
		apiErr(w, 401, "UNAUTHENTICATED", "authError", "Invalid Credentials")
		return "", false
	}
	if !has(scopes, scope) {
		apiErr(w, 403, "PERMISSION_DENIED", "insufficientPermissions", "Request had insufficient authentication scopes.")
		return "", false
	}
	return tok, true
}

func apiErr(w http.ResponseWriter, status int, st, reason, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
		"code": status, "message": msg, "status": st, "errors": []map[string]string{{"reason": reason, "message": msg}},
	}})
}

func (s *Server) send(w http.ResponseWriter, r *http.Request) {
	tok, ok := s.bearer(w, r, "https://www.googleapis.com/auth/gmail.send")
	if !ok {
		return
	}
	var in struct {
		Raw string `json:"raw"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<20)).Decode(&in); err != nil {
		apiErr(w, 400, "INVALID_ARGUMENT", "invalid", "bad body")
		return
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(in.Raw, "="))
	if err != nil {
		apiErr(w, 400, "INVALID_ARGUMENT", "invalidArgument", "Invalid value for ByteString")
		return
	}
	s.mu.Lock()
	mode := s.sendMode
	if mode != SendReject {
		s.mail = append(s.mail, Mail{Raw: raw, Token: tok})
	}
	id := strconv.Itoa(len(s.mail))
	s.mu.Unlock()
	switch mode {
	case SendReject:
		apiErr(w, 403, "PERMISSION_DENIED", "rateLimitExceeded", "Daily user sending quota exceeded.")
	case SendServerErr:
		apiErr(w, 503, "UNAVAILABLE", "backendError", "Backend Error")
	case SendDropAnswer:
		if h, ok := w.(http.Hijacker); ok {
			c, _, err := h.Hijack()
			if err == nil {
				_ = c.Close()
			}
		}
	default:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "msg" + id, "threadId": "thr" + id, "labelIds": []string{"SENT"}})
	}
}

func (s *Server) getFile(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.bearer(w, r, "https://www.googleapis.com/auth/drive"); !ok {
		return
	}
	s.mu.Lock()
	f := s.files[r.PathValue("id")]
	s.mu.Unlock()
	if f == nil {
		apiErr(w, 404, "NOT_FOUND", "notFound", "File not found: "+r.PathValue("id"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id": f.ID, "name": f.Name, "mimeType": f.MimeType, "trashed": f.Trashed,
		"capabilities": map[string]bool{"canShare": f.CanShare}, "owners": []map[string]string{{"emailAddress": s.Email}},
	})
}

func (s *Server) createPerm(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.bearer(w, r, "https://www.googleapis.com/auth/drive"); !ok {
		return
	}
	var in struct {
		Type, Role, EmailAddress string
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		apiErr(w, 400, "INVALID_ARGUMENT", "invalid", "bad body")
		return
	}
	id := r.PathValue("id")
	s.mu.Lock()
	_, known := s.files[id]
	if known {
		s.perms = append(s.perms, Permission{FileID: id, Email: in.EmailAddress, Role: in.Role, Type: in.Type,
			Notify: r.URL.Query().Get("sendNotificationEmail") != "false"})
	}
	n := len(s.perms)
	s.mu.Unlock()
	if !known {
		apiErr(w, 404, "NOT_FOUND", "notFound", "File not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"id": "perm" + strconv.Itoa(n)})
}
