// Package sentrytest is a fake Sentry for the connector's tests. It never talks
// to the network: it listens on a loopback port that the test owns.
//
// It answers the routes of the connector, in the shapes the real API uses as the
// author knows them (nothing here was compared with a real Sentry):
//
//	GET  /api/0/projects/{org}/{project}/issues/           a page of issues, with a Link header
//	GET  /api/0/organizations/{org}/issues/{id}/           one issue
//	GET  /api/0/organizations/{org}/issues/{id}/events/latest/
//	PUT  /api/0/organizations/{org}/issues/{id}/           {"status": ...} or {"assignedTo": ...}
//	POST /api/0/organizations/{org}/issues/{id}/comments/  {"text": ...}
//
// Every event carries what a real event can carry and chapd must never return:
// request headers and cookies, a request body, a user's email and address, local
// variables, breadcrumbs, tags and the exception's message. [Event].Sensitive is
// planted in all of them, so a test can look for it in a result.
//
// The fake is an https server on the loopback, and a connector under test must
// reach it the way it reaches Sentry: by the policy's base URL, which is [BaseURL],
// an https origin with an exact DNS host name. The client for that is
// [Server.HTTPClient]: it trusts the fake's certificate and sends every request to
// the fake, whatever host the URL names. So the strict rule of the connector is
// exercised by every test, and no test needs a relaxed one.
//
// The package does not import the connector, so the connector's own tests can
// import it without a cycle.
package sentrytest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// BaseURL is the base URL a test puts in the policy: an https origin with an
// exact DNS host name, as the policy rule requires. [Server.HTTPClient] sends it
// to the fake.
const BaseURL = "https://sentry.example.com"

// Frame is one stack frame of an event.
type Frame struct {
	Filename, AbsPath, Function string
	Line                        int
	InApp                       bool
}

// Exception is one exception of an event.
type Exception struct {
	Type, Value string
	Frames      []Frame // outermost call first, as Sentry sends them
}

// Event is the latest event of an issue.
type Event struct {
	ID, Date   string
	Exceptions []Exception // the oldest first, the one that was raised last
	// Sensitive is put in the request headers, cookies and body, the user, the
	// local variables of every frame, the breadcrumbs, the tags and the contexts.
	Sensitive string
}

// Issue is one issue of the fake.
type Issue struct {
	ID, ShortID, Title, Culprit, Level, Status string
	Count, FirstSeen, LastSeen                 string
	Project                                    string // the slug
	// Assignee is the email the fake shows as the assignee; AssigneeName is the name.
	Assignee, AssigneeName string
	Event                  *Event // nil: the issue has no event (404)
	Notes                  []string
	// AssignedWith is the raw `assignedTo` of the last assignment the fake took.
	AssignedWith string
}

// Request is one request the fake received. The credential is never recorded
// here: see [Server.Credentials].
type Request struct {
	Method, Path, Query string
	Body                string
}

// Server is the fake Sentry.
type Server struct {
	*httptest.Server

	mu      sync.Mutex
	org     string
	token   string
	echo    bool
	issues  map[string]*Issue
	reqs    []Request
	creds   []string
	writes  int
	applied int

	failNext     int // answer the next request with this status
	failWrite    int // answer the next write with this status, and change nothing
	redirectTo   string
	loseAnswer   bool // apply a write, then close the connection without an answer
	ignoreLimit  bool
	leakProjects bool
}

// New starts the fake. The organisation is "acme" and the token it accepts is
// "fake-token" until [Server.SetToken].
func New(t testing.TB) *Server {
	t.Helper()
	s := &Server{org: "acme", token: "fake-token", issues: map[string]*Issue{}}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

// HTTPClient returns an HTTP client that trusts the fake's certificate and sends
// every request to the fake, whatever host the URL names (and so, if it followed
// a redirect, to the fake again, where the test sees it). It follows redirects
// as Go's default client does: the connector is the one that must not.
func (s *Server) HTTPClient() *http.Client { return clientFor(s.Server) }

// Serve starts an https server with the handler and returns a client for it, as
// [Server.HTTPClient] does, and the server so a test can close it. It is for the
// test of a client against an answer the fake does not give.
func Serve(t testing.TB, h http.Handler) (*http.Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return clientFor(srv), srv
}

func clientFor(srv *httptest.Server) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	addr := srv.Listener.Addr().String()
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"}, // the name the test certificate holds
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		},
	}
}

// AddIssue adds an issue, or replaces the one with the same id. Empty fields get
// plain defaults.
func (s *Server) AddIssue(is Issue) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if is.ShortID == "" {
		is.ShortID = strings.ToUpper(is.Project) + "-" + strconv.Itoa(len(s.issues)+1)
	}
	if is.Level == "" {
		is.Level = "error"
	}
	if is.Status == "" {
		is.Status = "unresolved"
	}
	if is.Count == "" {
		is.Count = "7"
	}
	if is.FirstSeen == "" {
		is.FirstSeen = "2026-11-01T08:00:00Z"
	}
	if is.LastSeen == "" {
		is.LastSeen = "2026-11-20T09:30:00.123456Z"
	}
	s.issues[is.ID] = &is
}

// Issue returns a copy of the issue, or the zero value for an unknown id.
func (s *Server) Issue(id string) Issue {
	s.mu.Lock()
	defer s.mu.Unlock()
	if is := s.issues[id]; is != nil {
		c := *is
		c.Notes = append([]string(nil), is.Notes...)
		return c
	}
	return Issue{}
}

// Edit changes an issue under the fake's lock. It does nothing for an unknown id.
func (s *Server) Edit(id string, f func(is *Issue)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if is := s.issues[id]; is != nil {
		f(is)
	}
}

// SetToken sets the credential the fake accepts.
func (s *Server) SetToken(v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = v
}

// SetOrg sets the organisation slug the fake knows; any other is a 404.
func (s *Server) SetOrg(o string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.org = o
}

// Hostile makes the fake behave like a careless service: it stops accepting the
// credential it had (newToken is the one it accepts now), and its error text
// repeats the credential it received.
func (s *Server) Hostile(newToken string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token, s.echo = newToken, true
}

// FailNext makes the next request, whatever it is, answer with this status and
// no work. It is for a test of a refusal or a server error.
func (s *Server) FailNext(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failNext = status
}

// FailNextWrite makes the next write (a PUT or a POST) answer with this status
// and change nothing. A read is answered as usual.
func (s *Server) FailNextWrite(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failWrite = status
}

// RedirectTo makes every request answer 302 with Location to. A client that
// follows it sends its credential again, and the fake records it.
func (s *Server) RedirectTo(to string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.redirectTo = to
}

// LoseWriteAnswers makes a write that the fake accepts close the connection
// without answering: the change is made and the caller cannot tell.
func (s *Server) LoseWriteAnswers() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loseAnswer = true
}

// IgnoreLimit makes the list route ignore the limit param and return the whole
// project.
func (s *Server) IgnoreLimit() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ignoreLimit = true
}

// ListsEverything makes the list route ignore the project in its path and answer
// with the issues of every project, as a careless server could.
func (s *Server) ListsEverything() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leakProjects = true
}

// Requests returns every request received so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.reqs...)
}

// Credentials returns every credential the fake was sent.
func (s *Server) Credentials() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.creds...)
}

// WriteCalls is how many calls that could change the service the fake has
// received, accepted or not.
func (s *Server) WriteCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writes
}

// WritesApplied is how many of those calls the fake accepted and acted on.
func (s *Server) WritesApplied() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applied
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	s.reqs = append(s.reqs, Request{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Body: string(body)})
	s.creds = append(s.creds, bearer)
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	write := r.Method != http.MethodGet
	if write {
		s.writes++
	}
	if s.redirectTo != "" {
		http.Redirect(w, r, s.redirectTo, http.StatusFound)
		return
	}
	if s.failNext != 0 {
		code := s.failNext
		s.failNext = 0
		if code == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "7")
		}
		reply(code, map[string]string{"detail": "planned failure"})
		return
	}
	if write && s.failWrite != 0 && bearer == s.token {
		code := s.failWrite
		s.failWrite = 0
		if code == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "7")
		}
		reply(code, map[string]string{"detail": "planned failure"})
		return
	}
	if bearer != s.token {
		msg := "Invalid token"
		if s.echo {
			msg += " " + bearer
		}
		reply(http.StatusUnauthorized, map[string]string{"detail": msg})
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/0/"), "/"), "/")
	notFound := func() {
		reply(http.StatusNotFound, map[string]string{"detail": "The requested resource does not exist"})
	}
	switch {
	case len(parts) == 4 && parts[0] == "projects" && parts[3] == "issues" && r.Method == http.MethodGet:
		if parts[1] != s.org {
			notFound()
			return
		}
		s.list(w, r, parts[2])
	case len(parts) >= 4 && parts[0] == "organizations" && parts[2] == "issues":
		if parts[1] != s.org {
			notFound()
			return
		}
		is := s.issues[parts[3]]
		if is == nil {
			notFound()
			return
		}
		s.issue(w, r, is, parts[4:], body, write, reply, notFound)
	default:
		notFound()
	}
}

func (s *Server) issue(w http.ResponseWriter, r *http.Request, is *Issue, rest []string, body []byte, write bool, reply func(int, any), notFound func()) {
	switch {
	case len(rest) == 0 && r.Method == http.MethodGet:
		reply(http.StatusOK, s.issueJSON(is))
	case len(rest) == 2 && rest[0] == "events" && rest[1] == "latest" && r.Method == http.MethodGet:
		if is.Event == nil {
			notFound()
			return
		}
		reply(http.StatusOK, eventJSON(is.Event))
	case len(rest) == 0 && r.Method == http.MethodPut:
		var in struct {
			Status     *string `json:"status"`
			AssignedTo *string `json:"assignedTo"`
		}
		if json.Unmarshal(body, &in) != nil || (in.Status == nil) == (in.AssignedTo == nil) {
			reply(http.StatusBadRequest, map[string]string{"detail": "one of status and assignedTo"})
			return
		}
		if in.Status != nil {
			switch *in.Status {
			case "resolved", "unresolved", "ignored":
				is.Status = *in.Status
			default:
				reply(http.StatusBadRequest, map[string]string{"status": "bad status"})
				return
			}
		} else {
			is.Assignee, is.AssigneeName, is.AssignedWith = *in.AssignedTo, "Member "+*in.AssignedTo, *in.AssignedTo
		}
		s.applied++
		if s.loseAnswer {
			s.drop(w)
			return
		}
		reply(http.StatusOK, s.issueJSON(is))
	case len(rest) == 1 && rest[0] == "comments" && r.Method == http.MethodPost:
		var in struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(body, &in) != nil || strings.TrimSpace(in.Text) == "" {
			reply(http.StatusBadRequest, map[string]string{"text": "required"})
			return
		}
		is.Notes = append(is.Notes, in.Text)
		s.applied++
		if s.loseAnswer {
			s.drop(w)
			return
		}
		reply(http.StatusCreated, map[string]any{"id": strconv.Itoa(len(is.Notes)), "type": "note", "data": map[string]string{"text": in.Text}, "user": map[string]string{"email": "orchestrator@example.org"}})
	default:
		notFound()
	}
}

// drop closes the connection with no answer.
func (s *Server) drop(w http.ResponseWriter) {
	if h, ok := w.(http.Hijacker); ok {
		if c, _, err := h.Hijack(); err == nil {
			_ = c.Close()
		}
	}
}

func (s *Server) list(w http.ResponseWriter, r *http.Request, project string) {
	status, level := "unresolved", ""
	for _, tok := range strings.Fields(r.URL.Query().Get("query")) {
		switch {
		case strings.HasPrefix(tok, "is:"):
			status = strings.TrimPrefix(tok, "is:")
		case strings.HasPrefix(tok, "level:"):
			level = strings.TrimPrefix(tok, "level:")
		}
	}
	var match []*Issue
	for _, is := range s.issues {
		if (is.Project == project || s.leakProjects) && is.Status == status && (level == "" || is.Level == level) {
			match = append(match, is)
		}
	}
	sort.Slice(match, func(i, j int) bool {
		if match[i].LastSeen != match[j].LastSeen {
			return match[i].LastSeen > match[j].LastSeen
		}
		return match[i].ID < match[j].ID
	})
	limit := 25
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		limit = n
	}
	if s.ignoreLimit {
		limit = len(match) + 1
	}
	offset := 0
	if c := r.URL.Query().Get("cursor"); c != "" {
		f := strings.Split(c, ":")
		if len(f) != 3 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		offset, _ = strconv.Atoi(f[1])
	}
	if offset > len(match) {
		offset = len(match)
	}
	end := min(offset+limit, len(match))
	out := make([]any, 0, end-offset)
	for _, is := range match[offset:end] {
		out = append(out, s.issueJSON(is))
	}
	prev := fmt.Sprintf(`<%s/api/0/x/?cursor=0:%d:1>; rel="previous"; results="%t"; cursor="0:%d:1"`, BaseURL, max(offset-limit, 0), offset > 0, max(offset-limit, 0))
	next := fmt.Sprintf(`<%s/api/0/x/?cursor=0:%d:0>; rel="next"; results="%t"; cursor="0:%d:0"`, BaseURL, end, end < len(match), end)
	w.Header().Set("Link", prev+", "+next)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// issueJSON is an issue the way Sentry sends it, with fields the connector does
// not read: it must drop them.
func (s *Server) issueJSON(is *Issue) map[string]any {
	m := map[string]any{
		"id": is.ID, "shortId": is.ShortID, "title": is.Title, "culprit": is.Culprit, "level": is.Level,
		"status": is.Status, "count": is.Count, "userCount": 3, "firstSeen": is.FirstSeen, "lastSeen": is.LastSeen,
		"permalink":    s.URL + "/organizations/" + s.org + "/issues/" + is.ID + "/",
		"project":      map[string]any{"id": "11", "name": strings.ToUpper(is.Project), "slug": is.Project},
		"metadata":     map[string]any{"type": "Error", "value": "metadata value"},
		"isBookmarked": false, "hasSeen": true, "type": "error", "assignedTo": nil,
	}
	if is.Assignee != "" {
		m["assignedTo"] = map[string]any{"type": "user", "id": "7", "name": is.AssigneeName, "email": is.Assignee}
	}
	return m
}

// eventJSON is an event the way Sentry sends it, with everything sensitive that
// an event can carry.
func eventJSON(ev *Event) map[string]any {
	var values []any
	for _, ex := range ev.Exceptions {
		var frames []any
		for _, f := range ex.Frames {
			frames = append(frames, map[string]any{
				"filename": f.Filename, "absPath": f.AbsPath, "function": f.Function, "lineNo": f.Line, "inApp": f.InApp,
				"module":  "pkg." + f.Function,
				"vars":    map[string]any{"password": ev.Sensitive, "token": ev.Sensitive},
				"context": [][]any{{f.Line, "local_secret = '" + ev.Sensitive + "'"}},
			})
		}
		values = append(values, map[string]any{
			"type": ex.Type, "value": ex.Value + " " + ev.Sensitive, "module": "pkg",
			"stacktrace": map[string]any{"frames": frames},
		})
	}
	return map[string]any{
		"eventID": ev.ID, "id": ev.ID, "dateCreated": ev.Date, "message": "message " + ev.Sensitive,
		"user":     map[string]any{"email": ev.Sensitive + "@example.org", "ip_address": "192.0.2.7", "id": ev.Sensitive},
		"tags":     []any{map[string]any{"key": "secret", "value": ev.Sensitive}},
		"contexts": map[string]any{"device": map[string]any{"name": ev.Sensitive}},
		"entries": []any{
			map[string]any{"type": "exception", "data": map[string]any{"values": values}},
			map[string]any{"type": "request", "data": map[string]any{
				"url": "https://app.example.org/pay?token=" + ev.Sensitive, "method": "POST",
				"headers": [][]string{{"Authorization", "Bearer " + ev.Sensitive}, {"Cookie", "session=" + ev.Sensitive}},
				"cookies": [][]string{{"session", ev.Sensitive}},
				"data":    map[string]any{"card": ev.Sensitive},
			}},
			map[string]any{"type": "breadcrumbs", "data": map[string]any{"values": []any{
				map[string]any{"message": "typed " + ev.Sensitive, "category": "ui"},
			}}},
		},
	}
}
