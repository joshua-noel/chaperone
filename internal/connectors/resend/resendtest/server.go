// Package resendtest is a fake Resend service for the connector's tests. It
// never talks to the network: it is an https server on a loopback port that the
// test owns.
//
// The connector sends to one fixed address (https://api.resend.com). The test
// builds the client with [Server.HTTPClient]: that HTTP client trusts the fake's
// certificate and sends every request to the fake, whatever host the URL names.
//
// The fake is written from Resend's documentation, not from the service:
//
//   - POST /emails answers {"id": "<uuid>"}. A request without a User-Agent is
//     refused with 403, and an Idempotency-Key longer than 256 characters with
//     400 invalid_idempotency_key.
//   - An Idempotency-Key is remembered for 24 hours. The same key with the same
//     body returns the first answer and sends nothing. The same key with another
//     body answers 409 invalid_idempotent_request. [Server.ExpireIdempotencyKeys]
//     is the 24 hours passing: the key is forgotten, and a repeat sends again.
//   - A key with the permission sending_access can send and can do nothing else:
//     every other call answers 401 restricted_api_key. A sending_access key
//     restricted to a domain can send only from that domain.
//   - An error answers {"statusCode": n, "name": "<type>", "message": "<text>"}.
//     The body's shape is the one Resend's SDKs decode; the documentation page of
//     the error list names the types and the statuses, not the body.
//
// The package does not import the connector, so the connector's own tests can
// import it without a cycle.
package resendtest

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// SendingAccess is the permission of a key that can send and nothing else, as Resend
// names it.
const SendingAccess = "sending_access"

// Email is one message the fake accepted.
type Email struct {
	ID      string
	From    string
	To      []string
	Cc, Bcc []string
	Subject string
	Text    string
	HTML    string
}

// Request is one request the fake received. The key is never recorded here: see
// [Server.Credentials].
type Request struct {
	Method, Path   string
	IdempotencyKey string
	UserAgent      string
	ContentType    string
	// Body is the request body, as received.
	Body []byte
}

// Sent is one message the fake accepted and acted on.
type Sent struct {
	ID string
	// Fields is every top-level key of the body. A connector that sends only
	// plain text sends exactly from, to, subject, text and, when used, cc and bcc.
	Fields []string
	Email  Email
}

type key struct {
	permission string
	domain     string // for sending_access: the only domain it may send from
}

type idem struct {
	bodySHA string
	id      string
}

// Server is the fake service.
type Server struct {
	*httptest.Server

	mu      sync.Mutex
	keys    map[string]key
	echo    bool
	emails  map[string]*Email
	sent    []Sent
	reqs    []Request
	creds   []string
	idem    map[string]idem
	writes  int
	applied int
	next    int

	nextID       string
	failNext     *failure
	dropNext     bool
	redirectNext bool
	inProgress   map[string]bool
}

type failure struct {
	status     int
	name       string
	retryAfter string
}

// New starts the fake. It accepts no key until [Server.AddKey].
func New(t testing.TB) *Server {
	t.Helper()
	s := &Server{keys: map[string]key{}, emails: map[string]*Email{}, idem: map[string]idem{}, inProgress: map[string]bool{}}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

// HTTPClient returns an HTTP client that trusts the fake's certificate and
// sends every request to the fake, whatever host the URL names. It follows
// redirects as Go's default client does: the connector is the one that must not.
func (s *Server) HTTPClient() *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	addr := s.Listener.Addr().String()
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

// AddKey makes the fake accept token with a permission. domain is the one
// domain a sending_access key may send from ("" means any).
func (s *Server) AddKey(token, permission, domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[token] = key{permission: permission, domain: domain}
}

// RemoveKeys makes the fake accept no key.
func (s *Server) RemoveKeys() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = map[string]key{}
}

// NextID makes the next accepted message get this id instead of a UUID. A test
// uses it to make Resend answer with hostile text.
func (s *Server) NextID(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID = id
}

// FailNext makes the next POST answer with this status and error type, acting
// on nothing. retryAfter is the Retry-After header ("" for none).
func (s *Server) FailNext(status int, name, retryAfter string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failNext = &failure{status: status, name: name, retryAfter: retryAfter}
}

// DropNext makes the next POST act on the message and then cut the connection
// with no answer: the connector cannot tell whether the message was sent.
func (s *Server) DropNext() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropNext = true
}

// RedirectNext makes the next request answer 307 to another path.
func (s *Server) RedirectNext() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.redirectNext = true
}

// InProgress makes a request with this Idempotency-Key answer 409
// concurrent_idempotent_requests, as if another request with it were running.
func (s *Server) InProgress(idemKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inProgress[idemKey] = true
}

// ExpireIdempotencyKeys is the 24 hours of Resend's documentation passing: every
// key is forgotten, and a repeat of a request sends again.
func (s *Server) ExpireIdempotencyKeys() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.idem = map[string]idem{}
}

// Hostile makes the fake behave like a careless service: it stops accepting
// the keys it had (newToken is the only one it accepts now), and
// its error text repeats the key it received.
func (s *Server) Hostile(newToken string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = map[string]key{newToken: {permission: SendingAccess}}
	s.echo = true
}

// Requests returns every request received so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.reqs...)
}

// Sent returns every message the fake accepted and acted on.
func (s *Server) Sent() []Sent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Sent(nil), s.sent...)
}

// Credentials returns every key the fake was sent.
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

// WritesApplied is how many of those calls made a new message. A repeat that
// the idempotency key answered from memory is not one.
func (s *Server) WritesApplied() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applied
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.reqs = append(s.reqs, Request{
		Method: r.Method, Path: r.URL.Path, IdempotencyKey: r.Header.Get("Idempotency-Key"),
		UserAgent: r.Header.Get("User-Agent"), ContentType: r.Header.Get("Content-Type"), Body: body,
	})
	s.creds = append(s.creds, bearer)
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	fail := func(code int, name, msg string) {
		if s.echo {
			msg += " " + bearer
		}
		reply(code, map[string]any{"statusCode": code, "name": name, "message": msg})
	}
	isWrite := r.Method == http.MethodPost
	if isWrite {
		s.writes++
	}
	if s.redirectNext {
		s.redirectNext = false
		http.Redirect(w, r, "/redirected", http.StatusTemporaryRedirect)
		return
	}
	if r.Header.Get("User-Agent") == "" {
		reply(http.StatusForbidden, map[string]any{"error code": 1010})
		return
	}
	if bearer == "" {
		fail(http.StatusUnauthorized, "missing_api_key", "Missing API key")
		return
	}
	k, ok := s.keys[bearer]
	if !ok {
		fail(http.StatusUnauthorized, "validation_error", "API key is invalid")
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/emails":
		s.postEmail(w, r, k, body, fail, reply)
	default:
		// Resend gives a sending_access key no other call at all.
		if k.permission == SendingAccess {
			fail(http.StatusUnauthorized, "restricted_api_key", "This API key is restricted to only send emails.")
			return
		}
		fail(http.StatusNotFound, "not_found", "The requested endpoint does not exist.")
	}
}
func (s *Server) postEmail(w http.ResponseWriter, r *http.Request, k key, body []byte, fail func(int, string, string), reply func(int, any)) {
	if f := s.failNext; f != nil {
		s.failNext = nil
		if f.retryAfter != "" {
			w.Header().Set("Retry-After", f.retryAfter)
		}
		fail(f.status, f.name, "planted failure")
		return
	}
	idemKey := r.Header.Get("Idempotency-Key")
	if len(idemKey) > 256 {
		fail(http.StatusBadRequest, "invalid_idempotency_key", "Idempotency keys, if present, must have between 1 and 256 characters.")
		return
	}
	if idemKey != "" && s.inProgress[idemKey] {
		fail(http.StatusConflict, "concurrent_idempotent_requests", "There is another request in progress with the same idempotency key.")
		return
	}
	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		fail(http.StatusUnprocessableEntity, "validation_error", "The body is not JSON.")
		return
	}
	var e Email
	e.From, _ = fields["from"].(string)
	e.Subject, _ = fields["subject"].(string)
	e.Text, _ = fields["text"].(string)
	e.HTML, _ = fields["html"].(string)
	e.To, e.Cc, e.Bcc = strs(fields["to"]), strs(fields["cc"]), strs(fields["bcc"])
	if e.From == "" || len(e.To) == 0 || e.Subject == "" {
		fail(http.StatusUnprocessableEntity, "missing_required_field", "The request body is missing one or more required fields.")
		return
	}
	if k.permission == SendingAccess && k.domain != "" {
		_, dom, _ := strings.Cut(e.From, "@")
		if dom != k.domain {
			fail(http.StatusForbidden, "validation_error", "The domain is not verified for this API key.")
			return
		}
	}
	sum := sha256.Sum256(body)
	bodySHA := hex.EncodeToString(sum[:])
	if idemKey != "" {
		if prev, seen := s.idem[idemKey]; seen {
			if prev.bodySHA != bodySHA {
				fail(http.StatusConflict, "invalid_idempotent_request", "This idempotency key has been used with this HTTP method and endpoint within the last 24 hours, but the request body was modified and doesn't match the original request.")
				return
			}
			reply(http.StatusOK, map[string]string{"id": prev.id}) // the first answer, and nothing sent
			return
		}
	}
	s.next++
	id := fmt.Sprintf("00000000-0000-4000-8000-%012x", s.next)
	if s.nextID != "" {
		id, s.nextID = s.nextID, ""
	}
	e.ID = id
	s.applied++
	s.emails[id] = &e
	names := make([]string, 0, len(fields))
	for n := range fields {
		names = append(names, n)
	}
	sort.Strings(names)
	s.sent = append(s.sent, Sent{ID: id, Fields: names, Email: e})
	if idemKey != "" {
		s.idem[idemKey] = idem{bodySHA: bodySHA, id: id}
	}
	if s.dropNext {
		s.dropNext = false
		if hj, ok := w.(http.Hijacker); ok {
			if c, _, err := hj.Hijack(); err == nil {
				_ = c.Close()
				return
			}
		}
	}
	reply(http.StatusOK, map[string]string{"id": id})
}

func strs(v any) []string {
	var out []string
	switch x := v.(type) {
	case string:
		out = append(out, x)
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}
