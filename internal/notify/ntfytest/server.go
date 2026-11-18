// Package ntfytest is a fake ntfy server for Chaperone's tests (L1-13; reused by
// the approvals tests). It models only the JSON publish API the driver uses:
// POST or PUT of a JSON object to the server root.
//
// What is modelled, from the ntfy docs (https://docs.ntfy.sh/publish/):
//
//   - the topic is required and may contain only [-_A-Za-z0-9], at most 64
//     characters; anything else is HTTP 400;
//   - a message is at most 4,096 bytes (HTTP 400 here; the real server turns a
//     longer body into an attachment, which this driver never wants);
//   - success is HTTP 200 with a JSON event;
//   - a publish to a topic URL (not the root) is answered 404 on purpose, so a
//     driver that puts the topic in the URL fails its tests.
//
// Every accepted message is stored with its raw body, so tests can assert on the
// exact keys that reached the server. Faults are injected with
// [Server.SetStatus], [Server.Hang] and [Server.Close].
package ntfytest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"
	"time"
)

var topicRE = regexp.MustCompile(`^[-_A-Za-z0-9]{1,64}$`)

const maxMessage = 4096

// Message is one accepted publish.
type Message struct {
	// Raw is the request body exactly as received.
	Raw []byte
	// Fields is Raw decoded as a JSON object, so a test can list every key.
	Fields map[string]json.RawMessage
	// Topic, Title, Message and Priority are the decoded common fields.
	Topic    string
	Title    string
	Message  string
	Priority int
	// Path and Header describe the request.
	Path   string
	Header http.Header
}

// Server is a running fake. Its URL is a loopback http address, which the
// driver accepts for tests.
type Server struct {
	*httptest.Server

	mu       sync.Mutex
	msgs     []Message
	requests int
	status   int
	hang     chan struct{}
}

// New starts a fake and stops it when the test ends.
func New(t testing.TB) *Server {
	t.Helper()
	s := &Server{}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(func() {
		s.Release()
		s.Server.Close()
	})
	return s
}

// Messages returns every accepted message, oldest first.
func (s *Server) Messages() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message(nil), s.msgs...)
}

// MessagesFor returns the accepted messages published to topic.
func (s *Server) MessagesFor(topic string) []Message {
	var out []Message
	for _, m := range s.Messages() {
		if m.Topic == topic {
			out = append(out, m)
		}
	}
	return out
}

// Requests counts every request received, accepted or not.
func (s *Server) Requests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

// SetStatus makes every later request answer with code and store nothing, like
// an overloaded or rate-limiting server. Zero restores normal behaviour.
func (s *Server) SetStatus(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = code
}

// Hang makes later requests block until [Server.Release] (or the client gives
// up), like a server that accepts the connection and never answers.
func (s *Server) Hang() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hang == nil {
		s.hang = make(chan struct{})
	}
}

// Release unblocks hung requests and stops hanging new ones.
func (s *Server) Release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hang != nil {
		close(s.hang)
		s.hang = nil
	}
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests++
	status, hang := s.status, s.hang
	s.mu.Unlock()

	body, _ := io.ReadAll(io.LimitReader(r.Body, maxMessage+1024))
	if hang != nil {
		select {
		case <-hang:
		case <-r.Context().Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
	if status != 0 {
		reply(w, status, "injected fault")
		return
	}
	if r.URL.Path != "/" {
		reply(w, http.StatusNotFound, "page not found")
		return
	}
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		reply(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var in struct {
		Topic    string `json:"topic"`
		Title    string `json:"title"`
		Message  string `json:"message"`
		Priority int    `json:"priority"`
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &in) != nil || json.Unmarshal(body, &fields) != nil {
		reply(w, http.StatusBadRequest, "invalid json")
		return
	}
	if !topicRE.MatchString(in.Topic) {
		reply(w, http.StatusBadRequest, "invalid topic")
		return
	}
	if len(in.Message) > maxMessage {
		reply(w, http.StatusBadRequest, "message too long")
		return
	}
	if in.Priority < 0 || in.Priority > 5 {
		reply(w, http.StatusBadRequest, "invalid priority")
		return
	}
	s.mu.Lock()
	s.msgs = append(s.msgs, Message{Raw: body, Fields: fields, Topic: in.Topic, Title: in.Title, Message: in.Message,
		Priority: in.Priority, Path: r.URL.Path, Header: r.Header.Clone()})
	n := len(s.msgs)
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	// The real server echoes the topic in its reply; so does the fake, to prove the driver never logs a reply.
	_ = json.NewEncoder(w).Encode(map[string]any{"id": fmt.Sprintf("fake%06d", n), "time": time.Now().Unix(),
		"event": "message", "topic": in.Topic, "message": in.Message})
}

func reply(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"code": 40000 + status, "http": status, "error": msg})
}
