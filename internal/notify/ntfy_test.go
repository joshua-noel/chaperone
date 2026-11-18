package notify

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/notify/ntfytest"
)

func testTopic(t *testing.T) Topic {
	t.Helper()
	topic, _, err := InitTopic(t.Context(), &memStore{})
	if err != nil {
		t.Fatal(err)
	}
	return topic
}

func newNtfy(t *testing.T, srv *ntfytest.Server) (*Ntfy, Topic) {
	t.Helper()
	topic := testTopic(t)
	n, err := NewNtfy(NtfyConfig{Topic: topic, BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	return n, topic
}

func TestNtfyPublishesExactlyTheAllowlistedFields(t *testing.T) {
	srv := ntfytest.New(t)
	n, topic := newNtfy(t, srv)
	if err := n.Notify(t.Context(), goodWake()); err != nil {
		t.Fatal(err)
	}
	msgs := srv.MessagesFor(topic.Reveal())
	if len(msgs) != 1 || len(srv.Messages()) != 1 {
		t.Fatalf("messages = %d", len(srv.Messages()))
	}
	m := msgs[0]
	var keys []string
	for k := range m.Fields {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	// No click, attach, actions, icon, email, call, delay, tags or markdown.
	if want := []string{"message", "priority", "title", "topic"}; !slices.Equal(keys, want) {
		t.Fatalf("keys = %v, want %v", keys, want)
	}
	if m.Path != "/" {
		t.Errorf("path = %q: the topic must not be in the URL", m.Path)
	}
	if m.Title != "Chaperone: approval waiting" || m.Priority != 4 ||
		m.Message != "deploy storefront\nop 1a2b3c4d, expires 14:32 UTC\n3 pending" {
		t.Errorf("message = %+v", m)
	}
	for _, h := range []string{"Click", "Actions", "Attach", "Email", "Authorization", "X-Click", "X-Actions"} {
		if m.Header.Get(h) != "" {
			t.Errorf("header %s sent", h)
		}
	}
	if ct := m.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("content type %q", ct)
	}
}

// TestNtfyPriorityIsConstant: decision #16, no quiet hours; the priority does
// not depend on the clock, the pending count or the kind.
func TestNtfyPriorityIsConstant(t *testing.T) {
	srv := ntfytest.New(t)
	n, _ := newNtfy(t, srv)
	for i, kind := range []string{"deploy", "secrets.write", "pr.merge", "health"} {
		w := goodWake()
		w.Kind = kind
		w.Pending = i + 1
		w.ExpiresAt = w.ExpiresAt.Add(time.Duration(i) * 7 * time.Hour)
		if err := n.Notify(t.Context(), w); err != nil {
			t.Fatal(err)
		}
	}
	for _, m := range srv.Messages() {
		if m.Priority != 4 {
			t.Errorf("priority %d", m.Priority)
		}
	}
}

func TestNtfyRefusesInvalidWakeWithoutRequest(t *testing.T) {
	srv := ntfytest.New(t)
	n, _ := newNtfy(t, srv)
	w := goodWake()
	w.Kind = "deploy abcdef0123456789abcdef0123456789abcdef01"
	if err := n.Notify(t.Context(), w); !errors.Is(err, ErrInvalidWake) {
		t.Fatalf("err = %v", err)
	}
	if srv.Requests() != 0 {
		t.Fatal("a request was sent for an invalid wake-up")
	}
}

func TestNtfyServerRefusalKeepsOnlyStatus(t *testing.T) {
	srv := ntfytest.New(t)
	n, topic := newNtfy(t, srv)
	for _, code := range []int{400, 403, 429, 500, 503} {
		srv.SetStatus(code)
		err := n.Notify(t.Context(), goodWake())
		var pe *PublishError
		if !errors.Is(err, ErrPublish) || !errors.As(err, &pe) || pe.Status != code {
			t.Fatalf("status %d: err = %v", code, err)
		}
		if strings.Contains(err.Error(), topic.Reveal()) {
			t.Fatal("error carries the topic")
		}
	}
	if len(srv.Messages()) != 0 {
		t.Fatal("a refused message was stored")
	}
}

func TestNtfyDoesNotFollowRedirects(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer other.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	n, err := NewNtfy(NtfyConfig{Topic: testTopic(t), BaseURL: redir.URL})
	if err != nil {
		t.Fatal(err)
	}
	err = n.Notify(t.Context(), goodWake())
	var pe *PublishError
	if !errors.As(err, &pe) || pe.Status != http.StatusTemporaryRedirect {
		t.Fatalf("err = %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("the redirect was followed: the topic went to another host")
	}
}

func TestNtfyOutageReturnsAnErrorByTheTimeout(t *testing.T) {
	srv := ntfytest.New(t)
	srv.Hang()
	n, _ := newNtfy(t, srv)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := n.Notify(ctx, goodWake()); err == nil {
		t.Fatal("no error from a hung server")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %v", d)
	}
}

func TestNtfyUnreachableServer(t *testing.T) {
	srv := ntfytest.New(t)
	url := srv.URL
	srv.Close() // connection refused
	n, err := NewNtfy(NtfyConfig{Topic: testTopic(t), BaseURL: url})
	if err != nil {
		t.Fatal(err)
	}
	err = n.Notify(t.Context(), goodWake())
	if err == nil {
		t.Fatal("no error")
	}
}

func TestNewNtfyConfig(t *testing.T) {
	topic := testTopic(t)
	for _, tc := range []struct {
		name string
		cfg  NtfyConfig
		ok   bool
	}{
		{"default", NtfyConfig{Topic: topic}, true},
		{"https host", NtfyConfig{Topic: topic, BaseURL: "https://ntfy.example.net"}, true},
		{"https with slash", NtfyConfig{Topic: topic, BaseURL: "https://ntfy.example.net/"}, true},
		{"loopback http", NtfyConfig{Topic: topic, BaseURL: "http://127.0.0.1:8080"}, true},
		{"localhost http", NtfyConfig{Topic: topic, BaseURL: "http://localhost:8080"}, true},
		{"no topic", NtfyConfig{}, false},
		{"plain http", NtfyConfig{Topic: topic, BaseURL: "http://ntfy.sh"}, false},
		{"path", NtfyConfig{Topic: topic, BaseURL: "https://ntfy.sh/" + topic.Reveal()}, false},
		{"query", NtfyConfig{Topic: topic, BaseURL: "https://ntfy.sh/?x=1"}, false},
		{"userinfo", NtfyConfig{Topic: topic, BaseURL: "https://u:p@ntfy.sh"}, false},
		{"scheme", NtfyConfig{Topic: topic, BaseURL: "ftp://ntfy.sh"}, false},
		{"host missing", NtfyConfig{Topic: topic, BaseURL: "https://"}, false},
	} {
		_, err := NewNtfy(tc.cfg)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v", tc.name, err)
		}
		if err != nil && strings.Contains(err.Error(), topic.Reveal()) {
			t.Errorf("%s: config error carries the topic", tc.name)
		}
	}
}

func TestWireBodyHasNoUnexpectedKeys(t *testing.T) {
	b, err := json.Marshal(wire{Topic: "x", Push: Push{Title: "t", Message: "m", Priority: 4}})
	if err != nil || string(b) != `{"topic":"x","title":"t","message":"m","priority":4}` {
		t.Fatalf("%s %v", b, err)
	}
}
