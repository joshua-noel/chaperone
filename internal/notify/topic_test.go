package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

// memStore is an in-memory TopicStore; the vault implements the real one.
type memStore struct {
	mu    sync.Mutex
	topic string
	saves int
	err   error
}

func (m *memStore) LoadTopic(context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return "", m.err
	}
	if m.topic == "" {
		return "", fmt.Errorf("vault: %w", ErrTopicNotFound)
	}
	return m.topic, nil
}

func (m *memStore) SaveTopic(_ context.Context, t string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.topic, m.saves = t, m.saves+1
	return nil
}

func TestInitTopicGeneratesOnceAndPersists(t *testing.T) {
	s := &memStore{}
	a, created, err := InitTopic(t.Context(), s)
	if err != nil || !created {
		t.Fatalf("first: created=%v err=%v", created, err)
	}
	if len(a.Reveal()) != 32 || !topicRE.MatchString(a.Reveal()) {
		t.Fatalf("topic %q is not 128 bits as 32 hex", a.Reveal())
	}
	b, created, err := InitTopic(t.Context(), s)
	if err != nil || created || b.Reveal() != a.Reveal() || s.saves != 1 {
		t.Fatalf("second: created=%v err=%v same=%v saves=%d", created, err, b.Reveal() == a.Reveal(), s.saves)
	}
}

func TestInitTopicDiffersBetweenStores(t *testing.T) {
	seen := map[string]bool{}
	for range 50 {
		a, _, err := InitTopic(t.Context(), &memStore{})
		if err != nil {
			t.Fatal(err)
		}
		if seen[a.Reveal()] {
			t.Fatal("repeated topic")
		}
		seen[a.Reveal()] = true
	}
}

func TestInitTopicErrors(t *testing.T) {
	boom := errors.New("vault locked")
	if _, _, err := InitTopic(t.Context(), &memStore{err: boom}); !errors.Is(err, boom) {
		t.Errorf("load error not passed on: %v", err)
	}
	if _, _, err := InitTopic(t.Context(), &memStore{topic: "not-a-topic"}); err == nil {
		t.Error("a malformed stored topic was accepted")
	}
	if _, _, err := InitTopic(t.Context(), &memStore{topic: strings.Repeat("A", 32)}); err == nil {
		t.Error("an uppercase stored topic was accepted")
	}
}

func TestRotateTopic(t *testing.T) {
	s := &memStore{}
	a, _, _ := InitTopic(t.Context(), s)
	b, err := RotateTopic(t.Context(), s)
	if err != nil || a.Reveal() == b.Reveal() || s.topic != b.Reveal() {
		t.Fatalf("rotate: %v %v", err, a.Reveal() == b.Reveal())
	}
}

func TestGenerateTopicIs128Bits(t *testing.T) {
	got, err := generateTopic(bytes.NewReader(bytes.Repeat([]byte{0xab}, 64)))
	if err != nil || got.Reveal() != strings.Repeat("ab", 16) {
		t.Fatalf("%q %v", got.Reveal(), err)
	}
	if _, err := generateTopic(bytes.NewReader(make([]byte, 15))); err == nil {
		t.Fatal("short entropy source accepted")
	}
}

// TestTopicNeverPrints: every way Go formats a value prints the placeholder.
func TestTopicNeverPrints(t *testing.T) {
	topic, _, _ := InitTopic(t.Context(), &memStore{})
	secret := topic.Reveal()
	type holder struct {
		T  Topic
		P  *Topic
		In any
	}
	h := holder{topic, &topic, topic}
	var out []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T", "%10s", "%-40v"} {
		out = append(out, fmt.Sprintf(verb, topic), fmt.Sprintf(verb, &topic), fmt.Sprintf(verb, h), fmt.Sprintf(verb, []Topic{topic}),
			fmt.Sprintf(verb, map[string]Topic{"k": topic}))
	}
	out = append(out, fmt.Sprint(topic), fmt.Sprintln(topic), topic.String(), topic.GoString())
	j, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, string(j))
	txt, _ := topic.MarshalText()
	out = append(out, string(txt))
	var buf bytes.Buffer
	for _, hd := range []slog.Handler{slog.NewTextHandler(&buf, nil), slog.NewJSONHandler(&buf, nil)} {
		slog.New(hd).Info("x", "topic", topic, "h", h, "ptr", &topic, slog.Any("any", topic), slog.Group("g", "t", topic))
	}
	out = append(out, buf.String())
	for _, s := range out {
		if strings.Contains(s, secret) {
			t.Errorf("topic leaked: %q", s)
		}
	}
}
