package notify

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
)

// ErrTopicNotFound is what a [TopicStore] returns when no topic is stored yet.
var ErrTopicNotFound = errors.New("notify: no topic stored")

// topicBytes is the entropy of a topic: 128 bits (ADR-004).
const topicBytes = 16

var topicRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

const redacted = "[ntfy-topic]"

// Topic is the ntfy topic. ntfy has no sign-up, so the topic is the password:
// anyone who knows it can publish to the operator's phone and read what is
// published. The type therefore prints as a placeholder through fmt, slog, JSON
// and text encoders. The one way to read the value is [Topic.Reveal], used by
// the driver to publish and by `chapd` to print the topic once for the operator to
// subscribe the phone (step H4).
type Topic struct{ v string }

// ParseTopic validates a stored topic: 32 lowercase hex characters, the form
// [InitTopic] generates (128 bits).
func ParseTopic(s string) (Topic, error) {
	if !topicRE.MatchString(s) {
		return Topic{}, errors.New("notify: stored topic is not 32 lowercase hex characters")
	}
	return Topic{s}, nil
}

// Reveal returns the topic. Never log it.
func (t Topic) Reveal() string { return t.v }

// IsZero reports whether t holds no topic.
func (t Topic) IsZero() bool { return t.v == "" }

func (t Topic) String() string               { return redacted }
func (t Topic) GoString() string             { return redacted }
func (t Topic) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, redacted) }
func (t Topic) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (t Topic) MarshalJSON() ([]byte, error) { return json.Marshal(redacted) }
func (t Topic) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// TopicStore keeps the topic between runs. The vault implements it when it
// lands (L1-03); the value is a secret and must be stored like one.
type TopicStore interface {
	// LoadTopic returns the stored topic, or an error wrapping
	// [ErrTopicNotFound] if none was stored.
	LoadTopic(ctx context.Context) (string, error)
	// SaveTopic stores a new topic, replacing any old one (rotation).
	SaveTopic(ctx context.Context, topic string) error
}

// InitTopic returns the stored topic, generating and storing a random 128-bit
// one on first use. created is true only when it generated one; that is the one
// time `chapd` prints the topic. Call it once at start-up (it is not safe against
// two concurrent first calls).
func InitTopic(ctx context.Context, s TopicStore) (t Topic, created bool, err error) {
	v, err := s.LoadTopic(ctx)
	switch {
	case err == nil:
		t, err = ParseTopic(v)
		return t, false, err
	case !errors.Is(err, ErrTopicNotFound):
		return Topic{}, false, fmt.Errorf("notify: load topic: %w", err)
	}
	t, err = generateTopic(rand.Reader)
	if err != nil {
		return Topic{}, false, err
	}
	if err := s.SaveTopic(ctx, t.v); err != nil {
		return Topic{}, false, fmt.Errorf("notify: save topic: %w", err)
	}
	return t, true, nil
}

// RotateTopic generates a new topic and stores it in place of the old one. The
// phone must subscribe to the new one.
func RotateTopic(ctx context.Context, s TopicStore) (Topic, error) {
	t, err := generateTopic(rand.Reader)
	if err != nil {
		return Topic{}, err
	}
	if err := s.SaveTopic(ctx, t.v); err != nil {
		return Topic{}, fmt.Errorf("notify: save topic: %w", err)
	}
	return t, nil
}

func generateTopic(r io.Reader) (Topic, error) {
	var b [topicBytes]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return Topic{}, fmt.Errorf("notify: generate topic: %w", err)
	}
	return Topic{hex.EncodeToString(b[:])}, nil
}
