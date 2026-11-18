package notify

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/notify/ntfytest"
)

func goodAnchor() Anchor {
	return Anchor{
		Chain:    "chaperone.host1",
		HeadSeq:  1234,
		HeadHash: "sha256:" + strings.Repeat("ab", 32),
		KeyID:    "0123456789abcdef",
		Sig:      strings.Repeat("A", 86),
	}
}

// TestAnchorFieldAllowlist pins the fields: adding one fails here until the
// ADR-006 anchor section is amended.
func TestAnchorFieldAllowlist(t *testing.T) {
	var got []string
	rt := reflect.TypeOf(Anchor{})
	for i := range rt.NumField() {
		got = append(got, rt.Field(i).Name)
	}
	if want := []string{"Chain", "HeadSeq", "HeadHash", "KeyID", "Sig"}; !slices.Equal(got, want) {
		t.Errorf("Anchor fields = %v, want %v", got, want)
	}
}

func TestBuildAnchor(t *testing.T) {
	p, err := BuildAnchor(goodAnchor())
	if err != nil {
		t.Fatal(err)
	}
	want := "chaperone.host1\nhead seq 1234\nsha256:" + strings.Repeat("ab", 32) + "\nkey 0123456789abcdef\nsig " + strings.Repeat("A", 86)
	if p.Message != want || p.Title != "Chaperone: ledger anchor" || p.Priority != 3 {
		t.Errorf("push = %+v", p)
	}
}

func TestBuildAnchorRefusesFreeText(t *testing.T) {
	for name, mutate := range map[string]func(*Anchor){
		"chain text":    func(a *Anchor) { a.Chain = "chaperone.host1\nClick: https://evil.example" },
		"other chain":   func(a *Anchor) { a.Chain = "runner.host1" },
		"negative seq":  func(a *Anchor) { a.HeadSeq = -1 },
		"huge seq":      func(a *Anchor) { a.HeadSeq = 1 << 60 },
		"hash no tag":   func(a *Anchor) { a.HeadHash = strings.Repeat("ab", 32) },
		"hash text":     func(a *Anchor) { a.HeadHash = "sha256:" + strings.Repeat("ab", 31) + "\n\n" },
		"key text":      func(a *Anchor) { a.KeyID = "0123456789abcdeg" },
		"sig too short": func(a *Anchor) { a.Sig = "AAAA" },
		"sig text":      func(a *Anchor) { a.Sig = strings.Repeat("A", 85) + "\n" },
		"empty":         func(a *Anchor) { *a = Anchor{} },
	} {
		a := goodAnchor()
		mutate(&a)
		if _, err := BuildAnchor(a); !errors.Is(err, ErrInvalidAnchor) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestNtfyPublishesAnAnchor(t *testing.T) {
	srv := ntfytest.New(t)
	n, topic := newNtfy(t, srv)
	if err := n.NotifyAnchor(t.Context(), goodAnchor()); err != nil {
		t.Fatal(err)
	}
	msgs := srv.MessagesFor(topic.Reveal())
	if len(msgs) != 1 {
		t.Fatalf("messages = %d", len(msgs))
	}
	var keys []string
	for k := range msgs[0].Fields {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if want := []string{"message", "priority", "title", "topic"}; !slices.Equal(keys, want) {
		t.Fatalf("keys = %v, want %v", keys, want)
	}
	if msgs[0].Path != "/" || !strings.Contains(msgs[0].Message, "head seq 1234") {
		t.Errorf("message = %+v", msgs[0])
	}
	// An invalid anchor makes no request at all.
	bad := goodAnchor()
	bad.Chain = "x"
	before := srv.Requests()
	if err := n.NotifyAnchor(t.Context(), bad); !errors.Is(err, ErrInvalidAnchor) || srv.Requests() != before {
		t.Errorf("invalid anchor: err %v, requests %d -> %d", err, before, srv.Requests())
	}
	// A refusing server is an error, and the topic is not in it.
	srv.SetStatus(500)
	err := n.NotifyAnchor(t.Context(), goodAnchor())
	if !errors.Is(err, ErrPublish) || strings.Contains(err.Error(), topic.Reveal()) {
		t.Errorf("refused publish: %v", err)
	}
}
