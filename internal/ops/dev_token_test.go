package ops

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"log/slog"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/redact"
)

// A minted run token is a JWT, so the redactor always matches it. POST
// /v0/dev-tokens is the one answer that may carry it, in its top-level "token"
// field and nowhere else.

const mintedJWT = "eyJhbGciOiJFZERTQSIsInR5cCI6ImZhY3RvcnktcnVuK2p3dCJ9.eyJydW5faWQiOiJyLTlhMmIifQ.c2lnbmF0dXJlLXNpZ25hdHVyZS1zaWduYXR1cmU"

type fakeInterim struct{ reply func() any }

func (f fakeInterim) Mint(context.Context, string, DevTokenRequest) (any, error) {
	return f.reply(), nil
}

// fakeLedgerBackend answers GET /v0/ledger with one item.
type fakeLedgerBackend struct{ item string }

func (f fakeLedgerBackend) Query(context.Context, LedgerQuery) ([]json.RawMessage, *int64, error) {
	return []json.RawMessage{json.RawMessage(f.item)}, nil, nil
}
func (fakeLedgerBackend) Verify(context.Context, bool) (any, error) { return nil, nil }

// mintRig is a rig whose server has a real redactor and the interim route.
func mintRig(t *testing.T, reply func() any, led LedgerBackend) *rig {
	t.Helper()
	g := newRig(t, rigOpts{})
	g.svc.redactor = redact.NewRegistry()
	g.http.Close()
	g.srv = NewServer(ServerConfig{Svc: g.svc, Auth: &Auth{Run: g.ver, Orch: g.ver, Svc: g.svc}, Version: "test",
		Interim: fakeInterim{reply: reply}, Ledger: led})
	g.http = httptest.NewServer(g.srv)
	g.srv.cfg.Hosts = []string{strings.TrimPrefix(g.http.URL, "http://")}
	t.Cleanup(g.http.Close)
	if _, res := g.svc.redactor.Redact(mintedJWT); !res.Blocked() {
		t.Fatal("precondition: the redactor must match the minted token")
	}
	return g
}

func devTokenBody() map[string]any {
	return map[string]any{"project": "acme-shop", "profile": "host-interim", "repo": "acme/shop", "base": "main",
		"branch": "agent/r-9a2b", "paths": []string{"docs/**"}, "ops": []string{"pr.open"}, "minutes": 30}
}

func minted() any {
	return map[string]any{"token": mintedJWT, "run_id": "r-9a2b", "jti": "jti-5f8c1d2e3a4b5c6d", "expires_at": "2026-10-24T10:30:00Z"}
}

func TestDevTokenReturnsTheMintedToken(t *testing.T) {
	var logs bytes.Buffer
	oldSlog := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	log.SetOutput(&logs)
	t.Cleanup(func() { slog.SetDefault(oldSlog); log.SetOutput(os.Stderr) })

	g := mintRig(t, minted, nil)
	st, body, _ := g.call("POST", "/v0/dev-tokens", orchTok, devTokenBody())
	if st != 201 || body["token"] != mintedJWT || body["run_id"] != "r-9a2b" {
		t.Fatalf("mint: %d %v", st, body)
	}

	// Never logged, never ledgered.
	if strings.Contains(logs.String(), mintedJWT) || strings.Contains(logs.String(), mintedJWT[:30]) {
		t.Errorf("the token was logged:\n%s", logs.String())
	}
	for _, e := range g.led.rows(t, g.db, "") {
		if b, _ := json.Marshal(e); strings.Contains(string(b), mintedJWT[:30]) {
			t.Errorf("the token reached the ledger: %s", b)
		}
	}
}

// Only the value of the top-level token field is exempt. A JWT in any other
// field, a second copy of the token, or a token field below the top level is
// still REDACTION_BLOCKED, and the ledgered denial does not carry it.
func TestDevTokenKeepsFullRedactionElsewhere(t *testing.T) {
	other := "eyJhbGciOiJFZERTQSJ9.eyJydW4iOiJyLTdmM2EifQ.c2lnbmF0dXJlc2lnbmF0dXJl"
	cases := map[string]any{
		"a copy of the token in run_id":   map[string]any{"token": mintedJWT, "run_id": mintedJWT},
		"a second copy in a new field":    map[string]any{"token": mintedJWT, "run_id": "r-9a2b", "debug": mintedJWT},
		"another JWT in jti":              map[string]any{"token": mintedJWT, "run_id": "r-9a2b", "jti": other},
		"a different secret in a field":   map[string]any{"token": mintedJWT, "run_id": "r-9a2b", "note": "ghp_" + strings.Repeat("a", 36)},
		"the token one level down":        map[string]any{"token": "fine", "run_id": "r-9a2b", "x": map[string]any{"token": mintedJWT}},
		"the token field not a string":    map[string]any{"token": []string{mintedJWT}, "run_id": "r-9a2b"},
		"a token field next to a leak":    map[string]any{"token": mintedJWT + "." + other, "run_id": other},
		"the token under another key":     map[string]any{"access_token": mintedJWT, "run_id": "r-9a2b"},
		"a JWT as the value, not a token": map[string]any{"run_id": mintedJWT},
	}
	for name, reply := range cases {
		t.Run(name, func(t *testing.T) {
			g := mintRig(t, func() any { return reply }, nil)
			st, body, _ := g.call("POST", "/v0/dev-tokens", orchTok, devTokenBody())
			if st == 201 {
				t.Fatalf("a leak was sent: %v", body)
			}
			mustDenial(t, body, CodeRedactionBlocked)
			for _, e := range g.led.rows(t, g.db, "") {
				if b, _ := json.Marshal(e); strings.Contains(string(b), "eyJ") {
					t.Errorf("a token reached the ledger: %s", b)
				}
			}
		})
	}
}

// The exemption belongs to the mint answer alone: every other response keeps
// full redaction, including one that holds the very same token.
func TestOtherResponsesStayRedacted(t *testing.T) {
	item := `{"seq":1,"body":"` + mintedJWT + `"}`
	g := mintRig(t, minted, fakeLedgerBackend{item: item})
	st, body, _ := g.call("GET", "/v0/ledger", orchTok, nil)
	if st == 200 {
		t.Fatalf("the ledger answer carried a JWT: %v", body)
	}
	mustDenial(t, body, CodeRedactionBlocked)
}
