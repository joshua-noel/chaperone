package runtoken

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// memLedger is an Appender that checks every draft against the spec's
// ledger-event schema (completed with a placeholder envelope), so a draft the
// real ledger would refuse fails the test here.
type memLedger struct {
	t      *testing.T
	mu     sync.Mutex
	events []Event
	failOn string // event name to fail on; "*" fails every append
}

var severityNumber = map[string]int{"TRACE": 1, "DEBUG": 5, "INFO": 9, "WARN": 13, "ERROR": 17, "FATAL": 21}

func (m *memLedger) Append(_ context.Context, _ *store.Tx, e Event) error {
	m.t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failOn == "*" || m.failOn == e.Name {
		return errors.New("ledger down")
	}
	sev := e.Severity
	if sev == "" {
		sev = "INFO"
	}
	attrs, err := spec.Tree(e.Attributes)
	if err != nil {
		m.t.Fatalf("event %s attributes: %v", e.Name, err)
	}
	ev := map[string]any{
		"spec_version":    "0",
		"chain":           "chaperone.test",
		"seq":             float64(len(m.events) + 1),
		"prev_hash":       "sha256:" + hex.EncodeToString(make([]byte, 31)) + "01",
		"hash":            "sha256:" + hex.EncodeToString(make([]byte, 31)) + "02",
		"time_unix_nano":  "1792792800000000000",
		"trace_id":        "00112233445566778899aabbccddeeff",
		"span_id":         "0011223344556677",
		"severity_number": float64(severityNumber[sev]),
		"severity_text":   sev,
		"event_name":      e.Name,
		"resource":        map[string]any{"service.name": "chaperone", "service.instance.id": "test"},
		"attributes":      attrs,
	}
	if e.RunID != "" {
		ev["run_id"] = e.RunID
	}
	if e.Project != "" {
		ev["project"] = e.Project
	}
	if e.Body != "" {
		ev["body"] = e.Body
	}
	if err := spec.Validate(spec.SchemaEvent, ev); err != nil {
		m.t.Fatalf("event %s is not a valid ledger event: %v\n%+v", e.Name, err, e)
	}
	m.events = append(m.events, e)
	return nil
}

func (m *memLedger) names() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, e := range m.events {
		out = append(out, e.Name)
	}
	return out
}

func (m *memLedger) find(name string) []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Event
	for _, e := range m.events {
		if e.Name == name {
			out = append(out, e)
		}
	}
	return out
}

// issuer is a test signing key pinned in the key set.
type issuer struct {
	kid  string
	iss  string
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newIssuer(t *testing.T, kid, iss string) issuer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return issuer{kid: kid, iss: iss, priv: priv, pub: pub}
}

func (i issuer) sig(msg []byte) ([]byte, error) { return ed25519.Sign(i.priv, msg), nil }

func (i issuer) sign(t *testing.T, typ string, claims any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := signJWS(typ, i.kid, payload, i.sig)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// rawJWS assembles a compact token from a header and payload, signed by sign
// (nil: empty signature segment), without any of the profile's checks.
func rawJWS(t *testing.T, header map[string]any, claims any, sign func(input []byte) []byte) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	p, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	in := enc.EncodeToString(h) + "." + enc.EncodeToString(p)
	var sig []byte
	if sign != nil {
		sig = sign([]byte(in))
	}
	return in + "." + enc.EncodeToString(sig)
}

type env struct {
	t      *testing.T
	db     *store.DB
	led    *memLedger
	clock  time.Time
	far    issuer
	intr   issuer
	oth    issuer // a second, unrelated the runner: pinned, but registers nothing
	keys   *KeySet
	runs   *Runs
	ver    *Verifier
	orch   *Orchestrators
	ended  []RunRecord // AfterEnd calls
	txEnd  []RunRecord // TxEnd calls
	orchTx []string    // TxRevoke calls
	policy string
}

var testProfile = &spec.GenericProfile{
	Profile:      "code",
	BranchPrefix: "agent/",
	Ops: struct {
		Allow []string `json:"allow"`
	}{Allow: []string{"pr.open", "pr.update", "branch.push", "logs"}},
}

const testDigest = "sha256:79ade8ad9c78968f3b423865eb8c300cb34e816b416cac840d2b4fe9de29c2aa"

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ms, err := store.Migrations()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, ms); err != nil {
		t.Fatal(err)
	}
	e := &env{
		t: t, db: db, led: &memLedger{t: t},
		clock:  time.Date(2026, 10, 23, 22, 1, 0, 0, time.UTC),
		far:    newIssuer(t, "runner-1", "runner.host-1"),
		intr:   newIssuer(t, "interim-1", "chaperone.interim"),
		oth:    newIssuer(t, "runner-2", "runner.host-2"),
		policy: "baseline-test",
	}
	e.rebuild(true)
	return e
}

func (e *env) keyJSON(allowInterim bool) []byte {
	enc := base64.RawURLEncoding
	doc := map[string]any{
		"version":       1,
		"allow_interim": allowInterim,
		"keys": []any{
			map[string]any{"kid": e.far.kid, "issuer": e.far.iss, "public_key": enc.EncodeToString(e.far.pub)},
			map[string]any{"kid": e.oth.kid, "issuer": e.oth.iss, "public_key": enc.EncodeToString(e.oth.pub)},
			map[string]any{"kid": e.intr.kid, "issuer": e.intr.iss, "public_key": enc.EncodeToString(e.intr.pub),
				"interim": map[string]any{}},
		},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		e.t.Fatal(err)
	}
	return b
}

// rebuild reloads the key set (allow_interim as given) and every component
// over the same database, as a chapd restart does.
func (e *env) rebuild(allowInterim bool) {
	e.t.Helper()
	keys, err := ParseKeySet(e.keyJSON(allowInterim))
	if err != nil {
		e.t.Fatal(err)
	}
	e.keys = keys
	now := func() time.Time { return e.clock }
	profiles := func(d string) (*spec.GenericProfile, bool) { return testProfile, d == testDigest }
	e.runs, err = NewRuns(RunsConfig{
		DB: e.db, Keys: keys, Profiles: profiles, Appender: e.led, Now: now,
		TxEnd: func(_ context.Context, _ *store.Tx, r RunRecord, _ EndInfo) error {
			e.txEnd = append(e.txEnd, r)
			return nil
		},
		AfterEnd: func(_ context.Context, r RunRecord, _ EndInfo) { e.ended = append(e.ended, r) },
	})
	if err != nil {
		e.t.Fatal(err)
	}
	e.ver, err = NewVerifier(VerifierConfig{DB: e.db, Keys: keys, Profiles: profiles, Now: now})
	if err != nil {
		e.t.Fatal(err)
	}
	e.orch, err = NewOrchestrators(OrchConfig{
		DB: e.db, Appender: e.led, Now: now,
		PolicyVersion: func() string { return e.policy },
		TxRevoke: func(_ context.Context, _ *store.Tx, id string) error {
			e.orchTx = append(e.orchTx, id)
			return nil
		},
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

// claims returns the golden code-run claims with iat at the clock.
func (e *env) claims() spec.RunTokenClaims {
	iat := e.clock.Unix()
	return spec.RunTokenClaims{
		Iss: e.far.iss, Sub: "run:r-7f3a", Aud: "chaperone",
		Iat: iat, Exp: iat + 90*60 + 300,
		JTI: "n8Gf3kQ2xV7bTz1LwA9cYd", RunID: "r-7f3a", Project: "acme-shop",
		Profile: spec.TokenProfile{Name: "code", Version: "1.0.0", Digest: testDigest,
			OverlayDigest: "sha256:782eda6fe42a7759fe8b44ed92179f2a4182101d00a847ef58f23bd25e9bcb32"},
		BriefSHA:  "sha256:7ed2358fdd424519b90502f453c9ab84266b75d6c17db83fdb89511dd61d67c1",
		Isolation: "gvisor",
		TaskScope: spec.TaskScope{Repo: "acme/shop", Base: "main", Branch: "agent/r-7f3a",
			Paths: []string{"services/sync/src/**"}, Ops: []string{"pr.open", "branch.push"}},
		Budget: spec.Budget{Minutes: 90, Tokens: 2000000},
	}
}

func (e *env) ctl(act, runID string) string {
	e.t.Helper()
	return e.far.sign(e.t, typCtl, e.ctlClaims(act, runID))
}

func (e *env) ctlClaims(act, runID string) map[string]any {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		e.t.Fatal(err)
	}
	return map[string]any{
		"iss": e.far.iss, "aud": "chaperone", "iat": e.clock.Unix(), "exp": e.clock.Unix() + 60,
		"jti": base64.RawURLEncoding.EncodeToString(raw[:]), "act": act, "run_id": runID,
	}
}

// register registers claims through the real handler.
func (e *env) register(c spec.RunTokenClaims) string {
	e.t.Helper()
	tok := e.far.sign(e.t, typRun, c)
	if _, err := e.runs.Register(context.Background(), RegisterRequest{Control: e.ctl(actRunStart, c.RunID), Token: tok}); err != nil {
		e.t.Fatalf("register: %v", err)
	}
	return tok
}

func (e *env) verify(tok string) (*RunToken, error) { return e.ver.Verify(context.Background(), tok) }

// wantCode asserts err is a *Error with the given cause code.
func wantCode(t *testing.T, err error, code string) *Error {
	t.Helper()
	var re *Error
	if !errors.As(err, &re) {
		t.Fatalf("got %v, want a %s refusal", err, code)
	}
	if re.Code != code {
		t.Fatalf("got %s (%s), want %s", re.Code, re.Detail, code)
	}
	if re.Surface != surfaceOf(code) {
		t.Fatalf("surface %q for %s", re.Surface, code)
	}
	return re
}

func (e *env) end(runID string) error {
	return e.runs.End(context.Background(), EndRequest{Control: e.ctl(actRunEnd, runID), RunID: runID})
}

func mustNil(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func contains(s []string, v string) bool { return slices.Contains(s, v) }

func sprint(v any) string { return fmt.Sprint(v) }

func sha256Hex(s string) string { _, h := tokenHash(s); return h }
