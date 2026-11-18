package ops

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// ---- fake ledger -----------------------------------------------------------

// fakeLedger appends to a table in the same transaction, like the real one, so
// atomicity is tested against SQLite and not against a mock. Each event is
// validated against the spec's ledger-event schema (with a stand-in envelope).
type fakeLedger struct {
	t      *testing.T
	mu     sync.Mutex
	fail   func(Event) error // injected failure
	onNext func(Event)       // runs after the row is written, before commit
	seq    int
}

func initFakeLedger(ctx context.Context, db *store.DB) error {
	return db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS fake_ledger (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, run_id TEXT, project TEXT, orch TEXT,
            attrs TEXT, body TEXT, severity TEXT)`)
		return err
	})
}

func (l *fakeLedger) AppendTx(ctx context.Context, tx *store.Tx, e Event) error {
	if l.fail != nil {
		if err := l.fail(e); err != nil {
			return err
		}
	}
	if l.t != nil {
		validateEvent(l.t, e)
	}
	attrs, _ := json.Marshal(e.Attributes)
	orch, _ := e.Attributes["factory.orchestrator.id"].(string)
	if _, err := tx.ExecContext(ctx, `INSERT INTO fake_ledger (name, run_id, project, orch, attrs, body, severity) VALUES (?,?,?,?,?,?,?)`,
		e.Name, e.RunID, e.Project, orch, string(attrs), e.Body, e.Severity); err != nil {
		return err
	}
	if l.onNext != nil {
		l.onNext(e)
	}
	return nil
}

// validateEvent wraps e in a stand-in chain envelope and checks it against
// ledger-event.schema.json: attributes are closed per event name, an
// orchestrator event has no run_id, a run event has one.
func validateEvent(t *testing.T, e Event) {
	t.Helper()
	runID := e.RunID
	trace := spec.TraceID("r-test")
	if runID != "" {
		trace = spec.TraceID(runID)
	}
	sev := map[string]int{"": 9, "INFO": 9, "WARN": 13}[e.Severity]
	doc := map[string]any{
		"spec_version": "0", "chain": "chaperone.test", "seq": float64(1),
		"prev_hash":      "sha256:" + strings.Repeat("1", 64),
		"hash":           "sha256:" + strings.Repeat("2", 64),
		"time_unix_nano": "1790000000000000000", "trace_id": trace, "span_id": "00f067aa0ba902b7",
		"severity_number": float64(sev), "event_name": e.Name,
		"resource":   map[string]any{"service.name": "chaperone", "service.instance.id": "test"},
		"project":    e.Project,
		"attributes": e.Attributes,
	}
	if sev == 13 {
		doc["severity_text"] = "WARN"
	}
	if runID != "" {
		doc["run_id"] = runID
	}
	if e.Body != "" {
		doc["body"] = e.Body
	}
	if err := spec.Validate(spec.SchemaEvent, doc); err != nil {
		t.Errorf("event %s does not validate against the spec: %v\nattributes: %v", e.Name, err, e.Attributes)
	}
	if e.Attributes["factory.requester.kind"] == KindOrchestrator && runID != "" {
		t.Errorf("orchestrator event %s carries a run_id", e.Name)
	}
}

func (l *fakeLedger) rows(t *testing.T, db *store.DB, name string) []map[string]any {
	t.Helper()
	q := `SELECT seq, name, COALESCE(run_id,''), project, COALESCE(orch,''), attrs, body FROM fake_ledger`
	var args []any
	if name != "" {
		q += ` WHERE name = ?`
		args = append(args, name)
	}
	rs, err := db.SQL().Query(q+` ORDER BY seq`, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	var out []map[string]any
	for rs.Next() {
		var seq int
		var n, run, proj, orch, attrs, body string
		if err := rs.Scan(&seq, &n, &run, &proj, &orch, &attrs, &body); err != nil {
			t.Fatal(err)
		}
		var a map[string]any
		_ = json.Unmarshal([]byte(attrs), &a)
		out = append(out, map[string]any{"seq": seq, "name": n, "run_id": run, "project": proj, "orch": orch, "attrs": a, "body": body})
	}
	return out
}

// ---- fake adapter ----------------------------------------------------------

type fakeAdapter struct {
	mu      sync.Mutex
	check   func(*Request) (CheckResult, error)
	execute func(context.Context, *Request) (Outcome, error)
	checks  int
	execs   []string // execution ids
}

func (a *fakeAdapter) Check(_ context.Context, r *Request) (CheckResult, error) {
	a.mu.Lock()
	a.checks++
	f := a.check
	a.mu.Unlock()
	if f != nil {
		return f(r)
	}
	return CheckResult{Checks: []Check{{Name: "fake", Passed: true}}}, nil
}

func (a *fakeAdapter) Execute(ctx context.Context, r *Request) (Outcome, error) {
	a.mu.Lock()
	a.execs = append(a.execs, r.ExecutionID)
	f := a.execute
	a.mu.Unlock()
	if f != nil {
		return f(ctx, r)
	}
	return Outcome{ExternalRef: "https://example.invalid/ref/" + r.ID, Result: map[string]any{"ok": true}}, nil
}

func (a *fakeAdapter) executions() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.execs...)
}

// ---- fake verifiers --------------------------------------------------------

type fakeVerifier struct {
	runs  map[string]*Caller
	orchs map[string]*Caller
	errs  map[string]error
}

func (v *fakeVerifier) VerifyRun(_ context.Context, b string) (*Caller, error) {
	if err := v.errs[b]; err != nil {
		return nil, err
	}
	if c, ok := v.runs[b]; ok {
		cp := *c
		return &cp, nil
	}
	return nil, &VerifyError{Code: CodeTokenInvalid, Detail: "signature does not verify"}
}

func (v *fakeVerifier) VerifyOrch(_ context.Context, b string) (*Caller, error) {
	if err := v.errs[b]; err != nil {
		return nil, err
	}
	if c, ok := v.orchs[b]; ok {
		cp := *c
		return &cp, nil
	}
	return nil, &VerifyError{Code: CodeTokenInvalid, Detail: "unknown token"}
}

// ---- rig -------------------------------------------------------------------

const (
	runTok = "eyJhbGciOiJFZERTQSJ9.eyJydW4iOiJyLTdmM2EifQ.c2ln"
	// hiTok is a host-interim run: its profile ceiling includes the high-class ops.
	hiTok   = "eyJhbGciOiJFZERTQSJ9.eyJydW4iOiJyLTliMmMifQ.c2ln"
	orchTok = OrchPrefix + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

type rig struct {
	t       *testing.T
	db      *store.DB
	led     *fakeLedger
	svc     *Service
	srv     *Server
	http    *httptest.Server
	ad      *fakeAdapter
	ver     *fakeVerifier
	eff     *policy.Pack
	engine  *policy.Engine
	now     time.Time
	nowMu   sync.Mutex
	ids     int
	alerts  []Alert
	alertMu sync.Mutex
}

func (g *rig) Alert(_ context.Context, a Alert) {
	g.alertMu.Lock()
	g.alerts = append(g.alerts, a)
	g.alertMu.Unlock()
}

func (g *rig) alertList() []Alert {
	g.alertMu.Lock()
	defer g.alertMu.Unlock()
	return append([]Alert(nil), g.alerts...)
}

func (g *rig) clock() time.Time {
	g.nowMu.Lock()
	defer g.nowMu.Unlock()
	return g.now
}

func (g *rig) advance(d time.Duration) {
	g.nowMu.Lock()
	g.now = g.now.Add(d)
	g.nowMu.Unlock()
}

// openRigDB opens and migrates a database file and the fake ledger table.
func openRigDB(t *testing.T, path string) *store.DB {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	ms, err := store.Migrations()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, ms); err != nil {
		t.Fatal(err)
	}
	if err := initFakeLedger(ctx, db); err != nil {
		t.Fatal(err)
	}
	return db
}

// enabledPack is the shipped baseline with the named ops turned on.
func enabledPack(t *testing.T, cat *policy.Catalog, ops ...string) *policy.Pack {
	t.Helper()
	return packWith(t, cat, ops, nil)
}

// packWith is the shipped baseline with the ops in enable turned on and the ops in disable turned off (the baseline
// turns some ops on, and a test may want one back off, as after a rollback).
func packWith(t *testing.T, cat *policy.Catalog, enable, disable []string) *policy.Pack {
	t.Helper()
	src := string(policy.BaselineBytes())
	flip := func(op, from, to string) {
		key := op + ":"
		i := strings.Index(src, "  "+key)
		if i < 0 {
			t.Fatalf("op %s not in baseline", op)
		}
		eol := strings.Index(src[i:], "\n")
		j := strings.Index(src[i:i+eol], from)
		if j < 0 {
			return // already in the wanted state in the shipped baseline
		}
		src = src[:i+j] + to + src[i+j+len(from):]
	}
	for _, op := range enable {
		flip(op, "enabled: false", "enabled: true")
	}
	for _, op := range disable {
		flip(op, "enabled: true", "enabled: false")
	}
	p, err := policy.LoadBaseline([]byte(src), cat)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type rigOpts struct {
	enable    []string
	disable   []string // ops forced off although the shipped baseline turns them on
	approvals Approvals
	dbPath    string
	git       GitHandler
}

func newRig(t *testing.T, o rigOpts) *rig {
	t.Helper()
	cat, _, err := policy.Default()
	if err != nil {
		t.Fatal(err)
	}
	if o.dbPath == "" {
		o.dbPath = filepath.Join(t.TempDir(), "state.db")
	}
	g := &rig{t: t, now: time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC), ad: &fakeAdapter{}}
	g.db = openRigDB(t, o.dbPath)
	t.Cleanup(func() { g.db.Close() })
	g.led = &fakeLedger{t: t}
	pack := packWith(t, cat, o.enable, o.disable)
	g.eff = pack
	g.engine = policy.NewEngine(cat, pack, "")
	adapters := map[string]Adapter{}
	for _, op := range cat.Ops() {
		adapters[op] = g.ad
	}
	g.svc, err = NewService(Config{DB: g.db, Ledger: g.led, Policy: g.engine, Adapters: adapters, Approvals: o.approvals, Alerter: g, Now: g.clock})
	if err != nil {
		t.Fatal(err)
	}
	g.svc.idFn = func(prefix string) string {
		g.ids++
		return fmt.Sprintf("%s%06d", prefix, g.ids)
	}
	g.ver = &fakeVerifier{
		runs: map[string]*Caller{runTok: {
			Kind: KindRun, RunID: "r-7f3a", JTI: "jti-aaaaaaaaaaaaaaaa", Profile: "code", Project: "acme-shop",
			Repo: "acme/shop", Base: "main", Branch: "agent/r-7f3a",
			TokenOps: []string{"pr.open", "pr.update", "branch.push", "health", "logs", "deploy", "pr.merge"},
		}, hiTok: {
			Kind: KindRun, RunID: "r-9b2c", JTI: "jti-bbbbbbbbbbbbbbbb", Profile: "host-interim", Interim: true, Project: "acme-shop",
			Repo: "acme/shop", Base: "main", Branch: "agent/r-9b2c",
			TokenOps: []string{"pr.open", "pr.update", "pr.merge", "branch.push", "health", "logs", "deploy"},
		}},
		orchs: map[string]*Caller{orchTok: {
			Kind: KindOrchestrator, OrchID: "main", Fingerprint: "0a1b2c3d", Projects: []string{"acme-shop"},
			ScopeOps: []string{"pr.merge", "pr.open", "deploy", "health", "repo.settings"}, MintInterim: true,
		}},
		errs: map[string]error{},
	}
	g.srv = NewServer(ServerConfig{Svc: g.svc, Auth: &Auth{Run: g.ver, Orch: g.ver, Svc: g.svc}, Version: "test", Git: o.git})
	g.http = httptest.NewServer(g.srv)
	g.srv.cfg.Hosts = []string{strings.TrimPrefix(g.http.URL, "http://")}
	t.Cleanup(g.http.Close)
	return g
}

// call performs one HTTP call and decodes the JSON answer.
func (g *rig) call(method, path, token string, body any) (int, map[string]any, http.Header) {
	g.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		data, err := json.Marshal(b)
		if err != nil {
			g.t.Fatal(err)
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, g.http.URL+path, rd)
	if err != nil {
		g.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		g.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(data) > 0 {
		if err := json.Unmarshal(data, &out); err != nil {
			g.t.Fatalf("%s %s: body is not JSON: %q", method, path, data)
		}
	}
	return resp.StatusCode, out, resp.Header
}

// mustDenial checks that body is a valid spec denial with the wanted cause.
func mustDenial(t *testing.T, body map[string]any, cause string) map[string]any {
	t.Helper()
	if err := spec.Validate(spec.SchemaDenial, body); err != nil {
		t.Fatalf("denial does not validate against denial.schema.json: %v\n%v", err, body)
	}
	if body["cause_code"] != cause {
		t.Fatalf("cause_code = %v, want %s (why: %v)", body["cause_code"], cause, body["why"])
	}
	return body
}

func prMerge(sha string) map[string]any {
	return map[string]any{
		"op": "pr.merge", "target": map[string]any{"adapter": "github", "ref": "acme/shop#214"},
		"params": map[string]any{"base": "main", "head_sha": sha, "method": "squash"},
	}
}

func health() map[string]any {
	return map[string]any{"op": "health", "target": map[string]any{"adapter": "pilot", "ref": "readiness"}, "params": map[string]any{}}
}

func mergeOrch(sha string) map[string]any {
	m := prMerge(sha)
	m["project"] = "acme-shop"
	return m
}

const sha1 = "0588aa4ee0116267162e895016bcfda9ec3a3e2c"
const sha2 = "1111111111111111111111111111111111111111"

// scalar helpers
func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func opCount(t *testing.T, db *store.DB, where string, args ...any) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM ops WHERE `+where, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func ledgerCount(t *testing.T, db *store.DB) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM fake_ledger`).Scan(&n); err != nil && err != sql.ErrNoRows {
		t.Fatal(err)
	}
	return n
}

func tempDBPath(t *testing.T) string { return filepath.Join(t.TempDir(), "state.db") }

var _ = os.Getenv
