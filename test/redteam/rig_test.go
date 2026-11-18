package redteam

// The red-team rig: the chapd stack (store, vault, redaction registry, ledger,
// policy engine, ops service, run-token verifiers, interim issuer, HTTP server)
// wired as cmd/chapd/wire.go wires it, with one change: every op's adapter is a
// spy that records what it was asked and never touches the world. A test then
// attacks over HTTP and asserts two things: the refusal, and that the spy saw
// nothing it should not have.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/ledger"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/redact"
	"github.com/joshua-noel/chaperone/internal/runtoken"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
	"github.com/joshua-noel/chaperone/internal/vault"
)

const (
	rigProject = "acme-shop"
	rigRepo    = "acme/shop"
	rigBranch  = "agent/rt-1"
	sha1       = "0588aa4ee0116267162e895016bcfda9ec3a3e2c"
	sha2       = "1111111111111111111111111111111111111111"
)

// ---- spy adapter -----------------------------------------------------------

// spy is the adapter of every op: it records Check and Execute calls and never
// does anything. Executions is the number that must stay at zero whenever a
// test expects a block.
type spy struct {
	mu     sync.Mutex
	checks []*ops.Request
	execs  []*ops.Request
	// needsApproval makes Check ask for a human (as the gh adapter does for a
	// medium or high tier PR).
	needsApproval bool
	// result is returned by Execute.
	result map[string]any
	// extRef and execErr, when set, are what Execute returns as the external
	// reference and as its error.
	extRef  string
	execErr error
}

func (s *spy) Check(_ context.Context, r *ops.Request) (ops.CheckResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checks = append(s.checks, r)
	return ops.CheckResult{Checks: []ops.Check{{Name: "spy", Passed: true}}, NeedsApproval: s.needsApproval, ApprovalWhy: "spy asks for a human"}, nil
}

func (s *spy) Execute(_ context.Context, r *ops.Request) (ops.Outcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.execs = append(s.execs, r)
	if s.execErr != nil {
		return ops.Outcome{}, s.execErr
	}
	res := s.result
	if res == nil {
		res = map[string]any{"ok": true}
	}
	ref := "spy:" + r.ID
	if s.extRef != "" {
		ref = s.extRef
	}
	return ops.Outcome{ExternalRef: ref, Result: res}, nil
}

func (s *spy) executions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.execs)
}

// ---- test key wrapper ------------------------------------------------------

type aesWrap struct{ aead cipher.AEAD }

func newAESWrap(t testing.TB) vault.KeyWrapper {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		t.Fatal(err)
	}
	return aesWrap{g}
}

func (aesWrap) Name() string { return "test-aesgcm" }
func (w aesWrap) Wrap(p []byte) ([]byte, error) {
	n := make([]byte, w.aead.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return w.aead.Seal(n, n, p, nil), nil
}
func (w aesWrap) Unwrap(b []byte) ([]byte, error) {
	ns := w.aead.NonceSize()
	return w.aead.Open(nil, b[:ns], b[ns:], nil)
}

// ---- the rig ---------------------------------------------------------------

type rigOpts struct {
	enable        []string // ops turned on in the baseline
	allowInterim  *bool    // key set allow_interim; default true
	approvals     ops.Approvals
	needsApproval bool // the spy asks for a human on every request
	// interimOps narrows the interim key's op ceiling; nil means the full ceiling.
	interimOps []string
	// prMerge, when set, is the real pr.merge adapter (the one cmd/chapd installs)
	// over this merger, for the project rigProject, in repository prRepo; the
	// spy stays the adapter of every other op.
	prMerge *ops.PRMerger
	prRepo  string
	// deploy, when set, is the real deploy adapter (RT-23); the spy stays the
	// adapter of every other op.
	deploy ops.Adapter
	// adapters, when set, is called once the vault and the clock exist and
	// returns real adapters to install in place of the spy (RT-24 Google).
	adapters func(g *rig) map[string]ops.Adapter
	// log receives chapd's structured log; nil discards it. The canary tests
	// read it back.
	log io.Writer
	// orchOps and orchMint shape the orchestrator token; nil means the defaults.
	orchOps  []string
	noMint   bool
	orchDays int
}

type rig struct {
	t      *testing.T
	dir    string
	dbPath string
	db     *store.DB
	vault  *vault.Vault
	reg    *redact.Registry
	led    *ledger.Ledger
	svc    *ops.Service
	spy    *spy
	runs   *runtoken.Runs
	orch   *runtoken.Orchestrators
	ver    *runtoken.Verifier
	keys   *runtoken.KeySet
	minter *runtoken.Interim
	srv    *httptest.Server
	// afterEnd, when set, is told of every run that ends, as chapd's AfterEnd
	// hook tells the git proxy (RT-05).
	afterEnd func(runID string)

	// OrchToken is a live orchestrator token; RunnerKey signs runner-1 tokens
	// and AttackerKey is a key nobody pinned.
	OrchToken   string
	RunnerKey   ed25519.PrivateKey
	AttackerKey ed25519.PrivateKey
	// interimKey is the interim issuer's private key. Only the test has it; a
	// real agent does not (it lives in the vault).
	interimKey ed25519.PrivateKey
	opts       rigOpts
	keysJSON   string
	scfg       ops.ServerConfig
	handler    http.Handler

	mu  sync.Mutex
	now time.Time
	// seen holds every response body chapd has sent in this test.
	seen []string
}

func (g *rig) clock() time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.now
}

func (g *rig) advance(d time.Duration) {
	g.mu.Lock()
	g.now = g.now.Add(d)
	g.mu.Unlock()
}

// enabledPack is the shipped baseline with the named ops turned on.
func enabledPack(t testing.TB, cat *policy.Catalog, enable ...string) *policy.Pack {
	t.Helper()
	src := string(policy.BaselineBytes())
	for _, op := range enable {
		i := strings.Index(src, "  "+op+":")
		if i < 0 {
			t.Fatalf("op %s is not in the baseline", op)
		}
		j := strings.Index(src[i:], "enabled: false")
		if j < 0 {
			t.Fatalf("op %s has no enabled: false to flip", op)
		}
		src = src[:i+j] + "enabled: true" + src[i+j+len("enabled: false"):]
	}
	p, err := policy.LoadBaseline([]byte(src), cat)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func logSink(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	return w
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// newRig builds the stack in a fresh temporary directory (or o.dir).
func newRig(t *testing.T, o rigOpts) *rig {
	t.Helper()
	ctx := context.Background()
	g := &rig{t: t, opts: o, spy: &spy{needsApproval: o.needsApproval}, now: time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)}
	g.dir = t.TempDir()
	g.dbPath = filepath.Join(g.dir, "state.db")

	db, err := store.Open(ctx, g.dbPath)
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
	g.db = db

	// Vault, with the interim issuer's seed in it.
	g.reg = redact.NewRegistry()
	wrap := newAESWrap(t)
	vcfg := vault.Config{Dir: filepath.Join(g.dir, "vault"), KeyDir: filepath.Join(g.dir, "vault-keys"), DB: db, Wrapper: wrap, Registry: g.reg}
	if err := vault.Init(ctx, vcfg, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(ctx, vcfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	g.vault = v
	g.reg = v.Registry()

	seed, pub, err := runtoken.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sb, err := base64.RawURLEncoding.DecodeString(seed)
	if err != nil {
		t.Fatal(err)
	}
	g.interimKey = ed25519.NewKeyFromSeed(sb)
	if _, err := v.Import(ctx, vault.Meta{ID: "interim-key", Kind: "interim-signing-key"}, []byte(seed)); err != nil {
		t.Fatal(err)
	}
	if err := v.LoadRegistry(ctx); err != nil {
		t.Fatal(err)
	}

	fpub, fpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	g.RunnerKey = fpriv
	_, g.AttackerKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	allow := true
	if o.allowInterim != nil {
		allow = *o.allowInterim
	}
	interim := map[string]any{"max_seconds": 7200}
	if o.interimOps != nil {
		interim["ops"] = o.interimOps
	} else {
		interim["ops"] = runtoken.HostInterimCeiling
	}
	doc, _ := json.Marshal(map[string]any{"version": 1, "allow_interim": allow, "keys": []any{
		map[string]any{"kid": "runner-1", "issuer": "runner.test", "public_key": b64(fpub)},
		map[string]any{"kid": "interim-1", "issuer": "chaperone.interim", "public_key": pub, "interim": interim},
	}})
	g.keysJSON = string(doc)
	keys, err := runtoken.ParseKeySet(doc)
	if err != nil {
		t.Fatal(err)
	}
	g.keys = keys

	led, err := ledger.Open(ctx, db, ledger.Config{Instance: "redteam", Version: "test", Redactor: g.reg, Clock: g.clock, ExportDir: filepath.Join(g.dir, "export")})
	if err != nil {
		t.Fatal(err)
	}
	g.led = led
	sink := ledgerSink{l: led}

	cat, _, err := policy.Default()
	if err != nil {
		t.Fatal(err)
	}
	pack := enabledPack(t, cat, o.enable...)
	engine := policy.NewEngine(cat, pack, "")
	adapters := map[string]ops.Adapter{}
	for _, op := range cat.Ops() {
		adapters[op] = g.spy
	}
	if o.prMerge != nil {
		adapters["pr.merge"] = ops.NewPRMergeAdapter(o.prMerge, func(project string) (ops.PRPolicy, bool) {
			if project != rigProject {
				return ops.PRPolicy{}, false
			}
			return ops.PRPolicy{Version: "rt-1", Repo: o.prRepo, Base: "main"}, true
		})
	}
	if o.deploy != nil {
		adapters["deploy"] = o.deploy
	}
	if o.adapters != nil {
		for op, a := range o.adapters(g) {
			adapters[op] = a
		}
	}
	svc, err := ops.NewService(ops.Config{
		DB: db, Ledger: sink, Policy: engine, Adapters: adapters, Approvals: o.approvals, Redactor: g.reg,
		Log: slog.New(slog.NewTextHandler(logSink(o.log), &slog.HandlerOptions{Level: slog.LevelDebug})), Now: g.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	g.svc = svc

	orch, err := runtoken.NewOrchestrators(runtoken.OrchConfig{
		DB: db, Appender: sink, Redact: g.reg, Now: g.clock, PolicyVersion: pack.BaselineVersion,
		TxRevoke: func(ctx context.Context, tx *store.Tx, id string) error { return svc.CancelOrchOps(ctx, tx, id) },
	})
	if err != nil {
		t.Fatal(err)
	}
	g.orch = orch
	runs, err := runtoken.NewRuns(runtoken.RunsConfig{
		DB: db, Keys: keys, Appender: sink, Now: g.clock,
		TxEnd: func(ctx context.Context, tx *store.Tx, run runtoken.RunRecord, info runtoken.EndInfo) error {
			return svc.CancelRunOps(ctx, tx, run.RunID, "run ended")
		},
		AfterEnd: func(_ context.Context, run runtoken.RunRecord, _ runtoken.EndInfo) {
			if g.afterEnd != nil {
				g.afterEnd(run.RunID)
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	g.runs = runs
	g.newVerifier()

	signer := runtoken.NewVaultSigner(v, "interim-key", "interim-1")
	g.minter, err = runtoken.NewInterim(runtoken.InterimConfig{Runs: runs, Orch: orch, Signer: signer})
	if err != nil {
		t.Fatal(err)
	}

	g.scfg = ops.ServerConfig{
		Svc: svc, Version: "redteam",
		AllowInterim: keys.AllowInterim,
		Runs:         runsBackend{r: runs}, Ledger: ledgerBackend{l: led}, Interim: interimBackend{i: g.minter}, Vault: vaultBackend{v: v},
	}
	g.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		h := g.handler
		g.mu.Unlock()
		h.ServeHTTP(w, r)
	}))
	// The Host allowlist must hold the listener's address before the first request.
	g.scfg.Hosts = []string{g.srv.Listener.Addr().String()}
	g.restart()
	g.srv.Start()
	t.Cleanup(g.srv.Close)

	scope := runtoken.OrchScope{Projects: []string{rigProject}, MintInterim: !o.noMint,
		Ops: []string{"pr.open", "pr.update", "pr.merge", "branch.push", "health", "logs", "deploy", "mail.send", "drive.share", "data.apply", "repo.settings"}}
	if o.orchOps != nil {
		scope.Ops = o.orchOps
	}
	res, err := orch.Issue(ctx, runtoken.IssueParams{ID: "main", Scope: scope, Days: max(o.orchDays, 7)})
	if err != nil {
		t.Fatal(err)
	}
	g.OrchToken = res.Token
	return g
}

func (g *rig) newVerifier() {
	v, err := runtoken.NewVerifier(runtoken.VerifierConfig{DB: g.db, Keys: g.keys, Now: g.clock})
	if err != nil {
		g.t.Fatal(err)
	}
	g.ver = v
}

// restart rebuilds the token verifier and the HTTP handler over the same
// database, as a chapd restart does: nothing but SQLite carries over, so a
// revocation that held only in memory would be lost.
func (g *rig) restart() {
	g.newVerifier()
	cfg := g.scfg
	cfg.Auth = &ops.Auth{
		Run:  runVerifier{v: g.ver, stop: raiseTokenMisuse(g.led, idMaker("s-"), slog.New(slog.NewTextHandler(logSink(g.opts.log), nil)))},
		Orch: orchVerifier{o: g.orch}, Svc: g.svc,
	}
	h := ops.NewServer(cfg)
	g.mu.Lock()
	g.handler = h
	g.mu.Unlock()
}

// mint issues an interim run token with the orchestrator token through the
// same runtoken.Interim that `POST /v0/dev-tokens` calls. Tests of the HTTP
// route itself are TestDevTokenOverHTTP.
func (g *rig) mint(opsList ...string) (token, runID string) {
	g.t.Helper()
	if len(opsList) == 0 {
		opsList = []string{"pr.merge", "pr.open", "health", "deploy", "mail.send"}
	}
	res, err := g.minter.Mint(context.Background(), g.OrchToken, runtoken.MintRequest{
		Project: rigProject, Profile: "host-interim", Repo: rigRepo, Base: "main", Branch: rigBranch, Ops: opsList, Minutes: 30,
	})
	if err != nil {
		g.t.Fatalf("mint: %v", err)
	}
	return res.Token, res.Claims.RunID
}

// call performs one HTTP call and decodes the JSON answer.
func (g *rig) call(method, path, token string, body any) (int, map[string]any) {
	g.t.Helper()
	st, m, _ := g.callH(method, path, token, body)
	return st, m
}

func (g *rig) callH(method, path, token string, body any) (int, map[string]any, http.Header) {
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
	req, err := http.NewRequest(method, g.srv.URL+path, rd)
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
	g.mu.Lock()
	g.seen = append(g.seen, string(data))
	g.mu.Unlock()
	var out map[string]any
	if len(data) > 0 {
		if err := json.Unmarshal(data, &out); err != nil {
			g.t.Fatalf("%s %s: body is not JSON: %q", method, path, data)
		}
	}
	return resp.StatusCode, out, resp.Header
}

// mustDenial checks body against denial.schema.json and the wanted cause.
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

func opBody(op, ref string, params map[string]any) map[string]any {
	adapter := "github"
	switch op {
	case "deploy", "health":
		adapter = "pilot"
	case "mail.send":
		adapter = "gmail"
	}
	return map[string]any{"op": op, "target": map[string]any{"adapter": adapter, "ref": ref}, "params": params}
}

func mergeBody(sha string) map[string]any {
	return opBody("pr.merge", rigRepo+"#214", map[string]any{"base": "main", "head_sha": sha, "method": "squash"})
}

func deployBody(sha string) map[string]any {
	return opBody("deploy", "pilot", map[string]any{"sha": sha})
}

// count runs a COUNT query.
func (g *rig) count(q string, args ...any) int {
	g.t.Helper()
	var n int
	if err := g.db.SQL().QueryRow(q, args...).Scan(&n); err != nil {
		g.t.Fatal(err)
	}
	return n
}

// ledgerEvents returns every ledger event of the given name as raw JSON text.
func (g *rig) ledgerText() string {
	g.t.Helper()
	rows, err := g.db.SQL().Query(`SELECT * FROM ledger_events`)
	if err != nil {
		g.t.Fatal(err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var sb strings.Builder
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			g.t.Fatal(err)
		}
		for _, v := range vals {
			fmt.Fprintf(&sb, "%v|", v)
			if b, ok := v.([]byte); ok {
				sb.Write(b)
			}
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

func (g *rig) mustLedgerOK() {
	g.t.Helper()
	rep, err := g.led.Verify(context.Background(), false)
	if err != nil || !rep.OK() {
		g.t.Fatalf("the ledger does not verify: %v %v", err, rep.Problems())
	}
}
