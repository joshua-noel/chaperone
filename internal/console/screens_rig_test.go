package console

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/approvals"
	"github.com/joshua-noel/chaperone/internal/ledger"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/redact"
	"github.com/joshua-noel/chaperone/internal/runtoken"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
	"github.com/joshua-noel/chaperone/internal/vault"
)

// The L1-20 screens run here over the real parts: a real ledger with its
// schema checks, the real run and orchestrator registries, the real policy
// engine, a real vault (with a test key wrapper) and the real WebAuthn
// approvals path.

// ledSink adapts the ledger to the two appender interfaces the parts use.
type ledSink struct{ l *ledger.Ledger }

func (s ledSink) Append(ctx context.Context, tx *store.Tx, e runtoken.Event) error {
	_, err := s.l.AppendTx(ctx, tx, ledger.Draft{Name: e.Name, RunID: e.RunID, Project: e.Project, Severity: e.Severity, Attributes: e.Attributes, Body: e.Body})
	return err
}

func (s ledSink) AppendTx(ctx context.Context, tx *store.Tx, e approvals.LedgerEvent) error {
	_, err := s.l.AppendTx(ctx, tx, ledger.Draft{Name: e.Name, RunID: e.RunID, Project: e.Project, Severity: e.Severity, Attributes: e.Attributes, Body: e.Body})
	return err
}

// aesWrap is a test vault.KeyWrapper (DPAPI does not exist on Linux CI).
type aesWrap struct{ aead cipher.AEAD }

func newAESWrap(t testing.TB) aesWrap {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
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
	_, _ = rand.Read(n)
	return w.aead.Seal(n, n, p, nil), nil
}
func (w aesWrap) Unwrap(b []byte) ([]byte, error) {
	if len(b) < w.aead.NonceSize() {
		return nil, errors.New("short blob")
	}
	return w.aead.Open(nil, b[:w.aead.NonceSize()], b[w.aead.NonceSize():], nil)
}

type scrRig struct {
	*apprRig
	led     *ledger.Ledger
	runs    *runtoken.Runs
	orch    *runtoken.Orchestrators
	vault   *vault.Vault
	pol     *policy.Engine
	reg     *redact.Registry
	polDir  string
	export  string
	logs    *syncBuf
	dbPath  string
	seq     int
	vaultOn bool
}

func newScrRig(t *testing.T) *scrRig { return newScrRigOpts(t, true) }

// newScrRigCfg is newScrRig with a hook that may change the console's Config (frame ancestors).
func newScrRigCfg(t *testing.T, mut func(*Config)) *scrRig { return newScrRigOpts(t, true, mut) }

func newScrRigOpts(t *testing.T, withVault bool, mut ...func(*Config)) *scrRig {
	t.Helper()
	ctx := context.Background()
	var cfgMut func(*Config)
	if len(mut) > 0 {
		cfgMut = mut[0]
	}
	ar := newApprRigCfg(t, nil, cfgMut)
	sr := &scrRig{apprRig: ar, reg: redact.NewRegistry(), logs: &syncBuf{}, vaultOn: withVault}
	ar.con.log = slog.New(slog.NewTextHandler(sr.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	dir := t.TempDir()
	sr.export = filepath.Join(dir, "export")

	var err error
	sr.led, err = ledger.Open(ctx, ar.db, ledger.Config{Instance: "test", Version: "test", ExportDir: sr.export, Redactor: sr.reg})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sr.led.Close() })
	sink := ledSink{sr.led}

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	keys, err := runtoken.ParseKeySet([]byte(fmt.Sprintf(
		`{"version":1,"allow_interim":false,"keys":[{"kid":"runner-1","issuer":"runner.host-1","public_key":%q}]}`,
		b64.EncodeToString(pub))))
	if err != nil {
		t.Fatal(err)
	}
	nowFn := func() time.Time { ar.rig.mu.Lock(); defer ar.rig.mu.Unlock(); return ar.rig.now }

	cat, base, err := policy.Default()
	if err != nil {
		t.Fatal(err)
	}
	sr.polDir = filepath.Join(dir, "policy")
	if err := os.MkdirAll(sr.polDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sr.pol = policy.NewEngine(cat, base, sr.polDir)

	sr.runs, err = runtoken.NewRuns(runtoken.RunsConfig{DB: ar.db, Keys: keys, Appender: sink, Now: nowFn})
	if err != nil {
		t.Fatal(err)
	}
	sr.orch, err = runtoken.NewOrchestrators(runtoken.OrchConfig{DB: ar.db, Appender: sink, Redact: sr.reg, PolicyVersion: base.BaselineVersion, Now: nowFn})
	if err != nil {
		t.Fatal(err)
	}

	cfg := ScreensConfig{Version: "test-1.2.3", Runs: sr.runs, Orch: sr.orch, Ledger: sr.led, Policy: sr.pol, Projects: []string{"acme-shop"}}
	if withVault {
		vcfg := vault.Config{Dir: filepath.Join(dir, "vault"), KeyDir: filepath.Join(dir, "keys"), DB: ar.db, Wrapper: newAESWrap(t), Registry: sr.reg}
		if err := vault.Init(ctx, vcfg, func(string) error { return nil }); err != nil {
			t.Fatal(err)
		}
		sr.vault, err = vault.Open(ctx, vcfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(sr.vault.Close)
		cfg.Vault, cfg.Record = sr.vault, sink
	}
	if err := ar.con.UseScreens(cfg); err != nil {
		t.Fatal(err)
	}
	return sr
}

// seedRun inserts an active run, as Register would after verifying its token.
func (sr *scrRig) seedRun(id, project string) {
	sr.t.Helper()
	now := sr.rig.now
	claims, err := json.Marshal(spec.RunTokenClaims{
		Iss: "runner.host-1", Sub: id, Aud: "chaperone", Iat: now.Unix(), Exp: now.Add(time.Hour).Unix(), JTI: "jti-" + id + "-0123456789",
		RunID: id, Project: project, Profile: spec.TokenProfile{Name: "code", Version: "1"}, Budget: spec.Budget{Minutes: 30, Tokens: 100000},
	})
	if err != nil {
		sr.t.Fatal(err)
	}
	_, err = sr.db.SQL().Exec(`INSERT INTO runs (run_id, jti, project, profile_name, profile_version, issuer, kid, interim, iat, exp,
		claims_json, claims_sha256, state, registered_at) VALUES (?, ?, ?, 'code', '1', 'runner.host-1', 'runner-1', 0, ?, ?, ?, ?, 'active', ?)`,
		id, "jti-"+id+"-0123456789", project, now.Unix(), now.Add(time.Hour).Unix(), string(claims), strings.Repeat("0", 64), now.Unix())
	if err != nil {
		sr.t.Fatal(err)
	}
}

// seedDenial appends a denial event the way ops does.
func (sr *scrRig) seedDenial(run, project, code, body string) {
	sr.t.Helper()
	sr.seq++
	err := sr.db.Immediate(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		_, err := sr.led.AppendTx(ctx, tx, ledger.Draft{Name: "denial", RunID: run, Project: project, Severity: "WARN", Body: body,
			Attributes: map[string]any{"factory.denial.id": fmt.Sprintf("d-%06d", sr.seq), "factory.surface": "op",
				"factory.cause_code": code, "factory.thrash.count": float64(1), "factory.requester.kind": "run"}})
		return err
	})
	if err != nil {
		sr.t.Fatal(err)
	}
}

// seedOrchDenial records a denial of an orchestrator caller (no run), as chapd does.
func (sr *scrRig) seedOrchDenial(orch, project, code, body string) {
	sr.t.Helper()
	sr.seq++
	err := sr.db.Immediate(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		_, err := sr.led.AppendTx(ctx, tx, ledger.Draft{Name: "denial", Project: project, Severity: "WARN", Body: body,
			Attributes: map[string]any{"factory.denial.id": fmt.Sprintf("d-%06d", sr.seq), "factory.surface": "token",
				"factory.cause_code": code, "factory.thrash.count": float64(1), "factory.requester.kind": "orchestrator",
				"factory.orchestrator.id": orch}})
		return err
	})
	if err != nil {
		sr.t.Fatal(err)
	}
}

func (sr *scrRig) issueOrch(id string) string {
	sr.t.Helper()
	res, err := sr.orch.Issue(context.Background(), runtoken.IssueParams{ID: id,
		Scope: runtoken.OrchScope{Projects: []string{"acme-shop"}, Ops: []string{"health", "pr.*"}}, Days: 7})
	if err != nil {
		sr.t.Fatal(err)
	}
	return res.Token
}

func (sr *scrRig) events(name string) []spec.Event {
	sr.t.Helper()
	evs, err := sr.led.Query(context.Background(), ledger.QueryParams{EventName: name, Limit: 1000})
	if err != nil {
		sr.t.Fatal(err)
	}
	return evs
}

func (sr *scrRig) runState(id string) (state, cause string) {
	sr.t.Helper()
	var c *string
	if err := sr.db.SQL().QueryRow(`SELECT state, end_cause_code FROM runs WHERE run_id = ?`, id).Scan(&state, &c); err != nil {
		sr.t.Fatal(err)
	}
	if c != nil {
		cause = *c
	}
	return
}

// get fetches a page and requires 200.
func get(t *testing.T, b *browser, path string) string {
	t.Helper()
	rec := b.do("GET", path, nil, nil)
	if rec.Code != 200 {
		t.Fatalf("GET %s: %d %s", path, rec.Code, rec.Body)
	}
	return rec.Body.String()
}

// hxPost posts a form the way htmx does.
func hxPost(b *browser, path string, form url.Values) *httptest.ResponseRecorder {
	b.t.Helper()
	return b.do("POST", path, []byte(form.Encode()), map[string]string{
		"X-CSRF-Token": b.csrf(), "Content-Type": "application/x-www-form-urlencoded", "HX-Request": "true"})
}

func mustHave(t *testing.T, what, body string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if !strings.Contains(body, s) {
			t.Errorf("%s: missing %q in:\n%s", what, s, body)
		}
	}
}

func mustNotHave(t *testing.T, what, body string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if s != "" && strings.Contains(body, s) {
			t.Errorf("%s: must not contain %q", what, s)
		}
	}
}

var trRe = regexp.MustCompile(`(?s)<tr[ >].*?</tr>`)

// rowWith returns the first table row that contains needle.
func rowWith(t *testing.T, body, needle string) string {
	t.Helper()
	for _, r := range trRe.FindAllString(body, -1) {
		if strings.Contains(r, needle) {
			return r
		}
	}
	t.Fatalf("no table row contains %q in:\n%s", needle, body)
	return ""
}

// approveCard runs the whole Windows Hello approval of one card.
func (sr *scrRig) approveCard(b *browser, auth *authenticator, id string) {
	sr.t.Helper()
	bg := sr.begin(b, id)
	if rec := sr.finish(b, id, bg, auth.get(bg.options, pcOrigin.URL, opts{signCount: &zero})); rec.Code != 200 {
		sr.t.Fatalf("approve %s: %d %s", id, rec.Code, rec.Body)
	}
}
