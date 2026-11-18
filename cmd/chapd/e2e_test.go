package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/ledger"
	"github.com/joshua-noel/chaperone/internal/spec"
)

// e2e boots the real chapd (real ledger, real token verifiers, real policy)
// over a temporary database and talks to it over HTTP with real tokens.
type e2e struct {
	t     *testing.T
	app   *App
	srv   *httptest.Server
	db    string
	token string // orchestrator token, read back from the token file like `chap` does
}

func writeKeys(t *testing.T, dir string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{"version": 1, "allow_interim": true, "keys": []any{
		map[string]any{"kid": "runner-1", "issuer": "runner.test", "public_key": base64.RawURLEncoding.EncodeToString(pub)},
	}}
	b, _ := json.Marshal(doc)
	path := filepath.Join(dir, "run-keys.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newE2E(t *testing.T) *e2e {
	t.Helper()
	dir := t.TempDir()
	e := &e2e{t: t, db: filepath.Join(dir, "state.db")}
	keys := writeKeys(t, dir)

	// `chapd orch issue`, as the operator runs it (a scratch database is not the real one).
	tokenFile := filepath.Join(dir, "home", "orchestrator.token")
	var out, errb bytes.Buffer
	code := orchCmd([]string{"issue", "-db", e.db, "-project", "acme-shop", "-ops", "pr.merge,health,deploy", "-token-file", tokenFile, "-days", "7"}, &out, &errb)
	if code != 0 {
		t.Fatalf("orch issue: %d %s", code, errb.String())
	}
	raw, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	e.token = strings.TrimSpace(string(raw))
	if !strings.HasPrefix(e.token, "chap_orch_") {
		t.Fatalf("token file: %q", raw)
	}
	if strings.Contains(out.String()+errb.String(), e.token) {
		t.Fatal("chapd orch issue printed the token")
	}
	if !strings.Contains(out.String(), "fingerprint:") {
		t.Errorf("no fingerprint printed: %s", out.String())
	}

	app, err := Build(context.Background(), Config{DBPath: e.db, KeysPath: keys, Instance: "test"})
	if err != nil {
		t.Fatal(err)
	}
	e.app = app
	e.srv = httptest.NewServer(app.Handler())
	t.Cleanup(func() { e.srv.Close(); app.Close() })
	return e
}

func (e *e2e) call(method, path, token string, body any) (int, map[string]any) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Host = "127.0.0.1:55398"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	return resp.StatusCode, m
}

func mustValidDenial(t *testing.T, m map[string]any, code string) {
	t.Helper()
	if err := spec.Validate(spec.SchemaDenial, m); err != nil {
		t.Fatalf("denial does not validate against denial.schema.json: %v\n%v", err, m)
	}
	if m["cause_code"] != code {
		t.Fatalf("cause_code %v, want %s (%v)", m["cause_code"], code, m["why"])
	}
}

func TestE2EOrchestratorAcceptance(t *testing.T) {
	e := newE2E(t)

	// The orchestrator token file is private; the database holds only the hash.
	if st, err := os.Stat(filepath.Join(filepath.Dir(e.db), "home", "orchestrator.token")); err != nil || st.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("token file mode: %v %v", st, err)
	}
	if b, _ := os.ReadFile(e.db); bytes.Contains(b, []byte(e.token)) {
		t.Error("the plaintext token is in state.db")
	}

	st, body := e.call("GET", "/v0/status", e.token, nil)
	if st != 200 || body["requester"].(map[string]any)["orchestrator_id"] != "main" {
		t.Fatalf("status: %d %v", st, body)
	}
	if !strings.HasPrefix(body["policy_version"].(string), "baseline-") {
		t.Errorf("policy_version %v", body["policy_version"])
	}

	// An op outside the token's scope: OP_NOT_IN_TOKEN.
	mail := map[string]any{"op": "mail.send", "project": "acme-shop", "target": map[string]any{"adapter": "gmail", "ref": "l"}, "params": map[string]any{}}
	st, body = e.call("POST", "/v0/ops", e.token, mail)
	if st != 403 {
		t.Fatalf("%d %v", st, body)
	}
	mustValidDenial(t, body, "OP_NOT_IN_TOKEN")
	if body["orchestrator_id"] != "main" || body["run_id"] != nil {
		t.Errorf("orchestrator denial identity: %v", body)
	}

	// In scope but disabled (every op is): OP_DISABLED, twice -> thrash 2.
	merge := map[string]any{"op": "pr.merge", "project": "acme-shop", "target": map[string]any{"adapter": "github", "ref": "acme/shop#1"},
		"params": map[string]any{"base": "main", "head_sha": strings.Repeat("a", 40), "method": "squash"}}
	for i, want := range []float64{1, 2} {
		st, body = e.call("POST", "/v0/ops", e.token, merge)
		if st != 403 {
			t.Fatalf("%d %v", st, body)
		}
		mustValidDenial(t, body, "OP_DISABLED")
		if body["thrash"].(map[string]any)["count"] != want {
			t.Errorf("attempt %d: thrash %v", i, body["thrash"])
		}
	}

	// Another project: OP_NOT_IN_TOKEN too.
	merge["project"] = "other-shop"
	st, body = e.call("POST", "/v0/ops", e.token, merge)
	mustValidDenial(t, body, "OP_NOT_IN_TOKEN")

	// The catalog shows nothing enabled.
	st, body = e.call("GET", "/v0/catalog", e.token, nil)
	if st != 200 || len(body["ops"].([]any)) != 0 {
		t.Errorf("catalog: %d %v", st, body)
	}
	st, body = e.call("GET", "/v0/catalog?all=true", e.token, nil)
	if st != 200 || len(body["ops"].([]any)) != 29 {
		t.Errorf("catalog all: %d %d ops", st, len(body["ops"].([]any)))
	}

	// A run token that is not valid, and a request with no token.
	if st, body = e.call("GET", "/v0/status", "garbage", nil); st != 401 || body["type"] != "auth_error" {
		t.Errorf("garbage token: %d %v", st, body)
	}
	// Runs route needs the control JWT; a bearer is not accepted there.
	if st, body = e.call("GET", "/v0/runs", e.token, nil); st != 200 {
		t.Errorf("list runs: %d %v", st, body)
	}

	// Revoke: the next request is TOKEN_REVOKED, with orchestrator_id.
	var out, errb bytes.Buffer
	if code := orchCmd([]string{"revoke", "-db", e.db, "-id", "main"}, &out, &errb); code != 0 {
		t.Fatalf("revoke: %s", errb.String())
	}
	st, body = e.call("GET", "/v0/status", e.token, nil)
	if st != 401 {
		t.Fatalf("after revoke: %d %v", st, body)
	}
	mustValidDenial(t, body, "TOKEN_REVOKED")
	if body["orchestrator_id"] != "main" || body["project"] != "acme-shop" {
		t.Errorf("revoked denial: %v", body)
	}

	// The ledger holds all of it, chained, and verifies.
	rep, err := e.app.Ledger.Verify(context.Background(), false)
	if err != nil || !rep.OK() {
		t.Fatalf("ledger verify: %v %v", err, rep.Problems())
	}
	var denials, requests int
	rows, err := e.app.DB.SQL().Query(`SELECT event_name FROM ledger_events`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		switch n {
		case "denial":
			denials++
		case "op.request":
			requests++
		}
	}
	if denials != 5 || requests < 5 { // 4 op denials + the revoked token; 4 op.request + issue + revoke
		t.Errorf("ledger: %d denial and %d op.request events", denials, requests)
	}
	var open int
	if err := e.app.DB.SQL().QueryRow(`SELECT COUNT(*) FROM ops WHERE state NOT IN ('denied')`).Scan(&open); err != nil || open != 0 {
		t.Errorf("non-denied ops: %d %v", open, err)
	}
}

func TestOrchList(t *testing.T) {
	e := newE2E(t)
	var out, errb bytes.Buffer
	if code := orchCmd([]string{"list", "-db", e.db}, &out, &errb); code != 0 {
		t.Fatal(errb.String())
	}
	if !strings.Contains(out.String(), "main") || !strings.Contains(out.String(), "live") || strings.Contains(out.String(), e.token) {
		t.Errorf("list: %s", out.String())
	}
	// Re-issue rotates: the old token dies.
	oldTok := e.token
	var o2, e2 bytes.Buffer
	file := filepath.Join(t.TempDir(), "t.token")
	if code := orchCmd([]string{"issue", "-db", e.db, "-project", "acme-shop", "-ops", "health", "-token-file", file}, &o2, &e2); code != 0 {
		t.Fatal(e2.String())
	}
	if st, body := e.call("GET", "/v0/status", oldTok, nil); st != 401 || body["cause_code"] != "TOKEN_REVOKED" {
		t.Errorf("rotated token: %d %v", st, body)
	}
}

func TestRunUsage(t *testing.T) {
	for _, args := range [][]string{{"orch"}, {"orch", "bogus"}, {"orch", "issue"}, {"orch", "issue", "-project", "p"}, {"orch", "list", "extra"}, {"run", "-bogus"}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 2 {
			t.Errorf("%v: exit %d, want 2 (%s)", args, code, errb.String())
		}
	}
}

func TestListenAddressMustBeLoopback(t *testing.T) {
	for _, a := range []string{"0.0.0.0:55398", "192.0.2.2:55398", ":55398", "example.com:55398"} {
		if err := requireLoopback(a); err == nil {
			t.Errorf("%s accepted", a)
		}
	}
	for _, a := range []string{"127.0.0.1:55398", "[::1]:55398"} {
		if err := requireLoopback(a); err != nil {
			t.Errorf("%s: %v", a, err)
		}
	}
}

// GET /v0/ledger hands the orchestrator every event of the chain, whatever its
// project, so a read with no filter has no gap in seq (chaperone #60). the runner's
// Theatre checks the chain from this feed.
func TestE2ELedgerFeedHasNoGap(t *testing.T) {
	e := newE2E(t)
	ctx := context.Background()
	for i, project := range []string{"other-shop", "acme-shop", "other-shop", "storefront", "other-shop"} {
		d := ledger.Draft{
			Name: "op.request", Project: project,
			Attributes: map[string]any{
				"factory.request_id":      fmt.Sprintf("q-%06d", i+1),
				"factory.op":              "pr.open",
				"factory.op_hash":         "sha256:" + strings.Repeat("ab", 32),
				"factory.requester.kind":  "orchestrator",
				"factory.orchestrator.id": "main",
			},
		}
		if _, err := e.app.Ledger.Append(ctx, d); err != nil {
			t.Fatalf("append %d (%q): %v", i, project, err)
		}
	}
	headSeq, _, err := e.app.Ledger.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Page through the feed with a small limit, as a client does.
	var seqs []int64
	path := "/v0/ledger?limit=2"
	for range 20 {
		st, body := e.call("GET", path, e.token, nil)
		if st != 200 {
			t.Fatalf("GET %s: %d %v", path, st, body)
		}
		for _, it := range body["items"].([]any) {
			seqs = append(seqs, int64(it.(map[string]any)["seq"].(float64)))
		}
		next, _ := body["next_cursor"].(string)
		if next == "" {
			break
		}
		path = "/v0/ledger?limit=2&cursor=" + next
	}
	if int64(len(seqs)) != headSeq+1 {
		t.Fatalf("the feed has %d events, the chain %d: %v", len(seqs), headSeq+1, seqs)
	}
	for i, s := range seqs {
		if s != int64(i) {
			t.Fatalf("seq jumps at position %d: %v", i, seqs)
		}
	}
}
