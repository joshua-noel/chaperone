package redteam

// RT-26 (and the 19 Oct incident): a secret in a log. On 19 Oct a token printed
// by a tool ended up in a run log. Threat model: TB2-I1, TB5-I1 (a secret
// leaves the vault). Red-team list: docs/manual-crosswalk.md, RT-25 and
// RT-26, ticket L1-19 ("canary never appears anywhere").
//
// Setup: a canary secret is imported into the vault (so the redaction registry
// knows it), shaped so only the exact-value rule can catch it: it matches no
// token pattern, and it holds a quote, a backslash, an angle bracket and a
// slash so its JSON-escaped form differs from the raw one.
//
// Attack: make chapd say it, every way an agent or an adapter could: an adapter
// result that holds it raw, base64 (four variants), hex (both cases) and
// JSON-escaped, nested in lists and objects; an adapter error message; an
// external reference; a `logs` result with the canary in a line; the agent
// sending it in params, reason and target (a request echoed back in a denial,
// stored with the op, written to the ledger); an orchestrator doing the same.
// Then ask `chap`, the real binary, for everything it can print.
//
// Expected block, checked on every byte chapd and chap produced: no HTTP
// response body, no log line, no ledger event, no database or WAL byte, no
// JSONL export line, no file under chapd's directories (vault ciphertext
// included), and no `chap` stdout or stderr holds the canary in any of its
// forms. The control: the canary IS in the vault (the vault holds it and the
// registry masks it), and the same attack with the registry empty leaks, so the
// scan is not blind.
//
// Not covered (RT-25 gap, recorded in the table in doc.go): a secret split
// across two fields, or encoded another way (rot13, gzip, percent-encoding of
// unreserved characters); the registry matches the forms it lists, not every
// encoding.
//
// To see this fail, make Registry.RedactBytes return its input unchanged
// (internal/redact/registry.go): see mutation_test.go.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/joshua-noel/chaperone/internal/vault"
)

// lockedBuf is a log sink safe for slog's concurrent use.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

var _ io.Writer = (*lockedBuf)(nil)

type canary struct {
	raw   string
	forms map[string]string
}

func newCanary(t *testing.T) canary {
	t.Helper()
	var r [12]byte
	if _, err := rand.Read(r[:]); err != nil {
		t.Fatal(err)
	}
	raw := `cnry-` + hex.EncodeToString(r[:]) + `"q\z<b>/e`
	j, _ := json.Marshal(raw)
	htmlJSON := strings.ReplaceAll(strings.ReplaceAll(string(j[1:len(j)-1]), "<", `\u003c`), ">", `\u003e`)
	h := hex.EncodeToString([]byte(raw))
	return canary{raw: raw, forms: map[string]string{
		"raw":           raw,
		"base64 std":    base64.StdEncoding.EncodeToString([]byte(raw)),
		"base64 raw":    base64.RawStdEncoding.EncodeToString([]byte(raw)),
		"base64 url":    base64.URLEncoding.EncodeToString([]byte(raw)),
		"base64 rawurl": base64.RawURLEncoding.EncodeToString([]byte(raw)),
		"hex":           h,
		"HEX":           strings.ToUpper(h),
		"json":          string(j[1 : len(j)-1]),
		"json (html)":   htmlJSON,
		// The unique middle of the secret, in case a form is cut short.
		"core": raw[5:29],
	}}
}

// find returns the names of the forms present in text.
func (c canary) find(text string) []string {
	var out []string
	for name, f := range c.forms {
		if strings.Contains(text, f) {
			out = append(out, name)
		}
	}
	return out
}

// scanAll reports every place the canary appears among what the rig produced.
func (g *rig) scanAll(t *testing.T, c canary, logs *lockedBuf, extra map[string]string) []string {
	t.Helper()
	var found []string
	check := func(where, text string) {
		if forms := c.find(text); len(forms) > 0 {
			found = append(found, fmt.Sprintf("%s (%s)", where, strings.Join(forms, ", ")))
		}
	}
	g.mu.Lock()
	for i, s := range g.seen {
		check(fmt.Sprintf("http response #%d", i), s)
	}
	g.mu.Unlock()
	check("chapd log", logs.String())
	check("ledger events", g.ledgerText())
	for _, q := range []string{`SELECT group_concat(COALESCE(params_json,'') || COALESCE(result_json,'') || COALESCE(denial_json,'') || COALESCE(target_ref,'') || COALESCE(reason,'') || COALESCE(external_ref,''), char(10)) FROM ops`} {
		var s *string
		if err := g.db.SQL().QueryRow(q).Scan(&s); err == nil && s != nil {
			check("ops table", *s)
		}
	}
	// Every file under the rig's directory: database, WAL, export, vault.
	_ = filepath.WalkDir(g.dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if b, err := os.ReadFile(p); err == nil {
			check("file "+strings.TrimPrefix(p, g.dir), string(b))
		}
		return nil
	})
	for where, text := range extra {
		check(where, text)
	}
	return found
}

func (g *rig) importCanary(t *testing.T, c canary) {
	t.Helper()
	if _, err := g.vault.Import(context.Background(), vault.Meta{ID: "rt-canary", Kind: "test-canary", Owner: "red-team"}, []byte(c.raw)); err != nil {
		t.Fatal(err)
	}
}

func canaryResult(c canary) map[string]any {
	return map[string]any{
		"ok":     true,
		"log":    "deploy step 3: TOKEN=" + c.raw + " exported",
		"b64":    c.forms["base64 std"],
		"b64raw": c.forms["base64 rawurl"],
		"hex":    c.forms["hex"],
		"HEX":    c.forms["HEX"],
		"json":   "{\"token\":\"" + c.forms["json"] + "\"}",
		"nested": []any{map[string]any{"deep": []any{c.raw}}},
		c.raw:    "the secret as a key",
	}
}

func TestRT26CanaryNeverAppearsAnywhere(t *testing.T) {
	c := newCanary(t)
	logs := &lockedBuf{}
	ap := &fakeApprovals{}
	g := newRig(t, rigOpts{enable: []string{"health", "logs", "deploy", "mail.send", "drive.share", "pr.open"}, approvals: ap, log: logs})
	g.importCanary(t, c)
	g.spy.result = canaryResult(c)
	run, runID := g.mint("health", "logs", "deploy", "mail.send", "pr.open")
	bins := buildBinaries(t)

	// 1. Adapter results that hold the canary, in every form, for a read op and a logs op.
	for _, req := range []map[string]any{
		opBody("health", "readiness", map[string]any{}),
		opBody("logs", "web", map[string]any{"lines": 20}),
	} {
		st, body := g.call("POST", "/v0/ops", run, req)
		if st >= 500 {
			t.Fatalf("%d %v", st, body)
		}
		if id := str(body, "id"); id != "" {
			g.call("GET", "/v0/ops/"+id, run, nil)
			g.call("GET", "/v0/ops/"+id+"?wait=1", g.OrchToken, nil)
		}
	}
	// 2. Adapter failures and references that carry it.
	g.spy.mu.Lock()
	g.spy.execErr = fmt.Errorf("upstream said: bad credential %s", c.raw)
	g.spy.mu.Unlock()
	g.call("POST", "/v0/ops", run, opBody("health", "readiness", map[string]any{"probe": 1}))
	g.spy.mu.Lock()
	g.spy.execErr = nil
	g.spy.extRef = "ref-" + c.raw
	g.spy.mu.Unlock()
	g.call("POST", "/v0/ops", run, opBody("health", "readiness", map[string]any{"probe": 2}))

	// 4. The real chap, on every command, as the run and as the orchestrator.
	tokFile := filepath.Join(g.dir, "orch.token")
	if err := os.WriteFile(tokFile, []byte(g.OrchToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var chapOut strings.Builder
	chapRuns := 0
	chap := func(env []string, args ...string) {
		so, se, _ := runBin(t, bins.chap, append([]string{"CHAP_URL=" + g.srv.URL, "CHAP_PROJECT=" + rigProject}, env...), args...)
		chapOut.WriteString(so + se)
		chapRuns++
	}
	asRun := []string{"CHAP_RUN_TOKEN=" + run}
	asOrch := []string{"CHAP_RUN_TOKEN=", "CHAP_ORCHESTRATOR_TOKEN_FILE=" + tokFile}
	for _, args := range [][]string{
		{"health"}, {"health", "--json"}, {"logs", "web", "--lines", "5"}, {"deploy", sha1},
		{"request", "op", "deploy", "--reason", "ship it", "--params", `{"sha":"` + sha1 + `"}`},
		{"approve", "list"}, {"approve", "list", "--json"}, {"manual"}, {"manual", "--all"}, {"version"}, {"logo"},
		{"op", "show", "q-nosuchop"}, {"pr", "merge", "214", "--head", sha1, "--repo", rigRepo, "--dry-run"},
		{"nosuchcommand"},
	} {
		chap(asRun, args...)
	}
	for _, args := range [][]string{
		{"vault", "status"}, {"vault", "status", "--json"}, {"ledger", "verify"}, {"runs", "revoke", runID}, {"health"}, {"approve", "list"},
		{"dev-token", "--project", rigProject, "--repo", rigRepo, "--branch", "agent/rt-canary", "--path", "docs/**", "--op", "health", "--out", filepath.Join(g.dir, "run2.token")},
	} {
		chap(asOrch, args...)
	}
	// The one command allowed to hold a token wrote it to a file, not to stdout.
	if b, err := os.ReadFile(filepath.Join(g.dir, "run2.token")); err != nil || !strings.HasPrefix(string(b), "eyJ") {
		t.Errorf("dev-token wrote no token file: %v", err)
	} else if strings.Contains(chapOut.String(), strings.TrimSpace(string(b))[:40]) {
		t.Error("chap printed the minted run token")
	}
	if chapRuns == 0 {
		t.Fatal("chap never ran")
	}

	// 5. Force the JSONL export and look at everything.
	if _, err := g.led.Export(context.Background()); err != nil {
		t.Fatal(err)
	}
	if found := g.scanAll(t, c, logs, map[string]string{"chap stdout and stderr": chapOut.String()}); len(found) > 0 {
		t.Fatalf("the canary appears in:\n  %s", strings.Join(found, "\n  "))
	}
	for _, tok := range []string{run, g.OrchToken} {
		if strings.Contains(chapOut.String(), tok) {
			t.Error("chap printed a bearer token")
		}
	}
	g.mustLedgerOK()

	// Control A: the scan sees the canary when it is there. The vault imported
	// it; its ciphertext is on disk and the registry masks it, so the raw
	// value must not be in any file, yet the scanner finds a planted copy.
	planted := filepath.Join(g.dir, "planted.txt")
	if err := os.WriteFile(planted, []byte("x"+c.raw+"y"), 0o600); err != nil {
		t.Fatal(err)
	}
	if found := g.scanAll(t, c, logs, nil); len(found) == 0 {
		t.Fatal("the scanner is blind: a planted canary was not found")
	}
	os.Remove(planted)
	if _, res := g.reg.Redact("x" + c.raw + "y"); !res.Blocked() {
		t.Fatal("the registry does not know the canary")
	}
}

// Control B: with the registry empty, the same attack leaks. This proves the
// canary test measures the redaction, not an accident of the setup.
func TestRT26WithoutTheRegistryTheSameAttackLeaks(t *testing.T) {
	c := newCanary(t)
	logs := &lockedBuf{}
	g := newRig(t, rigOpts{enable: []string{"health"}, log: logs})
	g.spy.result = map[string]any{"ok": true, "log": "TOKEN=" + c.raw}
	run, _ := g.mint("health")
	st, body := g.call("POST", "/v0/ops", run, opBody("health", "readiness", map[string]any{}))
	if st >= 500 {
		t.Fatalf("%d %v", st, body)
	}
	if found := g.scanAll(t, c, logs, nil); len(found) == 0 {
		t.Fatal("with no secret registered the canary should reach the response and the database; the test would prove nothing")
	}
}

// The other direction: a secret the agent itself sends (it already holds it;
// the question is where chapd then writes it). Expected block: a request that
// carries a secret anywhere (target, params value or key, reason, an op name)
// is refused with REDACTION_BLOCKED, whose denial names nothing of the
// request, and no op row is stored; so the secret is in no response, no `ops`
// row, no database file, no ledger event or export, no log line and no `chap`
// output. A secret-shaped string the vault does not know (a GitHub token) is
// refused the same way. A clean request still stores its op (the control).
func TestRT26AgentSuppliedSecret(t *testing.T) {
	c := newCanary(t)
	logs := &lockedBuf{}
	ap := &fakeApprovals{}
	g := newRig(t, rigOpts{enable: []string{"health", "deploy", "mail.send"}, approvals: ap, log: logs})
	g.importCanary(t, c)
	run, _ := g.mint("health", "deploy", "mail.send")
	bins := buildBinaries(t)
	shaped := "ghp_" + strings.Repeat("a1B2c3D4e", 4) // not in the vault: the shape rule must catch it
	blocked := func(what, method, path, token string, body map[string]any) {
		t.Helper()
		st, got := g.call(method, path, token, body)
		if st != 403 || str(got, "cause_code") != "REDACTION_BLOCKED" {
			t.Errorf("%s: want 403 REDACTION_BLOCKED, got %d %v", what, st, got)
		}
		if forms := c.find(toJSON(got)); len(forms) > 0 || strings.Contains(toJSON(got), shaped) {
			t.Errorf("%s: the denial echoes the secret (%v): %v", what, forms, got)
		}
	}
	blocked("secret in target and params", "POST", "/v0/ops", run, opBody("health", c.raw, map[string]any{"note": c.raw, "b64": c.forms["base64 std"]}))
	blocked("secret in a mail body", "POST", "/v0/ops", run, opBody("mail.send", "operator", map[string]any{"to": "a@b.c", "subject": "s", "body": "token " + c.raw}))
	blocked("secret as a params key", "POST", "/v0/ops", run, opBody("health", "readiness", map[string]any{c.raw: "x"}))
	blocked("secret nested in params", "POST", "/v0/ops", run, opBody("health", "readiness", map[string]any{"a": []any{map[string]any{"b": c.raw}}}))
	blocked("secret in an unknown op's target", "POST", "/v0/ops", run, opBody("nonsense.op", c.raw, map[string]any{"x": c.raw}))
	blocked("secret in an op the token does not hold", "POST", "/v0/ops", run, opBody("pr.merge", c.raw, map[string]any{"x": c.raw}))
	dry := opBody("health", "readiness", map[string]any{"note": c.raw})
	dry["dry_run"] = true
	blocked("secret in a dry run", "POST", "/v0/ops", run, dry)
	body := approvalReq("deploy", c.raw, map[string]any{"sha": sha1, "note": c.raw})
	body["reason"] = "because " + c.raw
	blocked("secret in an approval request", "POST", "/v0/approvals", run, body)
	rb := approvalReq("deploy", "pilot", map[string]any{"sha": sha1})
	rb["reason"] = "because " + c.raw
	blocked("secret only in the reason", "POST", "/v0/approvals", run, rb)
	blocked("a GitHub token the vault does not know", "POST", "/v0/ops", run, opBody("health", "readiness", map[string]any{"note": shaped}))
	orch := opBody("health", "readiness", map[string]any{"note": c.raw})
	orch["project"] = rigProject
	blocked("the orchestrator's request", "POST", "/v0/ops", g.OrchToken, orch)
	g.call("POST", "/v0/ops", "not-a-token-"+c.raw, opBody("health", "readiness", map[string]any{}))
	g.call("GET", "/v0/ledger?run_id="+c.raw, g.OrchToken, nil)
	g.call("GET", "/v0/ledger?event_name="+c.raw, g.OrchToken, nil)
	// A refusal chapd raises itself echoes the path it was asked for: a secret
	// in the path never comes back (the denial's own scrub, not the request check).
	blocked("a GitHub token in the path of a bad request", "GET", "/v0/ops/"+shaped+"?wait=99", run, nil)
	g.call("GET", "/v0/vault/status", g.OrchToken, nil)

	var rows int
	if err := g.db.SQL().QueryRow(`SELECT COUNT(*) FROM ops`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("a request that held a secret left %d op row(s): %v", rows, err)
	}
	// Control: a clean request is stored, so the zero above is the refusal.
	if st, got := g.call("POST", "/v0/ops", run, opBody("health", "readiness", map[string]any{"note": "ok"})); st >= 400 {
		t.Fatalf("control: a clean request failed: %d %v", st, got)
	}
	if err := g.db.SQL().QueryRow(`SELECT COUNT(*) FROM ops`).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("control: %d op row(s): %v", rows, err)
	}

	bodyFile := filepath.Join(t.TempDir(), "body.txt")
	if err := os.WriteFile(bodyFile, []byte("note "+c.raw), 0o600); err != nil {
		t.Fatal(err)
	}
	var chapOut strings.Builder
	for _, args := range [][]string{
		{"deploy", c.raw}, {"mail", "send", "--to", "a@b.c", "--subject", "s", "--body-file", bodyFile},
		{"request", "op", "deploy", "--reason", "r " + c.raw, "--params", `{"sha":"` + sha1 + `"}`},
		{"op", "show", "q-" + c.raw}, {"nosuchcommand", c.raw},
	} {
		so, se, _ := runBin(t, bins.chap, []string{"CHAP_URL=" + g.srv.URL, "CHAP_PROJECT=" + rigProject, "CHAP_RUN_TOKEN=" + run}, args...)
		chapOut.WriteString(so + se)
	}
	if _, err := g.led.Export(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Asserted: the ledger (and so its export) and the log never hold it.
	if forms := c.find(g.ledgerText()); len(forms) > 0 {
		t.Errorf("the canary reached the ledger (%v)", forms)
	}
	if forms := c.find(logs.String()); len(forms) > 0 {
		t.Errorf("the canary reached chapd's log (%v)", forms)
	}
	_ = filepath.WalkDir(filepath.Join(g.dir, "export"), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if b, _ := os.ReadFile(p); len(c.find(string(b))) > 0 {
				t.Errorf("the canary is in the export %s", p)
			}
		}
		return nil
	})
	if forms := c.find(chapOut.String()); len(forms) > 0 {
		t.Errorf("chap printed what the agent sent (%v):\n%s", forms, chapOut.String())
	}
	if found := g.scanAll(t, c, logs, nil); len(found) > 0 {
		t.Errorf("the canary the agent sent appears in:\n  %s", strings.Join(found, "\n  "))
	}
}
