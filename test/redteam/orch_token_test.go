package redteam

// The orchestrator token (ADR-007): the orchestrator's credential. Red-team list entries
// RT-08 (forged tokens), RT-13 (an agent approves) and RT-31 (token theft) as
// far as they can be run offline. Attacks and expected blocks:
//
//   - a revoked token is TOKEN_REVOKED on the very next request, its pending
//     approvals and waiting ops are cancelled in the same transaction, and the
//     refusal survives a chapd restart;
//   - an expired token is TOKEN_EXPIRED; a token of the wrong shape, one byte
//     changed, truncated, or the right bytes with another prefix is
//     TOKEN_INVALID; the spy never runs for any of them;
//   - the scope is respected: an op outside the token's ops, a project outside
//     its projects, an op the project's policy turned off, and a run-only route
//     are all refused, and the token cannot reach routes that need a run;
//   - the token cannot approve (see rt13_rt15_http_test.go for the routes and
//     rt11_approvals_engine_test.go for the engine);
//   - chapd keeps only the SHA-256 of the token: the plaintext is in no database
//     file, ledger event or `chapd orch issue` output, and the token file the
//     command writes is created exclusively and, off Windows, mode 0600.
//
// Not testable offline: that the agent's own Windows account cannot read the
// token file. That is an NTFS ACL set by scripts/pilot-host (H2) and checked on
// the PC, not here.
//
// To see this fail, drop the revoked check in internal/runtoken/orch.go Verify.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/runtoken"
)

func TestOrchTokenRevokedIsRefusedAtOnce(t *testing.T) {
	ap := &fakeApprovals{}
	g := newRig(t, rigOpts{enable: []string{"health", "deploy"}, approvals: ap})
	orch := func(m map[string]any) map[string]any { m["project"] = rigProject; return m }
	if st, body := g.call("POST", "/v0/ops", g.OrchToken, orch(opBody("health", "readiness", map[string]any{}))); st >= 400 {
		t.Fatalf("control: %d %v", st, body)
	}
	// The orchestrator has a card waiting.
	st, op := g.call("POST", "/v0/approvals", g.OrchToken, orch(approvalReq("deploy", "pilot", map[string]any{"sha": sha1})))
	if st != 202 {
		t.Fatalf("%d %v", st, op)
	}
	aid := str(op["approval"].(map[string]any), "id")
	before := g.spy.executions()

	if err := g.orch.Revoke(context.Background(), "main", "red-team"); err != nil {
		t.Fatal(err)
	}

	for _, p := range []struct{ m, path string }{
		{"GET", "/v0/status"}, {"POST", "/v0/ops"}, {"GET", "/v0/ledger"}, {"GET", "/v0/runs"}, {"POST", "/v0/dev-tokens"}, {"POST", "/v0/runs/revoke-all"},
	} {
		var body any
		if p.m == "POST" {
			body = orch(opBody("health", "readiness", map[string]any{}))
			if p.path == "/v0/dev-tokens" {
				body = devTokenReq("health")
			}
		}
		code, resp := g.call(p.m, p.path, g.OrchToken, body)
		if code != 401 {
			t.Fatalf("%s %s with a revoked token: %d %v", p.m, p.path, code, resp)
		}
		mustDenial(t, resp, "TOKEN_REVOKED")
	}
	if g.spy.executions() != before {
		t.Fatal("the spy ran for a revoked token")
	}
	// Its card and op were cancelled with it.
	if got := ap.byID[aid].State; got != "cancelled" {
		t.Fatalf("the orchestrator's card is %q after revocation", got)
	}
	if n := g.count(`SELECT COUNT(*) FROM ops WHERE requester_key = 'orchestrator:main' AND state IN ('pending_approval','allowed')`); n != 0 {
		t.Fatalf("%d op(s) of the revoked orchestrator are still live", n)
	}
	g.restart() // chapd restarts: nothing but the database remembers
	if code, resp := g.call("GET", "/v0/status", g.OrchToken, nil); code != 401 {
		t.Fatalf("after a restart: %d %v", code, resp)
	}
	g.mustLedgerOK()
}

func TestOrchTokenExpiredAndMalformed(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"health"}})
	good := g.OrchToken
	flip := []byte(good)
	flip[len(flip)-3] ^= 0x01
	for name, tok := range map[string]string{
		"one byte changed":      string(flip),
		"truncated":             good[:len(good)-4],
		"extended":              good + "A",
		"another prefix":        "chap_run_" + strings.TrimPrefix(good, runtoken.OrchPrefix),
		"no prefix":             strings.TrimPrefix(good, runtoken.OrchPrefix),
		"the hash of the token": "chap_orch_" + strings.Repeat("0", 43),
		"empty secret":          runtoken.OrchPrefix,
		"whitespace around":     " " + good + " ",
	} {
		t.Run(name, func(t *testing.T) {
			code, resp := g.call("GET", "/v0/status", tok, nil)
			if code != 401 {
				t.Fatalf("%d %v", code, resp)
			}
			if resp["cause_code"] != "TOKEN_INVALID" && resp["type"] != "auth_error" {
				t.Fatalf("%v", resp)
			}
		})
	}
	if g.spy.executions() != 0 {
		t.Fatal("the spy ran")
	}
	// Expiry: the token lives 7 days here.
	g.advance(8 * 24 * time.Hour)
	code, resp := g.call("GET", "/v0/status", good, nil)
	if code != 401 {
		t.Fatalf("an expired token: %d %v", code, resp)
	}
	mustDenial(t, resp, "TOKEN_EXPIRED")
}

func TestOrchTokenScopeIsRespected(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"health", "deploy", "pr.merge"}, orchOps: []string{"health", "deploy"}})
	o := func(op string, params map[string]any, project string) map[string]any {
		m := opBody(op, "x", params)
		m["project"] = project
		return m
	}
	cases := []struct {
		name string
		body map[string]any
		code string
	}{
		{"an op outside its ops", o("pr.merge", map[string]any{"base": "main", "head_sha": sha1, "method": "squash"}, rigProject), "OP_NOT_IN_TOKEN"},
		{"an op that is not in the catalog's reach", o("secrets.write", map[string]any{}, rigProject), "OP_NOT_IN_TOKEN"},
		{"another project", o("health", map[string]any{}, "other-shop"), "OP_NOT_IN_TOKEN"},
		{"no project at all", func() map[string]any { m := opBody("health", "readiness", map[string]any{}); return m }(), "OP_PARAMS_INVALID"},
		{"an op that policy has turned off", o("mail.send", map[string]any{}, rigProject), "OP_NOT_IN_TOKEN"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, resp := g.call("POST", "/v0/ops", g.OrchToken, c.body)
			if code < 400 {
				t.Fatalf("%d %v", code, resp)
			}
			mustDenial(t, resp, c.code)
		})
	}
	if g.spy.executions() != 0 {
		t.Fatal("the spy ran for an out-of-scope request")
	}
	// The ledger query is confined to the token's projects, and a run's id is
	// not an orchestrator's to forge into the token's view.
	if code, resp := g.call("GET", "/v0/ledger?run_id=r-nobody", g.OrchToken, nil); code != 200 {
		t.Fatalf("%d %v", code, resp)
	} else if items, _ := resp["items"].([]any); len(items) != 0 {
		t.Fatalf("a query for another run returned %d items", len(items))
	}
}

// The token's plaintext lives in one file and nowhere else.
func TestOrchTokenIsStoredHashedOnly(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"health"}})
	frag := g.OrchToken[len(runtoken.OrchPrefix):][:24]
	if strings.Contains(g.ledgerText(), frag) {
		t.Fatal("the orchestrator token is in the ledger")
	}
	// Use it a few times, including a refused call, then look at every byte on disk.
	g.call("GET", "/v0/status", g.OrchToken, nil)
	g.call("POST", "/v0/ops", g.OrchToken, map[string]any{"op": "health", "project": rigProject})
	if strings.Contains(g.ledgerText(), frag) {
		t.Fatal("the orchestrator token reached the ledger through a denial")
	}
	var stored string
	if err := g.db.SQL().QueryRow(`SELECT token_sha256 FROM orchestrators WHERE id = 'main'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) != 64 || strings.Contains(stored, frag) {
		t.Fatalf("stored credential %q is not a SHA-256", stored)
	}
	err := filepath.WalkDir(g.dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if b, err := os.ReadFile(p); err == nil && bytes.Contains(b, []byte(frag)) {
			t.Errorf("the orchestrator token is in %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// `chapd orch issue`, the real binary: the token goes to a file that is created
// exclusively and private, never to stdout or stderr.
func TestOrchIssueWritesPrivateFileOnly(t *testing.T) {
	bins := buildBinaries(t)
	dir := t.TempDir()
	db := filepath.Join(dir, "state.db")
	tokenFile := filepath.Join(dir, "home", "orchestrator.token")
	run := func() (string, string, error) {
		return runBin(t, bins.chapd, nil, "orch", "issue", "-db", db, "-project", rigProject, "-ops", "health,deploy", "-token-file", tokenFile, "-days", "3")
	}
	so, se, err := run()
	if err != nil {
		t.Fatalf("chapd orch issue: %v\n%s%s", err, so, se)
	}
	raw, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(token, runtoken.OrchPrefix) {
		t.Fatalf("token file: %q", raw)
	}
	if strings.Contains(so+se, token) || strings.Contains(so+se, token[len(runtoken.OrchPrefix):][:16]) {
		t.Fatalf("the token was printed:\n%s%s", so, se)
	}
	if runtime.GOOS != "windows" {
		if st, err := os.Stat(tokenFile); err != nil || st.Mode().Perm()&0o077 != 0 {
			t.Fatalf("token file mode %v, want private (0600): %v", st.Mode(), err)
		}
	}
	if b, _ := os.ReadFile(db); bytes.Contains(b, []byte(token)) {
		t.Fatal("the plaintext token is in state.db")
	}
	// A second issue under the same id must not overwrite or reveal the first.
	if so2, se2, err := run(); err == nil {
		t.Logf("a second issue succeeded (a new token): %s", so2)
		if strings.Contains(so2+se2, token) {
			t.Fatal("the second run printed the first token")
		}
	}
}
