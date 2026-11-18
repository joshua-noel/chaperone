package redteam

// RT-52: the interim host token (ADR-005): the issuer that stands in until
// the runner exists. Attacks: an interim token after the issuer is switched off
// (`allow_interim=false`); asking the issuer for more than its ceiling; asking
// for it without the right orchestrator; and the mint route's own redaction.
// Red-team list: docs/manual-crosswalk.md, RT-52. Threat model: TB3-S4.
//
// Expected block:
//   - after the switch-off, chapd (restarted with allow_interim false) refuses
//     every interim token, including ones minted before, with TOKEN_INVALID,
//     and refuses to mint with OP_DISABLED; the orchestrator token still works;
//     the spy never runs for a refused token;
//   - a mint outside the ceiling is refused and registers no run;
//   - the minted token is returned once, to the orchestrator, and appears
//     nowhere else: not in the ledger, not in the database.
//
// To see this fail, drop the `AllowInterim` check in internal/runtoken/verify.go
// or the ceiling check in internal/runtoken/interim.go.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/runtoken"
	"github.com/joshua-noel/chaperone/internal/store"
)

// reboot is a chapd restart with a changed allow_interim: the key set is
// re-read, and the runs registry, verifier, issuer and handler are rebuilt over
// the same database.
func (g *rig) reboot(allow bool) {
	g.t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(g.keysJSON), &doc); err != nil {
		g.t.Fatal(err)
	}
	doc["allow_interim"] = allow
	raw, _ := json.Marshal(doc)
	g.keysJSON = string(raw)
	keys, err := runtoken.ParseKeySet(raw)
	if err != nil {
		g.t.Fatal(err)
	}
	g.keys = keys
	sink := ledgerSink{l: g.led}
	runs, err := runtoken.NewRuns(runtoken.RunsConfig{
		DB: g.db, Keys: keys, Appender: sink, Now: g.clock,
		TxEnd: func(ctx context.Context, tx *store.Tx, run runtoken.RunRecord, info runtoken.EndInfo) error {
			return g.svc.CancelRunOps(ctx, tx, run.RunID, "run ended")
		},
	})
	if err != nil {
		g.t.Fatal(err)
	}
	g.runs = runs
	g.minter, err = runtoken.NewInterim(runtoken.InterimConfig{Runs: runs, Orch: g.orch, Signer: runtoken.NewVaultSigner(g.vault, "interim-key", "interim-1")})
	if err != nil {
		g.t.Fatal(err)
	}
	g.scfg.AllowInterim = func() bool { return allow }
	g.scfg.Runs = runsBackend{r: runs}
	g.scfg.Interim = interimBackend{i: g.minter}
	g.restart()
}

func devTokenReq(opsList ...string) map[string]any {
	return map[string]any{"project": rigProject, "profile": "host-interim", "repo": rigRepo, "base": "main",
		"branch": rigBranch, "paths": []string{"docs/**"}, "ops": opsList, "minutes": 30}
}

func TestRT52InterimTokenAfterSwitchOff(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"health", "pr.merge"}})
	tok, runID := g.mint("health", "pr.merge")
	health := opBody("health", "readiness", map[string]any{})
	if st, body := g.call("POST", "/v0/ops", tok, health); st >= 400 {
		t.Fatalf("control: the interim token is refused before the switch-off: %d %v", st, body)
	}
	before := g.spy.executions()

	g.reboot(false) // the cut-over to the runner: allow_interim=false, chapd restarts

	for _, req := range []map[string]any{health, mergeBody(sha1)} {
		st, body := g.call("POST", "/v0/ops", tok, req)
		if st != 401 {
			t.Fatalf("after the switch-off: %d %v", st, body)
		}
		mustDenial(t, body, "TOKEN_INVALID")
		if !strings.Contains(strings.ToLower(str(body, "why")), "interim") {
			t.Errorf("the denial does not say interim tokens are off: %v", body["why"])
		}
	}
	if st, body := g.call("GET", "/v0/status", tok, nil); st != 401 {
		t.Fatalf("status with a dead interim token: %d %v", st, body)
	}
	if g.spy.executions() != before {
		t.Fatal("the spy ran for a refused token")
	}

	// Minting is shut too, for an orchestrator that is otherwise fine.
	st, body := g.call("POST", "/v0/dev-tokens", g.OrchToken, devTokenReq("health"))
	if st != 403 {
		t.Fatalf("mint after the switch-off: %d %v", st, body)
	}
	mustDenial(t, body, "OP_DISABLED")
	if n := g.count(`SELECT COUNT(*) FROM runs`); n != 1 {
		t.Fatalf("%d runs registered; the refused mint made one", n)
	}
	// The orchestrator token still works: only the interim path is shut.
	if st, body := g.call("GET", "/v0/status", g.OrchToken, nil); st != 200 {
		t.Fatalf("orchestrator after the switch-off: %d %v", st, body)
	}
	_ = runID
	g.mustLedgerOK()

	// Starting with it off from the beginning behaves the same.
	off := false
	g2 := newRig(t, rigOpts{allowInterim: &off})
	st, body = g2.call("POST", "/v0/dev-tokens", g2.OrchToken, devTokenReq("health"))
	if st != 403 {
		t.Fatalf("%d %v", st, body)
	}
	mustDenial(t, body, "OP_DISABLED")
}

func TestRT52MintCeiling(t *testing.T) {
	g := newRig(t, rigOpts{})
	mod := func(f func(m map[string]any)) map[string]any {
		m := devTokenReq("pr.open")
		f(m)
		return m
	}
	cases := []struct {
		name string
		body map[string]any
		code string
	}{
		{"a critical op", mod(func(m map[string]any) { m["ops"] = []string{"approvers.enroll"} }), "OP_NOT_IN_TOKEN"},
		{"secrets.write", mod(func(m map[string]any) { m["ops"] = []string{"secrets.write"} }), "OP_NOT_IN_TOKEN"},
		{"policy.activate", mod(func(m map[string]any) { m["ops"] = []string{"policy.activate"} }), "OP_NOT_IN_TOKEN"},
		{"repo.settings (critical)", mod(func(m map[string]any) { m["ops"] = []string{"repo.settings"} }), "OP_NOT_IN_TOKEN"},
		{"host.scripts.refresh (critical)", mod(func(m map[string]any) { m["ops"] = []string{"host.scripts.refresh"} }), "OP_NOT_IN_TOKEN"},
		{"one bad op among good ones", mod(func(m map[string]any) { m["ops"] = []string{"pr.open", "approvers.enroll"} }), "OP_NOT_IN_TOKEN"},
		{"a wildcard op", mod(func(m map[string]any) { m["ops"] = []string{"pr.*"} }), "OP_NOT_IN_TOKEN"},
		{"no ops", mod(func(m map[string]any) { m["ops"] = []string{} }), "OP_NOT_IN_TOKEN"},
		{"a project outside the orchestrator's", mod(func(m map[string]any) { m["project"] = "other-shop" }), "OP_NOT_IN_TOKEN"},
		{"a branch outside agent/", mod(func(m map[string]any) { m["branch"] = "feature/x" }), "SCOPE_BRANCH"},
		{"the base branch itself", mod(func(m map[string]any) { m["branch"] = "main" }), "SCOPE_BRANCH"},
		{"three hours", mod(func(m map[string]any) { m["minutes"] = 180 }), "OP_PARAMS_INVALID"},
		{"a real profile", mod(func(m map[string]any) { m["profile"] = "code" }), "OP_PARAMS_INVALID"},
		{"an unknown field", mod(func(m map[string]any) { m["isolation"] = "none" }), "OP_PARAMS_INVALID"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, body := g.call("POST", "/v0/dev-tokens", g.OrchToken, c.body)
			if st < 400 {
				t.Fatalf("minted: %d %v", st, body)
			}
			if body["token"] != nil {
				t.Fatalf("a refusal carries a token: %v", body)
			}
			if c.code != "SCOPE_BRANCH" && c.code != "OP_PARAMS_INVALID" {
				mustDenial(t, body, c.code)
			} else if st >= 500 {
				t.Fatalf("%d %v", st, body)
			}
		})
	}
	if n := g.count(`SELECT COUNT(*) FROM runs`); n != 0 {
		t.Fatalf("refused mints registered %d run(s)", n)
	}

	// An orchestrator that cannot mint, and one whose scope lacks the op.
	noMint := newRig(t, rigOpts{noMint: true})
	st, body := noMint.call("POST", "/v0/dev-tokens", noMint.OrchToken, devTokenReq("pr.open"))
	if st != 403 {
		t.Fatalf("an orchestrator without mint_interim: %d %v", st, body)
	}
	mustDenial(t, body, "OP_NOT_IN_TOKEN")
	narrow := newRig(t, rigOpts{orchOps: []string{"health"}})
	st, body = narrow.call("POST", "/v0/dev-tokens", narrow.OrchToken, devTokenReq("pr.merge"))
	if st != 403 {
		t.Fatalf("an op outside the orchestrator's scope: %d %v", st, body)
	}
	mustDenial(t, body, "OP_NOT_IN_TOKEN")

	// The key's own, narrower ceiling.
	small := newRig(t, rigOpts{interimOps: []string{"pr.open", "health"}})
	st, body = small.call("POST", "/v0/dev-tokens", small.OrchToken, devTokenReq("deploy"))
	if st != 403 {
		t.Fatalf("an op outside the key's ceiling: %d %v", st, body)
	}
	mustDenial(t, body, "OP_NOT_IN_TOKEN")
}

// TestDevTokenOverHTTP is the control of the two tests above and of RT-26 for
// the one route that hands out a secret: the mint answer carries the token
// through the redactor once, and only there.
func TestDevTokenOverHTTP(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"health"}})
	st, body := g.call("POST", "/v0/dev-tokens", g.OrchToken, devTokenReq("health", "pr.open"))
	if st != 201 {
		t.Fatalf("mint: %d %v", st, body)
	}
	tok := str(body, "token")
	if strings.Count(tok, ".") != 2 || !strings.HasPrefix(tok, "eyJ") {
		t.Fatalf("the answer has no JWT: %v", body)
	}
	if _, res := g.reg.Redact(tok); !res.Blocked() {
		t.Fatal("the redactor does not recognise the token, so the route proved nothing")
	}
	if st, b := g.call("POST", "/v0/ops", tok, opBody("health", "readiness", map[string]any{})); st >= 400 {
		t.Fatalf("the minted token does not work: %d %v", st, b)
	}

	// Nothing but that one answer holds it: not the ledger, not the database.
	frag := tok[:48]
	if strings.Contains(g.ledgerText(), frag) {
		t.Fatal("the token is in the ledger")
	}
	for _, f := range []string{g.dbPath, g.dbPath + "-wal"} {
		if b, err := os.ReadFile(f); err == nil && bytes.Contains(b, []byte(frag)) {
			t.Fatalf("the token is in %s", f)
		}
	}
	// A repeat mint is a new run and a new token; the first stays valid until its run ends.
	st, body2 := g.call("POST", "/v0/dev-tokens", g.OrchToken, devTokenReq("health"))
	if st != 201 || body2["token"] == body["token"] || body2["run_id"] == body["run_id"] {
		t.Fatalf("second mint: %d %v", st, body2)
	}
	// The same answer anywhere else would be blocked: the ledger query, for one, never returns it.
	st, led := g.call("GET", "/v0/ledger?limit=200", g.OrchToken, nil)
	if st != 200 || strings.Contains(toJSON(led), frag) {
		t.Fatalf("ledger query: %d", st)
	}
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// RT-52 (a): from a host-interim run, each high-impact op is refused or becomes
// an approval request; none executes without a fresh approval bound to that
// request and run, including one a human granted to someone else's identical
// request. The table of op against outcome is in the test log. repo.settings
// and host.scripts.refresh are critical: the mint ceiling refuses them (see
// TestRT52MintCeiling), so a run token never holds them and every request for
// them is OP_NOT_IN_TOKEN.
func TestRT52PolicyCeilingTable(t *testing.T) {
	highImpact := []string{"deploy", "data.apply", "mail.send", "drive.share", "notion.write", "repo.settings", "host.scripts.refresh"}
	ap := &fakeApprovals{}
	g := newRig(t, rigOpts{enable: highImpact, approvals: ap, orchOps: highImpact})
	run, _ := g.mint(highImpact[:5]...)
	params := map[string]map[string]any{
		"deploy": {"sha": sha1}, "data.apply": {"migration": "0042"}, "mail.send": {"to": "a@example.test", "subject": "s", "body": "b"},
		"drive.share": {"file": "f1", "to": "a@example.test", "role": "reader"}, "notion.write": {"page": "p1", "text": "t"},
		"repo.settings": {"setting": "default_branch", "value": "main"}, "host.scripts.refresh": {},
	}
	for _, op := range highImpact {
		st, body := g.call("POST", "/v0/ops", run, opBody(op, "x", params[op]))
		code := str(body, "cause_code")
		t.Logf("RT-52(a) %-22s -> HTTP %d %s", op, st, code)
		if st < 400 || (code != "OP_APPROVAL_REQUIRED" && code != "OP_POLICY_REFUSED" && code != "OP_NOT_IN_TOKEN") {
			t.Errorf("%s from a host-interim run: %d %v", op, st, body)
		}
	}
	if g.spy.executions() != 0 {
		t.Fatal("a high-impact op executed without an approval")
	}

	// An approval a human granted to the orchestrator's identical request is not portable.
	orch := opBody("deploy", "pilot", map[string]any{"sha": sha1})
	orch["project"] = rigProject
	orch["kind"], orch["reason"] = "op", "red-team"
	st, op := g.call("POST", "/v0/approvals", g.OrchToken, orch)
	if st != 202 {
		t.Fatalf("%d %v", st, op)
	}
	aid := str(op["approval"].(map[string]any), "id")
	ap.set(aid, "approved")
	for _, who := range []string{run} {
		b := opBody("deploy", "pilot", map[string]any{"sha": sha1})
		b["approval_id"] = aid
		st, body := g.call("POST", "/v0/ops", who, b)
		if st < 400 {
			t.Fatalf("the orchestrator's approval released a run's identical request: %d %v", st, body)
		}
	}
	if g.spy.executions() != 0 {
		t.Fatal("an op executed on someone else's approval")
	}
}

// The mint ceiling and the policy's host-interim profile agree: every op the
// key set's ceiling lets a token hold is an op the profile lets a run ask for
// (a token can hold repo.settings only if some request for it can pass, and
// both lists keep the critical kinds out).
func TestRT52CeilingMatchesPolicyProfile(t *testing.T) {
	_, pack, err := policy.Default()
	if err != nil {
		t.Fatal(err)
	}
	profile := pack.Profiles["host-interim"]
	for _, op := range runtoken.HostInterimCeiling {
		if !slices.Contains(profile, op) {
			t.Errorf("the mint ceiling holds %s, the host-interim profile does not", op)
		}
	}
	for _, op := range []string{"repo.settings", "host.scripts.refresh", "secrets.write", "approvers.enroll", "policy.activate"} {
		if slices.Contains(runtoken.HostInterimCeiling, op) || slices.Contains(profile, op) {
			t.Errorf("critical op %s is in the mint ceiling or the host-interim profile", op)
		}
	}
}
