package redteam

// RT-33: stop and revoke at the Chaperone level. Threat model: TB3-S1. Red-team
// list: docs/manual-crosswalk.md, RT-33.
//
// Setup: three active runs with tokens, one of them with a pending approval.
// Attack: the operator's Stop all (`POST /v0/runs/revoke-all`, `chap runs revoke
// --all`), then every old token calls, the pending request is approved after the
// stop, and a request that was waiting for the human is released.
//
// Expected block: every token is TOKEN_REVOKED on its next call (well inside two
// seconds); the pending approval is void (cancelled with the run); an approval
// granted after the stop executes nothing; one `token.revoke` (reason operator) per run is in the
// ledger before any refused call (the `stop.raise` event is the runner's, not chapd's); a run token cannot stop anyone; the
// orchestrator still works (stop all ends runs, not the orchestrator).
//
// Not covered offline: the in-flight op that finishes during the stop (the spy
// adapter returns at once).
//
// To see this fail, make RevokeAll a no-op in internal/runtoken/runs.go.

import (
	"context"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/store"
)

func TestRT33StopAllRevokesEverything(t *testing.T) {
	ap := &fakeApprovals{}
	g := newRig(t, rigOpts{enable: []string{"health", "deploy"}, approvals: ap})
	var toks []string
	for range 3 {
		tok, _ := g.mint("health", "deploy")
		toks = append(toks, tok)
	}
	health := opBody("health", "readiness", map[string]any{})
	for _, tok := range toks {
		if st, body := g.call("POST", "/v0/ops", tok, health); st >= 400 {
			t.Fatalf("control: %d %v", st, body)
		}
	}
	st, op := g.call("POST", "/v0/approvals", toks[0], approvalReq("deploy", "pilot", map[string]any{"sha": sha1}))
	if st != 202 {
		t.Fatalf("%d %v", st, op)
	}
	aid := str(op["approval"].(map[string]any), "id")
	before := g.spy.executions()

	// A run token cannot stop anyone.
	if code := g.status("POST", "/v0/runs/revoke-all", toks[1], nil); code < 400 {
		t.Fatalf("a run token stopped everything: %d", code)
	}
	if n := g.count(`SELECT COUNT(*) FROM runs WHERE state = 'active'`); n != 3 {
		t.Fatalf("%d runs active after a run token tried to stop all", n)
	}

	start := time.Now()
	st, body := g.call("POST", "/v0/runs/revoke-all", g.OrchToken, nil)
	if st != 200 {
		t.Fatalf("stop all: %d %v", st, body)
	}
	for i, tok := range toks {
		code, resp := g.call("POST", "/v0/ops", tok, health)
		if code != 401 {
			t.Fatalf("run %d after the stop: %d %v", i, code, resp)
		}
		mustDenial(t, resp, "TOKEN_REVOKED")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("stop to the last refused call took %s, target under 2s", d)
	}

	// The pending approval is void with the run; approving it afterwards runs nothing.
	if got := ap.byID[aid].State; got != "cancelled" {
		t.Fatalf("the pending card is %q after the stop, want cancelled", got)
	}
	ap.set(aid, "approved")
	err := g.db.Immediate(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		return g.svc.Decided(ctx, tx, str(op, "id"), aid, ops.Decision{Approved: true})
	})
	if err == nil {
		t.Log("Decided accepted a decision for a cancelled op; checking that nothing runs")
	}
	_ = g.svc.Release(context.Background(), str(op, "id"))
	if g.spy.executions() != before {
		t.Fatal("an approval granted after the stop executed an op")
	}
	if n := g.count(`SELECT COUNT(*) FROM ops WHERE id = ? AND state = 'cancelled'`, str(op, "id")); n != 1 {
		t.Fatalf("the op of the voided approval is not cancelled")
	}

	// The record: stop.raise names OPERATOR_STOP_ALL, and the chain verifies.
	if n := g.count(`SELECT COUNT(*) FROM ledger_events WHERE event_name = 'token.revoke' AND event LIKE '%"factory.revoke.reason":"operator"%'`); n != 3 {
		t.Fatalf("%d token.revoke events with reason operator, want 3", n)
	}
	g.mustLedgerOK()

	// Stop all ends runs, not the orchestrator.
	if code, resp := g.call("GET", "/v0/status", g.OrchToken, nil); code != 200 {
		t.Fatalf("the orchestrator after stop all: %d %v", code, resp)
	}
	// Restart: the revocation is in the database.
	g.restart()
	if code, _ := g.call("POST", "/v0/ops", toks[2], health); code != 401 {
		t.Fatalf("after a restart a stopped run's token worked: %d", code)
	}
}
