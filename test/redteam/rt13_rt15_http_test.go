package redteam

// RT-13 (an agent approves its own request) and RT-15 (push-bomb) over HTTP,
// against chapd's ops layer with the spy adapter. The approvals engine's own
// rules are attacked in rt11_approvals_engine_test.go.
//
// RT-13 attack: with a run token and with the orchestrator token, try every
// plausible route and verb that could decide a card (approve, confirm, decide,
// deny, PATCH or PUT the card, a body that claims a decision), and ask for the
// op under another caller's approval. Expected block: no route decides; every
// answer is a client error; the card stays pending; the spy never runs; and
// there is no way to read another caller's card.
//
// RT-15 attack: a run asks for twenty different high-class ops in a row, then
// repeats one of them. Expected block: two cards at most per caller (the rest
// 429 OP_POLICY_REFUSED with Retry-After and an APPROVAL_FLOOD stop in the
// ledger), the repeat is the same op (dedupe, no second card), nothing runs.
//
// To see RT-13 fail, mount a decision route that accepts a bearer token. To see
// RT-15 fail, remove the pending cap in internal/ops/service.go (pendingCap).

import (
	"fmt"
	"strings"
	"testing"
)

func TestRT13ApprovalCannotBeDecidedOverTheAPI(t *testing.T) {
	ap := &fakeApprovals{}
	g := newRig(t, rigOpts{enable: []string{"deploy"}, approvals: ap})
	run, _ := g.mint("deploy")
	st, op := g.call("POST", "/v0/approvals", run, approvalReq("deploy", "pilot", map[string]any{"sha": sha1}))
	if st != 202 {
		t.Fatalf("%d %v", st, op)
	}
	aid := str(op["approval"].(map[string]any), "id")
	opID := str(op, "id")

	suffixes := []string{"", "/approve", "/approved", "/decide", "/decision", "/confirm", "/deny", "/grant", "/accept", "/assert", "/begin", "/challenge"}
	prefixes := []string{"/v0/approvals/", "/v0/ops/", "/approvals/", "/v0/approval/", "/console/approvals/"}
	bodies := []any{nil, map[string]any{"decision": "approved"}, map[string]any{"state": "approved", "approved": true}}
	tokens := map[string]string{"run": run, "orchestrator": g.OrchToken, "no token": ""}
	for who, tok := range tokens {
		for _, p := range prefixes {
			for _, sfx := range suffixes {
				for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
					for _, b := range bodies {
						id := aid
						if p == "/v0/ops/" {
							id = opID
						}
						if code := g.status(method, p+id+sfx, tok, b); code < 400 || code >= 500 {
							t.Fatalf("%s %s%s%s with %s token: %d", method, p, id, sfx, who, code)
						}
					}
				}
			}
		}
	}
	if got := ap.byID[aid].State; got != "pending" {
		t.Fatalf("the card is %q after the attack", got)
	}
	if g.count(`SELECT COUNT(*) FROM ops WHERE id = ? AND state = 'pending_approval'`, opID) != 1 {
		t.Fatal("the op left pending_approval")
	}
	if g.spy.executions() != 0 {
		t.Fatal("the spy ran")
	}

	// A caller cannot use, or even see, another caller's card.
	other, _ := g.mint("deploy")
	body := opBody("deploy", "pilot", map[string]any{"sha": sha1})
	body["approval_id"] = aid
	if code, resp := g.call("POST", "/v0/ops", other, body); code < 400 {
		t.Fatalf("another run used this run's card: %d %v", code, resp)
	} else {
		mustDenial(t, resp, "OP_PARAMS_INVALID")
	}
	if code, resp := g.call("GET", "/v0/approvals/"+aid, other, nil); code < 400 {
		t.Fatalf("another run read this run's card: %d %v", code, resp)
	}
	if g.spy.executions() != 0 {
		t.Fatal("the spy ran")
	}
}

func TestRT15PushBombOverHTTP(t *testing.T) {
	ap := &fakeApprovals{}
	g := newRig(t, rigOpts{enable: []string{"deploy"}, approvals: ap})
	run, runID := g.mint("deploy")

	var created, refused int
	var first map[string]any
	for i := range 20 {
		sha := fmt.Sprintf("%040x", i+1)
		code, resp, hdr := g.callH("POST", "/v0/approvals", run, approvalReq("deploy", "pilot", map[string]any{"sha": sha}))
		switch code {
		case 202:
			created++
			if first == nil {
				first = resp
			}
		case 429:
			refused++
			d := mustDenial(t, resp, "OP_POLICY_REFUSED")
			if !strings.Contains(fmt.Sprint(d["why"]), "flood") {
				t.Fatalf("why: %v", d["why"])
			}
			if hdr.Get("Retry-After") == "" {
				t.Fatal("no Retry-After")
			}
		default:
			t.Fatalf("request %d: %d %v", i, code, resp)
		}
	}
	if created != 2 || refused != 18 {
		t.Fatalf("%d cards and %d refusals, want 2 and 18", created, refused)
	}
	if ap.cards() != 2 {
		t.Fatalf("%d cards exist", ap.cards())
	}
	// The flood is on the record: one APPROVAL_FLOOD stop per refused request, against this run.
	if n := g.count(`SELECT COUNT(*) FROM ledger_events WHERE event_name = 'stop.raise' AND run_id = ? AND event LIKE '%APPROVAL_FLOOD%'`, runID); n != 18 {
		t.Fatalf("%d APPROVAL_FLOOD stop events, want 18", n)
	}
	// Repeating a request that has a card is the same op: no new card, no refusal.
	code, again := g.call("POST", "/v0/approvals", run, approvalReq("deploy", "pilot", map[string]any{"sha": fmt.Sprintf("%040x", 1)}))
	if code != 202 || again["id"] != first["id"] || ap.cards() != 2 {
		t.Fatalf("dedupe: %d %v (cards %d)", code, again["id"], ap.cards())
	}
	if g.spy.executions() != 0 {
		t.Fatal("the spy ran")
	}
	g.mustLedgerOK()
}
