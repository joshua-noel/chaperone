package redteam

// RT-24: the 22 Oct demo email. An agent sent an email on the operator's behalf
// with no approval. Threat model: TB4-T2 (high-class op without a human).
// Red-team list: docs/manual-crosswalk.md, RT-24.
//
// Part 1 is the shipped state: chapd's baseline has every op disabled and no
// adapter for mail.send, so the call is refused OP_DISABLED (nothing to run).
// Part 2 is what the Gmail adapter's ticket will change: the op enabled and an
// adapter wired. The call must then be refused OP_APPROVAL_REQUIRED, with a
// ready-to-use `chap request op` line; the spy adapter (a stand-in for Gmail)
// is never executed before a human decision, however the caller asks: as a run
// or as the orchestrator, with a made-up approval id, with another op's
// approval, with an approval for a different recipient, or by repeating the
// request. After a decision, only the exact approved message goes out, once.
//
// To see this test fail, make the policy engine treat the high class as
// routine (internal/policy/engine.go), or let internal/ops release without a
// recorded approval.

import (
	"testing"
)

func mailParams(to string) map[string]any {
	return map[string]any{"to": to, "subject": "Demo follow-up", "body": "Hello from the demo."}
}

func TestRT24DemoEmail(t *testing.T) {
	t.Run("shipped baseline: disabled, no adapter", func(t *testing.T) {
		g := newRig(t, rigOpts{})
		run, _ := g.mint("mail.send")
		st, body := g.call("POST", "/v0/ops", run, opBody("mail.send", "operator", mailParams("gilliano@example.com")))
		if st != 403 {
			t.Fatalf("%d %v", st, body)
		}
		mustDenial(t, body, "OP_DISABLED")
		if g.spy.executions() != 0 {
			t.Fatal("the email went out")
		}
	})

	t.Run("enabled: refused until a human approves", func(t *testing.T) {
		ap := &fakeApprovals{}
		g := newRig(t, rigOpts{enable: []string{"mail.send", "deploy"}, approvals: ap})
		run, _ := g.mint("mail.send", "deploy")
		mail := opBody("mail.send", "operator", mailParams("gilliano@example.com"))

		// Asked outright, many times, as the run and as the orchestrator.
		for i := range 10 {
			st, body := g.call("POST", "/v0/ops", run, mail)
			if st != 403 {
				t.Fatalf("attempt %d: %d %v", i, st, body)
			}
			d := mustDenial(t, body, "OP_APPROVAL_REQUIRED")
			if req, _ := d["request"].(map[string]any); req == nil || req["possible"] != true || str(req, "command") == "" {
				t.Fatalf("the denial does not say how to ask: %v", d["request"])
			}
		}
		orchMail := opBody("mail.send", "operator", mailParams("gilliano@example.com"))
		orchMail["project"] = rigProject
		if st, body := g.call("POST", "/v0/ops", g.OrchToken, orchMail); st != 403 {
			t.Fatalf("orchestrator: %d %v", st, body)
		} else {
			mustDenial(t, body, "OP_APPROVAL_REQUIRED")
		}

		// Claiming an approval it does not have.
		for name, id := range map[string]string{"made up": "a-999999", "empty-looking": "a-000000"} {
			m := opBody("mail.send", "operator", mailParams("gilliano@example.com"))
			m["approval_id"] = id
			st, body := g.call("POST", "/v0/ops", run, m)
			if st < 400 {
				t.Fatalf("%s approval id: %d %v", name, st, body)
			}
		}

		// Asking creates a card and nothing else.
		st, op := g.call("POST", "/v0/approvals", run, approvalReq("mail.send", "operator", mailParams("gilliano@example.com")))
		if st != 202 || op["state"] != "pending_approval" {
			t.Fatalf("%d %v", st, op)
		}
		aid := str(op["approval"].(map[string]any), "id")
		// A second card for a deploy; its approval must not release the email.
		st, dep := g.call("POST", "/v0/approvals", run, approvalReq("deploy", "pilot", map[string]any{"sha": sha1}))
		if st != 202 {
			t.Fatalf("%d %v", st, dep)
		}
		depApproval := str(dep["approval"].(map[string]any), "id")
		if g.spy.executions() != 0 {
			t.Fatal("the email went out before anyone decided")
		}

		// Another op's approval, or one made for another recipient, never releases this email.
		m := opBody("mail.send", "operator", mailParams("gilliano@example.com"))
		m["approval_id"] = depApproval
		st, body := g.call("POST", "/v0/ops", run, m)
		if st != 409 {
			t.Fatalf("a deploy approval used for mail: %d %v", st, body)
		}
		mustDenial(t, body, "APPROVAL_HASH_MISMATCH")
		other := opBody("mail.send", "operator", mailParams("attacker@example.net"))
		other["approval_id"] = aid
		st, body = g.call("POST", "/v0/ops", run, other)
		if st != 409 {
			t.Fatalf("another recipient under the first card: %d %v", st, body)
		}
		mustDenial(t, body, "APPROVAL_HASH_MISMATCH")
		if g.spy.executions() != 0 {
			t.Fatal("the email went out on a mismatched approval")
		}

		// Control: the operator approves the card; exactly that email goes, once.
		g.decide(t, ap, str(op, "id"), aid, true)
		waitOpState(t, g, run, str(op, "id"), "succeeded")
		if n := g.spy.executions(); n != 1 {
			t.Fatalf("%d executions after the approval, want 1", n)
		}
		g.spy.mu.Lock()
		sent := g.spy.execs[0].Params
		g.spy.mu.Unlock()
		if sent["to"] != "gilliano@example.com" {
			t.Fatalf("the approved email went to %v", sent["to"])
		}
		again := opBody("mail.send", "operator", mailParams("gilliano@example.com"))
		again["approval_id"] = aid
		g.call("POST", "/v0/ops", run, again)
		if n := g.spy.executions(); n != 1 {
			t.Fatalf("a second send came out of one approval: %d executions", n)
		}
		g.mustLedgerOK()
	})
}
