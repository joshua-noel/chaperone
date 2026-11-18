package redteam

// RT-01, RT-02 and RT-03 once more, end to end: an agent's HTTP request to
// chapd, through the real token verifier, the real policy engine and op state
// machine, and the real pr.merge adapter (the one cmd/chapd installs), down to a
// fake GitHub. rt01/rt02/rt03 attack the merger directly, twenty times each;
// this file proves the same blocks hold on the path an agent actually uses, and
// that the approval step cannot be skipped or claimed from there.
//
// Expected block: a red or stale PR is refused OP_POLICY_REFUSED with the stop
// code in the reason; a PR that needs an approval is held (a card is created, no
// merge); an approval for one head cannot release another; params that claim an
// approval are refused; nothing reaches GitHub's merge endpoint until a human
// decision, and after it exactly the approved head merges, once.
//
// To see this fail, change `req.Approved = true` in Execute
// (internal/ops/pr_merge_adapter.go) to run before Check, or drop NeedsApproval
// from Check.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
)

func mergeHTTPBody(repo string, n int, head string) map[string]any {
	return opBody("pr.merge", fmt.Sprintf("%s#%d", repo, n), map[string]any{"base": "main", "head_sha": head, "method": "squash"})
}

func TestRTMergeOverHTTP(t *testing.T) {
	x := newRT01For(t, "acme", "shop")
	ap := &fakeApprovals{}
	g := newRig(t, rigOpts{enable: []string{"pr.merge"}, approvals: ap, prMerge: x.m, prRepo: "acme/shop"})
	run, _ := g.mint("pr.merge")
	repo := "acme/shop"

	// RT-01 over HTTP: red, running, none, forged.
	redN, redHead := x.pr(t, "agent/red", rt01Verify("completed", "failure"))
	runN, runHead := x.pr(t, "agent/running", rt01Verify("in_progress", ""))
	noneN, noneHead := x.pr(t, "agent/none", nil)
	forgedN, forgedHead := x.pr(t, "agent/forged", &ghtest.Check{Name: "verify", AppID: 999, Status: "completed", Conclusion: "success"})
	for name, c := range map[string]struct {
		n    int
		head string
		stop string
	}{
		"red (22 Oct)":  {redN, redHead, "CI_RED"},
		"in progress":   {runN, runHead, "verify"},
		"no verify":     {noneN, noneHead, "CI_STALE"},
		"forged verify": {forgedN, forgedHead, "CI_STALE"},
	} {
		t.Run("RT-01 "+name, func(t *testing.T) {
			for range 5 {
				st, body := g.call("POST", "/v0/ops", run, mergeHTTPBody(repo, c.n, c.head))
				if st < 400 {
					t.Fatalf("%d %v", st, body)
				}
				d := mustDenial(t, body, "OP_POLICY_REFUSED")
				if !strings.Contains(fmt.Sprint(d["why"]), c.stop) {
					t.Fatalf("the denial does not name %s: %v", c.stop, d["why"])
				}
			}
		})
	}

	// RT-02 over HTTP: a push after green CI; the caller names the green head.
	staleN, h1 := x.pr(t, "agent/stale", rt01Verify("completed", "success"))
	x.r.Commit("agent/stale")
	if st, body := g.call("POST", "/v0/ops", run, mergeHTTPBody(repo, staleN, h1)); st < 400 {
		t.Fatalf("stale head: %d %v", st, body)
	} else {
		d := mustDenial(t, body, "OP_POLICY_REFUSED")
		if !strings.Contains(fmt.Sprint(d["why"]), "CI_STALE") {
			t.Fatalf("%v", d["why"])
		}
	}

	if n := x.s.Count("PUT", "/merge"); n != 0 {
		t.Fatalf("%d merge request(s) reached GitHub for red or stale PRs", n)
	}
	for _, n := range []int{redN, runN, noneN, forgedN, staleN} {
		if ok, _ := x.r.Merged(n); ok {
			t.Fatalf("PR #%d merged", n)
		}
	}

	// RT-03 over HTTP: a workflow change needs an approval, and only that head.
	files := ghtest.File{Filename: ".github/workflows/ci.yml"}
	n1, head1 := x.prFiles(t, "agent/wf1", files)
	n2, head2 := x.prFiles(t, "agent/wf2", files)

	t.Run("RT-03 params cannot claim an approval", func(t *testing.T) {
		for _, extra := range []map[string]any{{"approved": true}, {"approval": "a-000001"}, {"tier": "low"}} {
			b := mergeHTTPBody(repo, n1, head1)
			for k, v := range extra {
				b["params"].(map[string]any)[k] = v
			}
			st, body := g.call("POST", "/v0/ops", run, b)
			if st < 400 {
				t.Fatalf("%v: %d %v", extra, st, body)
			}
			mustDenial(t, body, "OP_PARAMS_INVALID")
		}
	})
	t.Run("RT-03 asked outright, a high tier PR needs an approval and does not merge", func(t *testing.T) {
		for range 5 {
			st, body := g.call("POST", "/v0/ops", run, mergeHTTPBody(repo, n1, head1))
			if st < 400 {
				t.Fatalf("%d %v", st, body)
			}
			mustDenial(t, body, "OP_APPROVAL_REQUIRED")
		}
		if x.s.Count("PUT", "/merge") != 0 {
			t.Fatal("merged without an approval")
		}
	})

	// The card is made; nothing merges until the operator decides.
	st, op1 := g.call("POST", "/v0/approvals", run, approvalReq("pr.merge", fmt.Sprintf("%s#%d", repo, n1), map[string]any{"base": "main", "head_sha": head1, "method": "squash"}))
	if st != 202 {
		t.Fatalf("%d %v", st, op1)
	}
	aid1 := str(op1["approval"].(map[string]any), "id")
	if x.s.Count("PUT", "/merge") != 0 {
		t.Fatal("merged while the card was pending")
	}

	// The approval for PR 1 cannot release PR 2, nor PR 1 at another head.
	for name, b := range map[string]map[string]any{
		"another PR":                mergeHTTPBody(repo, n2, head2),
		"the same PR, another head": mergeHTTPBody(repo, n1, head2),
	} {
		b["approval_id"] = aid1
		st, body := g.call("POST", "/v0/ops", run, b)
		if st != 409 {
			t.Fatalf("%s: %d %v", name, st, body)
		}
		mustDenial(t, body, "APPROVAL_HASH_MISMATCH")
	}
	if x.s.Count("PUT", "/merge") != 0 {
		t.Fatal("merged on a mismatched approval")
	}

	// The head moves while the card waits: the approval is for the old head and
	// the merge is refused (the PR head is no longer the one approved).
	x.r.Commit("agent/wf1")
	g.decide(t, ap, str(op1, "id"), aid1, true)
	waitOpState(t, g, run, str(op1, "id"), "refused")
	if x.s.Count("PUT", "/merge") != 0 {
		t.Fatal("an approved head that moved was merged")
	}
	if ok, _ := x.r.Merged(n1); ok {
		t.Fatal("PR 1 merged at a head nobody approved")
	}

	// Control: a second card, approved while the head is unchanged, merges that head once.
	st, op2 := g.call("POST", "/v0/approvals", run, approvalReq("pr.merge", fmt.Sprintf("%s#%d", repo, n2), map[string]any{"base": "main", "head_sha": head2, "method": "squash"}))
	if st != 202 {
		t.Fatalf("%d %v", st, op2)
	}
	aid2 := str(op2["approval"].(map[string]any), "id")
	g.decide(t, ap, str(op2, "id"), aid2, true)
	waitOpState(t, g, run, str(op2, "id"), "succeeded")
	if ok, _ := x.r.Merged(n2); !ok {
		t.Fatal("the approved PR did not merge")
	}
	if n := x.s.Count("PUT", "/merge"); n != 1 {
		t.Fatalf("%d merge requests, want exactly 1", n)
	}
	// Replaying the approval does not merge again, and the other PR stays open.
	b := mergeHTTPBody(repo, n2, head2)
	b["approval_id"] = aid2
	g.call("POST", "/v0/ops", run, b)
	if n := x.s.Count("PUT", "/merge"); n != 1 {
		t.Fatalf("a replay merged again: %d merge requests", n)
	}
	if ok, _ := x.r.Merged(n1); ok {
		t.Fatal("PR 1 merged")
	}
	if n := x.s.LiveTokens(); n != 0 {
		t.Fatalf("%d installation token(s) left live", n)
	}
	g.mustLedgerOK()
}
