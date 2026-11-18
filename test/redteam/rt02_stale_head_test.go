package redteam

// RT-02: merge on stale CI. Replays 18 Oct, when a PR was merged after a push
// that CI had never seen (the green `verify` belonged to the head before it).
// Threat model: TB3-E1, TB4-T1. Red-team list: docs/manual-crosswalk.md,
// RT-02 (head changes between the check and the merge).
//
// Setup: a PR with a green `verify` on head H1. Attack, each as its own case:
// a commit lands on the PR branch after CI went green and the caller still
// names H1; the caller names the new head H2, on which `verify` never ran; the
// caller names a SHA that is not the PR's head; the base moves so the PR is
// behind; the head moves between evaluation and the write, either before the
// recheck or after it (only GitHub's `sha` check can see the latter); and the
// base moves between evaluation and the write.
//
// Expected block: every case is a refusal that says why, with stop CI_STALE;
// the PUT merge either is never sent or is sent once, pinned to the evaluated
// head, and answered 409 (never retried); the PR stays open; every installation
// token, the write token included, is revoked. Baseline: a bare client that
// merges without the pin and without the check merges H2 although `verify`
// never ran on it, which is what happened on 18 Oct.
//
// To see this test fail, make the head comparison in internal/ops/pr_merge.go
// accept any head (the `head_matches_request` check), or drop `sha` from the
// merge request.

import (
	"context"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/ops"
)

func wantNamedFailure(t *testing.T, v ops.PRVerdict, name string) {
	t.Helper()
	for _, c := range v.Checks {
		if c.Name == name && !c.Passed {
			return
		}
	}
	t.Fatalf("the denial does not name the failed check %q: %+v", name, v.Checks)
}

func TestRT02MergeOnStaleCI(t *testing.T) {
	x := newRT01(t)
	ctx := context.Background()

	// Baseline: the attack works without the control. A push after a green run,
	// then a merge that neither pins the head nor reads CI, merges code CI never saw.
	t.Run("baseline: without the control the unseen head merges", func(t *testing.T) {
		n, _ := x.pr(t, "agent/baseline", rt01Verify("completed", "success"))
		unseen := x.r.Commit("agent/baseline")
		tok, err := x.c.MintToken(ctx, 7, gh.TokenRequest{Repositories: []string{"rt-sandbox"}, Permissions: gh.PermsMerge()})
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := x.c.RevokeToken(ctx, tok); err != nil {
				t.Error(err)
			}
		}()
		if _, err := x.c.MergePull(ctx, tok, x.repo, n, gh.MergeRequest{SHA: unseen}); err != nil {
			t.Fatalf("the attack does not work on this fake, so the replay would be vacuous: %v", err)
		}
		if ok, _ := x.r.Merged(n); !ok {
			t.Fatal("baseline PR not merged")
		}
	})

	writes := func() int { return x.s.Count("PUT", "/merge") }
	baseWrites := writes()

	type attempt struct {
		name  string
		setup func() (n int, named string) // returns the PR and the head the caller names
		check string                       // the failed check the denial must name
	}
	attempts := []attempt{
		{"a push after green CI; the caller names the green head (18 Oct)", func() (int, string) {
			n, h1 := x.pr(t, "agent/stale-old", rt01Verify("completed", "success"))
			x.r.Commit("agent/stale-old")
			return n, h1
		}, "head_matches_request"},
		{"a push after green CI; the caller names the new head, never tested", func() (int, string) {
			n, _ := x.pr(t, "agent/stale-new", rt01Verify("completed", "success"))
			return n, x.r.Commit("agent/stale-new")
		}, "verify"},
		{"several pushes after green CI", func() (int, string) {
			n, h1 := x.pr(t, "agent/stale-many", rt01Verify("completed", "success"))
			for range 3 {
				x.r.Commit("agent/stale-many")
			}
			return n, h1
		}, "head_matches_request"},
		{"the caller names a SHA that is not the head", func() (int, string) {
			n, _ := x.pr(t, "agent/stale-other", rt01Verify("completed", "success"))
			return n, strings.Repeat("a", 40)
		}, "head_matches_request"},
		{"the base moved: the PR is behind", func() (int, string) {
			n, h1 := x.pr(t, "agent/stale-behind", rt01Verify("completed", "success"))
			x.r.Commit(rt01Base)
			return n, h1
		}, "base_current"},
	}
	var open []int
	for _, a := range attempts {
		t.Run(a.name, func(t *testing.T) {
			n, named := a.setup()
			open = append(open, n)
			for i := range 10 {
				for _, dry := range []bool{false, true} {
					r := x.req(n, named)
					r.DryRun = dry
					res, err := x.m.Merge(ctx, r)
					if err != nil {
						t.Fatalf("attempt %d: %v", i, err)
					}
					v := res.Verdict
					if res.Merged || v.Outcome != ops.PRRefuse || v.Cause != ops.PRCausePolicyRefused || v.Why == "" {
						t.Fatalf("attempt %d: not a refusal: %+v", i, v)
					}
					if v.Stop != ops.StopCIStale {
						t.Fatalf("attempt %d: stop = %q, want %q", i, v.Stop, ops.StopCIStale)
					}
					wantNamedFailure(t, v, a.check)
				}
			}
		})
	}
	if n := writes(); n != baseWrites {
		t.Fatalf("%d merge request(s) reached GitHub for a stale PR", n-baseWrites)
	}

	// The race cases: GitHub changes between the evaluation and the write.
	t.Run("the head moves after the evaluation, before the recheck", func(t *testing.T) {
		n, h1 := x.pr(t, "agent/race-recheck", rt01Verify("completed", "success"))
		x.s.Before("GET", "/compare/", func() { x.r.Commit("agent/race-recheck") })
		before := writes()
		res, err := x.m.Merge(ctx, x.req(n, h1))
		if err != nil || res.Merged || res.Verdict.Outcome != ops.PRRefuse {
			t.Fatalf("%+v %v", res, err)
		}
		wantNamedFailure(t, res.Verdict, "recheck_head_matches_request")
		if res.Verdict.Stop != ops.StopCIStale || writes() != before {
			t.Fatalf("stop %q, merge requests %d", res.Verdict.Stop, writes()-before)
		}
	})
	t.Run("the base moves after the evaluation, before the recheck", func(t *testing.T) {
		n, h1 := x.pr(t, "agent/race-base", rt01Verify("completed", "success"))
		x.s.Before("GET", "/files", func() { x.r.Commit(rt01Base) })
		before := writes()
		res, err := x.m.Merge(ctx, x.req(n, h1))
		if err != nil || res.Merged || res.Verdict.Outcome != ops.PRRefuse {
			t.Fatalf("%+v %v", res, err)
		}
		wantNamedFailure(t, res.Verdict, "recheck_base_current")
		if writes() != before {
			t.Fatal("merged on a moved base")
		}
	})
	t.Run("the head moves after the recheck: GitHub's sha pin answers 409, no retry", func(t *testing.T) {
		n, h1 := x.pr(t, "agent/race-write", rt01Verify("completed", "success"))
		x.s.Before("PUT", "/merge", func() { x.r.Commit("agent/race-write") })
		before := writes()
		res, err := x.m.Merge(ctx, x.req(n, h1))
		if err != nil || res.Merged || res.Verdict.Outcome != ops.PRRefuse {
			t.Fatalf("%+v %v", res, err)
		}
		wantNamedFailure(t, res.Verdict, "merge_write")
		if res.Verdict.Stop != ops.StopCIStale || !strings.Contains(res.Verdict.Why, "409") {
			t.Fatalf("%+v", res.Verdict)
		}
		if writes()-before != 1 {
			t.Fatalf("%d merge requests, want exactly 1: a 409 is never retried", writes()-before)
		}
		if !res.WriteTokenRevoked {
			t.Fatal("the write token was not revoked after the refused merge")
		}
		open = append(open, n)
	})

	for _, n := range open {
		if ok, _ := x.r.Merged(n); ok {
			t.Fatalf("PR #%d merged", n)
		}
	}
	if n := x.s.LiveTokens(); n != 0 {
		t.Fatalf("%d installation token(s) left unrevoked", n)
	}

	// Control: with CI green on the exact head and the base current the same
	// path merges (the test is not simply broken).
	t.Run("control: green verify on the exact head merges", func(t *testing.T) {
		n, h := x.pr(t, "agent/fresh", rt01Verify("completed", "success"))
		res, err := x.m.Merge(ctx, x.req(n, h))
		if err != nil || !res.Merged || res.MergeCommitSHA == "" {
			t.Fatalf("%+v %v", res, err)
		}
		if n := x.s.LiveTokens(); n != 0 {
			t.Fatalf("%d installation token(s) left unrevoked", n)
		}
	})
}
