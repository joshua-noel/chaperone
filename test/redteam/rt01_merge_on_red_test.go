package redteam

// RT-01: merge on red CI. Replays the 22 Oct incident, in which a merge agent
// merged a pull request while `verify` was red. Threat model: TB3-E1, TB4-T1 (top-10
// rank 5). Red-team list: docs/manual-crosswalk.md, RT-01.
//
// Setup, as in the red-team list: a Free-plan repository (GitHub itself
// enforces nothing: the fake answers a merge call with 200 whatever `verify`
// says), a PR whose `verify` finished `failure` on its head, a second whose
// `verify` is `in_progress`, a third with no `verify` at all, and a control PR
// whose `verify` is green.
//
// Attack: ask `pr.merge` for each PR, twenty times, also as a dry run, also
// claiming an approval, also naming another PR's green head, also with a
// forged `verify` from another GitHub App.
//
// Expected block: every attempt is a refusal (OP_POLICY_REFUSED) that says why;
// the red PR maps to the CI_RED stop; no merge request ever reaches GitHub, the
// PRs stay open and the base branch tip does not move. The control PR merges, so
// the test is not simply broken. Before all of that, a baseline shows the attack
// WORKS when the control is skipped: the same red PR merges through a bare
// GitHub client. That is the "fails on a baseline without its control" rule.
//
// To see this test fail, remove the conclusion check in judgeCheck
// (internal/ops/pr_merge.go): the red PR then merges and TestRT01 goes red.

import (
	"context"
	"testing"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
	"github.com/joshua-noel/chaperone/internal/ops"
)

const rt01Base = "main"

type rt01 struct {
	s    *ghtest.Server
	c    *gh.Client
	r    *ghtest.Repo
	repo gh.Repo
	m    *ops.PRMerger
}

func newRT01(t *testing.T) *rt01 { return newRT01For(t, "example-org", "rt-sandbox") }

func newRT01For(t *testing.T, account, name string) *rt01 {
	t.Helper()
	s := ghtest.New(t)
	c, err := gh.New(gh.Config{AppID: s.AppID(), Keys: gh.StaticKey{Key: s.Key()}, BaseURL: s.URL(), Now: s.Now})
	if err != nil {
		t.Fatal(err)
	}
	in := s.AddInstallation(7, account, map[string]string{
		"contents": "write", "pull_requests": "write", "checks": "read", "deployments": "write", "metadata": "read",
	})
	// Free plan: no Protect() call, so GitHub merges whatever it is asked to.
	r := in.AddRepo(name, rt01Base)
	m, err := ops.NewPRMerger(ops.PRMergerConfig{GitHub: c, Tokens: &ops.InstallationMinter{Client: c}})
	if err != nil {
		t.Fatal(err)
	}
	return &rt01{s: s, c: c, r: r, repo: gh.Repo{Owner: account, Name: name}, m: m}
}

// pr opens a docs-only PR (low tier, so only CI stands between it and a merge)
// with the given verify run on its head, or none.
func (x *rt01) pr(t *testing.T, branch string, check *ghtest.Check) (int, string) {
	t.Helper()
	x.r.Branch(branch, rt01Base)
	head := x.r.Commit(branch)
	n := x.r.OpenPR(ghtest.PROptions{Title: "docs: update notes", Head: branch, Base: rt01Base})
	x.r.SetFiles(n, ghtest.File{Filename: "docs/notes.md"})
	if check != nil {
		x.r.SetCheck(head, *check)
	}
	return n, head
}

func (x *rt01) req(n int, head string) ops.PRMergeRequest {
	return ops.PRMergeRequest{Repo: x.repo, Number: n, Base: rt01Base, HeadSHA: head,
		Policy: ops.PRPolicy{Version: "rt-1", Base: rt01Base}}
}

func rt01Verify(status, conclusion string) *ghtest.Check {
	return &ghtest.Check{Name: "verify", AppID: gh.GitHubActionsAppID, Status: status, Conclusion: conclusion}
}

// TestRT01MergeOnRed replays 22 Oct (a merge on red).
func TestRT01MergeOnRed(t *testing.T) {
	x := newRT01(t)
	ctx := context.Background()

	// Baseline, control skipped: the repository is on the Free plan and GitHub
	// merges a red PR when asked. This is what happened on 22 Oct. If this stops
	// merging, the replay below proves nothing.
	t.Run("baseline: without the control the red PR merges", func(t *testing.T) {
		_, head := x.pr(t, "agent/baseline", rt01Verify("completed", "failure"))
		tok, err := x.c.MintToken(ctx, 7, gh.TokenRequest{Repositories: []string{"rt-sandbox"}, Permissions: gh.PermsMerge()})
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := x.c.RevokeToken(ctx, tok); err != nil {
				t.Error(err)
			}
		}()
		if _, err := x.c.MergePull(ctx, tok, x.repo, 1, gh.MergeRequest{SHA: head}); err != nil {
			t.Fatalf("the attack does not work on this fake, so the replay would be vacuous: %v", err)
		}
		if ok, _ := x.r.Merged(1); !ok {
			t.Fatal("baseline PR not merged")
		}
	})

	// The PRs of the replay branch from the base as it is now.
	red, redHead := x.pr(t, "agent/red", rt01Verify("completed", "failure"))
	running, runningHead := x.pr(t, "agent/running", rt01Verify("in_progress", ""))
	none, noneHead := x.pr(t, "agent/none", nil)
	forged, forgedHead := x.pr(t, "agent/forged", &ghtest.Check{Name: "verify", AppID: 999, Status: "completed", Conclusion: "success"})
	// The latest verify run on the head decides: a green run followed by a red
	// re-run is red (an older green run must not hide it).
	rerun, rerunHead := x.pr(t, "agent/rerun", rt01Verify("completed", "success"))
	x.r.SetCheck(rerunHead, *rt01Verify("completed", "failure"))
	green, greenHead := x.pr(t, "agent/green", rt01Verify("completed", "success"))
	baseTip := x.r.Head(rt01Base)

	attempts := []struct {
		name  string
		n     int
		head  string
		check string // the failing check the denial must name
		stop  string // the stop code the refusal maps to
	}{
		{"verify failure", red, redHead, "verify", ops.StopCIRed},
		{"verify in_progress", running, runningHead, "verify", ""},
		{"no verify", none, noneHead, "verify", ops.StopCIStale},
		{"verify forged by another GitHub App", forged, forgedHead, "verify", ops.StopCIStale},
		{"an old green run hidden by a red re-run", rerun, rerunHead, "verify", ops.StopCIRed},
		{"red PR, caller names the head of a green PR", red, greenHead, "head_matches_request", ops.StopCIStale},
	}
	for _, a := range attempts {
		t.Run(a.name, func(t *testing.T) {
			for i := range 20 {
				for _, variant := range []struct {
					name     string
					dry      bool
					approved bool
				}{{"plain", false, false}, {"dry-run", true, false}, {"claims an approval", false, true}} {
					r := x.req(a.n, a.head)
					r.DryRun, r.Approved = variant.dry, variant.approved
					res, err := x.m.Merge(ctx, r)
					if err != nil {
						t.Fatalf("attempt %d (%s): %v", i, variant.name, err)
					}
					v := res.Verdict
					if res.Merged || v.Outcome != ops.PRRefuse || v.Cause != ops.PRCausePolicyRefused || v.Why == "" {
						t.Fatalf("attempt %d (%s): not a refusal: %+v", i, variant.name, v)
					}
					if v.Stop != a.stop {
						t.Fatalf("attempt %d (%s): stop = %q, want %q", i, variant.name, v.Stop, a.stop)
					}
					failed := false
					for _, c := range v.Checks {
						if c.Name == a.check && !c.Passed {
							failed = true
						}
					}
					if !failed {
						t.Fatalf("attempt %d (%s): denial does not name %q: %+v", i, variant.name, a.check, v.Checks)
					}
				}
			}
		})
	}

	// Pass evidence: no merge request reached GitHub after the baseline's one,
	// every PR is still open, the base tip did not move, no token is left.
	if n := x.s.Count("PUT", "/merge"); n != 1 {
		t.Fatalf("%d merge requests reached GitHub, want only the baseline's 1", n)
	}
	for name, n := range map[string]int{"red": red, "running": running, "none": none, "forged": forged, "rerun": rerun} {
		if ok, _ := x.r.Merged(n); ok {
			t.Fatalf("PR %q (#%d) merged", name, n)
		}
	}
	if tip := x.r.Head(rt01Base); tip != baseTip {
		t.Fatalf("base tip moved from %s to %s", baseTip, tip)
	}
	if n := x.s.LiveTokens(); n != 0 {
		t.Fatalf("%d installation token(s) left unrevoked", n)
	}

	// Control: a green PR does merge through the same path (the test is not broken).
	t.Run("control: green verify on the exact head merges", func(t *testing.T) {
		res, err := x.m.Merge(ctx, x.req(green, greenHead))
		if err != nil || !res.Merged || res.MergeCommitSHA == "" {
			t.Fatalf("%+v %v", res, err)
		}
		if ok, sha := x.r.Merged(green); !ok || sha != res.MergeCommitSHA {
			t.Fatalf("merged=%v sha=%s", ok, sha)
		}
		if n := x.s.LiveTokens(); n != 0 {
			t.Fatalf("%d installation token(s) left unrevoked", n)
		}
	})
}
