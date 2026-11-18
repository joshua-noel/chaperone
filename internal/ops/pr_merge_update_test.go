package ops_test

import (
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/gh/ghtest"

	"github.com/joshua-noel/chaperone/internal/ops"
)

func (f *fx) ureq(n int, head string) ops.PRUpdateRequest {
	return ops.PRUpdateRequest{Repo: f.repo, Number: n, ExpectedHeadSHA: head, Policy: f.pol}
}

func (f *fx) updates() int { return f.s.Count("PUT", "/update-branch") }

func TestUpdateBranchSuccess(t *testing.T) {
	f := newFx(t)
	n, head := f.green(t, "agent/x")
	f.r.Commit(base) // the base moves on: the PR is behind
	res, err := f.m.UpdateBranch(ctx, f.ureq(n, head))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Updated || res.Verdict.Outcome != ops.PRAllow || res.OldHead != head || res.NewHead == head || res.NewHead != f.r.PRHead(n) {
		t.Fatalf("%+v", res)
	}
	if f.updates() != 1 || !res.WriteTokenRevoked {
		t.Fatalf("updates=%d revoked=%v", f.updates(), res.WriteTokenRevoked)
	}
	f.noLeak(t)

	// The new head voids the old verify: pr.merge on it starts again at step 2 and is refused.
	mres, err := f.m.Merge(ctx, f.req(n, res.NewHead))
	f.refused(t, n, mres, err)
	wantFailed(t, mres.Verdict, "verify")
	// And the old head is no longer the PR's head.
	mres, err = f.m.Merge(ctx, f.req(n, head))
	f.refused(t, n, mres, err)
	wantFailed(t, mres.Verdict, "head_matches_request")
}

func TestUpdateBranchRefusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(f *fx) (int, string)
		check string
	}{
		{"head differs from expected_head_sha", func(f *fx) (int, string) {
			n, head := f.green(t, "agent/x")
			f.r.Commit(base)
			f.r.Commit("agent/x")
			return n, head
		}, "head_matches_request"},
		{"not behind: nothing to update", func(f *fx) (int, string) { return f.green(t, "agent/x") }, "branch_behind"},
		{"fork", func(f *fx) (int, string) {
			f.r.Branch("agent/x", base)
			head := f.r.Commit("agent/x")
			n := f.r.OpenPR(ghtest.PROptions{Title: "docs: update notes", Head: "agent/x", Base: base, Fork: true})
			f.r.Commit(base)
			return n, head
		}, "head_same_repo"},
		{"PR does not exist", func(f *fx) (int, string) {
			_, head := f.green(t, "agent/x")
			return 99, head
		}, "pr_exists"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFx(t)
			n, head := c.setup(f)
			res, err := f.m.UpdateBranch(ctx, f.ureq(n, head))
			if err != nil {
				t.Fatal(err)
			}
			if res.Verdict.Outcome != ops.PRRefuse || res.Verdict.Cause != ops.PRCausePolicyRefused || res.Updated {
				t.Fatalf("%+v", res.Verdict)
			}
			wantFailed(t, res.Verdict, c.check)
			if f.updates() != 0 || f.s.Count("POST", "/access_tokens") != 1 {
				t.Fatal("a refused update minted a write token or wrote")
			}
			f.noLeak(t)
		})
	}
}

// The head moves after the check and before the write: GitHub answers 422 on
// expected_head_sha; refused once, never retried.
func TestUpdateBranchHeadMovesBeforeTheWrite(t *testing.T) {
	f := newFx(t)
	n, head := f.green(t, "agent/x")
	f.r.Commit(base)
	f.s.Before("PUT", "/update-branch", func() { f.r.Commit("agent/x") })
	res, err := f.m.UpdateBranch(ctx, f.ureq(n, head))
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict.Outcome != ops.PRRefuse || res.Updated || !strings.Contains(res.Verdict.Why, "422") {
		t.Fatalf("%+v", res.Verdict)
	}
	if f.updates() != 1 {
		t.Fatalf("%d update requests, want 1 (no retry)", f.updates())
	}
	if !res.WriteTokenRevoked {
		t.Fatal("write token not revoked")
	}
	f.noLeak(t)
}

func TestUpdateBranchNeedsExpectedHead(t *testing.T) {
	f := newFx(t)
	n, _ := f.green(t, "agent/x")
	for _, head := range []string{"", "abc", strings.Repeat("A", 40)} {
		if _, err := f.m.UpdateBranch(ctx, f.ureq(n, head)); err == nil {
			t.Errorf("expected_head_sha %q accepted", head)
		}
	}
	if len(f.s.Requests()) != 0 {
		t.Fatal("an invalid request reached GitHub")
	}
}

// pr.update and pr.merge on one repo never overlap: the update waits for the merge.
func TestUpdateBranchSharesTheRepoMutex(t *testing.T) {
	f := newFx(t)
	n1, h1 := f.green(t, "agent/one")
	n2, h2 := f.green(t, "agent/two")
	release := make(chan struct{})
	f.s.Before("PUT", "/pulls/1/merge", func() { <-release })
	merged := make(chan error, 1)
	go func() { _, err := f.m.Merge(ctx, f.req(n1, h1)); merged <- err }()
	waitFor(t, func() bool { return f.s.Count("GET", "/compare/") >= 2 }) // merge 1 is parked at its write

	updated := make(chan *ops.PRUpdateResult, 1)
	go func() {
		res, err := f.m.UpdateBranch(ctx, f.ureq(n2, h2))
		if err != nil {
			t.Error(err)
		}
		updated <- res
	}()
	time.Sleep(300 * time.Millisecond)
	for _, r := range f.s.Requests() {
		if strings.Contains(r.Path, "/pulls/2") {
			t.Fatalf("pr.update ran while a merge held the repo: %s %s", r.Method, r.Path)
		}
	}
	close(release)
	if err := <-merged; err != nil {
		t.Fatal(err)
	}
	// After the merge the base moved, so PR 2 is behind and its update goes through.
	if res := <-updated; res == nil || !res.Updated {
		t.Fatalf("%+v", res)
	}
}
