package gh_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
)

// protectedFixture is a repo with Team-plan style protection: `verify` from
// GitHub Actions must be success on the exact head, and the head must be up to date.
func protectedFixture(t *testing.T) *fixture {
	f := newFixture(t)
	f.r.Protect(ghtest.Protection{RequiredCheck: "verify", RequiredAppID: gh.GitHubActionsAppID, StrictUpToDate: true})
	return f
}

func merges(f *fixture) int { return f.s.Count("PUT", "/merge") }

// refusedOnce asserts the call failed with want after exactly one merge request
// and that nothing merged: a refused merge is never retried.
func refusedOnce(t *testing.T, f *fixture, pr int, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
	if n := merges(f); n != 1 {
		t.Fatalf("%d merge requests, want exactly 1 (no retry)", n)
	}
	if ok, _ := f.r.Merged(pr); ok {
		t.Fatal("the PR was merged")
	}
	var apiErr *gh.APIError
	if !errors.As(err, &apiErr) || apiErr.Message == "" {
		t.Fatalf("no APIError detail: %v", err)
	}
}

func TestMergeSuccess(t *testing.T) {
	f := protectedFixture(t)
	n, head := f.pr(t, "agent/ok")
	f.r.SetCheck(head, verify("completed", "success"))
	tok := f.mint(t, gh.PermsMerge())
	res, err := f.c.MergePull(ctx, tok, f.repo, n, gh.MergeRequest{SHA: head, CommitTitle: "feat: ok"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Merged || res.SHA == "" {
		t.Fatalf("%+v", res)
	}
	if ok, sha := f.r.Merged(n); !ok || sha != res.SHA {
		t.Fatalf("merged=%v sha=%s", ok, sha)
	}
	var body map[string]string
	for _, r := range f.s.Requests() {
		if r.Method == "PUT" && strings.HasSuffix(r.Path, "/merge") {
			_ = json.Unmarshal([]byte(r.Body), &body)
		}
	}
	if body["sha"] != head || body["merge_method"] != "squash" || body["commit_title"] != "feat: ok" {
		t.Fatalf("merge body = %v", body)
	}
	// and the PR now reads back as merged (ADR-002 step 9)
	p, err := f.c.GetPull(ctx, f.all(t), f.repo, n)
	if err != nil || !p.Merged || p.MergeCommitSHA != res.SHA || p.State != "closed" {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestMergeRefusedWhenVerifyNotSuccessOnExactHead(t *testing.T) {
	cases := map[string]func(f *fixture, head string){
		"verify missing": func(f *fixture, head string) {},
		"queued":         func(f *fixture, head string) { f.r.SetCheck(head, verify("queued", "")) },
		"in_progress":    func(f *fixture, head string) { f.r.SetCheck(head, verify("in_progress", "")) },
		"cancelled":      func(f *fixture, head string) { f.r.SetCheck(head, verify("completed", "cancelled")) },
		"skipped":        func(f *fixture, head string) { f.r.SetCheck(head, verify("completed", "skipped")) },
		"failure":        func(f *fixture, head string) { f.r.SetCheck(head, verify("completed", "failure")) },
		"neutral":        func(f *fixture, head string) { f.r.SetCheck(head, verify("completed", "neutral")) },
		"success then rerun failed": func(f *fixture, head string) {
			f.r.SetCheck(head, verify("completed", "success"))
			f.r.SetCheck(head, verify("completed", "failure"))
		},
		"verify posted by another app": func(f *fixture, head string) {
			f.r.SetCheck(head, ghtest.Check{Name: "verify", AppID: 999, Status: "completed", Conclusion: "success"})
		},
		"other check named differently": func(f *fixture, head string) {
			f.r.SetCheck(head, ghtest.Check{Name: "lint", AppID: gh.GitHubActionsAppID, Status: "completed", Conclusion: "success"})
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f := protectedFixture(t)
			n, head := f.pr(t, "agent/red")
			setup(f, head)
			_, err := f.c.MergePull(ctx, f.mint(t, gh.PermsMerge()), f.repo, n, gh.MergeRequest{SHA: head})
			refusedOnce(t, f, n, err, gh.ErrNotAllowed)
		})
	}
}

func TestMergeRefusedWhenVerifyIsOnAnOlderHead(t *testing.T) {
	f := protectedFixture(t)
	n, old := f.pr(t, "agent/stale")
	f.r.SetCheck(old, verify("completed", "success"))
	head := f.r.Commit("agent/stale") // a new head; verify never ran on it
	if head == old {
		t.Fatal("head did not move")
	}
	_, err := f.c.MergePull(ctx, f.mint(t, gh.PermsMerge()), f.repo, n, gh.MergeRequest{SHA: head})
	refusedOnce(t, f, n, err, gh.ErrNotAllowed)
}

func TestMergeRefusedWhenBehind(t *testing.T) {
	f := protectedFixture(t)
	n, head := f.pr(t, "agent/behind")
	f.r.SetCheck(head, verify("completed", "success"))
	f.r.Commit(base) // the base moves on
	_, err := f.c.MergePull(ctx, f.mint(t, gh.PermsMerge()), f.repo, n, gh.MergeRequest{SHA: head})
	refusedOnce(t, f, n, err, gh.ErrNotAllowed)

	// update-branch fixes it; the new head has no verify, so it is refused again until verify runs
	tok := f.mint(t, gh.PermsMerge())
	if _, err := f.c.UpdatePullBranch(ctx, tok, f.repo, n, head); err != nil {
		t.Fatal(err)
	}
	newHead := f.r.PRHead(n)
	if newHead == head {
		t.Fatal("update-branch did not move the head")
	}
	_, err = f.c.MergePull(ctx, tok, f.repo, n, gh.MergeRequest{SHA: newHead})
	if !errors.Is(err, gh.ErrNotAllowed) {
		t.Fatalf("new head without verify: %v", err)
	}
	f.r.SetCheck(newHead, verify("completed", "success"))
	if _, err := f.c.MergePull(ctx, tok, f.repo, n, gh.MergeRequest{SHA: newHead}); err != nil {
		t.Fatalf("after verify on the new head: %v", err)
	}
}

func TestMergeHeadMovedIs409AndNotRetried(t *testing.T) {
	f := protectedFixture(t)
	n, head := f.pr(t, "agent/race")
	f.r.SetCheck(head, verify("completed", "success"))
	tok := f.mint(t, gh.PermsMerge())
	// Someone pushes between the caller's checks and its merge write.
	f.s.Before("PUT", "/merge", func() { f.r.Commit("agent/race") })
	_, err := f.c.MergePull(ctx, tok, f.repo, n, gh.MergeRequest{SHA: head})
	refusedOnce(t, f, n, err, gh.ErrConflict)
	var apiErr *gh.APIError
	if errors.As(err, &apiErr) && apiErr.Status != 409 {
		t.Fatalf("status %d", apiErr.Status)
	}
}

func TestMergeRefusedStateAndPolicy(t *testing.T) {
	t.Run("draft", func(t *testing.T) {
		f := newFixture(t)
		f.r.Branch("agent/d", base)
		head := f.r.Commit("agent/d")
		n := f.r.OpenPR(ghtest.PROptions{Title: "feat: d", Head: "agent/d", Base: base, Draft: true})
		_, err := f.c.MergePull(ctx, f.mint(t, gh.PermsMerge()), f.repo, n, gh.MergeRequest{SHA: head})
		refusedOnce(t, f, n, err, gh.ErrNotAllowed)
	})
	t.Run("conflict", func(t *testing.T) {
		f := newFixture(t)
		n, head := f.pr(t, "agent/c")
		f.r.SetConflict(n, true)
		_, err := f.c.MergePull(ctx, f.mint(t, gh.PermsMerge()), f.repo, n, gh.MergeRequest{SHA: head})
		refusedOnce(t, f, n, err, gh.ErrNotAllowed)
	})
	t.Run("already merged", func(t *testing.T) {
		f := newFixture(t)
		n, head := f.pr(t, "agent/m")
		tok := f.mint(t, gh.PermsMerge())
		if _, err := f.c.MergePull(ctx, tok, f.repo, n, gh.MergeRequest{SHA: head}); err != nil {
			t.Fatal(err)
		}
		_, err := f.c.MergePull(ctx, tok, f.repo, n, gh.MergeRequest{SHA: head})
		if !errors.Is(err, gh.ErrNotAllowed) || merges(f) != 2 {
			t.Fatalf("err=%v merges=%d", err, merges(f))
		}
	})
	t.Run("method disallowed", func(t *testing.T) {
		f := newFixture(t)
		f.r.DisallowMergeMethod("squash")
		n, head := f.pr(t, "agent/x")
		_, err := f.c.MergePull(ctx, f.mint(t, gh.PermsMerge()), f.repo, n, gh.MergeRequest{SHA: head})
		refusedOnce(t, f, n, err, gh.ErrNotAllowed)
	})
	t.Run("unknown PR", func(t *testing.T) {
		f := newFixture(t)
		_, head := f.pr(t, "agent/y")
		_, err := f.c.MergePull(ctx, f.mint(t, gh.PermsMerge()), f.repo, 99, gh.MergeRequest{SHA: head})
		if !errors.Is(err, gh.ErrNotFound) {
			t.Fatal(err)
		}
	})
}

func TestMergeClientSideRefusals(t *testing.T) {
	f := newFixture(t)
	n, head := f.pr(t, "agent/cs")
	tok := f.mint(t, gh.PermsMerge())
	cases := map[string]gh.MergeRequest{
		"no sha":          {},
		"abbreviated sha": {SHA: head[:7]},
		"upper-case sha":  {SHA: strings.ToUpper(head)},
		"branch as sha":   {SHA: "main"},
		"bad method":      {SHA: head, Method: "fast-forward"},
	}
	for name, req := range cases {
		if _, err := f.c.MergePull(ctx, tok, f.repo, n, req); !errors.Is(err, gh.ErrInvalidArgument) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := f.c.MergePull(ctx, tok, f.repo, 0, gh.MergeRequest{SHA: head}); !errors.Is(err, gh.ErrInvalidArgument) {
		t.Errorf("pr 0: %v", err)
	}
	if merges(f) != 0 {
		t.Fatal("an invalid request was sent")
	}
}

// On a Free-plan repository GitHub itself merges a red, stale PR. That is the
// reason ADR-002 makes Chaperone the only control: the fake must behave the same,
// so L1-10 can prove that Chaperone refuses before the write.
func TestFreePlanRepoMergesRedPR(t *testing.T) {
	f := newFixture(t)
	n, head := f.pr(t, "agent/red")
	f.r.SetCheck(head, verify("completed", "failure"))
	f.r.Commit(base) // and the PR is behind
	if _, err := f.c.MergePull(ctx, f.mint(t, gh.PermsMerge()), f.repo, n, gh.MergeRequest{SHA: head}); err != nil {
		t.Fatalf("an unprotected repo merges: %v", err)
	}
}
