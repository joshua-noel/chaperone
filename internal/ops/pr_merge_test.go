package ops_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
	"github.com/joshua-noel/chaperone/internal/ops"
)

const base = "feat/d1-private-pilot" // a base with a slash, as in ADR-002

var ctx = context.Background()

type fx struct {
	s    *ghtest.Server
	c    *gh.Client
	r    *ghtest.Repo
	repo gh.Repo
	m    *ops.PRMerger
	pol  ops.PRPolicy
}

func newFx(t *testing.T) *fx {
	t.Helper()
	s := ghtest.New(t)
	c, err := gh.New(gh.Config{AppID: s.AppID(), Keys: gh.StaticKey{Key: s.Key()}, BaseURL: s.URL(), Now: s.Now})
	if err != nil {
		t.Fatal(err)
	}
	in := s.AddInstallation(7, "example-org", map[string]string{
		"contents": "write", "pull_requests": "write", "checks": "read", "deployments": "write", "metadata": "read",
	})
	f := &fx{s: s, c: c, r: in.AddRepo("storefront", base), repo: gh.Repo{Owner: "example-org", Name: "storefront"}}
	in.AddRepo("other", "main")
	f.pol = ops.PRPolicy{Version: "test-1", Base: base}
	f.m = f.merger(t, c)
	return f
}

func (f *fx) merger(t *testing.T, api ops.GitHubAPI) *ops.PRMerger {
	t.Helper()
	m, err := ops.NewPRMerger(ops.PRMergerConfig{GitHub: api, Tokens: &ops.InstallationMinter{Client: f.c}})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// open makes a PR from a new branch with one commit and the given changed
// files (default: one doc). It has no verify run yet.
func (f *fx) open(t *testing.T, branch, title string, files ...string) (int, string) {
	t.Helper()
	f.r.Branch(branch, base)
	head := f.r.Commit(branch)
	n := f.r.OpenPR(ghtest.PROptions{Title: title, Head: branch, Base: base})
	if len(files) == 0 {
		files = []string{"docs/notes.md"}
	}
	fs := make([]ghtest.File, len(files))
	for i, p := range files {
		fs[i] = ghtest.File{Filename: p}
	}
	f.r.SetFiles(n, fs...)
	return n, head
}

// green opens a low-tier PR with a good title and a green verify on its head.
func (f *fx) green(t *testing.T, branch string, files ...string) (int, string) {
	t.Helper()
	n, head := f.open(t, branch, "docs: update notes", files...)
	f.r.SetCheck(head, verify("completed", "success"))
	return n, head
}

func verify(status, conclusion string) ghtest.Check {
	return ghtest.Check{Name: "verify", AppID: gh.GitHubActionsAppID, Status: status, Conclusion: conclusion}
}

func (f *fx) req(n int, head string) ops.PRMergeRequest {
	return ops.PRMergeRequest{Repo: f.repo, Number: n, Base: base, HeadSHA: head, Policy: f.pol}
}

func (f *fx) writes() int { return f.s.Count("PUT", "/merge") }

// refused asserts a clean refusal: no error, outcome refuse with the policy
// cause, nothing merged, no merge request sent, every token revoked.
func (f *fx) refused(t *testing.T, n int, res *ops.PRMergeResult, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("err = %v, want a refusal result", err)
	}
	v := res.Verdict
	if v.Outcome != ops.PRRefuse || v.Cause != ops.PRCausePolicyRefused || v.WouldAllow() || res.Merged {
		t.Fatalf("verdict = %+v", v)
	}
	if v.Why == "" {
		t.Fatal("a refusal must say why")
	}
	if ok, _ := f.r.Merged(n); ok {
		t.Fatal("the PR was merged")
	}
	f.noLeak(t)
}

func (f *fx) noLeak(t *testing.T) {
	t.Helper()
	if n := f.s.LiveTokens(); n != 0 {
		t.Fatalf("%d installation token(s) left unrevoked", n)
	}
}

func failedNames(v ops.PRVerdict) []string {
	var out []string
	for _, c := range v.Checks {
		if !c.Passed {
			out = append(out, c.Name)
		}
	}
	return out
}

func wantFailed(t *testing.T, v ops.PRVerdict, name string) {
	t.Helper()
	for _, n := range failedNames(v) {
		if n == name {
			return
		}
	}
	t.Fatalf("check %q did not fail: %+v", name, v.Checks)
}

func TestMergeSuccessLowTier(t *testing.T) {
	f := newFx(t)
	n, head := f.green(t, "agent/ok")
	res, err := f.m.Merge(ctx, f.req(n, head))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Merged || res.Verdict.Outcome != ops.PRAllow || res.Verdict.Tier != ops.TierLow || res.Verdict.PolicyVersion != "test-1" {
		t.Fatalf("%+v", res)
	}
	ok, sha := f.r.Merged(n)
	if !ok || res.MergeCommitSHA != sha {
		t.Fatalf("merged=%v sha=%s result=%s", ok, sha, res.MergeCommitSHA)
	}
	if want := "https://github.test/example-org/storefront/pull/1"; res.ExternalRef != want {
		t.Fatalf("external_ref = %q, want %q", res.ExternalRef, want)
	}
	// Exactly one write, carrying the checked head, squash, and the PR title.
	var body map[string]string
	for _, r := range f.s.Requests() {
		if r.Method == "PUT" && strings.HasSuffix(r.Path, "/merge") {
			_ = json.Unmarshal([]byte(r.Body), &body)
		}
	}
	if f.writes() != 1 || body["sha"] != head || body["merge_method"] != "squash" || body["commit_title"] != "docs: update notes" {
		t.Fatalf("writes=%d body=%v", f.writes(), body)
	}
	// Two tokens: a read-only one for the checks, a write one for the merge only.
	if !res.WriteTokenRevoked || len(res.Warnings) != 0 {
		t.Fatalf("revoked=%v warnings=%v", res.WriteTokenRevoked, res.Warnings)
	}
	if mints, revokes := f.s.Count("POST", "/access_tokens"), f.s.Count("DELETE", "/installation/token"); mints != 2 || revokes != 2 {
		t.Fatalf("mints=%d revokes=%d", mints, revokes)
	}
	var perms []map[string]string
	for _, r := range f.s.Requests() {
		if r.Method == "POST" && strings.HasSuffix(r.Path, "/access_tokens") {
			var b struct{ Permissions map[string]string }
			_ = json.Unmarshal([]byte(r.Body), &b)
			perms = append(perms, b.Permissions)
		}
	}
	if perms[0]["contents"] != "read" || perms[0]["pull_requests"] != "read" || perms[1]["contents"] != "write" {
		t.Fatalf("token permissions: %v", perms)
	}
	f.noLeak(t)
}

func TestMergeRefusals(t *testing.T) {
	type tc struct {
		name  string
		setup func(f *fx) (n int, head string)
		check string // the failing check the verdict must name
		stop  string
	}
	withVerify := func(c ghtest.Check) func(f *fx) (int, string) {
		return func(f *fx) (int, string) {
			n, head := f.open(t, "agent/x", "docs: update notes")
			f.r.SetCheck(head, c)
			return n, head
		}
	}
	// rerun records the runs in order on one head: the last is the latest.
	rerun := func(runs ...ghtest.Check) func(f *fx) (int, string) {
		return func(f *fx) (int, string) {
			n, head := f.open(t, "agent/x", "docs: update notes")
			for _, c := range runs {
				f.r.SetCheck(head, c)
			}
			return n, head
		}
	}
	cases := []tc{
		{"verify missing", func(f *fx) (int, string) { return f.open(t, "agent/x", "docs: update notes") }, "verify", ops.StopCIStale},
		{"queued", withVerify(verify("queued", "")), "verify", ""},
		{"in_progress", withVerify(verify("in_progress", "")), "verify", ""},
		{"cancelled", withVerify(verify("completed", "cancelled")), "verify", ops.StopCIRed},
		{"skipped", withVerify(verify("completed", "skipped")), "verify", ops.StopCIRed},
		{"failure", withVerify(verify("completed", "failure")), "verify", ops.StopCIRed},
		{"neutral", withVerify(verify("completed", "neutral")), "verify", ops.StopCIRed},
		{"timed_out", withVerify(verify("completed", "timed_out")), "verify", ops.StopCIRed},
		{"verify posted by another app", withVerify(ghtest.Check{Name: "verify", AppID: 999, Status: "completed", Conclusion: "success"}), "verify", ops.StopCIStale},
		{"verify posted by no app", withVerify(ghtest.Check{Name: "verify", Status: "completed", Conclusion: "success"}), "verify", ops.StopCIStale},
		{"another check name is green", withVerify(ghtest.Check{Name: "lint", AppID: gh.GitHubActionsAppID, Status: "completed", Conclusion: "success"}), "verify", ops.StopCIStale},
		{"green run, then a rerun that failed", rerun(verify("completed", "success"), verify("completed", "failure")), "verify", ops.StopCIRed},
		{"green run, then a rerun in_progress", rerun(verify("completed", "success"), verify("in_progress", "")), "verify", ""},
		{"green run, then a rerun queued", rerun(verify("completed", "success"), verify("queued", "")), "verify", ""},
		{"green run, then a rerun cancelled", rerun(verify("completed", "success"), verify("completed", "cancelled")), "verify", ops.StopCIRed},
		{"green run, then a rerun skipped", rerun(verify("completed", "success"), verify("completed", "skipped")), "verify", ops.StopCIRed},
		{"extra required check missing", func(f *fx) (int, string) {
			f.pol.ExtraChecks = []string{"e2e"}
			return f.green(t, "agent/x")
		}, "e2e", ops.StopCIStale},
		{"draft", func(f *fx) (int, string) {
			f.r.Branch("agent/x", base)
			head := f.r.Commit("agent/x")
			n := f.r.OpenPR(ghtest.PROptions{Title: "docs: update notes", Head: "agent/x", Base: base, Draft: true})
			f.r.SetFiles(n, ghtest.File{Filename: "docs/notes.md"})
			f.r.SetCheck(head, verify("completed", "success"))
			return n, head
		}, "pr_not_draft", ""},
		{"fork", func(f *fx) (int, string) {
			f.r.Branch("agent/x", base)
			head := f.r.Commit("agent/x")
			n := f.r.OpenPR(ghtest.PROptions{Title: "docs: update notes", Head: "agent/x", Base: base, Fork: true})
			f.r.SetFiles(n, ghtest.File{Filename: "docs/notes.md"})
			f.r.SetCheck(head, verify("completed", "success"))
			return n, head
		}, "head_same_repo", ""},
		{"wrong base", func(f *fx) (int, string) {
			f.r.Branch("release", base)
			f.r.Branch("agent/x", "release")
			head := f.r.Commit("agent/x")
			n := f.r.OpenPR(ghtest.PROptions{Title: "docs: update notes", Head: "agent/x", Base: "release"})
			f.r.SetFiles(n, ghtest.File{Filename: "docs/notes.md"})
			f.r.SetCheck(head, verify("completed", "success"))
			return n, head
		}, "base_branch", ""},
		{"conflict", func(f *fx) (int, string) {
			n, head := f.green(t, "agent/x")
			f.r.SetConflict(n, true)
			return n, head
		}, "mergeable", ""},
		{"head differs: verify is on an older head (18 Oct)", func(f *fx) (int, string) {
			n, old := f.green(t, "agent/x")
			f.r.Commit("agent/x") // a push after CI went green
			return n, old         // the caller still names the green head
		}, "head_matches_request", ops.StopCIStale},
		{"head differs: caller names the new head, verify never ran on it", func(f *fx) (int, string) {
			n, _ := f.green(t, "agent/x")
			return n, f.r.Commit("agent/x")
		}, "verify", ops.StopCIStale},
		{"head differs: caller names an unrelated SHA", func(f *fx) (int, string) {
			n, _ := f.green(t, "agent/x")
			return n, strings.Repeat("a", 40)
		}, "head_matches_request", ops.StopCIStale},
		{"behind the base", func(f *fx) (int, string) {
			n, head := f.green(t, "agent/x")
			f.r.Commit(base)
			return n, head
		}, "base_current", ops.StopCIStale},
		{"title too long", func(f *fx) (int, string) {
			n, head := f.open(t, "agent/x", "docs: "+strings.Repeat("a", 67)) // 73 characters
			f.r.SetCheck(head, verify("completed", "success"))
			return n, head
		}, "title", ""},
		{"title not conventional", func(f *fx) (int, string) {
			n, head := f.open(t, "agent/x", "Update the notes")
			f.r.SetCheck(head, verify("completed", "success"))
			return n, head
		}, "title", ""},
		{"title with a second line", func(f *fx) (int, string) {
			n, head := f.open(t, "agent/x", "docs: update notes\nCo-authored-by: x")
			f.r.SetCheck(head, verify("completed", "success"))
			return n, head
		}, "title", ""},
		{"PR does not exist", func(f *fx) (int, string) {
			_, head := f.green(t, "agent/x")
			return 99, head
		}, "pr_exists", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFx(t)
			n, head := c.setup(f)
			res, err := f.m.Merge(ctx, f.req(n, head))
			f.refused(t, n, res, err)
			wantFailed(t, res.Verdict, c.check)
			if res.Verdict.Stop != c.stop {
				t.Fatalf("stop = %q, want %q (%s)", res.Verdict.Stop, c.stop, res.Verdict.Why)
			}
			if f.writes() != 0 {
				t.Fatalf("%d merge request(s) sent for a refused PR", f.writes())
			}
			if f.s.Count("POST", "/access_tokens") != 1 {
				t.Fatal("a write token was minted for a refused PR")
			}
			// Never loop: a second call is a fresh evaluation, still refused, still no write.
			res2, err := f.m.Merge(ctx, f.req(n, head))
			f.refused(t, n, res2, err)
			if f.writes() != 0 {
				t.Fatal("a repeat call merged")
			}
		})
	}
}

// A verify that exists only as a commit status is no check run: ignored.
func TestMergeIgnoresCommitStatusVerify(t *testing.T) {
	f := newFx(t)
	n, head := f.open(t, "agent/x", "docs: update notes")
	// The fake has no statuses endpoint, which is the point: Chaperone must only
	// ever read check runs. A status can never make the PR mergeable.
	res, err := f.m.Merge(ctx, f.req(n, head))
	f.refused(t, n, res, err)
	wantFailed(t, res.Verdict, "verify")
	for _, r := range f.s.Requests() {
		if strings.Contains(r.Path, "/status") {
			t.Fatalf("read a commit status: %s", r.Path)
		}
	}
}

func TestMergeRefusesMismatchedBaseParam(t *testing.T) {
	f := newFx(t)
	n, head := f.green(t, "agent/x")
	r := f.req(n, head)
	r.Base = "main"
	res, err := f.m.Merge(ctx, r)
	f.refused(t, n, res, err)
	wantFailed(t, res.Verdict, "base_branch")
}

func TestMergeHeadMovesBeforeTheWrite(t *testing.T) {
	t.Run("between the check and the write: GitHub answers 409", func(t *testing.T) {
		f := newFx(t)
		n, head := f.green(t, "agent/race")
		// Someone pushes after step 7 and before the merge call lands. The fake
		// moves the head just as the PUT arrives, so only GitHub's `sha` check can see it.
		f.s.Before("PUT", "/merge", func() { f.r.Commit("agent/race") })
		res, err := f.m.Merge(ctx, f.req(n, head))
		f.refused(t, n, res, err)
		wantFailed(t, res.Verdict, "merge_write")
		if res.Verdict.Stop != ops.StopCIStale || !strings.Contains(res.Verdict.Why, "409") {
			t.Fatalf("%+v", res.Verdict)
		}
		if f.writes() != 1 {
			t.Fatalf("%d merge requests, want exactly 1: a 409 is never retried", f.writes())
		}
		if !res.WriteTokenRevoked {
			t.Fatal("the write token must be revoked after a refused merge too")
		}
	})
	t.Run("between step 2 and step 7: the recheck refuses, no write token", func(t *testing.T) {
		f := newFx(t)
		n, head := f.green(t, "agent/race")
		f.s.Before("GET", "/compare/", func() { f.r.Commit("agent/race") })
		res, err := f.m.Merge(ctx, f.req(n, head))
		f.refused(t, n, res, err)
		wantFailed(t, res.Verdict, "recheck_head_matches_request")
		if f.writes() != 0 || f.s.Count("POST", "/access_tokens") != 1 {
			t.Fatalf("writes=%d mints=%d", f.writes(), f.s.Count("POST", "/access_tokens"))
		}
	})
	t.Run("the base moves before step 7", func(t *testing.T) {
		f := newFx(t)
		n, head := f.green(t, "agent/race")
		f.s.Before("GET", "/files", func() { f.r.Commit(base) })
		res, err := f.m.Merge(ctx, f.req(n, head))
		f.refused(t, n, res, err)
		wantFailed(t, res.Verdict, "recheck_base_current")
		if f.writes() != 0 {
			t.Fatal("merged on a moved base")
		}
	})
	t.Run("the title is edited into a bad one before step 7", func(t *testing.T) {
		f := newFx(t)
		n, head := f.green(t, "agent/race")
		m := f.merger(t, &titleEdit{Client: f.c, after: 1, title: "WIP stuff"})
		res, err := m.Merge(ctx, f.req(n, head))
		f.refused(t, n, res, err)
		wantFailed(t, res.Verdict, "recheck_title")
		if f.writes() != 0 {
			t.Fatal("merged under a title that was never checked")
		}
	})
}

// titleEdit rewrites the PR title from the (after+1)th read on, as someone
// editing it between step 2 and step 7.
type titleEdit struct {
	*gh.Client
	after int
	title string
	reads int
}

func (e *titleEdit) GetPull(ctx context.Context, tok *gh.Token, repo gh.Repo, n int) (*gh.Pull, error) {
	p, err := e.Client.GetPull(ctx, tok, repo, n)
	if err == nil {
		if e.reads >= e.after {
			p.Title = e.title
		}
		e.reads++
	}
	return p, err
}

// The card shows one title and the merge uses the PR's title as the commit header: an edit after the approval would
// merge under words the operator never saw. With the approved title in the request, the merge refuses (CI_STALE: a new
// request is needed) and never mints a write token; with the same title it merges under exactly that header.
func TestMergeRefusesATitleThatIsNotTheApprovedOne(t *testing.T) {
	t.Run("edited before the release check: refused at step 6", func(t *testing.T) {
		f := newFx(t)
		n, head := f.green(t, "agent/retitled") // the PR reads "docs: update notes"
		r := f.req(n, head)
		r.ApprovedTitle = "feat(cart): add a delivery fee"
		res, err := f.m.Merge(ctx, r)
		f.refused(t, n, res, err)
		wantFailed(t, res.Verdict, "title_approved")
		if res.Verdict.Stop != ops.StopCIStale || strings.Contains(res.Verdict.Why, "docs: update notes") {
			t.Fatalf("verdict %+v: want CI_STALE and a reason that does not repeat the title", res.Verdict)
		}
		if f.writes() != 0 {
			t.Fatal("merged under a title the approver never saw")
		}
	})
	t.Run("edited between the check and the merge: the recheck refuses, no write token", func(t *testing.T) {
		f := newFx(t)
		n, head := f.green(t, "agent/retitled")
		m := f.merger(t, &titleEdit{Client: f.c, after: 1, title: "fix: hotfix"}) // a good title: only the approval differs
		r := f.req(n, head)
		r.ApprovedTitle = "docs: update notes"
		res, err := m.Merge(ctx, r)
		f.refused(t, n, res, err)
		wantFailed(t, res.Verdict, "recheck_title")
		if res.Verdict.Stop != ops.StopCIStale || f.writes() != 0 || f.s.Count("POST", "/access_tokens") != 1 {
			t.Fatalf("verdict %+v, writes %d, mints %d", res.Verdict, f.writes(), f.s.Count("POST", "/access_tokens"))
		}
	})
	t.Run("the approved title: merged under that header", func(t *testing.T) {
		f := newFx(t)
		n, head := f.green(t, "agent/same")
		r := f.req(n, head)
		r.ApprovedTitle = "docs: update notes"
		res, err := f.m.Merge(ctx, r)
		if err != nil || !res.Merged || f.writes() != 1 {
			t.Fatalf("res %+v, err %v, writes %d", res, err, f.writes())
		}
		var body struct {
			CommitTitle string `json:"commit_title"`
		}
		for _, q := range f.s.Requests() {
			if q.Method == "PUT" && strings.HasSuffix(q.Path, "/merge") {
				if err := json.Unmarshal([]byte(q.Body), &body); err != nil {
					t.Fatal(err)
				}
			}
		}
		if body.CommitTitle != "docs: update notes" {
			t.Fatalf("commit_title = %q", body.CommitTitle)
		}
		f.noLeak(t)
	})
}

func TestMergeDryRun(t *testing.T) {
	t.Run("green low PR: allow, nothing written", func(t *testing.T) {
		f := newFx(t)
		n, head := f.green(t, "agent/x")
		r := f.req(n, head)
		r.DryRun = true
		res, err := f.m.Merge(ctx, r)
		if err != nil || !res.Verdict.WouldAllow() || res.Merged || res.ExternalRef != "" {
			t.Fatalf("%+v %v", res, err)
		}
		if f.writes() != 0 || f.s.Count("POST", "/access_tokens") != 1 {
			t.Fatalf("writes=%d mints=%d: a dry run needs no write token", f.writes(), f.s.Count("POST", "/access_tokens"))
		}
		if ok, _ := f.r.Merged(n); ok {
			t.Fatal("dry run merged")
		}
		f.noLeak(t)
	})
	t.Run("red PR: refuse", func(t *testing.T) {
		f := newFx(t)
		n, head := f.open(t, "agent/x", "docs: update notes")
		f.r.SetCheck(head, verify("completed", "failure"))
		r := f.req(n, head)
		r.DryRun = true
		res, err := f.m.Merge(ctx, r)
		f.refused(t, n, res, err)
	})
	t.Run("medium PR: approval", func(t *testing.T) {
		f := newFx(t)
		n, head := f.green(t, "agent/x", "internal/app/app.go")
		r := f.req(n, head)
		r.DryRun = true
		res, err := f.m.Merge(ctx, r)
		if err != nil || res.Verdict.Outcome != ops.PRApproval || res.Verdict.WouldAllow() {
			t.Fatalf("%+v %v", res, err)
		}
	})
	t.Run("a dry run does not take the repo lock", func(t *testing.T) {
		f := newFx(t)
		n1, h1 := f.green(t, "agent/one")
		n2, h2 := f.green(t, "agent/two")
		release := make(chan struct{})
		f.s.Before("PUT", "/pulls/1/merge", func() { <-release })
		done := make(chan error, 1)
		go func() { _, err := f.m.Merge(ctx, f.req(n1, h1)); done <- err }()
		waitFor(t, func() bool {
			return f.s.Count("DELETE", "/installation/token") == 0 && f.s.Count("GET", "/compare/") >= 2
		})
		r := f.req(n2, h2)
		r.DryRun = true
		if res, err := f.m.Merge(ctx, r); err != nil || !res.Verdict.WouldAllow() {
			t.Fatalf("%+v %v", res, err)
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestMergeRiskTiers(t *testing.T) {
	cases := []struct {
		name  string
		files []string
		tier  ops.PRTier
	}{
		{"docs and tests are low", []string{"docs/guide.md", "internal/app/app_test.go"}, ops.TierLow},
		{"application code is medium", []string{"docs/guide.md", "internal/app/app.go"}, ops.TierMedium},
		{"workflow is high", []string{"docs/guide.md", ".github/workflows/ci.yml"}, ops.TierHigh},
		{"migration is high", []string{"supabase/migrations/0042_add.sql"}, ops.TierHigh},
		{"host script is high", []string{"scripts/pilot-host/pilot.sh"}, ops.TierHigh},
		{"unclassifiable path is high", []string{"docs/guide.md", "tools/blob.xyz"}, ops.TierHigh},
		{"no files is high", []string{}, ops.TierHigh},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFx(t)
			n, head := f.green(t, "agent/x")
			fs := make([]ghtest.File, len(c.files))
			for i, p := range c.files {
				fs[i] = ghtest.File{Filename: p}
			}
			f.r.SetFiles(n, fs...)
			res, err := f.m.Merge(ctx, f.req(n, head))
			if err != nil {
				t.Fatal(err)
			}
			if res.Verdict.Tier != c.tier {
				t.Fatalf("tier = %s, want %s", res.Verdict.Tier, c.tier)
			}
			ok, _ := f.r.Merged(n)
			if c.tier == ops.TierLow {
				if !res.Merged || !ok {
					t.Fatalf("low tier must merge on the checks: %+v", res.Verdict)
				}
				return
			}
			v := res.Verdict
			if res.Merged || ok || v.Outcome != ops.PRApproval || v.Cause != ops.PRCauseApprovalRequired || f.writes() != 0 {
				t.Fatalf("%s tier merged or did not ask for approval: %+v", c.tier, v)
			}
			if f.s.Count("POST", "/access_tokens") != 1 {
				t.Fatal("a write token was minted before approval")
			}
			f.noLeak(t)

			// Once the op pipeline passes a verified approval, the same op merges.
			r := f.req(n, head)
			r.Approved = true
			res, err = f.m.Merge(ctx, r)
			if err != nil || !res.Merged {
				t.Fatalf("approved merge: %+v %v", res, err)
			}
		})
	}
}

// An approval is for one head: it is carried by the op hash, and the op's
// head_sha must equal the PR's head. An approval for H does not merge H2.
func TestMergeApprovalForOneHeadDoesNotMergeAnother(t *testing.T) {
	f := newFx(t)
	n, h1 := f.green(t, "agent/x", "internal/app/app.go")
	h2 := f.r.Commit("agent/x")
	f.r.SetCheck(h2, verify("completed", "success"))
	r := f.req(n, h1) // the request (and its approval) are for H1
	r.Approved = true
	res, err := f.m.Merge(ctx, r)
	f.refused(t, n, res, err)
	wantFailed(t, res.Verdict, "head_matches_request")
	if f.writes() != 0 {
		t.Fatal("merged a head the approval does not name")
	}
}

// Medium and high PRs are only asked about once they are otherwise mergeable:
// a red medium PR is refused, not sent to a human.
func TestMergeRedMediumPRIsRefusedNotAsked(t *testing.T) {
	f := newFx(t)
	n, head := f.open(t, "agent/x", "docs: update notes", "internal/app/app.go")
	f.r.SetCheck(head, verify("completed", "failure"))
	res, err := f.m.Merge(ctx, f.req(n, head))
	f.refused(t, n, res, err)
	if res.Verdict.Outcome == ops.PRApproval {
		t.Fatal("asked for approval on a red PR")
	}
}

func TestMergeRenamedFromHighPathIsHigh(t *testing.T) {
	f := newFx(t)
	n, head := f.green(t, "agent/x")
	f.r.SetFiles(n, ghtest.File{Filename: "docs/ci.md", Status: "renamed", PreviousFilename: ".github/workflows/ci.yml"})
	res, err := f.m.Merge(ctx, f.req(n, head))
	if err != nil || res.Verdict.Tier != ops.TierHigh || res.Verdict.Outcome != ops.PRApproval {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestMergeProjectTierGlobs(t *testing.T) {
	f := newFx(t)
	f.pol.Tiers = ops.PRTierGlobs{High: []string{"internal/ledger/**"}, Low: []string{"web/content/**"}}
	n, head := f.green(t, "agent/x", "internal/ledger/ledger.go")
	res, err := f.m.Merge(ctx, f.req(n, head))
	if err != nil || res.Verdict.Tier != ops.TierHigh {
		t.Fatalf("%+v %v", res, err)
	}
	f.r.SetFiles(n, ghtest.File{Filename: "web/content/index.ts"})
	res, err = f.m.Merge(ctx, f.req(n, head))
	if err != nil || res.Verdict.Tier != ops.TierLow || !res.Merged {
		t.Fatalf("a path the project flags low merges: %+v %v", res, err)
	}
}

func TestMergeRequestValidation(t *testing.T) {
	f := newFx(t)
	n, head := f.green(t, "agent/x")
	bad := map[string]func(r *ops.PRMergeRequest){
		"no head":       func(r *ops.PRMergeRequest) { r.HeadSHA = "" },
		"short head":    func(r *ops.PRMergeRequest) { r.HeadSHA = head[:7] },
		"upper-case":    func(r *ops.PRMergeRequest) { r.HeadSHA = strings.ToUpper(head) },
		"pr 0":          func(r *ops.PRMergeRequest) { r.Number = 0 },
		"no merge base": func(r *ops.PRMergeRequest) { r.Policy.Base = "" },
		"bad repo":      func(r *ops.PRMergeRequest) { r.Repo = gh.Repo{Owner: "a b", Name: "c"} },
		"bad tier glob": func(r *ops.PRMergeRequest) { r.Policy.Tiers.High = []string{"[x"} },
		"empty extra":   func(r *ops.PRMergeRequest) { r.Policy.ExtraChecks = []string{""} },
	}
	for name, mod := range bad {
		r := f.req(n, head)
		mod(&r)
		if _, err := f.m.Merge(ctx, r); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if len(f.s.Requests()) != 0 {
		t.Fatalf("an invalid request reached GitHub: %v", f.s.Requests())
	}
}

// GitHub 5xx on the merge call: one request, no retry, and the op fails
// (the PR reads open, so the merge did not happen).
func TestMergeServerErrorIsNotRetried(t *testing.T) {
	f := newFx(t)
	n, head := f.green(t, "agent/x")
	f.s.Inject("PUT", "/merge", ghtest.Unavailable())
	res, err := f.m.Merge(ctx, f.req(n, head))
	if err == nil || res != nil || errors.Is(err, ops.ErrMergeUnconfirmed) {
		t.Fatalf("res=%v err=%v", res, err)
	}
	if !errors.Is(err, gh.ErrServer) {
		t.Fatalf("err = %v", err)
	}
	if f.writes() != 1 {
		t.Fatalf("%d merge requests, want 1", f.writes())
	}
	if ok, _ := f.r.Merged(n); ok {
		t.Fatal("merged")
	}
	f.noLeak(t)
}

// mergeThenFail merges for real and then reports a transport error, as a
// timeout after GitHub already merged would.
type mergeThenFail struct {
	*gh.Client
	failReadBack bool
	merged       bool
}

func (m *mergeThenFail) MergePull(ctx context.Context, tok *gh.Token, repo gh.Repo, n int, req gh.MergeRequest) (*gh.MergeResult, error) {
	if _, err := m.Client.MergePull(ctx, tok, repo, n, req); err != nil {
		return nil, err
	}
	m.merged = true
	return nil, errors.New("read tcp: i/o timeout")
}

func (m *mergeThenFail) GetPull(ctx context.Context, tok *gh.Token, repo gh.Repo, n int) (*gh.Pull, error) {
	if m.failReadBack && m.merged {
		return nil, errors.New("read tcp: i/o timeout")
	}
	return m.Client.GetPull(ctx, tok, repo, n)
}

func TestMergeTimeoutAfterMergeIsReadBack(t *testing.T) {
	f := newFx(t)
	n, head := f.green(t, "agent/x")
	m := f.merger(t, &mergeThenFail{Client: f.c})
	res, err := m.Merge(ctx, f.req(n, head))
	if err != nil || !res.Merged || res.MergeCommitSHA == "" || res.ExternalRef == "" {
		t.Fatalf("%+v %v", res, err)
	}
	f.noLeak(t)
}

func TestMergeUnreadableAfterWriteIsUnconfirmed(t *testing.T) {
	f := newFx(t)
	n, head := f.green(t, "agent/x")
	m := f.merger(t, &mergeThenFail{Client: f.c, failReadBack: true})
	res, err := m.Merge(ctx, f.req(n, head))
	if !errors.Is(err, ops.ErrMergeUnconfirmed) || res != nil {
		t.Fatalf("res=%v err=%v", res, err)
	}
	if f.writes() != 1 {
		t.Fatalf("%d merge requests, want 1", f.writes())
	}
	f.noLeak(t)
}

func TestMergeRevokeFailureIsAWarningAfterTheMerge(t *testing.T) {
	f := newFx(t)
	n, head := f.green(t, "agent/x")
	f.s.Inject("DELETE", "/installation/token", ghtest.Unavailable())
	res, err := f.m.Merge(ctx, f.req(n, head))
	if err != nil || !res.Merged {
		t.Fatalf("%+v %v", res, err)
	}
	if res.WriteTokenRevoked || len(res.Warnings) == 0 {
		t.Fatalf("revoked=%v warnings=%v", res.WriteTokenRevoked, res.Warnings)
	}
	for _, w := range res.Warnings {
		if strings.Contains(w, "ghs_") {
			t.Fatalf("warning leaks a token: %s", w)
		}
	}
}

func TestMergeRepoMutex(t *testing.T) {
	f := newFx(t)
	n1, h1 := f.green(t, "agent/one")
	n2, h2 := f.green(t, "agent/two")
	release := make(chan struct{})
	f.s.Before("PUT", "/pulls/1/merge", func() { <-release })

	type out struct {
		res *ops.PRMergeResult
		err error
	}
	first, second := make(chan out, 1), make(chan out, 1)
	go func() { r, err := f.m.Merge(ctx, f.req(n1, h1)); first <- out{r, err} }()
	waitFor(t, func() bool { return f.s.Count("GET", "/compare/") >= 2 }) // merge 1 is parked at its write
	go func() { r, err := f.m.Merge(ctx, f.req(n2, h2)); second <- out{r, err} }()

	time.Sleep(300 * time.Millisecond)
	for _, r := range f.s.Requests() {
		if strings.Contains(r.Path, "/pulls/2") {
			t.Fatalf("second merge started while the first held the repo: %s %s", r.Method, r.Path)
		}
	}
	close(release)
	a := <-first
	if a.err != nil || !a.res.Merged {
		t.Fatalf("first: %+v %v", a.res, a.err)
	}
	// The second ran strictly after the first, so it saw the base the first
	// moved: it is behind and is refused, which is exactly what "one merge at a
	// time" is for.
	b := <-second
	f.refused(t, n2, b.res, b.err)
	wantFailed(t, b.res.Verdict, "base_current")
}

func TestMergeWaitingForTheLockEndsWithTheContext(t *testing.T) {
	f := newFx(t)
	n1, h1 := f.green(t, "agent/one")
	n2, h2 := f.green(t, "agent/two")
	release := make(chan struct{})
	f.s.Before("PUT", "/pulls/1/merge", func() { <-release })
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _, _ = f.m.Merge(ctx, f.req(n1, h1)) }()
	waitFor(t, func() bool { return f.s.Count("GET", "/compare/") >= 2 })

	cctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if _, err := f.m.Merge(cctx, f.req(n2, h2)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	close(release)
	wg.Wait()
}

// A different repository is not blocked by a merge in this one.
func TestMergeMutexIsPerRepo(t *testing.T) {
	f := newFx(t)
	n1, h1 := f.green(t, "agent/one")
	release := make(chan struct{})
	f.s.Before("PUT", "/pulls/1/merge", func() { <-release })
	done := make(chan error, 1)
	go func() { _, err := f.m.Merge(ctx, f.req(n1, h1)); done <- err }()
	waitFor(t, func() bool { return f.s.Count("GET", "/compare/") >= 2 })

	other := gh.Repo{Owner: "example-org", Name: "other"}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	// The request fails validation at GitHub (no such PR), but it must get that
	// far, which it can only do if it was not queued behind the other repo.
	res, err := f.m.Merge(cctx, ops.PRMergeRequest{Repo: other, Number: 1, Base: "main", HeadSHA: strings.Repeat("b", 40),
		Policy: ops.PRPolicy{Base: "main"}})
	if err != nil || res.Verdict.Outcome != ops.PRRefuse {
		t.Fatalf("%+v %v", res, err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestReplay18OctMergeOnStaleCI replays 2026-10-18: a merge watcher merged on
// a green result that belonged to an older head. Every step that used the old
// result must be refused, and only a green verify on the new head merges.
func TestReplay18OctMergeOnStaleCI(t *testing.T) {
	f := newFx(t)
	n, h1 := f.green(t, "agent/x") // CI went green on H1
	h2 := f.r.Commit("agent/x")    // a push lands afterwards: H2 has never run

	// The watcher still holds H1.
	res, err := f.m.Merge(ctx, f.req(n, h1))
	f.refused(t, n, res, err)
	wantFailed(t, res.Verdict, "head_matches_request")
	if res.Verdict.Stop != ops.StopCIStale {
		t.Fatalf("stop = %q", res.Verdict.Stop)
	}

	// It re-reads the PR and names H2, but verify has not run on H2.
	res, err = f.m.Merge(ctx, f.req(n, h2))
	f.refused(t, n, res, err)
	wantFailed(t, res.Verdict, "verify")

	// Only a green verify on H2 merges, and the merge names H2.
	f.r.SetCheck(h2, verify("completed", "success"))
	res, err = f.m.Merge(ctx, f.req(n, h2))
	if err != nil || !res.Merged {
		t.Fatalf("%+v %v", res, err)
	}
	if f.writes() != 1 {
		t.Fatalf("%d merge requests, want 1", f.writes())
	}
	for _, r := range f.s.Requests() {
		if r.Method == "PUT" && strings.HasSuffix(r.Path, "/merge") && !strings.Contains(r.Body, h2) {
			t.Fatalf("the merge did not carry the verified head: %s", r.Body)
		}
	}
}

// Operator decision (24 Oct): of several `verify` runs on the exact head the
// latest wins (highest started_at, then id). An older failed run no longer
// blocks a green re-run.
func TestMergeLatestVerifyRunWins(t *testing.T) {
	t0 := time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)
	at := func(c ghtest.Check, d time.Duration) ghtest.Check { c.StartedAt = t0.Add(d); return c }
	cases := []struct {
		name string
		runs []ghtest.Check
	}{
		{"fail then rerun pass", []ghtest.Check{verify("completed", "failure"), verify("completed", "success")}},
		{"cancelled then rerun pass", []ghtest.Check{verify("completed", "cancelled"), verify("completed", "success")}},
		{"pass then pass", []ghtest.Check{verify("completed", "success"), verify("completed", "success")}},
		{"started_at beats id: the green run started later but has the lower id", []ghtest.Check{
			at(verify("completed", "success"), time.Hour), at(verify("completed", "failure"), 0)}},
		{"same started_at: the higher id wins", []ghtest.Check{
			at(verify("completed", "failure"), 0), at(verify("completed", "success"), 0)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFx(t)
			n, head := f.open(t, "agent/x", "docs: update notes")
			for _, r := range c.runs {
				f.r.SetCheck(head, r)
			}
			res, err := f.m.Merge(ctx, f.req(n, head))
			if err != nil || !res.Merged {
				t.Fatalf("%+v %v", res, err)
			}
		})
	}
	// And the same orders the other way round are refused.
	refused := []struct {
		name string
		runs []ghtest.Check
	}{
		{"started_at beats id: the red run started later", []ghtest.Check{
			at(verify("completed", "failure"), time.Hour), at(verify("completed", "success"), 0)}},
		{"same started_at: the higher id is red", []ghtest.Check{
			at(verify("completed", "success"), 0), at(verify("completed", "failure"), 0)}},
	}
	for _, c := range refused {
		t.Run(c.name, func(t *testing.T) {
			f := newFx(t)
			n, head := f.open(t, "agent/x", "docs: update notes")
			for _, r := range c.runs {
				f.r.SetCheck(head, r)
			}
			res, err := f.m.Merge(ctx, f.req(n, head))
			f.refused(t, n, res, err)
			wantFailed(t, res.Verdict, "verify")
			if f.writes() != 0 {
				t.Fatal("merged")
			}
		})
	}
}
