package gh_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
)

func TestGetPull(t *testing.T) {
	f := newFixture(t)
	n, head := f.pr(t, "agent/g")
	tok := f.all(t)
	p, err := f.c.GetPull(ctx, tok, f.repo, n)
	if err != nil {
		t.Fatal(err)
	}
	if p.Number != n || p.State != "open" || p.Draft || p.Merged || p.Head.SHA != head || p.Head.Ref != "agent/g" ||
		p.Base.Ref != base || p.Base.Repo.FullName != "example-org/storefront" ||
		p.Head.Repo.FullName != "example-org/storefront" || p.Mergeable == nil || !*p.Mergeable || p.MergeableState != "clean" {
		t.Fatalf("%+v", p)
	}
	// behind, conflicted, fork
	f.r.Commit(base)
	if p, _ := f.c.GetPull(ctx, tok, f.repo, n); p.MergeableState != "behind" {
		t.Errorf("state %q", p.MergeableState)
	}
	f.r.SetConflict(n, true)
	if p, _ := f.c.GetPull(ctx, tok, f.repo, n); p.MergeableState != "dirty" || *p.Mergeable {
		t.Errorf("conflict: %+v", p)
	}
	f.r.Branch("agent/fork", base)
	f.r.Commit("agent/fork")
	fn := f.r.OpenPR(ghtest.PROptions{Title: "x", Head: "agent/fork", Base: base, Fork: true})
	if p, _ := f.c.GetPull(ctx, tok, f.repo, fn); p.Head.Repo.FullName == "example-org/storefront" {
		t.Errorf("fork head repo = %q", p.Head.Repo.FullName)
	}
	if _, err := f.c.GetPull(ctx, tok, f.repo, 404); !errors.Is(err, gh.ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
}

func TestListPullFilesPaginates(t *testing.T) {
	f := newFixture(t)
	n, _ := f.pr(t, "agent/files")
	var files []ghtest.File
	for i := range 250 {
		files = append(files, ghtest.File{Filename: fmt.Sprintf("docs/f%03d.md", i), Additions: 1})
	}
	files = append(files, ghtest.File{Filename: "new.go", Status: "renamed", PreviousFilename: ".github/workflows/ci.yml"})
	f.r.SetFiles(n, files...)
	got, err := f.c.ListPullFiles(ctx, f.all(t), f.repo, n)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 251 || got[0].Filename != "docs/f000.md" || got[250].PreviousFilename != ".github/workflows/ci.yml" || got[250].Status != "renamed" {
		t.Fatalf("got %d files, last %+v", len(got), got[len(got)-1])
	}
	if c := f.s.Count("GET", "/files"); c != 3 {
		t.Fatalf("%d requests, want 3 pages", c)
	}
}

func TestListPullFilesTruncatedAtCap(t *testing.T) {
	f := newFixture(t)
	n, _ := f.pr(t, "agent/huge")
	files := make([]ghtest.File, 3000)
	for i := range files {
		files[i].Filename = fmt.Sprintf("f%d", i)
	}
	f.r.SetFiles(n, files...)
	if _, err := f.c.ListPullFiles(ctx, f.all(t), f.repo, n); !errors.Is(err, gh.ErrListTruncated) {
		t.Fatalf("3000 files: %v", err)
	}
	// 2999 is complete
	f.r.SetFiles(n, files[:2999]...)
	if got, err := f.c.ListPullFiles(ctx, f.all(t), f.repo, n); err != nil || len(got) != 2999 {
		t.Fatalf("2999 files: %d %v", len(got), err)
	}
}

func TestListCheckRuns(t *testing.T) {
	f := newFixture(t)
	_, head := f.pr(t, "agent/c")
	tok := f.all(t)
	f.r.SetCheck(head, verify("completed", "failure"))
	f.r.SetCheck(head, verify("completed", "success")) // a rerun
	f.r.SetCheck(head, ghtest.Check{Name: "verify", AppID: 999, Status: "completed", Conclusion: "success"})
	f.r.SetCheck(head, ghtest.Check{Name: "lint", AppID: gh.GitHubActionsAppID, Status: "in_progress"})

	q := gh.CheckRunQuery{CheckName: "verify", AppID: gh.GitHubActionsAppID}
	runs, err := f.c.ListCheckRuns(ctx, tok, f.repo, head, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].Conclusion != "success" || runs[0].Status != "completed" ||
		runs[0].AppID != gh.GitHubActionsAppID || runs[0].HeadSHA != head || runs[0].Name != "verify" {
		t.Fatalf("latest of verify from Actions: %+v", runs)
	}
	// the query parameters GitHub needs for exactly that were sent
	last := f.s.Requests()[len(f.s.Requests())-1]
	v, _ := url.ParseQuery(last.Query)
	if v.Get("check_name") != "verify" || v.Get("app_id") != "15368" || v.Get("filter") != "latest" {
		t.Fatalf("query = %s", last.Query)
	}
	q.All = true
	if runs, _ = f.c.ListCheckRuns(ctx, tok, f.repo, head, q); len(runs) != 2 {
		t.Fatalf("all runs of verify from Actions: %+v", runs)
	}
	if runs, _ = f.c.ListCheckRuns(ctx, tok, f.repo, head, gh.CheckRunQuery{}); len(runs) != 3 {
		t.Fatalf("latest of every name and app: %+v", runs)
	}
	// a commit without runs, an unknown commit, a short SHA
	_, other := f.pr(t, "agent/c2")
	if runs, err = f.c.ListCheckRuns(ctx, tok, f.repo, other, q); err != nil || len(runs) != 0 {
		t.Fatalf("no runs: %+v %v", runs, err)
	}
	if _, err = f.c.ListCheckRuns(ctx, tok, f.repo, strings.Repeat("a", 40), q); !errors.Is(err, gh.ErrUnprocessable) {
		t.Fatalf("unknown sha: %v", err)
	}
	if _, err = f.c.ListCheckRuns(ctx, tok, f.repo, head[:8], q); !errors.Is(err, gh.ErrInvalidArgument) {
		t.Fatalf("short sha: %v", err)
	}
	// a token without checks:read
	noChecks := f.mint(t, gh.PermsFetch())
	if _, err = f.c.ListCheckRuns(ctx, noChecks, f.repo, head, q); !errors.Is(err, gh.ErrForbidden) {
		t.Fatalf("no checks permission: %v", err)
	}
}

func TestListCheckRunsIncompleteIsAnError(t *testing.T) {
	f := newFixture(t)
	_, head := f.pr(t, "agent/many")
	for i := range 150 {
		f.r.SetCheck(head, ghtest.Check{Name: fmt.Sprintf("job-%d", i), AppID: gh.GitHubActionsAppID, Status: "completed", Conclusion: "success"})
	}
	if _, err := f.c.ListCheckRuns(ctx, f.all(t), f.repo, head, gh.CheckRunQuery{}); !errors.Is(err, gh.ErrListTruncated) {
		t.Fatalf("150 runs on a 100-run page: %v", err)
	}
}

func TestCompare(t *testing.T) {
	f := newFixture(t)
	_, head := f.pr(t, "agent/cmp")
	tok := f.all(t)
	c, err := f.c.Compare(ctx, tok, f.repo, base, head)
	if err != nil || c.Status != "ahead" || c.AheadBy != 1 || c.BehindBy != 0 || c.TotalCommits != 1 || c.BaseSHA != f.r.Head(base) || c.MergeBaseSHA != f.r.Head(base) {
		t.Fatalf("%+v %v", c, err)
	}
	f.r.Commit(base)
	if c, err = f.c.Compare(ctx, tok, f.repo, base, head); err != nil || c.Status != "diverged" || c.BehindBy != 1 || c.AheadBy != 1 {
		t.Fatalf("behind: %+v %v", c, err)
	}
	if c, err = f.c.Compare(ctx, tok, f.repo, base, base); err != nil || c.Status != "identical" {
		t.Fatalf("identical: %+v %v", c, err)
	}
	if _, err = f.c.Compare(ctx, tok, f.repo, base, strings.Repeat("b", 40)); !errors.Is(err, gh.ErrNotFound) {
		t.Fatalf("unknown head: %v", err)
	}
	for _, bad := range []string{"", "a..b", "a b", "a?b", "a%2Fb", "x:y", "-x", "a/", "a\\b", "a\x00b"} {
		if _, err = f.c.Compare(ctx, tok, f.repo, bad, head); !errors.Is(err, gh.ErrInvalidArgument) {
			t.Errorf("base %q: %v", bad, err)
		}
	}
}

func TestCreatePull(t *testing.T) {
	f := newFixture(t)
	f.r.Branch("agent/new", base)
	f.r.Commit("agent/new")
	tok := f.all(t)
	p, err := f.c.CreatePull(ctx, tok, f.repo, gh.NewPull{Title: "feat: new", Head: "agent/new", Base: base, Body: "why", Draft: true})
	if err != nil {
		t.Fatal(err)
	}
	if p.Number != 1 || p.Head.Ref != "agent/new" || p.Base.Ref != base || !p.Draft || p.State != "open" {
		t.Fatalf("%+v", p)
	}
	// refusals
	if _, err = f.c.CreatePull(ctx, tok, f.repo, gh.NewPull{Title: "dup", Head: "agent/new", Base: base}); !errors.Is(err, gh.ErrUnprocessable) {
		t.Errorf("duplicate: %v", err)
	}
	if _, err = f.c.CreatePull(ctx, tok, f.repo, gh.NewPull{Title: "x", Head: "agent/missing", Base: base}); !errors.Is(err, gh.ErrUnprocessable) {
		t.Errorf("missing head: %v", err)
	}
	if _, err = f.c.CreatePull(ctx, tok, f.repo, gh.NewPull{Title: "x", Head: "agent/new", Base: "nope"}); !errors.Is(err, gh.ErrUnprocessable) {
		t.Errorf("missing base: %v", err)
	}
	f.r.Branch("agent/empty", base)
	if _, err = f.c.CreatePull(ctx, tok, f.repo, gh.NewPull{Title: "x", Head: "agent/empty", Base: base}); !errors.Is(err, gh.ErrUnprocessable) {
		t.Errorf("no commits: %v", err)
	}
	// client side: forks, blank title
	n := f.s.Count("POST", "/pulls")
	if _, err = f.c.CreatePull(ctx, tok, f.repo, gh.NewPull{Title: "x", Head: "someone:agent/new", Base: base}); !errors.Is(err, gh.ErrInvalidArgument) {
		t.Errorf("fork head: %v", err)
	}
	if _, err = f.c.CreatePull(ctx, tok, f.repo, gh.NewPull{Title: " ", Head: "agent/new", Base: base}); !errors.Is(err, gh.ErrInvalidArgument) {
		t.Errorf("blank title: %v", err)
	}
	if f.s.Count("POST", "/pulls") != n {
		t.Error("an invalid create was sent")
	}
	// a token without pull_requests:write
	if _, err = f.c.CreatePull(ctx, f.mint(t, gh.PermsFetch()), f.repo, gh.NewPull{Title: "x", Head: "agent/new", Base: base}); !errors.Is(err, gh.ErrForbidden) {
		t.Errorf("read-only: %v", err)
	}
}

func TestUpdatePullBranch(t *testing.T) {
	f := newFixture(t)
	n, head := f.pr(t, "agent/up")
	tok := f.mint(t, gh.PermsMerge())

	if _, err := f.c.UpdatePullBranch(ctx, tok, f.repo, n, head); !errors.Is(err, gh.ErrUnprocessable) {
		t.Fatalf("up to date: %v", err) // GitHub: no new commits on base
	}
	f.r.Commit(base)
	// the head moves under the caller: 422, no update
	stale := f.r.Commit("agent/up")
	if _, err := f.c.UpdatePullBranch(ctx, tok, f.repo, n, head); !errors.Is(err, gh.ErrUnprocessable) {
		t.Fatalf("expected_head_sha is stale: %v", err)
	}
	if f.r.PRHead(n) != stale {
		t.Fatal("head changed despite the 422")
	}
	f.r.SetConflict(n, true)
	if _, err := f.c.UpdatePullBranch(ctx, tok, f.repo, n, stale); !errors.Is(err, gh.ErrUnprocessable) {
		t.Fatalf("conflict: %v", err)
	}
	f.r.SetConflict(n, false)
	msg, err := f.c.UpdatePullBranch(ctx, tok, f.repo, n, stale)
	if err != nil || msg == "" {
		t.Fatalf("%q %v", msg, err)
	}
	if f.r.PRHead(n) == stale {
		t.Fatal("head did not move")
	}
	if c, _ := f.c.Compare(ctx, f.all(t), f.repo, base, f.r.PRHead(n)); c.BehindBy != 0 {
		t.Fatalf("still behind: %+v", c)
	}
	// expected_head_sha is required
	if _, err := f.c.UpdatePullBranch(ctx, tok, f.repo, n, ""); !errors.Is(err, gh.ErrInvalidArgument) {
		t.Fatalf("no sha: %v", err)
	}
}

func TestDeployments(t *testing.T) {
	f := newFixture(t)
	_, head := f.pr(t, "agent/dep")
	tok := f.mint(t, gh.PermsDeploy())
	d, err := f.c.CreateDeployment(ctx, tok, f.repo, gh.DeploymentRequest{Ref: head, Environment: "pilot", Description: "deploy " + head[:8]})
	if err != nil {
		t.Fatal(err)
	}
	if d.ID == 0 || d.SHA != head || d.Environment != "pilot" {
		t.Fatalf("%+v", d)
	}
	var body struct {
		AutoMerge        bool      `json:"auto_merge"`
		RequiredContexts *[]string `json:"required_contexts"`
	}
	for _, r := range f.s.Requests() {
		if strings.HasSuffix(r.Path, "/deployments") {
			_ = json.Unmarshal([]byte(r.Body), &body)
		}
	}
	if body.AutoMerge || body.RequiredContexts == nil || len(*body.RequiredContexts) != 0 {
		t.Fatalf("deployment body must send auto_merge=false and required_contexts=[]: %s", f.s.Requests()[len(f.s.Requests())-1].Body)
	}
	for _, st := range []string{gh.DeployInProgress, gh.DeploySuccess} {
		if _, err := f.c.CreateDeploymentStatus(ctx, tok, f.repo, d.ID, gh.DeploymentStatusRequest{State: st, LogURL: "https://example.test/log"}); err != nil {
			t.Fatalf("%s: %v", st, err)
		}
	}
	rec := f.r.Deployments()
	if len(rec) != 1 || len(rec[0].Statuses) != 2 || rec[0].Statuses[1] != "success" {
		t.Fatalf("%+v", rec)
	}
	// refusals
	f.r.SetCheck(head, verify("completed", "failure"))
	if _, err := f.c.CreateDeployment(ctx, tok, f.repo, gh.DeploymentRequest{Ref: head, Environment: "pilot"}); err != nil {
		t.Fatalf("a record of a deploy is not gated on checks: %v", err)
	}
	if _, err := f.c.CreateDeployment(ctx, tok, f.repo, gh.DeploymentRequest{Ref: strings.Repeat("c", 40), Environment: "pilot"}); !errors.Is(err, gh.ErrUnprocessable) {
		t.Errorf("unknown ref: %v", err)
	}
	if _, err := f.c.CreateDeploymentStatus(ctx, tok, f.repo, 12345, gh.DeploymentStatusRequest{State: gh.DeploySuccess}); !errors.Is(err, gh.ErrNotFound) {
		t.Errorf("unknown deployment: %v", err)
	}
	if _, err := f.c.CreateDeploymentStatus(ctx, tok, f.repo, d.ID, gh.DeploymentStatusRequest{State: "done"}); !errors.Is(err, gh.ErrInvalidArgument) {
		t.Errorf("bad state: %v", err)
	}
	if _, err := f.c.CreateDeployment(ctx, tok, f.repo, gh.DeploymentRequest{Ref: head}); !errors.Is(err, gh.ErrInvalidArgument) {
		t.Errorf("no environment: %v", err)
	}
	if _, err := f.c.CreateDeployment(ctx, f.mint(t, gh.PermsEvaluateMerge()), f.repo, gh.DeploymentRequest{Ref: head, Environment: "pilot"}); !errors.Is(err, gh.ErrForbidden) {
		t.Errorf("no deployments permission: %v", err)
	}
}
