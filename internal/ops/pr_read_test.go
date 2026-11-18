package ops_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/spec"
)

// The pr read ops against the fake GitHub (ghtest): what each one returns, what
// it asks GitHub for, and every way a request is refused or a read fails.

type readFx struct {
	s    *ghtest.Server
	c    *gh.Client
	r    *ghtest.Repo
	repo string
}

// newReadFx is a fake GitHub whose App holds MORE than the read ops need, so
// a test can see that the op still asks for read only.
func newReadFx(t *testing.T, granted map[string]string) *readFx {
	t.Helper()
	s := ghtest.New(t)
	c, err := gh.New(gh.Config{AppID: s.AppID(), Keys: gh.StaticKey{Key: s.Key()}, BaseURL: s.URL(), Now: s.Now})
	if err != nil {
		t.Fatal(err)
	}
	if granted == nil {
		granted = map[string]string{"pull_requests": "write", "checks": "write", "contents": "write", "issues": "write", "metadata": "read"}
	}
	in := s.AddInstallation(31, "example-org", granted)
	f := &readFx{s: s, c: c, r: in.AddRepo("storefront", "main"), repo: "example-org/storefront"}
	in.AddRepo("other", "main")
	return f
}

func (f *readFx) adapter(t *testing.T, op string) *ops.PRReadAdapter {
	t.Helper()
	a, err := ops.NewPRReadAdapter(op, ops.PRReadConfig{
		GitHub: f.c, Tokens: &ops.InstallationMinter{Client: f.c},
		Project: func(p string) (ops.PRProject, bool) {
			if p == "storefront" {
				return ops.PRProject{Repo: f.repo, Base: "main"}, true
			}
			return ops.PRProject{}, false
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func readerCaller() *ops.Caller {
	return &ops.Caller{Kind: ops.KindOrchestrator, OrchID: "main", Projects: []string{"storefront"}, ScopeOps: ops.PRReadOps}
}

func (f *readFx) req(op string, n int, params map[string]any) *ops.Request {
	return &ops.Request{Op: op, Project: "storefront", Caller: readerCaller(), ExecutionID: "x-1",
		Target: spec.Target{Adapter: "github", Ref: fmt.Sprintf("%s#%d", f.repo, n)}, Params: params}
}

// pr opens a PR from a new branch with one commit.
func (f *readFx) pr(branch string, o ghtest.PROptions) (int, string) {
	f.r.Branch(branch, "main")
	head := f.r.Commit(branch)
	o.Head, o.Base = branch, "main"
	if o.Title == "" {
		o.Title = "feat: " + branch
	}
	return f.r.OpenPR(o), head
}

func (f *readFx) run(t *testing.T, op string, n int, params map[string]any) ops.Outcome {
	t.Helper()
	a := f.adapter(t, op)
	req := f.req(op, n, params)
	if _, err := a.Check(context.Background(), req); err != nil {
		t.Fatalf("%s check: %v", op, err)
	}
	out, err := a.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("%s execute returned an error (it must report a failed outcome instead): %v", op, err)
	}
	return out
}

func mustSucceed(t *testing.T, out ops.Outcome) map[string]any {
	t.Helper()
	if out.Failed || out.Unconfirmed || out.Result == nil {
		t.Fatalf("outcome: %+v", out)
	}
	return out.Result
}

func mustFail(t *testing.T, out ops.Outcome, want string) map[string]any {
	t.Helper()
	msg, _ := out.Result["error"].(string)
	if !out.Failed || out.Unconfirmed || !strings.Contains(msg, want) {
		t.Fatalf("want a failed outcome saying %q, got %+v", want, out)
	}
	return out.Result
}

// onlyReads checks that nothing but GETs (and the token calls) reached GitHub, and that the tokens asked for the
// permissions in want and nothing else.
func (f *readFx) onlyReads(t *testing.T, want ...string) {
	t.Helper()
	var tokens int
	for _, r := range f.s.Requests() {
		switch {
		case r.Method == "GET":
		case r.Method == "POST" && strings.Contains(r.Path, "access_tokens"):
			tokens++
			for _, w := range want {
				if !strings.Contains(r.Body, w) {
					t.Errorf("token request lacks %s: %s", w, r.Body)
				}
			}
			for _, bad := range []string{"write", "admin", "contents", "issues", "deployments"} {
				if strings.Contains(r.Body, bad) {
					t.Errorf("token request holds %q: %s", bad, r.Body)
				}
			}
		case r.Method == "DELETE" && strings.Contains(r.Path, "installation/token"):
		default:
			t.Errorf("a read op sent %s %s", r.Method, r.Path)
		}
	}
	if tokens == 0 {
		t.Error("no token was minted")
	}
	if n := f.s.LiveTokens(); n != 0 {
		t.Errorf("%d tokens still live", n)
	}
}

func TestPRViewReadsThePullRequest(t *testing.T) {
	f := newReadFx(t, nil)
	n, head := f.pr("agent/v", ghtest.PROptions{Body: "Why: the cart total was wrong.\n\nFixes the rounding.", Author: "octo", Labels: []string{"bug", "ci"}})
	f.r.SetFiles(n, ghtest.File{Filename: "a.go", Additions: 3, Deletions: 1}, ghtest.File{Filename: "b.go", Additions: 2})
	a := f.adapter(t, ops.OpPRView)
	req := f.req(ops.OpPRView, n, map[string]any{})

	res, err := a.Check(context.Background(), req)
	if err != nil || len(res.Checks) == 0 || res.NeedsApproval {
		t.Fatalf("check: %+v %v", res, err)
	}
	if len(f.s.Requests()) != 0 {
		t.Fatalf("Check reached GitHub: %v", f.s.Requests())
	}
	out, err := a.Execute(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	r := mustSucceed(t, out)
	if !strings.Contains(out.ExternalRef, "/pull/1") {
		t.Errorf("external ref %q", out.ExternalRef)
	}
	hd, bs := r["head"].(map[string]any), r["base"].(map[string]any)
	main := f.r.Head("main")
	want := map[string]any{
		"number": 1, "title": "feat: agent/v", "state": "open", "draft": false, "merged": false, "author": "octo",
		"body": "Why: the cart total was wrong.\n\nFixes the rounding.", "body_truncated": false,
		"mergeable": true, "mergeable_state": "clean", "commits": 1, "additions": 5, "deletions": 1, "changed_files": 2,
	}
	for k, v := range want {
		if r[k] != v {
			t.Errorf("%s = %v (%T), want %v", k, r[k], r[k], v)
		}
	}
	if ls := r["labels"].([]string); len(ls) != 2 || ls[0] != "bug" || ls[1] != "ci" {
		t.Errorf("labels %v", r["labels"])
	}
	if hd["ref"] != "agent/v" || hd["sha"] != head || hd["repo"] != f.repo || hd["fork"] != false || bs["ref"] != "main" || bs["sha"] != main {
		t.Errorf("head %v base %v", hd, bs)
	}
	f.onlyReads(t, `"pull_requests":"read"`, `"metadata":"read"`)
	if strings.Contains(fmt.Sprint(f.s.Requests()), "check-runs") {
		t.Error("pr.view read the check runs")
	}
}

func TestPRViewEdgeCases(t *testing.T) {
	f := newReadFx(t, nil)
	// Not computed yet, a draft, a fork, no author.
	n, _ := f.pr("agent/fork", ghtest.PROptions{Draft: true, Fork: true})
	f.r.SetMergeableUnknown(n, true)
	r := mustSucceed(t, f.run(t, ops.OpPRView, n, map[string]any{}))
	if v, ok := r["mergeable"]; !ok || v != nil || r["mergeable_state"] != "unknown" {
		t.Errorf("mergeable while GitHub computes it: %v %v", v, r["mergeable_state"])
	}
	if r["draft"] != true || r["author"] != "" || r["head"].(map[string]any)["fork"] != true {
		t.Errorf("%v", r)
	}
	// A conflict.
	m, _ := f.pr("agent/conflict", ghtest.PROptions{})
	f.r.SetConflict(m, true)
	r = mustSucceed(t, f.run(t, ops.OpPRView, m, map[string]any{}))
	if r["mergeable"] != false || r["mergeable_state"] != "dirty" {
		t.Errorf("conflict: %v %v", r["mergeable"], r["mergeable_state"])
	}
	// A body past the cap is cut on a character boundary and says so.
	long := strings.Repeat("é", ops.PRBodyMax) // 2 bytes each: twice the cap
	k, _ := f.pr("agent/long", ghtest.PROptions{Body: long})
	r = mustSucceed(t, f.run(t, ops.OpPRView, k, map[string]any{}))
	body := r["body"].(string)
	if r["body_truncated"] != true || len(body) > ops.PRBodyMax || len(body) < ops.PRBodyMax-2 || !utf8.ValidString(body) {
		t.Errorf("body: truncated=%v, %d bytes", r["body_truncated"], len(body))
	}
}

func TestPRDiff(t *testing.T) {
	f := newReadFx(t, nil)
	n, head := f.pr("agent/d", ghtest.PROptions{})
	f.r.SetFiles(n,
		ghtest.File{Filename: "a.go", Patch: "@@ -1 +1 @@\n-old\n+new"},
		ghtest.File{Filename: "img.png"})
	r := mustSucceed(t, f.run(t, ops.OpPRDiff, n, map[string]any{}))
	diff := r["diff"].(string)
	if !strings.HasPrefix(diff, "diff --git a/a.go b/a.go\n") || !strings.Contains(diff, "-old\n+new\n") ||
		!strings.Contains(diff, "Binary files a/img.png and b/img.png differ") {
		t.Errorf("diff:\n%s", diff)
	}
	if r["head_sha"] != head || r["base_ref"] != "main" || r["truncated"] != false || r["size"] != len(diff) || r["returned"] != len(diff) || r["cap"] != ops.PRDiffMax {
		t.Errorf("%v", r)
	}
	f.onlyReads(t, `"pull_requests":"read"`, `"metadata":"read"`)
}

func TestPRDiffIsCappedAtALineEnd(t *testing.T) {
	f := newReadFx(t, nil)
	n, _ := f.pr("agent/big", ghtest.PROptions{})
	line := "+" + strings.Repeat("ü", 49) + "\n" // 100 bytes
	patch := "@@ -0,0 +1,10000 @@\n" + strings.Repeat(line, 10000)
	f.r.SetFiles(n, ghtest.File{Filename: "big.txt", Patch: patch})
	r := mustSucceed(t, f.run(t, ops.OpPRDiff, n, map[string]any{}))
	diff := r["diff"].(string)
	if r["truncated"] != true || len(diff) > ops.PRDiffMax || len(diff) < ops.PRDiffMax-200 || r["returned"] != len(diff) {
		t.Fatalf("truncated=%v returned=%v, %d bytes (cap %d)", r["truncated"], r["returned"], len(diff), ops.PRDiffMax)
	}
	if size := r["size"].(int); size < 1_000_000 {
		t.Errorf("size %d is not the whole diff", size)
	}
	if !strings.HasSuffix(diff, "\n") || !utf8.ValidString(diff) || strings.Count(diff, "ü")%49 != 0 {
		t.Errorf("the cut is not at a line end: ...%q", diff[len(diff)-30:])
	}
}

func TestPRDiffExpectedHead(t *testing.T) {
	f := newReadFx(t, nil)
	n, head := f.pr("agent/e", ghtest.PROptions{})
	f.r.SetFiles(n, ghtest.File{Filename: "a.go", Patch: "@@ -1 +1 @@\n-a\n+b"})
	mustSucceed(t, f.run(t, ops.OpPRDiff, n, map[string]any{"expected_head_sha": head}))

	moved := f.r.Commit("agent/e")
	out := f.run(t, ops.OpPRDiff, n, map[string]any{"expected_head_sha": head})
	res := mustFail(t, out, "is not "+head[:12])
	if res["head_sha"] != moved {
		t.Errorf("the failure must name the new head: %v", res)
	}
	if c := f.s.Count("GET", "/pulls/1"); c != 3 { // the read that passed (pull request and diff) and the one that stopped at the head check
		t.Errorf("%d reads of the pull request, want 3", c)
	}
	mustSucceed(t, f.run(t, ops.OpPRDiff, n, map[string]any{"expected_head_sha": moved}))
}

func TestPRChecks(t *testing.T) {
	f := newReadFx(t, nil)
	n, head := f.pr("agent/c", ghtest.PROptions{})
	f.r.SetCheck(head, ghtest.Check{Name: "verify", AppID: gh.GitHubActionsAppID, Status: "completed", Conclusion: "failure"})
	f.r.SetCheck(head, ghtest.Check{Name: "verify", AppID: gh.GitHubActionsAppID, Status: "completed", Conclusion: "success"}) // a rerun
	f.r.SetCheck(head, ghtest.Check{Name: "lint", AppID: gh.GitHubActionsAppID, Status: "in_progress"})
	f.r.SetCheck(head, ghtest.Check{Name: "e2e", AppID: gh.GitHubActionsAppID, Status: "completed", Conclusion: "timed_out"})
	f.r.SetCheck(head, ghtest.Check{Name: "docs", AppID: gh.GitHubActionsAppID, Status: "completed", Conclusion: "skipped"})
	f.r.SetCheck(head, ghtest.Check{Name: "local-ci", AppID: ghtest.OwnAppID, Status: "completed", Conclusion: "action_required"})
	f.r.SetCheck(head, ghtest.Check{Name: "odd", AppID: 7, Status: "completed", Conclusion: "mystery"})
	r := mustSucceed(t, f.run(t, ops.OpPRChecks, n, map[string]any{}))
	if r["head_sha"] != head || r["number"] != 1 {
		t.Errorf("%v", r)
	}
	sum := r["summary"].(map[string]any)
	if sum["total"] != 6 || sum["passed"] != 2 || sum["failed"] != 2 || sum["pending"] != 1 || sum["other"] != 1 {
		t.Errorf("summary %v", sum)
	}
	var names []string
	byName := map[string]map[string]any{}
	for _, x := range r["runs"].([]any) {
		m := x.(map[string]any)
		names = append(names, m["name"].(string))
		byName[m["name"].(string)] = m
	}
	// verify's rerun replaces the failed run: the latest run of a name counts. Sorted by name.
	if strings.Join(names, ",") != "docs,e2e,lint,local-ci,odd,verify" {
		t.Errorf("names %v", names)
	}
	if v := byName["verify"]; v["conclusion"] != "success" || v["status"] != "completed" || v["app_id"] != int64(gh.GitHubActionsAppID) || v["started_at"] == nil {
		t.Errorf("verify %v", v)
	}
	if v := byName["lint"]; v["conclusion"] != "" || v["status"] != "in_progress" {
		t.Errorf("lint %v", v)
	}
	f.onlyReads(t, `"pull_requests":"read"`, `"checks":"read"`, `"metadata":"read"`)
}

func TestPRChecksNoRunsAndMovedHead(t *testing.T) {
	f := newReadFx(t, nil)
	n, head := f.pr("agent/none", ghtest.PROptions{})
	r := mustSucceed(t, f.run(t, ops.OpPRChecks, n, map[string]any{}))
	if len(r["runs"].([]any)) != 0 || r["summary"].(map[string]any)["total"] != 0 {
		t.Errorf("no runs: %v", r)
	}
	moved := f.r.Commit("agent/none")
	mustFail(t, f.run(t, ops.OpPRChecks, n, map[string]any{"expected_head_sha": head}), "is not "+head[:12])
	r = mustSucceed(t, f.run(t, ops.OpPRChecks, n, map[string]any{"expected_head_sha": moved}))
	if r["head_sha"] != moved {
		t.Errorf("checks are of the current head: %v", r)
	}
}

func TestPRFilesPages(t *testing.T) {
	f := newReadFx(t, nil)
	n, head := f.pr("agent/p", ghtest.PROptions{})
	var files []ghtest.File
	for i := range 45 {
		files = append(files, ghtest.File{Filename: fmt.Sprintf("src/f%02d.go", i), Additions: i, Patch: "@@ -1 +1 @@\n-a\n+b"})
	}
	files[44] = ghtest.File{Filename: "src/new.go", Status: "renamed", PreviousFilename: "src/old.go"} // no patch: binary or too big
	f.r.SetFiles(n, files...)

	page := func(params map[string]any) map[string]any {
		return mustSucceed(t, f.run(t, ops.OpPRFiles, n, params))
	}
	r := page(map[string]any{})
	if r["page"] != 1 || r["per_page"] != ops.PRFilesPerPage || r["count"] != 30 || r["total"] != 45 || r["has_more"] != true || r["head_sha"] != head {
		t.Errorf("default page: %v", r)
	}
	if fl := r["files"].([]any); fl[0].(map[string]any)["filename"] != "src/f00.go" || fl[0].(map[string]any)["has_patch"] != true {
		t.Errorf("first file %v", fl[0])
	}
	r = page(map[string]any{"page": 3.0, "per_page": 20.0}) // JSON numbers are float64
	if r["count"] != 5 || r["has_more"] != false || r["total"] != 45 {
		t.Errorf("page 3 of 20: %v", r)
	}
	last := r["files"].([]any)[4].(map[string]any)
	if last["filename"] != "src/new.go" || last["previous_filename"] != "src/old.go" || last["status"] != "renamed" || last["has_patch"] != false {
		t.Errorf("renamed file %v", last)
	}
	if _, ok := r["files"].([]any)[0].(map[string]any)["patch"]; ok {
		t.Error("pr.files returns patches: pr.diff is the op for them")
	}
	r = page(map[string]any{"page": 2.0, "per_page": 20.0})
	if r["count"] != 20 || r["has_more"] != true {
		t.Errorf("page 2 of 20: %v", r)
	}
	if r = page(map[string]any{"page": 9.0}); r["count"] != 0 || r["has_more"] != false || len(r["files"].([]any)) != 0 {
		t.Errorf("a page past the end: %v", r)
	}
	f.onlyReads(t, `"pull_requests":"read"`, `"metadata":"read"`)
}

func TestPRFilesPastGitHubsCap(t *testing.T) {
	f := newReadFx(t, nil)
	n, _ := f.pr("agent/huge", ghtest.PROptions{})
	a := f.adapter(t, ops.OpPRFiles)
	for name, params := range map[string]map[string]any{
		"page 31 of 100":  {"page": 31.0, "per_page": 100.0},
		"page 101 of 30":  {"page": 101.0},
		"per_page 101":    {"per_page": 101.0},
		"page 0":          {"page": 0.0},
		"negative":        {"per_page": -5.0},
		"fraction":        {"page": 1.5},
		"text":            {"page": "2"},
		"bool":            {"per_page": true},
		"unknown param":   {"patch": true},
		"head not a sha":  {"expected_head_sha": "main"},
		"head upper case": {"expected_head_sha": strings.Repeat("A", 40)},
		"head short":      {"expected_head_sha": "0588aa4"},
		"head not text":   {"expected_head_sha": 5.0},
	} {
		_, err := a.Check(context.Background(), f.req(ops.OpPRFiles, n, params))
		if code := refusalCode(t, err); code != ops.CodeParamsInvalid {
			t.Errorf("%s: %s", name, code)
		}
	}
	if _, err := a.Check(context.Background(), f.req(ops.OpPRFiles, n, map[string]any{"page": 30.0, "per_page": 100.0})); err != nil {
		t.Errorf("the last page GitHub lists: %v", err)
	}
	if len(f.s.Requests()) != 0 {
		t.Errorf("a refused request reached GitHub: %v", f.s.Requests())
	}
}

func TestPRReadRefusals(t *testing.T) {
	f := newReadFx(t, nil)
	n, _ := f.pr("agent/r", ghtest.PROptions{})
	run := &ops.Caller{Kind: ops.KindRun, RunID: "r-7f3a", Project: "storefront", Repo: f.repo}
	for _, op := range ops.PRReadOps {
		a := f.adapter(t, op)
		for name, tc := range map[string]struct {
			mut  func(*ops.Request)
			code string
		}{
			"a run":            {func(r *ops.Request) { r.Caller = run }, ops.CodePolicyRefused},
			"no caller":        {func(r *ops.Request) { r.Caller = nil }, ops.CodePolicyRefused},
			"other repo":       {func(r *ops.Request) { r.Target.Ref = fmt.Sprintf("example-org/other#%d", n) }, ops.CodeScopePath},
			"other owner":      {func(r *ops.Request) { r.Target.Ref = fmt.Sprintf("evil/storefront#%d", n) }, ops.CodeScopePath},
			"no pr number":     {func(r *ops.Request) { r.Target.Ref = f.repo }, ops.CodeParamsInvalid},
			"zero":             {func(r *ops.Request) { r.Target.Ref = f.repo + "#0" }, ops.CodeParamsInvalid},
			"leading zero":     {func(r *ops.Request) { r.Target.Ref = f.repo + "#01" }, ops.CodeParamsInvalid},
			"not a number":     {func(r *ops.Request) { r.Target.Ref = f.repo + "#x" }, ops.CodeParamsInvalid},
			"not a repo":       {func(r *ops.Request) { r.Target.Ref = "storefront#1" }, ops.CodeParamsInvalid},
			"bad adapter":      {func(r *ops.Request) { r.Target.Adapter = "pilot" }, ops.CodeParamsInvalid},
			"project no block": {func(r *ops.Request) { r.Project = "acme-shop" }, ops.CodePolicyRefused},
			"unknown param":    {func(r *ops.Request) { r.Params = map[string]any{"token": "x"} }, ops.CodeParamsInvalid},
		} {
			req := f.req(op, n, map[string]any{})
			tc.mut(req)
			if _, err := a.Check(context.Background(), req); err == nil || refusalCode(t, err) != tc.code {
				t.Errorf("%s check %s: %v, want %s", op, name, err, tc.code)
			}
			// Execute re-validates: a request that reaches it without Check is still refused, and sends nothing.
			out, err := a.Execute(context.Background(), req)
			if err != nil || !out.Failed || out.Unconfirmed {
				t.Errorf("%s execute %s: %+v %v", op, name, out, err)
			}
		}
	}
	if len(f.s.Requests()) != 0 {
		t.Errorf("a refused request reached GitHub: %v", f.s.Requests())
	}
	// The repository of the project may be written in any case.
	req := f.req(ops.OpPRView, n, map[string]any{})
	req.Target.Ref = strings.ToUpper(f.repo[:1]) + f.repo[1:] + "#1"
	if _, err := f.adapter(t, ops.OpPRView).Check(context.Background(), req); err != nil {
		t.Errorf("repository in another case: %v", err)
	}
}

func TestPRReadFailures(t *testing.T) {
	t.Run("pull request that does not exist", func(t *testing.T) {
		f := newReadFx(t, nil)
		for _, op := range ops.PRReadOps {
			mustFail(t, f.run(t, op, 99, map[string]any{}), "pull request #99 does not exist in example-org/storefront")
		}
		if n := f.s.LiveTokens(); n != 0 {
			t.Errorf("%d tokens still live", n)
		}
	})
	t.Run("the App lacks the permission", func(t *testing.T) {
		f := newReadFx(t, map[string]string{"issues": "write", "metadata": "read"})
		n, _ := f.pr("agent/x", ghtest.PROptions{})
		mustFail(t, f.run(t, ops.OpPRView, n, map[string]any{}), "Pull requests permission")
		if strings.Contains(fmt.Sprint(f.s.Requests()), "/pulls/") {
			t.Error("a read happened without a token")
		}
	})
	t.Run("pr.checks needs checks:read, the others do not", func(t *testing.T) {
		f := newReadFx(t, map[string]string{"pull_requests": "read", "metadata": "read"})
		n, head := f.pr("agent/x", ghtest.PROptions{})
		f.r.SetCheck(head, ghtest.Check{Name: "verify", AppID: gh.GitHubActionsAppID, Status: "completed", Conclusion: "success"})
		mustSucceed(t, f.run(t, ops.OpPRView, n, map[string]any{}))
		mustFail(t, f.run(t, ops.OpPRChecks, n, map[string]any{}), "Checks permission")
	})
	t.Run("GitHub answers 5xx", func(t *testing.T) {
		f := newReadFx(t, nil)
		n, _ := f.pr("agent/x", ghtest.PROptions{})
		f.s.Inject("GET", "/pulls/", ghtest.Unavailable())
		out := f.run(t, ops.OpPRView, n, map[string]any{})
		mustFail(t, out, "GitHub refused pr.view (503)")
		if out.Unconfirmed || out.ExternalRef != "" {
			t.Errorf("a failed read is never unconfirmed: %+v", out)
		}
		if f.s.LiveTokens() != 0 {
			t.Error("token left live")
		}
	})
	t.Run("the diff is too big for GitHub", func(t *testing.T) {
		f := newReadFx(t, nil)
		n, _ := f.pr("agent/x", ghtest.PROptions{})
		f.r.SetFiles(n, ghtest.File{Filename: "a", Patch: "@@\n+x"})
		// The pull request's JSON passes; GitHub refuses the diff of the same pull request.
		f.s.Before("GET", "/pulls/1", func() {
			f.s.Inject("GET", "/pulls/1", ghtest.Fault{Status: 406, Message: "Sorry, the diff exceeded the maximum number of lines (20000)"})
		})
		mustFail(t, f.run(t, ops.OpPRDiff, n, map[string]any{}), "GitHub refused pr.diff (406): Sorry, the diff exceeded")
	})
	t.Run("GitHub rate limits chapd", func(t *testing.T) {
		f := newReadFx(t, nil)
		n, _ := f.pr("agent/x", ghtest.PROptions{})
		f.s.Inject("GET", "/pulls/", f.s.PrimaryRateLimit(90*time.Minute))
		res := mustFail(t, f.run(t, ops.OpPRView, n, map[string]any{}), "rate limiting")
		if !strings.Contains(res["error"].(string), "resets at") {
			t.Errorf("no reset time: %v", res)
		}
		f.s.ClearFaults()
		f.s.Inject("GET", "/pulls/", ghtest.SecondaryRateLimit(45*time.Second))
		res = mustFail(t, f.run(t, ops.OpPRView, n, map[string]any{}), "retry in 45 s")
		if res["retry_after_seconds"] != 45 {
			t.Errorf("retry_after_seconds: %v", res)
		}
	})
	t.Run("more check runs than one page", func(t *testing.T) {
		f := newReadFx(t, nil)
		n, head := f.pr("agent/x", ghtest.PROptions{})
		for i := range 101 {
			f.r.SetCheck(head, ghtest.Check{Name: fmt.Sprintf("job-%03d", i), AppID: gh.GitHubActionsAppID, Status: "completed", Conclusion: "success"})
		}
		// The fake pages at 100 and says how many exist: the client refuses a partial list.
		mustFail(t, f.run(t, ops.OpPRChecks, n, map[string]any{}), "incomplete")
	})
}

func TestNewPRReadAdapterRefuses(t *testing.T) {
	f := newReadFx(t, nil)
	if _, err := ops.NewPRReadAdapter("pr.merge", ops.PRReadConfig{GitHub: f.c, Tokens: &ops.InstallationMinter{Client: f.c}, Project: func(string) (ops.PRProject, bool) { return ops.PRProject{}, false }}); err == nil {
		t.Error("an adapter for a write op")
	}
	if _, err := ops.NewPRReadAdapter(ops.OpPRView, ops.PRReadConfig{}); err == nil {
		t.Error("an adapter with no GitHub")
	}
}
