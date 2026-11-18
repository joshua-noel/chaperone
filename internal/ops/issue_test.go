package ops_test

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/spec"
)

const watcherLabel = "source:error-watcher"

// issueFx is a fake GitHub whose App holds the permissions in granted.
type issueFx struct {
	s    *ghtest.Server
	c    *gh.Client
	r    *ghtest.Repo
	repo string
}

func newIssueFx(t *testing.T, granted map[string]string) *issueFx {
	t.Helper()
	s := ghtest.New(t)
	c, err := gh.New(gh.Config{AppID: s.AppID(), Keys: gh.StaticKey{Key: s.Key()}, BaseURL: s.URL(), Now: s.Now})
	if err != nil {
		t.Fatal(err)
	}
	in := s.AddInstallation(11, "example-org", granted)
	f := &issueFx{s: s, c: c, r: in.AddRepo("storefront", "main"), repo: "example-org/storefront"}
	in.AddRepo("other", "main")
	return f
}

func issueGrants() map[string]string { return map[string]string{"issues": "write", "metadata": "read"} }

func (f *issueFx) adapter(t *testing.T, op string) *ops.IssueAdapter {
	t.Helper()
	a, err := ops.NewIssueAdapter(op, ops.IssueConfig{
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

func watcher() *ops.Caller {
	return &ops.Caller{Kind: ops.KindOrchestrator, OrchID: "error-watcher", Projects: []string{"storefront"},
		ScopeOps: []string{ops.OpIssueOpen, ops.OpIssueComment, ops.OpIssueReopen}}
}

func (f *issueFx) req(op, ref string, params map[string]any) *ops.Request {
	return &ops.Request{Op: op, Project: "storefront", Caller: watcher(), ExecutionID: "x-1",
		Target: spec.Target{Adapter: "github", Ref: ref}, Params: params}
}

func openParams() map[string]any {
	return map[string]any{"title": "TypeError in /api/orders", "body": "stack...", "labels": []any{watcherLabel, "bug"}}
}

// writes counts the requests that reached GitHub beyond the token calls.
func (f *issueFx) writes() int {
	return f.s.Count("POST", "/issues") + f.s.Count("PATCH", "/issues")
}

func TestIssueOpen(t *testing.T) {
	f := newIssueFx(t, issueGrants())
	a := f.adapter(t, ops.OpIssueOpen)
	req := f.req(ops.OpIssueOpen, f.repo, openParams())
	res, err := a.Check(context.Background(), req)
	if err != nil || len(res.Checks) == 0 || res.NeedsApproval {
		t.Fatalf("check: %+v %v", res, err)
	}
	if f.s.Count("POST", "access_tokens") != 0 {
		t.Error("Check of issue.open reached GitHub")
	}
	out, err := a.Execute(context.Background(), req)
	if err != nil || out.Failed || out.Unconfirmed {
		t.Fatalf("execute: %+v %v", out, err)
	}
	if !strings.Contains(out.ExternalRef, "/issues/1") || out.Result["number"] != float64(1) {
		t.Errorf("outcome: %+v", out)
	}
	v, ok := f.r.Issue(1)
	if !ok || v.Title != "TypeError in /api/orders" || v.Body != "stack..." || len(v.Labels) != 2 || v.Labels[0] != watcherLabel || v.State != "open" {
		t.Errorf("issue on GitHub: %+v", v)
	}
	if n := f.s.LiveTokens(); n != 0 {
		t.Errorf("%d tokens still live", n)
	}
	for _, r := range f.s.Requests() {
		if strings.Contains(r.Path, "access_tokens") && (!strings.Contains(r.Body, `"issues":"write"`) ||
			strings.Contains(r.Body, "contents") || strings.Contains(r.Body, "pull_requests")) {
			t.Errorf("token request must ask for issues:write only (and metadata): %s", r.Body)
		}
	}
}

func TestIssueOpenRefusals(t *testing.T) {
	f := newIssueFx(t, issueGrants())
	a := f.adapter(t, ops.OpIssueOpen)
	long := strings.Repeat("x", 10001)
	many := make([]any, 11)
	for i := range many {
		many[i] = watcherLabel
	}
	for name, tc := range map[string]struct {
		mut  func(*ops.Request)
		code string
	}{
		"no labels":          {func(r *ops.Request) { r.Params = with(r.Params, "labels", nil) }, ops.CodeParamsInvalid},
		"wrong label":        {func(r *ops.Request) { r.Params = with(r.Params, "labels", []any{"bug"}) }, ops.CodePolicyRefused},
		"label look-alike":   {func(r *ops.Request) { r.Params = with(r.Params, "labels", []any{"source:error-watcher2"}) }, ops.CodePolicyRefused},
		"label case differs": {func(r *ops.Request) { r.Params = with(r.Params, "labels", []any{"Source:Error-Watcher"}) }, ops.CodePolicyRefused},
		"labels not a list":  {func(r *ops.Request) { r.Params = with(r.Params, "labels", watcherLabel) }, ops.CodeParamsInvalid},
		"label not text":     {func(r *ops.Request) { r.Params = with(r.Params, "labels", []any{watcherLabel, 7.0}) }, ops.CodeParamsInvalid},
		"too many labels":    {func(r *ops.Request) { r.Params = with(r.Params, "labels", many) }, ops.CodeParamsInvalid},
		"long label": {func(r *ops.Request) {
			r.Params = with(r.Params, "labels", []any{watcherLabel, strings.Repeat("l", 51)})
		}, ops.CodeParamsInvalid},
		"other repo":           {func(r *ops.Request) { r.Target.Ref = "example-org/other" }, ops.CodeScopePath},
		"other owner":          {func(r *ops.Request) { r.Target.Ref = "evil/storefront" }, ops.CodeScopePath},
		"project without repo": {func(r *ops.Request) { r.Project = "acme-shop" }, ops.CodeParamsInvalid},
		"number in target":     {func(r *ops.Request) { r.Target.Ref = "example-org/storefront#3" }, ops.CodeParamsInvalid},
		"bad adapter":          {func(r *ops.Request) { r.Target.Adapter = "pilot" }, ops.CodeParamsInvalid},
		"no title":             {func(r *ops.Request) { r.Params = with(r.Params, "title", nil) }, ops.CodeParamsInvalid},
		"blank title":          {func(r *ops.Request) { r.Params = with(r.Params, "title", "  ") }, ops.CodeParamsInvalid},
		"two-line title":       {func(r *ops.Request) { r.Params = with(r.Params, "title", "a\nb") }, ops.CodeParamsInvalid},
		"long title":           {func(r *ops.Request) { r.Params = with(r.Params, "title", strings.Repeat("t", 201)) }, ops.CodeParamsInvalid},
		"long body":            {func(r *ops.Request) { r.Params = with(r.Params, "body", long) }, ops.CodeParamsInvalid},
		"unknown param":        {func(r *ops.Request) { r.Params = with(r.Params, "assignees", []any{"x"}) }, ops.CodeParamsInvalid},
		"a run asks": {func(r *ops.Request) {
			r.Caller = &ops.Caller{Kind: ops.KindRun, RunID: "r-1", Project: "storefront", Repo: "example-org/storefront"}
		}, ops.CodePolicyRefused},
	} {
		t.Run(name, func(t *testing.T) {
			req := f.req(ops.OpIssueOpen, f.repo, openParams())
			tc.mut(req)
			_, err := a.Check(context.Background(), req)
			if got := refusalCode(t, err); got != tc.code {
				t.Errorf("code %s, want %s (%v)", got, tc.code, err)
			}
			out, err := a.Execute(context.Background(), req)
			if err != nil || !out.Failed {
				t.Errorf("Execute of a refused request: %+v %v, want failed without a call", out, err)
			}
		})
	}
	if n := f.s.Count("POST", "/issues") + f.s.Count("POST", "access_tokens"); n != 0 {
		t.Errorf("a refused request reached GitHub (%d calls)", n)
	}
	if f.r.IssueCount() != 0 {
		t.Error("an issue was created")
	}
}

func TestIssueCommentAndReopenLabelRule(t *testing.T) {
	f := newIssueFx(t, issueGrants())
	labelled := f.r.AddIssue(ghtest.IssueOptions{Title: "watcher", Labels: []string{watcherLabel}, Closed: true})
	bare := f.r.AddIssue(ghtest.IssueOptions{Title: "human", Labels: []string{"bug"}, Closed: true})
	pull := f.r.AddIssue(ghtest.IssueOptions{Title: "a pr", Labels: []string{watcherLabel}, IsPull: true})
	ref := func(n int) string { return f.repo + "#" + strconv.Itoa(n) }

	comment, reopen := f.adapter(t, ops.OpIssueComment), f.adapter(t, ops.OpIssueReopen)

	// Allowed: a labelled issue.
	creq := f.req(ops.OpIssueComment, ref(labelled), map[string]any{"body": "seen again"})
	if _, err := comment.Check(context.Background(), creq); err != nil {
		t.Fatalf("comment check: %v", err)
	}
	out, err := comment.Execute(context.Background(), creq)
	if err != nil || out.Failed || out.Result["comment_id"] == nil || !strings.Contains(out.ExternalRef, "#issuecomment-") {
		t.Fatalf("comment: %+v %v", out, err)
	}
	rreq := f.req(ops.OpIssueReopen, ref(labelled), map[string]any{})
	if _, err := reopen.Check(context.Background(), rreq); err != nil {
		t.Fatalf("reopen check: %v", err)
	}
	out, err = reopen.Execute(context.Background(), rreq)
	if err != nil || out.Failed || out.Result["reopened"] != true {
		t.Fatalf("reopen: %+v %v", out, err)
	}
	if v, _ := f.r.Issue(labelled); v.State != "open" || v.Reason != "reopened" || len(v.Comments) != 1 || v.Comments[0].Body != "seen again" {
		t.Errorf("issue after: %+v", v)
	}
	// Reopening an open issue writes nothing.
	before := f.s.Count("PATCH", "/issues")
	if out, err = reopen.Execute(context.Background(), rreq); err != nil || out.Failed || out.Result["reopened"] != false || f.s.Count("PATCH", "/issues") != before {
		t.Errorf("reopen of an open issue: %+v %v", out, err)
	}
	if f.s.LiveTokens() != 0 {
		t.Error("tokens still live")
	}

	// Denied: no label, a pull request, a missing issue, another repository, a bad ref.
	writes := f.writes()
	for name, tc := range map[string]struct {
		ref  string
		code string
		why  string
	}{
		"no label":      {ref(bare), ops.CodePolicyRefused, watcherLabel},
		"pull request":  {ref(pull), ops.CodePolicyRefused, "pull request"},
		"missing":       {ref(99), ops.CodeParamsInvalid, "does not exist"},
		"other repo":    {"example-org/other#1", ops.CodeScopePath, "not"},
		"no number":     {f.repo, ops.CodeParamsInvalid, "issue number"},
		"zero":          {f.repo + "#0", ops.CodeParamsInvalid, "positive"},
		"leading zeros": {f.repo + "#007", ops.CodeParamsInvalid, "positive"},
	} {
		for op, a := range map[string]*ops.IssueAdapter{ops.OpIssueComment: comment, ops.OpIssueReopen: reopen} {
			t.Run(op+" "+name, func(t *testing.T) {
				params := map[string]any{}
				if op == ops.OpIssueComment {
					params["body"] = "x"
				}
				req := f.req(op, tc.ref, params)
				_, err := a.Check(context.Background(), req)
				if got := refusalCode(t, err); got != tc.code || !strings.Contains(err.Error(), tc.why) {
					t.Errorf("%v, want %s containing %q", err, tc.code, tc.why)
				}
				if out, err := a.Execute(context.Background(), req); err != nil || !out.Failed {
					t.Errorf("Execute of a refused request: %+v %v", out, err)
				}
			})
		}
	}
	if f.writes() != writes {
		t.Errorf("a refused request wrote to GitHub")
	}
	// Params: comment needs a body within the cap; reopen takes none.
	for name, req := range map[string]*ops.Request{
		"comment no body":      f.req(ops.OpIssueComment, ref(labelled), map[string]any{}),
		"comment long body":    f.req(ops.OpIssueComment, ref(labelled), map[string]any{"body": strings.Repeat("c", 10001)}),
		"comment extra param":  f.req(ops.OpIssueComment, ref(labelled), map[string]any{"body": "x", "state": "closed"}),
		"reopen with a param":  f.req(ops.OpIssueReopen, ref(labelled), map[string]any{"state": "closed"}),
		"a run asks (comment)": {Op: ops.OpIssueComment, Project: "storefront", Caller: &ops.Caller{Kind: ops.KindRun}, Target: spec.Target{Adapter: "github", Ref: ref(labelled)}, Params: map[string]any{"body": "x"}},
	} {
		a := comment
		if strings.HasPrefix(name, "reopen") {
			a = reopen
		}
		if _, err := a.Check(context.Background(), req); err == nil {
			t.Errorf("%s: no refusal", name)
		}
	}
}

func TestIssueLabelRemovedBetweenCheckAndExecute(t *testing.T) {
	f := newIssueFx(t, issueGrants())
	n := f.r.AddIssue(ghtest.IssueOptions{Title: "watcher", Labels: []string{watcherLabel}})
	a := f.adapter(t, ops.OpIssueComment)
	req := f.req(ops.OpIssueComment, f.repo+"#"+strconv.Itoa(n), map[string]any{"body": "late"})
	if _, err := a.Check(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	f.s.Before("GET", "/issues/", func() { f.r.SetIssueLabels(n, "bug") })
	out, err := a.Execute(context.Background(), req)
	if err != nil || !out.Failed || !strings.Contains(out.Result["error"].(string), watcherLabel) {
		t.Fatalf("execute: %+v %v, want failed naming the label", out, err)
	}
	if v, _ := f.r.Issue(n); len(v.Comments) != 0 {
		t.Error("the comment was posted")
	}
}

func TestIssueAppWithoutIssuesPermission(t *testing.T) {
	f := newIssueFx(t, map[string]string{"contents": "write", "pull_requests": "write", "metadata": "read"})
	// The operator has not granted Issues to the App yet: every issue op says so, and writes nothing.
	open := f.adapter(t, ops.OpIssueOpen)
	out, err := open.Execute(context.Background(), f.req(ops.OpIssueOpen, f.repo, openParams()))
	if err != nil || !out.Failed || !strings.Contains(out.Result["error"].(string), "Issues permission") {
		t.Errorf("open: %+v %v", out, err)
	}
	n := f.r.AddIssue(ghtest.IssueOptions{Title: "watcher", Labels: []string{watcherLabel}})
	_, err = f.adapter(t, ops.OpIssueComment).Check(context.Background(), f.req(ops.OpIssueComment, f.repo+"#"+strconv.Itoa(n), map[string]any{"body": "x"}))
	if got := refusalCode(t, err); got != ops.CodePolicyRefused || !strings.Contains(err.Error(), "Issues permission") {
		t.Errorf("comment check: %v", err)
	}
	if f.writes() != 0 {
		t.Error("wrote to GitHub")
	}
}

func TestIssueOpenGitHubAnswers(t *testing.T) {
	f := newIssueFx(t, issueGrants())
	a := f.adapter(t, ops.OpIssueOpen)
	req := f.req(ops.OpIssueOpen, f.repo, openParams())
	// A refusal GitHub made (rate limit, 4xx) is `failed`, with its words.
	f.s.Inject("POST", "/issues", ghtest.Fault{Status: 422, Message: "Validation Failed", Times: 1})
	out, err := a.Execute(context.Background(), req)
	if err != nil || !out.Failed || !strings.Contains(out.Result["error"].(string), "422") {
		t.Errorf("4xx: %+v %v, want failed", out, err)
	}
	// 5xx: the issue may exist, so the error comes back and the op is unconfirmed.
	f.s.Inject("POST", "/issues", ghtest.Fault{Status: 503, Message: "down", Times: 1})
	if out, err = a.Execute(context.Background(), req); err == nil || out.Failed {
		t.Errorf("5xx: %+v %v, want an error", out, err)
	}
	if f.r.IssueCount() != 0 {
		t.Error("an issue exists")
	}
	if f.s.LiveTokens() != 0 {
		t.Error("tokens still live")
	}
}

func TestNewIssueAdapterNeedsItsParts(t *testing.T) {
	f := newIssueFx(t, issueGrants())
	good := ops.IssueConfig{GitHub: f.c, Tokens: &ops.InstallationMinter{Client: f.c}, Project: func(string) (ops.PRProject, bool) { return ops.PRProject{}, false }}
	if _, err := ops.NewIssueAdapter("pr.open", good); err == nil {
		t.Error("accepted a non-issue op")
	}
	for _, c := range []ops.IssueConfig{{Tokens: good.Tokens, Project: good.Project}, {GitHub: f.c, Project: good.Project}, {GitHub: f.c, Tokens: good.Tokens}} {
		if _, err := ops.NewIssueAdapter(ops.OpIssueOpen, c); err == nil {
			t.Error("accepted an incomplete config")
		}
	}
}
