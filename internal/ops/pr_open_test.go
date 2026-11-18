package ops_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/spec"
)

const openBranch = "agent/r-7f3a"

func (f *fx) opener(t *testing.T, project func(string) (ops.PRProject, bool)) *ops.PROpen {
	t.Helper()
	a, err := ops.NewPROpen(ops.PROpenConfig{GitHub: f.c, Tokens: &ops.InstallationMinter{Client: f.c}, Project: project})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (f *fx) runCaller() *ops.Caller {
	return &ops.Caller{Kind: ops.KindRun, RunID: "r-7f3a", Project: "storefront", Repo: f.repo.String(), Base: base, Branch: openBranch}
}

func (f *fx) openReq(c *ops.Caller, params map[string]any) *ops.Request {
	return &ops.Request{
		Op: "pr.open", Project: "storefront", Caller: c, ExecutionID: "x-1",
		Target: spec.Target{Adapter: "github", Ref: f.repo.String()}, Params: params,
	}
}

func okParams() map[string]any {
	return map[string]any{"title": "docs: notes", "body": "why", "head": openBranch, "base": base}
}

func with(m map[string]any, k string, v any) map[string]any {
	out := map[string]any{}
	for kk, vv := range m {
		out[kk] = vv
	}
	if v == nil {
		delete(out, k)
	} else {
		out[k] = v
	}
	return out
}

func refusalCode(t *testing.T, err error) string {
	t.Helper()
	var r *ops.Refusal
	if !errors.As(err, &r) {
		t.Fatalf("want a refusal, got %v", err)
	}
	return r.Code
}

func TestPROpenRunOpensItsOwnBranch(t *testing.T) {
	f := newFx(t)
	f.r.Branch(openBranch, base)
	f.r.Commit(openBranch)
	a := f.opener(t, nil)
	req := f.openReq(f.runCaller(), with(okParams(), "draft", true))
	if _, err := a.Check(context.Background(), req); err != nil {
		t.Fatalf("check: %v", err)
	}
	out, err := a.Execute(context.Background(), req)
	if err != nil || out.Failed || out.Unconfirmed {
		t.Fatalf("execute: %+v %v", out, err)
	}
	if !strings.Contains(out.ExternalRef, "/pull/1") || out.Result["number"] != float64(1) || out.Result["draft"] != true {
		t.Errorf("outcome: %+v", out)
	}
	if n := f.s.Count("POST", "/pulls"); n != 1 {
		t.Errorf("%d POST /pulls, want 1", n)
	}
	if n := f.s.LiveTokens(); n != 0 {
		t.Errorf("%d tokens still live after the call", n)
	}
	for _, r := range f.s.Requests() {
		if strings.Contains(r.Path, "access_tokens") && !strings.Contains(r.Body, `"pull_requests":"write"`) {
			t.Errorf("token request: %s", r.Body)
		}
	}
}

func TestPROpenRefusals(t *testing.T) {
	f := newFx(t)
	a := f.opener(t, nil)
	run := f.runCaller()
	for name, tc := range map[string]struct {
		mut  func(*ops.Request)
		code string
	}{
		"other head":     {func(r *ops.Request) { r.Params = with(r.Params, "head", "agent/other") }, ops.CodeScopeBranch},
		"main as head":   {func(r *ops.Request) { r.Params = with(r.Params, "head", base) }, ops.CodeParamsInvalid},
		"other base":     {func(r *ops.Request) { r.Params = with(r.Params, "base", "main") }, ops.CodeScopeBranch},
		"fork head":      {func(r *ops.Request) { r.Params = with(r.Params, "head", "evil:"+openBranch) }, ops.CodeParamsInvalid},
		"other repo":     {func(r *ops.Request) { r.Target.Ref = "example-org/other" }, ops.CodeScopePath},
		"bad target":     {func(r *ops.Request) { r.Target.Ref = "nonsense" }, ops.CodeParamsInvalid},
		"bad adapter":    {func(r *ops.Request) { r.Target.Adapter = "pilot" }, ops.CodeParamsInvalid},
		"unknown param":  {func(r *ops.Request) { r.Params = with(r.Params, "reviewers", "x") }, ops.CodeParamsInvalid},
		"no title":       {func(r *ops.Request) { r.Params = with(r.Params, "title", nil) }, ops.CodeParamsInvalid},
		"blank title":    {func(r *ops.Request) { r.Params = with(r.Params, "title", "  ") }, ops.CodeParamsInvalid},
		"long title":     {func(r *ops.Request) { r.Params = with(r.Params, "title", strings.Repeat("t", 201)) }, ops.CodeParamsInvalid},
		"long body":      {func(r *ops.Request) { r.Params = with(r.Params, "body", strings.Repeat("b", 20001)) }, ops.CodeParamsInvalid},
		"title not text": {func(r *ops.Request) { r.Params = with(r.Params, "title", 7.0) }, ops.CodeParamsInvalid},
		"draft not bool": {func(r *ops.Request) { r.Params = with(r.Params, "draft", "yes") }, ops.CodeParamsInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			req := f.openReq(run, okParams())
			tc.mut(req)
			_, err := a.Check(context.Background(), req)
			if got := refusalCode(t, err); got != tc.code {
				t.Errorf("code %s, want %s", got, tc.code)
			}
			out, err := a.Execute(context.Background(), req)
			if err != nil || !out.Failed {
				t.Errorf("Execute of a refused request: %+v %v, want failed without a call", out, err)
			}
		})
	}
	if n := f.s.Count("POST", "/pulls") + f.s.Count("POST", "access_tokens"); n != 0 {
		t.Errorf("a refused request reached GitHub (%d calls)", n)
	}
}

func TestPROpenOrchestrator(t *testing.T) {
	f := newFx(t)
	f.r.Branch("feat/x", base)
	f.r.Commit("feat/x")
	proj := func(name string) (ops.PRProject, bool) {
		if name == "storefront" {
			return ops.PRProject{Repo: f.repo.String(), Base: base}, true
		}
		return ops.PRProject{}, false
	}
	orch := &ops.Caller{Kind: ops.KindOrchestrator, OrchID: "main", Projects: []string{"storefront"}}
	params := with(with(okParams(), "head", "feat/x"), "title", "feat: x")

	a := f.opener(t, proj)
	if _, err := a.Check(context.Background(), f.openReq(orch, params)); err != nil {
		t.Fatalf("orchestrator, own project: %v", err)
	}
	if out, err := a.Execute(context.Background(), f.openReq(orch, params)); err != nil || out.Failed {
		t.Fatalf("execute: %+v %v", out, err)
	}

	req := f.openReq(orch, with(params, "base", "main"))
	if _, err := a.Check(context.Background(), req); refusalCode(t, err) != ops.CodeScopeBranch {
		t.Errorf("wrong base: %v", err)
	}
	req = f.openReq(orch, params)
	req.Target.Ref = "example-org/other"
	if _, err := a.Check(context.Background(), req); refusalCode(t, err) != ops.CodeScopePath {
		t.Errorf("other repo: %v", err)
	}
	req = f.openReq(orch, params)
	req.Project = "unknown"
	if _, err := a.Check(context.Background(), req); refusalCode(t, err) != ops.CodeParamsInvalid {
		t.Errorf("unknown project: %v", err)
	}
	if _, err := f.opener(t, nil).Check(context.Background(), f.openReq(orch, params)); refusalCode(t, err) != ops.CodeParamsInvalid {
		t.Errorf("no resolver: %v", err)
	}
}

func TestPROpenGitHubAnswers(t *testing.T) {
	f := newFx(t)
	f.r.Branch(openBranch, base)
	f.r.Commit(openBranch)
	a := f.opener(t, nil)
	run := f.runCaller()
	exec := func() (ops.Outcome, error) { return a.Execute(context.Background(), f.openReq(run, okParams())) }

	// 422: the head has no commits ahead, or the PR exists. A result, not a retry.
	if out, err := exec(); err != nil || out.Failed {
		t.Fatalf("first: %+v %v", out, err)
	}
	out, err := exec()
	if err != nil || !out.Failed || !strings.Contains(out.Result["error"].(string), "422") {
		t.Errorf("duplicate PR: %+v %v, want failed with the 422", out, err)
	}

	// A rate limit and a 4xx are refusals GitHub made: failed. 5xx: unknown.
	f.s.Inject("POST", "/pulls", f.s.PrimaryRateLimit(time.Minute))
	if out, err := exec(); err != nil || !out.Failed {
		t.Errorf("rate limit: %+v %v, want failed", out, err)
	}
	f.s.ClearFaults()
	f.s.Inject("POST", "/pulls", ghtest.Unavailable())
	if out, err := exec(); err == nil || out.Failed {
		t.Errorf("503: %+v %v, want an error (unconfirmed)", out, err)
	}
	f.s.ClearFaults()
	f.s.Inject("POST", "access_tokens", ghtest.Unavailable())
	if out, err := exec(); err != nil || !out.Failed {
		t.Errorf("mint failure: %+v %v, want failed (nothing was sent)", out, err)
	}
	if n := f.s.LiveTokens(); n != 0 {
		t.Errorf("%d live tokens left behind", n)
	}
}
