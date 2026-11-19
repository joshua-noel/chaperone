package ops_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/spec"
)

// ADR-002 amendment 10: the ci.report adapter. The caller names a run; the repository, the head and the
// conclusion come from chapd's own record of the run.

type ciFx struct {
	s    *ghtest.Server
	in   *ghtest.Installation
	r    *ghtest.Repo
	head string
	runs map[string]ops.CIRun
	pol  ops.PRPolicy
	ad   ops.Adapter
}

func newCIFx(t *testing.T) *ciFx {
	t.Helper()
	s := ghtest.New(t)
	c, err := gh.New(gh.Config{AppID: s.AppID(), Keys: gh.StaticKey{Key: s.Key()}, BaseURL: s.URL(), Now: s.Now})
	if err != nil {
		t.Fatal(err)
	}
	in := s.AddInstallation(7, "example-org", map[string]string{
		"contents": "write", "pull_requests": "write", "checks": "write", "metadata": "read",
	})
	f := &ciFx{s: s, in: in, r: in.AddRepo("chaperone", "main"), runs: map[string]ops.CIRun{}}
	f.r.Branch("feat/x", "main")
	f.head = f.r.Commit("feat/x")
	f.pol = ops.PRPolicy{Version: "test-1", Repo: "example-org/chaperone", Base: "main", LocalCI: &ops.PRLocalCI{Check: "local-ci"}}
	f.runs["r-ci01"] = ops.CIRun{RunID: "r-ci01", Project: "chaperone", Profile: "ci", Repo: "example-org/chaperone", Head: f.head, Ended: true, Outcome: "done"}
	ad, err := ops.NewCIReportAdapter(ops.CIReportConfig{
		GitHub: c, Tokens: &ops.InstallationMinter{Client: c},
		Runs: func(_ context.Context, id string) (ops.CIRun, error) {
			if run, ok := f.runs[id]; ok {
				return run, nil
			}
			return ops.CIRun{}, ops.ErrCIRunUnknown
		},
		Policy: func(project string) (ops.PRPolicy, bool) {
			if project == "chaperone" {
				return f.pol, true
			}
			return ops.PRPolicy{}, false
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.ad = ad
	return f
}

func (f *ciFx) req(runID string) *ops.Request {
	return &ops.Request{
		Op: "ci.report", Project: "chaperone", ID: "q-000001",
		Target: spec.Target{Adapter: "runner", Ref: runID},
		Params: map[string]any{"run_id": runID},
		Caller: &ops.Caller{Kind: ops.KindOrchestrator, OrchID: "o-main"},
	}
}

func (f *ciFx) noLeak(t *testing.T) {
	t.Helper()
	if n := f.s.LiveTokens(); n != 0 {
		t.Fatalf("%d installation token(s) left unrevoked", n)
	}
}

func TestCIReportPostsTheRunsResult(t *testing.T) {
	for outcome, want := range map[string]string{"done": "success", "failed": "failure", "killed": "failure", "blocked": "failure"} {
		t.Run(outcome, func(t *testing.T) {
			f := newCIFx(t)
			run := f.runs["r-ci01"]
			run.Outcome = outcome
			f.runs["r-ci01"] = run

			cr, err := f.ad.Check(ctx, f.req("r-ci01"))
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range cr.Checks {
				if !c.Passed {
					t.Errorf("check %s failed: %s", c.Name, c.Detail)
				}
			}
			if cr.NeedsApproval {
				t.Error("ci.report is routine: no approval")
			}
			if n := f.s.Count("POST", "/check-runs"); n != 0 {
				t.Fatalf("Check posted %d check run(s)", n)
			}

			out, err := f.ad.Execute(ctx, f.req("r-ci01"))
			if err != nil || out.Failed || out.Unconfirmed {
				t.Fatalf("execute: %v %+v", err, out)
			}
			got := f.r.OwnChecks(f.head)
			if len(got) != 1 || got[0].Name != "local-ci" || got[0].Conclusion != want || got[0].Status != "completed" || got[0].AppID != ghtest.OwnAppID {
				t.Fatalf("what GitHub holds on %s: %+v, want %s", f.head, got, want)
			}
			if !strings.Contains(got[0].Summary, "r-ci01") || !strings.Contains(got[0].Summary, f.head) || !strings.Contains(got[0].Summary, outcome) {
				t.Errorf("summary = %q", got[0].Summary)
			}
			if out.Result["conclusion"] != want || out.Result["head_sha"] != f.head || out.Result["run_id"] != "r-ci01" || out.ExternalRef == "" {
				t.Errorf("result = %+v ref %q", out.Result, out.ExternalRef)
			}
			f.noLeak(t)
		})
	}
}

// What pr.merge needs: the posted check run satisfies a local_ci policy on exactly that head, and a red report
// does not.
func TestCIReportFeedsPRMerge(t *testing.T) {
	f := newCIFx(t)
	f.r.OpenPR(ghtest.PROptions{Title: "docs: note", Head: "feat/x", Base: "main"})
	f.r.SetFiles(1, ghtest.File{Filename: "docs/notes.md"})
	c, _ := gh.New(gh.Config{AppID: f.s.AppID(), Keys: gh.StaticKey{Key: f.s.Key()}, BaseURL: f.s.URL(), Now: f.s.Now})
	m, err := ops.NewPRMerger(ops.PRMergerConfig{GitHub: c, Tokens: &ops.InstallationMinter{Client: c}})
	if err != nil {
		t.Fatal(err)
	}
	f.pol.LocalCI.Instead = true
	req := ops.PRMergeRequest{Repo: gh.Repo{Owner: "example-org", Name: "chaperone"}, Number: 1, Base: "main", HeadSHA: f.head, Policy: f.pol, DryRun: true}

	res, err := m.Merge(ctx, req)
	if err != nil || res.Verdict.WouldAllow() {
		t.Fatalf("before any report: %v %+v", err, res.Verdict)
	}
	if out, err := f.ad.Execute(ctx, f.req("r-ci01")); err != nil || out.Failed {
		t.Fatalf("report: %v %+v", err, out)
	}
	res, err = m.Merge(ctx, req)
	if err != nil || !res.Verdict.WouldAllow() {
		t.Fatalf("after a green report: %v %+v", err, res.Verdict)
	}
	// The same run reported again after it was found red replaces the green one (latest wins).
	run := f.runs["r-ci01"]
	run.Outcome = "failed"
	f.runs["r-ci01"] = run
	if out, err := f.ad.Execute(ctx, f.req("r-ci01")); err != nil || out.Failed {
		t.Fatalf("second report: %v %+v", err, out)
	}
	res, err = m.Merge(ctx, req)
	if err != nil || res.Verdict.WouldAllow() || res.Verdict.Stop != ops.StopCIRed {
		t.Fatalf("after a red report: %v %+v", err, res.Verdict)
	}
}

func TestCIReportRefusals(t *testing.T) {
	type tc struct {
		name    string
		setup   func(f *ciFx, r *ops.Request)
		code    string
		contain string
	}
	run := func(f *ciFx, mod func(*ops.CIRun)) {
		r := f.runs["r-ci01"]
		mod(&r)
		f.runs["r-ci01"] = r
	}
	for _, c := range []tc{
		{"a run asks", func(f *ciFx, r *ops.Request) {
			r.Caller = &ops.Caller{Kind: ops.KindRun, RunID: "r-ci01", Profile: "ci", Project: "chaperone"}
		}, ops.CodePolicyRefused, "orchestrator only"},
		{"no caller", func(f *ciFx, r *ops.Request) { r.Caller = nil }, ops.CodePolicyRefused, "orchestrator only"},
		{"wrong target adapter", func(f *ciFx, r *ops.Request) { r.Target.Adapter = "github" }, ops.CodeParamsInvalid, "target adapter"},
		{"target is not the run", func(f *ciFx, r *ops.Request) { r.Target.Ref = "r-ci02" }, ops.CodeParamsInvalid, "target ref"},
		{"missing run id", func(f *ciFx, r *ops.Request) { r.Params = map[string]any{} }, ops.CodeParamsInvalid, "run_id"},
		{"a repository param", func(f *ciFx, r *ops.Request) { r.Params["repo"] = "example-org/storefront" }, ops.CodeParamsInvalid, "unknown param"},
		{"a head param", func(f *ciFx, r *ops.Request) { r.Params["head_sha"] = strings.Repeat("a", 40) }, ops.CodeParamsInvalid, "unknown param"},
		{"a conclusion param", func(f *ciFx, r *ops.Request) { r.Params["conclusion"] = "success" }, ops.CodeParamsInvalid, "unknown param"},
		{"unknown run", func(f *ciFx, r *ops.Request) { r.Params["run_id"], r.Target.Ref = "r-nope", "r-nope" }, ops.CodePolicyRefused, "no record of run"},
		{"no pr block", func(f *ciFx, r *ops.Request) { r.Project = "acme-shop" }, ops.CodePolicyRefused, "no pr: block"},
		{"no local_ci block", func(f *ciFx, r *ops.Request) { f.pol.LocalCI = nil }, ops.CodePolicyRefused, "no pr.local_ci"},
		{"run of another project", func(f *ciFx, r *ops.Request) { run(f, func(x *ops.CIRun) { x.Project = "acme-shop" }) }, ops.CodePolicyRefused, "another project"},
		{"a code run", func(f *ciFx, r *ops.Request) { run(f, func(x *ops.CIRun) { x.Profile = "code" }) }, ops.CodePolicyRefused, "profile code"},
		{"a host-interim run", func(f *ciFx, r *ops.Request) { run(f, func(x *ops.CIRun) { x.Profile = "host-interim" }) }, ops.CodePolicyRefused, "profile host-interim"},
		{"run still active", func(f *ciFx, r *ops.Request) { run(f, func(x *ops.CIRun) { x.Ended, x.Outcome = false, "" }) }, ops.CodePolicyRefused, "has not ended"},
		{"no outcome kept", func(f *ciFx, r *ops.Request) { run(f, func(x *ops.CIRun) { x.Outcome = "" }) }, ops.CodePolicyRefused, "kept no outcome"},
		{"run checked another repo", func(f *ciFx, r *ops.Request) {
			run(f, func(x *ops.CIRun) { x.Repo = "example-org/storefront" })
		}, ops.CodePolicyRefused, "reports only for example-org/chaperone"},
		{"run repo is not a repo", func(f *ciFx, r *ops.Request) { run(f, func(x *ops.CIRun) { x.Repo = "chaperone" }) }, ops.CodePolicyRefused, "reports only for"},
		{"head is a branch", func(f *ciFx, r *ops.Request) { run(f, func(x *ops.CIRun) { x.Head = "main" }) }, ops.CodePolicyRefused, "no pinned commit"},
		{"head is short", func(f *ciFx, r *ops.Request) { run(f, func(x *ops.CIRun) { x.Head = x.Head[:7] }) }, ops.CodePolicyRefused, "no pinned commit"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newCIFx(t)
			r := f.req("r-ci01")
			c.setup(f, r)
			before := len(f.s.Requests())
			_, err := f.ad.Check(ctx, r)
			var ref *ops.Refusal
			if !errors.As(err, &ref) || ref.Code != c.code || !strings.Contains(ref.Why, c.contain) {
				t.Fatalf("Check err = %v, want %s containing %q", err, c.code, c.contain)
			}
			// Execute re-checks and posts nothing either.
			out, err := f.ad.Execute(ctx, r)
			if err != nil || !out.Failed {
				t.Fatalf("Execute: %v %+v", err, out)
			}
			if got := len(f.s.Requests()); got != before {
				t.Fatalf("a refused report reached GitHub (%d requests)", got-before)
			}
			if n := len(f.r.OwnChecks(f.head)); n != 0 {
				t.Fatalf("%d check run(s) posted", n)
			}
		})
	}
}

// Until the operator approves `checks: write` for the App (the installation still holds checks: read), the report
// fails with a message that names the step, and nothing is posted or left unrevoked.
func TestCIReportWithoutTheChecksWritePermission(t *testing.T) {
	f := newCIFx(t)
	f.in.Granted["checks"] = "read"
	out, err := f.ad.Execute(ctx, f.req("r-ci01"))
	if err != nil || !out.Failed {
		t.Fatalf("execute: %v %+v", err, out)
	}
	msg, _ := out.Result["error"].(string)
	if !strings.Contains(msg, "checks: write") || !strings.Contains(msg, "docs/runbooks/ci-report.md") {
		t.Errorf("error = %q", msg)
	}
	if n := len(f.r.OwnChecks(f.head)); n != 0 {
		t.Errorf("%d check run(s) posted", n)
	}
	f.noLeak(t)
}

func TestCIReportTokenIsNarrow(t *testing.T) {
	f := newCIFx(t)
	if out, err := f.ad.Execute(ctx, f.req("r-ci01")); err != nil || out.Failed {
		t.Fatalf("execute: %v %+v", err, out)
	}
	var minted []string
	for _, r := range f.s.Requests() {
		if r.Method == "POST" && strings.HasSuffix(r.Path, "/access_tokens") {
			minted = append(minted, r.Body)
		}
	}
	if len(minted) != 1 || !strings.Contains(minted[0], `"checks":"write"`) || !strings.Contains(minted[0], `"chaperone"`) ||
		strings.Contains(minted[0], "contents") || strings.Contains(minted[0], "pull_requests") {
		t.Fatalf("token requests: %v", minted)
	}
}

func TestNewCIReportAdapterNeedsEverything(t *testing.T) {
	if _, err := ops.NewCIReportAdapter(ops.CIReportConfig{}); err == nil {
		t.Error("an empty config must be refused")
	}
}

// ci.report is repeat-safe: a second Execute with the same execution id finds the check run the first one posted
// (it carries the execution id as external_id) and posts nothing. Another execution id is a new report.
func TestCIReportRepeatPostsNothingNew(t *testing.T) {
	f := newCIFx(t)
	req := f.req("r-ci01")
	req.ExecutionID = "x-first"
	first, err := f.ad.Execute(ctx, req)
	if err != nil || first.Failed || first.Unconfirmed {
		t.Fatalf("first: %v %+v", err, first)
	}
	if first.Result["already_posted"] != nil {
		t.Errorf("the first report says it was posted before: %+v", first.Result)
	}
	again, err := f.ad.Execute(ctx, req)
	if err != nil || again.Failed || again.Unconfirmed {
		t.Fatalf("repeat: %v %+v", err, again)
	}
	if n := f.s.Count("POST", "/check-runs"); n != 1 {
		t.Fatalf("a repeat posted again: %d check runs", n)
	}
	if again.Result["already_posted"] != true || again.Result["check_run_id"] != first.Result["check_run_id"] || again.ExternalRef != first.ExternalRef {
		t.Errorf("repeat = %+v (%q), first = %+v (%q)", again.Result, again.ExternalRef, first.Result, first.ExternalRef)
	}
	if got := f.r.OwnChecks(f.head); len(got) != 1 || got[0].ExternalID != "x-first" {
		t.Errorf("what GitHub holds: %+v", got)
	}

	other := f.req("r-ci01")
	other.ExecutionID = "x-second"
	if out, err := f.ad.Execute(ctx, other); err != nil || out.Failed || out.Result["already_posted"] != nil {
		t.Fatalf("another execution id: %v %+v", err, out)
	}
	if n := f.s.Count("POST", "/check-runs"); n != 2 {
		t.Errorf("another execution id should post: %d check runs", n)
	}
	f.noLeak(t)
}

// Another App's check run of the same name, head and external_id is not this adapter's own: it is posted anyway.
func TestCIReportIgnoresAnotherAppsRunWithTheSameExternalID(t *testing.T) {
	f := newCIFx(t)
	f.r.SetCheck(f.head, ghtest.Check{Name: "local-ci", AppID: gh.GitHubActionsAppID, Status: "completed", Conclusion: "success", ExternalID: "x-first"})
	req := f.req("r-ci01")
	req.ExecutionID = "x-first"
	out, err := f.ad.Execute(ctx, req)
	if err != nil || out.Failed || out.Result["already_posted"] != nil {
		t.Fatalf("execute: %v %+v", err, out)
	}
	if got := f.r.OwnChecks(f.head); len(got) != 1 {
		t.Errorf("own runs: %+v", got)
	}
}
