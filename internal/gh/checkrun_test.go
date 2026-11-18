package gh_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
)

// The installation of the fixture holds `checks: read`, as the App did before ADR-002 amendment 10. A token for
// ci.report asks for `checks: write`, and GitHub refuses the request until the operator approves the permission.
func TestReportCITokenNeedsTheOperatorStep(t *testing.T) {
	f := newFixture(t)
	_, err := f.c.MintToken(ctx, 7, gh.TokenRequest{Repositories: []string{"storefront"}, Permissions: gh.PermsReportCI()})
	var api *gh.APIError
	if !errors.As(err, &api) || api.Status != 422 {
		t.Fatalf("minting checks:write on an installation that holds checks:read: %v", err)
	}
	f.in.Granted["checks"] = "write" // the operator approved the new permission
	tok := f.mint(t, gh.PermsReportCI())
	head := f.r.Commit(base)
	if _, err := f.c.CreateCheckRun(ctx, tok, f.repo, gh.CheckRunRequest{Name: "local-ci", HeadSHA: head, Conclusion: "success", Title: "t", Summary: "s"}); err != nil {
		t.Fatal(err)
	}
}

func TestCreateCheckRun(t *testing.T) {
	f := newFixture(t)
	f.in.Granted["checks"] = "write"
	tok := f.mint(t, gh.PermsReportCI())
	head := f.r.Commit(base)

	run, err := f.c.CreateCheckRun(ctx, tok, f.repo, gh.CheckRunRequest{Name: "local-ci", HeadSHA: head, Conclusion: "failure", Title: "red", Summary: "step 9 failed", DetailsURL: "https://example.test/x"})
	if err != nil {
		t.Fatal(err)
	}
	if run.ID == 0 || run.Name != "local-ci" || run.HeadSHA != head || run.Status != "completed" || run.Conclusion != "failure" || run.AppID != ghtest.OwnAppID {
		t.Fatalf("run = %+v", run)
	}
	// The check run belongs to the App, and pr.merge's lookup by that App finds it and nothing from Actions.
	runs, err := f.c.ListCheckRuns(ctx, f.mint(t, gh.PermsEvaluateMerge()), f.repo, head, gh.CheckRunQuery{CheckName: "local-ci", AppID: ghtest.OwnAppID, All: true})
	if err != nil || len(runs) != 1 || runs[0].ID != run.ID || runs[0].AppID != ghtest.OwnAppID {
		t.Fatalf("lookup by the App: %v %+v", err, runs)
	}
	if runs, _ := f.c.ListCheckRuns(ctx, f.mint(t, gh.PermsEvaluateMerge()), f.repo, head, gh.CheckRunQuery{CheckName: "local-ci", AppID: gh.GitHubActionsAppID, All: true}); len(runs) != 0 {
		t.Errorf("Actions has no run named local-ci: %+v", runs)
	}
	if got := f.r.OwnChecks(head); len(got) != 1 || got[0].Title != "red" || got[0].Summary != "step 9 failed" {
		t.Errorf("what GitHub holds: %+v", got)
	}
	if id, err := f.c.AppNumericID(ctx, f.repo); err != nil || id != ghtest.OwnAppID {
		t.Errorf("AppNumericID = %d, %v", id, err)
	}
}

func TestCreateCheckRunRefusals(t *testing.T) {
	f := newFixture(t)
	f.in.Granted["checks"] = "write"
	head := f.r.Commit(base)
	good := gh.CheckRunRequest{Name: "local-ci", HeadSHA: head, Conclusion: "success"}
	for name, mod := range map[string]func(*gh.CheckRunRequest){
		"neutral is never posted": func(r *gh.CheckRunRequest) { r.Conclusion = "neutral" },
		"no conclusion":           func(r *gh.CheckRunRequest) { r.Conclusion = "" },
		"short head":              func(r *gh.CheckRunRequest) { r.HeadSHA = head[:7] },
		"empty name":              func(r *gh.CheckRunRequest) { r.Name = "" },
		"name with a newline":     func(r *gh.CheckRunRequest) { r.Name = "a\nb" },
		"summary too long":        func(r *gh.CheckRunRequest) { r.Summary = strings.Repeat("x", 4001) },
	} {
		req := good
		mod(&req)
		if _, err := f.c.CreateCheckRun(ctx, f.mint(t, gh.PermsReportCI()), f.repo, req); !errors.Is(err, gh.ErrInvalidArgument) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := len(f.r.OwnChecks(head)); n != 0 {
		t.Errorf("%d check run(s) were posted by refused calls", n)
	}
	// A read-only token cannot post.
	_, err := f.c.CreateCheckRun(ctx, f.mint(t, gh.PermsEvaluateMerge()), f.repo, good)
	var api *gh.APIError
	if !errors.As(err, &api) || api.Status != 403 {
		t.Errorf("a checks:read token: %v", err)
	}
	// A commit GitHub does not know.
	bad := good
	bad.HeadSHA = strings.Repeat("a", 40)
	if _, err := f.c.CreateCheckRun(ctx, f.mint(t, gh.PermsReportCI()), f.repo, bad); !errors.As(err, &api) || api.Status != 422 {
		t.Errorf("an unknown commit: %v", err)
	}
}
