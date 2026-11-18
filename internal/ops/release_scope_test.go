package ops

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/joshua-noel/chaperone/internal/gh"
)

// First the runner run, 25 Oct 2026: a run's own `chap pr open` passed its check at
// the request and was then refused SCOPE_PATH at release, because the caller
// was rebuilt from the op row without the task scope (repo, base, branch). The
// run saw "refused", "both checks passed" and no reason.

type stubPulls struct {
	mu      sync.Mutex
	created []gh.NewPull
}

func (s *stubPulls) CreatePull(_ context.Context, _ *gh.Token, repo gh.Repo, in gh.NewPull) (*gh.Pull, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.created = append(s.created, in)
	return &gh.Pull{Number: 7, HTMLURL: "https://github.com/" + repo.String() + "/pull/7"}, nil
}

func (s *stubPulls) RevokeToken(context.Context, *gh.Token) error { return nil }

type stubMinter struct{}

func (stubMinter) Mint(context.Context, gh.Repo, map[string]string) (*gh.Token, error) {
	return &gh.Token{}, nil
}

func prOpenBody(repo string, params map[string]any) map[string]any {
	return map[string]any{"op": "pr.open", "target": map[string]any{"adapter": "github", "ref": repo}, "params": params}
}

func (g *rig) realPROpen() *stubPulls {
	g.t.Helper()
	api := &stubPulls{}
	a, err := NewPROpen(PROpenConfig{GitHub: api, Tokens: stubMinter{}})
	if err != nil {
		g.t.Fatal(err)
	}
	g.svc.adapters["pr.open"] = a
	return api
}

func TestRunPROpenSurvivesTheReleaseRecheck(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"pr.open"}})
	api := g.realPROpen()

	code, body, _ := g.call("POST", "/v0/ops", runTok, prOpenBody("acme/shop",
		map[string]any{"title": "docs: add a line", "head": "agent/r-7f3a", "base": "main"}))
	if code != 200 || body["state"] != "succeeded" {
		t.Fatalf("pr.open by its own run: %d state=%v denial=%v result=%v", code, body["state"], body["denial"], body["result"])
	}
	if !strings.HasSuffix(str(body, "external_ref"), "/pull/7") {
		t.Errorf("external_ref %q", str(body, "external_ref"))
	}
	if len(api.created) != 1 || api.created[0].Head != "agent/r-7f3a" || api.created[0].Base != "main" {
		t.Errorf("pull requests created: %+v", api.created)
	}
}

// The scope is judged at release as it was at the request: a different repo is
// refused at the request already, and nothing reaches GitHub.
func TestRunPROpenOtherRepoIsStillRefused(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"pr.open"}})
	api := g.realPROpen()
	code, body, _ := g.call("POST", "/v0/ops", runTok, prOpenBody("acme/other",
		map[string]any{"title": "t", "head": "agent/r-7f3a", "base": "main"}))
	if code != 403 {
		t.Fatalf("status %d: %v", code, body)
	}
	mustDenial(t, body, CodeScopePath)
	if len(api.created) != 0 {
		t.Errorf("a pull request was created: %+v", api.created)
	}
}

// A refusal made at release (here: the adapter's second check fails, as when
// the head moved or the policy changed) carries the denial: cause code, why and
// the request line, in the reply, in `GET /v0/ops/{id}` and in the ledger.
func TestReleaseRefusalCarriesTheDenial(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"pr.open"}})
	n := 0
	g.ad.check = func(r *Request) (CheckResult, error) {
		n++
		if n == 1 {
			return CheckResult{Checks: []Check{{Name: "repo", Passed: true, Detail: "acme/shop"}}}, nil
		}
		return CheckResult{}, &Refusal{Code: CodeScopePath, Surface: "scope", Why: "this run's token covers acme/shop only, not acme/other"}
	}
	code, body, _ := g.call("POST", "/v0/ops", runTok, prOpenBody("acme/shop",
		map[string]any{"title": "t", "head": "agent/r-7f3a", "base": "main"}))
	if code != 200 || body["state"] != "refused" {
		t.Fatalf("%d %v", code, body)
	}
	for name, view := range map[string]map[string]any{"submit reply": body, "op show": opShow(g, str(body, "id"))} {
		den, _ := view["denial"].(map[string]any)
		if den == nil {
			t.Fatalf("%s: a refused op has no denial: %v", name, view)
		}
		mustDenial(t, den, CodeScopePath)
		if den["surface"] != "scope" || !strings.Contains(str(den, "why"), "acme/shop only") {
			t.Errorf("%s: denial %v", name, den)
		}
		if den["request"].(map[string]any)["possible"] != false {
			t.Errorf("%s: a scope refusal cannot be asked for: %v", name, den["request"])
		}
	}
	var refusals int
	for _, r := range g.led.rows(t, g.db, "op.result") {
		if a := r["attrs"].(map[string]any); a["factory.outcome"] == "refused" && a["factory.cause_code"] == CodeScopePath {
			refusals++
		}
	}
	if refusals != 1 {
		t.Errorf("%d refused op.result events with SCOPE_PATH, want 1", refusals)
	}
	if got := len(g.led.rows(t, g.db, "denial")); got != 1 {
		t.Errorf("%d denial events, want 1", got)
	}
}

func opShow(g *rig, id string) map[string]any {
	g.t.Helper()
	code, body, _ := g.call("GET", "/v0/ops/"+id, runTok, nil)
	if code != 200 {
		g.t.Fatalf("GET op %s: %d %v", id, code, body)
	}
	return body
}

func TestRecordKeepsTheRunScopeAndNothingForOthers(t *testing.T) {
	run := &Caller{Kind: KindRun, RunID: "r-7f3a", Project: "p", Repo: "acme/shop", Base: "main", Branch: "agent/r-7f3a", Paths: []string{"README.md", "docs/**"}}
	rec := &record{RequesterKind: KindRun, RunID: "r-7f3a", Project: "p", ScopeJSON: scopeJSON(run)}
	got := rec.caller()
	if got.Repo != "acme/shop" || got.Base != "main" || got.Branch != "agent/r-7f3a" || len(got.Paths) != 2 || got.Paths[1] != "docs/**" {
		t.Errorf("run scope lost: %+v", got)
	}
	if old := (&record{RequesterKind: KindRun, RunID: "r-7f3a", Project: "p"}).caller(); old.Repo != "" || old.Branch != "" {
		t.Errorf("a row without a stored scope must rebuild with none: %+v", old)
	}
	if s := scopeJSON(&Caller{Kind: KindOrchestrator, OrchID: "main"}); s != "" {
		t.Errorf("an orchestrator has no task scope, stored %q", s)
	}
}

// A failed op says why in chapd's log too (for pr.open: GitHub's own words).
func TestFailedOpIsLoggedWithItsError(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"pr.open"}})
	var buf bytes.Buffer
	g.svc.log = slog.New(slog.NewTextHandler(&buf, nil))
	g.ad.execute = func(context.Context, *Request) (Outcome, error) {
		return Outcome{Failed: true, Result: map[string]any{"error": "GitHub refused the pull request (422): Validation Failed (PullRequest custom: not all refs are readable)"}}, nil
	}
	code, body, _ := g.call("POST", "/v0/ops", runTok, prOpenBody("acme/shop",
		map[string]any{"title": "t", "head": "agent/r-7f3a", "base": "main"}))
	if code != 200 || body["state"] != "failed" {
		t.Fatalf("%d %v", code, body)
	}
	if !strings.Contains(buf.String(), "op failed") || !strings.Contains(buf.String(), "not all refs are readable") {
		t.Errorf("log: %s", buf.String())
	}
}
