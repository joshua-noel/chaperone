package keys

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/spec"
)

func newAdapter(t *testing.T, g *rig, enabled func(project, op string) bool) *IssueAdapter {
	t.Helper()
	cat, _, err := policy.Default()
	if err != nil {
		t.Fatal(err)
	}
	if enabled == nil {
		enabled = func(string, string) bool { return true }
	}
	a, err := NewIssueAdapter(IssueConfig{
		Store: g.s, Catalog: cat, Enabled: enabled,
		Project: func(p string) (ops.PRProject, bool) {
			if p == "acme-shop" {
				return ops.PRProject{Repo: "acme/shop", Base: "main"}, true
			}
			return ops.PRProject{}, false
		},
		Approval: func(_ context.Context, requestID string) (string, string, error) {
			var id, who string
			err := g.db.SQL().QueryRow(`SELECT approval_id, approver FROM approvals WHERE request_id = ?`, requestID).Scan(&id, &who)
			return id, who, err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func issueReq(g *rig, mutate func(p map[string]any)) *ops.Request {
	_, rq := g.approved()
	p := map[string]any{
		"holder": "scout", "holder_kind": "agent", "ops": []any{"pr.diff", "pr.view"}, "units": []any{"acme/shop"},
		"ttl_hours": float64(24), "rate_per_hour": float64(300),
	}
	if mutate != nil {
		mutate(p)
	}
	return &ops.Request{
		ID: rq, Op: OpIssue, Project: "acme-shop", Params: p,
		Target: spec.Target{Adapter: "chaperone", Ref: "key:scout"}, Caller: &ops.Caller{Kind: ops.KindOrchestrator, OrchID: "main"},
	}
}

func refusalOf(t *testing.T, err error) *ops.Refusal {
	t.Helper()
	var ref *ops.Refusal
	if !errors.As(err, &ref) {
		t.Fatalf("got %v, want a refusal", err)
	}
	return ref
}

func TestIssueRulesAreTableTested(t *testing.T) {
	g := newRig(t)
	a := newAdapter(t, g, nil)
	ctx := context.Background()
	day := float64(24)
	for _, c := range []struct {
		name   string
		mutate func(p map[string]any)
		ok     bool
		why    string // a substring of the refusal
	}{
		{"routine ops for 24 hours", nil, true, ""},
		{"routine ops for the maximum, 30 days", func(p map[string]any) { p["ttl_hours"] = 30 * day }, true, ""},
		{"routine ops for 31 days", func(p map[string]any) { p["ttl_hours"] = 31 * day }, false, "at most 30 days"},
		{"a risky op is allowed, ask-only, for 7 days", func(p map[string]any) {
			p["ops"], p["units"], p["ttl_hours"] = []any{"deploy"}, nil, 7*day
		}, true, ""},
		{"a risky op for 8 days (sensitive)", func(p map[string]any) {
			p["ops"], p["units"], p["ttl_hours"] = []any{"deploy"}, nil, 8*day
		}, false, "at most 7 days"},
		{"a risky op next to routine ones for 30 days", func(p map[string]any) {
			p["ops"], p["ttl_hours"] = []any{"deploy", "pr.view"}, 30*day
		}, false, "at most 7 days"},
		{"a critical op", func(p map[string]any) { p["ops"] = []any{"pr.view", "repo.settings"} }, false, "can never be in a key"},
		{"policy.activate", func(p map[string]any) { p["ops"] = []any{"policy.activate"} }, false, "can never be in a key"},
		{"keys.issue", func(p map[string]any) { p["ops"] = []any{"keys.issue"} }, false, "can never be in a key"},
		{"an op nobody knows", func(p map[string]any) { p["ops"] = []any{"nope.nope"} }, false, "unknown op"},
		{"an op with no unit kind", func(p map[string]any) { p["ops"], p["units"] = []any{"pr.merge"}, nil }, false, "names no unit"},
		{"a repository op with no repository", func(p map[string]any) { p["units"] = nil }, false, "names the repository"},
		{"a repository for no repository op", func(p map[string]any) { p["ops"] = []any{"health"} }, false, "none of the ops"},
		{"another repository", func(p map[string]any) { p["units"] = []any{"acme/other"} }, false, "cannot cover"},
		{"a rate of 301", func(p map[string]any) { p["rate_per_hour"] = float64(301) }, false, "lowered, never raised"},
		{"a lowered rate", func(p map[string]any) { p["rate_per_hour"] = float64(10) }, true, ""},
		{"an unknown holder kind", func(p map[string]any) { p["holder_kind"] = "robot" }, false, "person or an agent"},
		{"ops out of order", func(p map[string]any) { p["ops"] = []any{"pr.view", "pr.diff"} }, false, "sorted order"},
		{"a repeated op", func(p map[string]any) { p["ops"] = []any{"pr.view", "pr.view"} }, false, "sorted order"},
		{"an upper-case repository", func(p map[string]any) { p["units"] = []any{"Acme/Shop"} }, false, "lower case"},
		{"no lifetime", func(p map[string]any) { delete(p, "ttl_hours") }, false, "required"},
		{"a fractional lifetime", func(p map[string]any) { p["ttl_hours"] = 1.5 }, false, "whole number"},
		{"an owner in the params", func(p map[string]any) { p["owner"] = "someone" }, false, "unknown param"},
	} {
		res, err := a.Check(ctx, issueReq(g, c.mutate))
		if (err == nil) != c.ok {
			t.Errorf("%s: Check = %v, want ok=%v", c.name, err, c.ok)
			continue
		}
		if err != nil {
			if ref := refusalOf(t, err); !strings.Contains(ref.Why, c.why) {
				t.Errorf("%s: why = %q, want %q", c.name, ref.Why, c.why)
			}
			continue
		}
		if len(res.Evidence) != 1 || !strings.Contains(res.Evidence[0].Text, "It cannot approve anything") {
			t.Errorf("%s: the card's evidence: %+v", c.name, res.Evidence)
		}
	}
}

func TestOnlyTheOrchestratorMayAskForAKey(t *testing.T) {
	g := newRig(t)
	a := newAdapter(t, g, nil)
	for name, c := range map[string]*ops.Caller{
		"a key":    {Kind: ops.KindKey, KeyID: "k-0123456789abcdef", KeyOwner: "main"},
		"a run":    {Kind: ops.KindRun, RunID: "r-1"},
		"no one":   nil,
		"a ghost":  {Kind: "ghost"},
		"neither":  {},
		"a person": {Kind: "person"},
	} {
		req := issueReq(g, nil)
		req.Caller = c
		_, err := a.Check(context.Background(), req)
		if ref := refusalOf(t, err); !strings.Contains(ref.Why, "orchestrator token only") {
			t.Errorf("%s: %q", name, ref.Why)
		}
	}
}

func TestPolicyMustHaveTheOpsOnForTheProject(t *testing.T) {
	g := newRig(t)
	a := newAdapter(t, g, func(_, op string) bool { return op != "pr.diff" })
	_, err := a.Check(context.Background(), issueReq(g, nil))
	if ref := refusalOf(t, err); !strings.Contains(ref.Why, "pr.diff is disabled by policy") {
		t.Errorf("why = %q", ref.Why)
	}
}

func TestACardNamesWhatTheKeyDoesAndRiskyOpsAreMarked(t *testing.T) {
	g := newRig(t)
	a := newAdapter(t, g, nil)
	res, err := a.Check(context.Background(), issueReq(g, func(p map[string]any) {
		p["ops"], p["units"], p["ttl_hours"], p["holder_kind"], p["holder"] = []any{"deploy", "health"}, nil, float64(72), "person", "gilliano"
	}))
	if err != nil {
		t.Fatal(err)
	}
	text := res.Evidence[0].Text
	for _, want := range []string{`person "gilliano"`, "acting for main", "project acme-shop", "- deploy: ", "every use of the key still raises its own card",
		"- health: ", "3 days from the moment this card is approved", "300 calls an hour", "never shown"} {
		if !strings.Contains(text, want) {
			t.Errorf("the card does not say %q:\n%s", want, text)
		}
	}
	if strings.Count(text, "every use of the key still raises its own card") != 1 {
		t.Error("a routine op was marked risky")
	}
	if strings.Contains(text, "chap_key_") {
		t.Error("the card holds a key")
	}
}

func TestExecuteWritesTheKeyOnceAndRefusesAStoppedAgent(t *testing.T) {
	g := newRig(t)
	a := newAdapter(t, g, nil)
	ctx := context.Background()
	req := issueReq(g, nil)
	out, err := a.Execute(ctx, req)
	if err != nil || out.Failed {
		t.Fatalf("execute: %v %+v", err, out)
	}
	id, _ := out.Result["key_id"].(string)
	if id != KeyIDFor(req.ID) || out.ExternalRef != id {
		t.Errorf("result: %v", out.Result)
	}
	for k, v := range out.Result {
		if s, _ := v.(string); strings.Contains(s, Prefix+"A") || strings.HasPrefix(s, Prefix) {
			t.Errorf("result %s holds a key", k)
		}
	}
	if again, err := a.Execute(ctx, req); err != nil || again.ExternalRef != id || countKeys(t, g.db) != 1 {
		t.Errorf("a retried execution made another key: %v %v", err, again)
	}
	got, _ := g.s.Get(ctx, id)
	if got.GrantedBy != "approver.operator" || got.Owner != "main" || got.Holder != "scout" || got.State != "granted" {
		t.Errorf("row: %+v", got)
	}
	// Stop the agent by hand: a new request for it fails at the check, and a late execution fails closed.
	if _, _, err := g.s.Claim(ctx, id, "orchestrator:main"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.s.Revoke(ctx, id, "orchestrator:main", true); err != nil {
		t.Fatal(err)
	}
	second := issueReq(g, nil)
	if _, err := a.Check(ctx, second); err == nil || !strings.Contains(err.Error(), "stopped by a human: ask your owner") {
		t.Errorf("check for a stopped agent: %v", err)
	}
	out, err = a.Execute(ctx, second)
	if err != nil || !out.Failed || !strings.Contains(out.Result["error"].(string), "stopped by a human") {
		t.Errorf("execute for a stopped agent: %v %+v", err, out)
	}
	if countKeys(t, g.db) != 1 {
		t.Error("a key was made for a stopped agent")
	}
}

// Making a key is an approved act: with no signed approval for the op, the
// adapter makes no key, and the store refuses a grant that names no approval or
// no approver, whatever the caller says.
func TestExecuteWithoutASignedApprovalMakesNoKey(t *testing.T) {
	g := newRig(t)
	a := newAdapter(t, g, nil)
	ctx := context.Background()
	req := issueReq(g, nil)
	req.ID = "q-neverapproved1" // no card was ever made or signed for this request
	if out, err := a.Execute(ctx, req); err == nil {
		t.Errorf("an op with no approval made a key: %+v", out)
	}
	if n := countKeys(t, g.db); n != 0 {
		t.Errorf("%d keys exist after an op with no approval", n)
	}
	_, rq := g.approved()
	grant := Grant{
		Project: "acme-shop", Owner: "main", HolderKind: HolderPerson, Holder: "ci", Ops: []string{"pr.view"}, Units: []string{"acme/shop"},
		TTLHours: 24, Rate: 300, RequestID: rq, Claimant: "orchestrator:main",
	}
	if _, err := g.s.Issue(ctx, grant); err == nil {
		t.Error("the store made a key with no approval and no approver")
	}
	grant.ApprovalID = "a-whatever"
	if _, err := g.s.Issue(ctx, grant); err == nil {
		t.Error("the store made a key with no approver")
	}
	if n := countKeys(t, g.db); n != 0 {
		t.Errorf("%d keys exist after refused grants", n)
	}
}
