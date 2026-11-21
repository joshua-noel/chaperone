package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/connectors/linear/lineartest"
)

// The operator board is team SHOP with the label claude; the issue ops work in
// the team AGT on issues labelled agent.
const issuesProject = `project: acme-shop
linear:
  team: SHOP
  label: claude
  states: [Blocked]
  issues:
    team: AGT
    label: agent
    states: [In Progress, Done]
    labels: [bug]
    link_hosts: [github.com]
    comment: true
`

func newIssueE2E(t *testing.T) *linearE2E {
	t.Helper()
	l := newLinearE2EWith(t, true, true, issuesProject, true)
	l.fake.AddIssue(lineartest.Issue{Identifier: "AGT-1", TeamKey: "AGT", Title: "Fix the cart total", Labels: []string{"agent"}})
	l.fake.AddIssue(lineartest.Issue{Identifier: "AGT-2", TeamKey: "AGT", Title: "Landed from the operator board", Labels: []string{"agent", "claude"}})
	l.fake.DefineLabel("bug", "")
	return l
}

// Through the whole pipeline (token, policy, catalog, adapter, ledger): the issue
// ops work on the issue team and never reach the operator board.
func TestIssueOpsThroughChapdReachTheIssueTeamOnly(t *testing.T) {
	l := newIssueE2E(t)

	for _, c := range []struct {
		op, ref string
		params  map[string]any
	}{
		{"issue.get", "AGT-1", nil},
		{"issue.list", "team", nil},
		{"issue.comment", "AGT-1", map[string]any{"body": "Looking at it."}},
		{"issue.label", "AGT-1", map[string]any{"add": "bug"}},
		{"issue.move", "AGT-1", map[string]any{"state": "In Progress"}},
		{"issue.link", "AGT-1", map[string]any{"url": "https://github.com/example-org/storefront/pull/9"}},
	} {
		st, op := l.ask(c.op, c.ref, c.params)
		if st != 200 || op["state"] != "succeeded" {
			t.Fatalf("%s: %d %v", c.op, st, op)
		}
		evs := l.events(op["id"].(string))
		if len(evs) != 2 || attr(evs[0], "factory.op") != c.op || attr(evs[1], "factory.outcome") != "succeeded" {
			t.Fatalf("%s events: %+v", c.op, evs)
		}
	}
	got := l.fake.Issue("AGT-1")
	if got.State != "In Progress" || !slices.Equal(got.Labels, []string{"agent", "bug"}) || len(got.Comments) != 1 || len(got.Links) != 1 {
		t.Fatalf("AGT-1 after the ops: %+v", got)
	}
	// The list shows AGT-1 and not the item that carries the operator-board label.
	_, op := l.ask("issue.list", "team", nil)
	var ids []string
	for _, it := range op["result"].(map[string]any)["items"].([]any) {
		ids = append(ids, it.(map[string]any)["identifier"].(string))
	}
	if !slices.Equal(ids, []string{"AGT-1"}) {
		t.Errorf("list: %v", ids)
	}

	// Every op refuses an operator-board item: by team, and by label in the issue team.
	for name, c := range map[string]struct {
		op, ref string
		params  map[string]any
	}{
		"get, intake team":      {"issue.get", "SHOP-1", nil},
		"comment, intake team":  {"issue.comment", "SHOP-1", map[string]any{"body": "hi"}},
		"move, intake team":     {"issue.move", "SHOP-1", map[string]any{"state": "Done"}},
		"list, the intake team": {"issue.list", "SHOP", nil},
		"comment, intake label": {"issue.comment", "AGT-2", map[string]any{"body": "hi"}},
		"label, intake label":   {"issue.label", "AGT-2", map[string]any{"add": "bug"}},
		"move, intake label":    {"issue.move", "AGT-2", map[string]any{"state": "Done"}},
		"link, intake label":    {"issue.link", "AGT-2", map[string]any{"url": "https://github.com/a/b"}},
	} {
		st, body := l.ask(c.op, c.ref, c.params)
		if st != 403 {
			t.Errorf("%s: status %d %v", name, st, body)
			continue
		}
		mustValidDenial(t, body, "OP_POLICY_REFUSED")
		if !strings.Contains(toJSONString(body), "intake_label_excluded") {
			t.Errorf("%s: the denial does not name the condition: %v", name, body)
		}
	}
	if a, b := l.fake.Issue("SHOP-1"), l.fake.Issue("AGT-2"); len(a.Comments) != 0 || a.State != "Todo" || len(b.Comments) != 0 || b.State != "Todo" || len(b.Links) != 0 || !slices.Equal(b.Labels, []string{"agent", "claude"}) {
		t.Errorf("an operator-board item changed: %+v / %+v", a, b)
	}
	// get of an operator-board item in the issue team: the op fails and returns none of its text.
	st, op := l.ask("issue.get", "AGT-2", nil)
	if st != 200 || op["state"] != "failed" || strings.Contains(toJSONString(op), "Landed from the operator board") {
		t.Errorf("get AGT-2: %d %v", st, op)
	}
}

// The intake ops keep working beside the issue ops, and issue.comment aimed at
// GitHub (no GitHub App in this rig) is not answered by the Linear adapter.
func TestIssueOpsDoNotDisturbTheIntakeOpsOrAnotherTarget(t *testing.T) {
	l := newIssueE2E(t)
	if st, op := l.ask("intake.comment", "SHOP-1", map[string]any{"body": "Picked up by the orchestrator"}); st != 200 || op["state"] != "succeeded" {
		t.Fatalf("intake.comment: %d %v", st, op)
	}
	sent := len(l.fake.Requests())
	st, body := l.call("POST", "/v0/ops", l.token, map[string]any{
		"op": "issue.comment", "project": "acme-shop", "target": map[string]any{"adapter": "github", "ref": "example-org/storefront#401"},
		"params": map[string]any{"body": "hi"},
	})
	if st != 400 && st != 403 {
		t.Fatalf("issue.comment for a GitHub target: %d %v", st, body)
	}
	if n := len(l.fake.Requests()); n != sent {
		t.Errorf("%d Linear requests were made for a GitHub target", n-sent)
	}
}

func toJSONString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// A project with no issues block: the shipped-on issue.comment name still does
// not reach Linear.
func TestIssueCommentIsRefusedForLinearWithoutTheIssuesBlock(t *testing.T) {
	l := newLinearE2EWith(t, true, true, intakeBlock, true)
	l.fake.AddIssue(lineartest.Issue{Identifier: "AGT-1", TeamKey: "AGT", Title: "x", Labels: []string{"agent"}})
	st, body := l.ask("issue.comment", "AGT-1", map[string]any{"body": "hi"})
	if st != 403 && st != 400 {
		t.Fatalf("status %d %v", st, body)
	}
	mustValidDenial(t, body, "OP_POLICY_REFUSED")
	if n := len(l.fake.Requests()); n != 0 {
		t.Errorf("%d requests reached Linear", n)
	}
}

// The review's case: an operator adds a linear.issues block only so that agents
// can read, with the shipped baseline in which issue.comment is on for GitHub.
// Linear comments stay off until the block says comment: true.
func TestAnIssuesBlockWithoutTheCommentSwitchDoesNotLetTokensCommentOnLinear(t *testing.T) {
	readOnly := strings.Replace(issuesProject, "    comment: true\n", "", 1)
	if readOnly == issuesProject {
		t.Fatal("the fixture has no comment switch to remove")
	}
	l := newLinearE2EWith(t, true, true, readOnly, true)
	l.fake.AddIssue(lineartest.Issue{Identifier: "AGT-1", TeamKey: "AGT", Title: "x", Labels: []string{"agent"}})
	st, body := l.ask("issue.comment", "AGT-1", map[string]any{"body": "hi"})
	if st != 403 && st != 400 {
		t.Fatalf("status %d %v", st, body)
	}
	mustValidDenial(t, body, "OP_POLICY_REFUSED")
	if !strings.Contains(toJSONString(body), "comment: true") {
		t.Errorf("the denial does not say what to set: %v", body)
	}
	if got := l.fake.Issue("AGT-1"); len(got.Comments) != 0 {
		t.Errorf("a comment was posted: %+v", got)
	}
}
