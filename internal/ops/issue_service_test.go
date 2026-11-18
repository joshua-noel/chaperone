package ops

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
)

// The issue ops through the whole service: token scope, policy pack, rate
// limits, the adapter against a fake GitHub, and the ledger.

var watcherTok = OrchPrefix + strings.Repeat("B", 43)

const (
	issueRepo  = "example-org/storefront"
	issueLabel = "source:error-watcher"
)

type issueRig struct {
	*rig
	s *ghtest.Server
	r *ghtest.Repo
}

func newIssueRig(t *testing.T) *issueRig {
	t.Helper()
	g := newRig(t, rigOpts{}) // the shipped baseline: issue ops are on
	s := ghtest.New(t)
	c, err := gh.New(gh.Config{AppID: s.AppID(), Keys: gh.StaticKey{Key: s.Key()}, BaseURL: s.URL(), Now: s.Now})
	if err != nil {
		t.Fatal(err)
	}
	in := s.AddInstallation(21, "example-org", map[string]string{"issues": "write", "metadata": "read"})
	r := in.AddRepo("storefront", "main")
	in.AddRepo("other", "main")
	for _, op := range []string{OpIssueOpen, OpIssueComment, OpIssueReopen} {
		a, err := NewIssueAdapter(op, IssueConfig{
			GitHub: c, Tokens: &InstallationMinter{Client: c},
			Project: func(p string) (PRProject, bool) {
				if p == "storefront" {
					return PRProject{Repo: issueRepo, Base: "main"}, true
				}
				return PRProject{}, false
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		g.svc.adapters[op] = a
	}
	// The error watcher's token: three ops, one project, nothing else.
	g.ver.orchs[watcherTok] = &Caller{Kind: KindOrchestrator, OrchID: "error-watcher", Fingerprint: "0f0f0f0f",
		Projects: []string{"storefront"}, ScopeOps: []string{OpIssueOpen, OpIssueComment, OpIssueReopen}}
	return &issueRig{rig: g, s: s, r: r}
}

func (g *issueRig) ask(token, op, ref string, params map[string]any) (int, map[string]any, http.Header) {
	return g.call("POST", "/v0/ops", token, map[string]any{
		"op": op, "project": "storefront", "target": map[string]any{"adapter": "github", "ref": ref}, "params": params,
	})
}

func (g *issueRig) open(title string, labels ...any) (int, map[string]any, http.Header) {
	return g.ask(watcherTok, OpIssueOpen, issueRepo, map[string]any{"title": title, "labels": labels})
}

func TestIssueOpsAllowedAndLedgered(t *testing.T) {
	g := newIssueRig(t)

	st, body, _ := g.open("TypeError in /api/orders", issueLabel, "bug")
	if st != 200 || body["state"] != "succeeded" || !strings.Contains(str(body, "external_ref"), "/issues/1") {
		t.Fatalf("issue.open: %d %v", st, body)
	}
	v, _ := g.r.Issue(1)
	if v.Title != "TypeError in /api/orders" || len(v.Labels) != 2 {
		t.Fatalf("issue on GitHub: %+v", v)
	}
	st, body, _ = g.ask(watcherTok, OpIssueComment, issueRepo+"#1", map[string]any{"body": "seen 3 more times"})
	if st != 200 || body["state"] != "succeeded" {
		t.Fatalf("issue.comment: %d %v", st, body)
	}
	g.r.CloseIssue(1)
	st, body, _ = g.ask(watcherTok, OpIssueReopen, issueRepo+"#1", map[string]any{})
	if st != 200 || body["state"] != "succeeded" {
		t.Fatalf("issue.reopen: %d %v", st, body)
	}
	if v, _ = g.r.Issue(1); v.State != "open" || len(v.Comments) != 1 {
		t.Errorf("issue after: %+v", v)
	}

	// Ledger: per op one op.request and one op.result, from the orchestrator
	// "error-watcher", with no run id (the fake ledger also validates each
	// event against the spec schema).
	reqs, results := g.led.rows(t, g.db, "op.request"), g.led.rows(t, g.db, "op.result")
	if len(reqs) != 3 || len(results) != 3 || len(g.led.rows(t, g.db, "denial")) != 0 {
		t.Fatalf("ledger: %d op.request, %d op.result, want 3 and 3: %v", len(reqs), len(results), g.led.rows(t, g.db, ""))
	}
	for i, op := range []string{OpIssueOpen, OpIssueComment, OpIssueReopen} {
		for _, e := range []map[string]any{reqs[i], results[i]} {
			a := e["attrs"].(map[string]any)
			if a["factory.requester.kind"] != KindOrchestrator || e["run_id"] != "" || e["orch"] != "error-watcher" || e["project"] != "storefront" {
				t.Errorf("event %v of %s: %v", e["name"], op, e)
			}
		}
		ra, sa := reqs[i]["attrs"].(map[string]any), results[i]["attrs"].(map[string]any)
		if ra["factory.op"] != op || ra["factory.reversibility"] == nil || sa["factory.request_id"] != ra["factory.request_id"] {
			t.Errorf("%s: request event %v, result event %v", op, ra, sa)
		}
		if sa["factory.outcome"] != "succeeded" {
			t.Errorf("%s result: %v", op, sa)
		}
	}
	if n := g.s.LiveTokens(); n != 0 {
		t.Errorf("%d GitHub tokens left live", n)
	}
}

func TestIssueOpsPolicyDenials(t *testing.T) {
	g := newIssueRig(t)
	own := g.r.AddIssue(ghtest.IssueOptions{Title: "watcher's", Labels: []string{issueLabel}, Closed: true})
	human := g.r.AddIssue(ghtest.IssueOptions{Title: "a person's", Labels: []string{"bug"}, Closed: true})

	denied := 0
	deny := func(name string, st int, body map[string]any, cause string, why string) {
		t.Helper()
		denied++
		if st != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403: %v", name, st, body)
			return
		}
		mustDenial(t, body, cause)
		if !strings.Contains(str(body, "why"), why) {
			t.Errorf("%s: why = %q, want it to contain %q", name, body["why"], why)
		}
		if body["orchestrator_id"] != "error-watcher" || body["run_id"] != nil {
			t.Errorf("%s: denial identity: %v", name, body)
		}
	}

	st, body, _ := g.open("no label", "bug")
	deny("open without the label", st, body, "OP_POLICY_REFUSED", issueLabel)
	st, body, _ = g.ask(watcherTok, OpIssueOpen, "example-org/other", map[string]any{"title": "x", "labels": []any{issueLabel}})
	deny("open in another repo", st, body, "SCOPE_PATH", "example-org/other")
	st, body, _ = g.ask(watcherTok, OpIssueComment, issueRepo+"#"+strconv.Itoa(human), map[string]any{"body": "x"})
	deny("comment on an unlabelled issue", st, body, "OP_POLICY_REFUSED", issueLabel)
	st, body, _ = g.ask(watcherTok, OpIssueReopen, issueRepo+"#"+strconv.Itoa(human), map[string]any{})
	deny("reopen an unlabelled issue", st, body, "OP_POLICY_REFUSED", issueLabel)
	st, body, _ = g.ask(watcherTok, OpIssueReopen, "example-org/other#1", map[string]any{})
	deny("reopen in another repo", st, body, "SCOPE_PATH", "example-org/other")

	// Outside the token: the watcher's token has no pr.merge, and no other project.
	st, body, _ = g.ask(watcherTok, "pr.merge", "example-org/storefront#214", map[string]any{"base": "main", "head_sha": sha1, "method": "squash"})
	mustDenial(t, body, "OP_NOT_IN_TOKEN")
	st, body, _ = g.call("POST", "/v0/ops", watcherTok, map[string]any{
		"op": OpIssueOpen, "project": "acme-shop", "target": map[string]any{"adapter": "github", "ref": "acme/shop"},
		"params": map[string]any{"title": "x", "labels": []any{issueLabel}},
	})
	mustDenial(t, body, "OP_NOT_IN_TOKEN")
	// Not for a run, even one whose token names the op: the profile ceiling has none of them.
	g.ver.runs[runTok].TokenOps = append(g.ver.runs[runTok].TokenOps, OpIssueOpen)
	st, body, _ = g.call("POST", "/v0/ops", runTok, map[string]any{
		"op": OpIssueOpen, "target": map[string]any{"adapter": "github", "ref": "acme/shop"},
		"params": map[string]any{"title": "x", "labels": []any{issueLabel}},
	})
	mustDenial(t, body, "OP_NOT_IN_TOKEN")
	// Not for the main orchestrator unless its scope says so.
	st, body, _ = g.call("POST", "/v0/ops", orchTok, map[string]any{
		"op": OpIssueOpen, "project": "acme-shop", "target": map[string]any{"adapter": "github", "ref": "acme/shop"},
		"params": map[string]any{"title": "x", "labels": []any{issueLabel}},
	})
	mustDenial(t, body, "OP_NOT_IN_TOKEN")
	_ = st

	if g.s.Count("POST", "/issues") != 0 || g.s.Count("PATCH", "/issues") != 0 || g.r.IssueCount() != 2 {
		t.Errorf("a denied request wrote to GitHub")
	}
	if own == 0 || len(g.led.rows(t, g.db, "denial")) < denied {
		t.Errorf("denials are not all ledgered: %v", g.led.rows(t, g.db, "denial"))
	}
	for _, e := range g.led.rows(t, g.db, "op.result") {
		t.Errorf("a denied request has an op.result: %v", e)
	}
}

func TestIssueOpenRateLimit(t *testing.T) {
	g := newIssueRig(t)
	eff := g.engine.For("storefront")
	perMin, perHour := eff.Rate(OpIssueOpen), eff.RateHour(OpIssueOpen)
	if perHour != 20 || perMin < 1 || perMin > perHour {
		t.Fatalf("the shipped policy has %d per minute and %d per hour for issue.open, want a per-hour cap of 20", perMin, perHour)
	}
	n := 0
	open := func() (int, map[string]any, http.Header) {
		n++
		return g.open("error "+strconv.Itoa(n), issueLabel)
	}

	// The per-minute rate: one more than allowed in a minute is refused, a minute later it passes.
	for range perMin {
		if st, body, _ := open(); st != 200 {
			t.Fatalf("call %d: %d %v", n, st, body)
		}
	}
	st, body, hdr := open()
	n-- // refused: not a call that counts
	if st != http.StatusTooManyRequests || hdr.Get("Retry-After") == "" || !strings.Contains(str(body, "why"), "per minute") {
		t.Fatalf("over the minute rate: %d %v", st, body)
	}
	mustDenial(t, body, "OP_POLICY_REFUSED")

	// Up to 20 in the hour, then no more until the oldest leaves the window.
	for n < perHour {
		g.advance(61 * time.Second)
		for range perMin {
			if n == perHour {
				break
			}
			if st, body, _ := open(); st != 200 {
				t.Fatalf("call %d: %d %v", n, st, body)
			}
		}
	}
	g.advance(61 * time.Second)
	st, body, hdr = open()
	n--
	if st != http.StatusTooManyRequests || !strings.Contains(str(body, "why"), "per hour") || hdr.Get("Retry-After") == "" {
		t.Fatalf("the 21st call in an hour: %d %v", st, body)
	}
	mustDenial(t, body, "OP_POLICY_REFUSED")
	if got := g.r.IssueCount(); got != perHour {
		t.Errorf("%d issues on GitHub, want %d", got, perHour)
	}
	// An hour after the first call, the slot is free again.
	g.advance(time.Hour)
	if st, body, _ := open(); st != 200 {
		t.Fatalf("after the hour: %d %v", st, body)
	}
}
