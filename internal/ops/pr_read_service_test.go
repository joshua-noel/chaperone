package ops

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
	"github.com/joshua-noel/chaperone/internal/redact"
)

// The pr read ops through the whole service: the shipped policy (on), a rollback (off), the
// token's scope, rate limits, the adapter against a fake GitHub, redaction and
// the ledger.

var readerTok = OrchPrefix + strings.Repeat("C", 43)

const readRepo = "example-org/storefront"

type readRig struct {
	*rig
	s *ghtest.Server
	r *ghtest.Repo
}

// newReadRig installs the real adapters over a fake GitHub. enable names the
// ops the policy pack turns on besides the shipped baseline, which turns the four read ops on.
func newReadRig(t *testing.T, enable ...string) *readRig {
	t.Helper()
	return newReadRigWith(t, rigOpts{enable: enable})
}

func newReadRigWith(t *testing.T, o rigOpts) *readRig {
	t.Helper()
	g := newRig(t, o)
	s := ghtest.New(t)
	c, err := gh.New(gh.Config{AppID: s.AppID(), Keys: gh.StaticKey{Key: s.Key()}, BaseURL: s.URL(), Now: s.Now})
	if err != nil {
		t.Fatal(err)
	}
	in := s.AddInstallation(41, "example-org", map[string]string{"pull_requests": "write", "checks": "write", "contents": "write", "metadata": "read"})
	r := in.AddRepo("storefront", "main")
	in.AddRepo("other", "main")
	for _, op := range PRReadOps {
		a, err := NewPRReadAdapter(op, PRReadConfig{
			GitHub: c, Tokens: &InstallationMinter{Client: c},
			Project: func(p string) (PRProject, bool) {
				if p == "storefront" {
					return PRProject{Repo: readRepo, Base: "main"}, true
				}
				return PRProject{}, false
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		g.svc.adapters[op] = a
	}
	g.ver.orchs[readerTok] = &Caller{Kind: KindOrchestrator, OrchID: "dashboard", Fingerprint: "0e0e0e0e",
		Projects: []string{"storefront"}, ScopeOps: PRReadOps}
	return &readRig{rig: g, s: s, r: r}
}

func (g *readRig) ask(token, op string, n int, params map[string]any) (int, map[string]any, http.Header) {
	return g.call("POST", "/v0/ops", token, map[string]any{
		"op": op, "project": "storefront", "target": map[string]any{"adapter": "github", "ref": readRepo + "#" + strconv.Itoa(n)}, "params": params,
	})
}

func (g *readRig) openPR(branch string, o ghtest.PROptions) (int, string) {
	g.r.Branch(branch, "main")
	head := g.r.Commit(branch)
	o.Head, o.Base, o.Title = branch, "main", "feat: "+branch
	return g.r.OpenPR(o), head
}

func result(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	res, ok := body["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result in %v", body)
	}
	return res
}

// The shipped baseline turns the four read ops on: with nothing enabled by the test, an orchestrator whose
// token lists them reads the pull request.
func TestPRReadOpsAreOnInTheShippedBaseline(t *testing.T) {
	g := newReadRig(t) // nothing enabled by the test: the shipped pack
	n, _ := g.openPR("agent/a", ghtest.PROptions{})
	for _, op := range PRReadOps {
		if st, body, _ := g.ask(readerTok, op, n, map[string]any{}); st != http.StatusOK || str(body, "outcome") != "succeeded" {
			t.Errorf("%s: %d %v", op, st, body)
		}
	}
}

// A rollback (the four lines set back to `enabled: false`, chapd reinstalled) leaves them refused as disabled,
// without a request to GitHub.
func TestPRReadOpsAreRefusedWhenThePolicyTurnsThemOff(t *testing.T) {
	g := newReadRigWith(t, rigOpts{disable: PRReadOps})
	n, _ := g.openPR("agent/a", ghtest.PROptions{})
	for _, op := range PRReadOps {
		st, body, _ := g.ask(readerTok, op, n, map[string]any{})
		if st != http.StatusForbidden {
			t.Errorf("%s: %d %v", op, st, body)
			continue
		}
		mustDenial(t, body, "OP_DISABLED")
		if !strings.Contains(str(body, "why"), op+" is disabled by policy") {
			t.Errorf("%s why = %q", op, body["why"])
		}
	}
	if len(g.s.Requests()) != 0 {
		t.Errorf("a disabled op reached GitHub: %v", g.s.Requests())
	}
}

func TestPRReadOpsAllowedAndLedgered(t *testing.T) {
	g := newReadRig(t, PRReadOps...)
	n, head := g.openPR("agent/a", ghtest.PROptions{Body: "The body.", Author: "octo", Labels: []string{"bug"}})
	g.r.SetFiles(n, ghtest.File{Filename: "a.go", Additions: 2, Deletions: 1, Patch: "@@ -1 +1 @@\n-a\n+b"})
	g.r.SetCheck(head, ghtest.Check{Name: "verify", AppID: gh.GitHubActionsAppID, Status: "completed", Conclusion: "success"})

	// The shipped manual lists them as routine.
	for _, op := range PRReadOps {
		if e, ok := g.engine.Catalog().Lookup(op); !ok || e.Class != "routine" || e.Surface != "op" {
			t.Errorf("catalog entry of %s: %+v", op, e)
		}
	}

	st, body, _ := g.ask(readerTok, OpPRView, n, map[string]any{})
	if st != 200 || body["state"] != "succeeded" || !strings.Contains(str(body, "external_ref"), "/pull/1") {
		t.Fatalf("pr.view: %d %v", st, body)
	}
	if res := result(t, body); res["title"] != "feat: agent/a" || res["body"] != "The body." || res["author"] != "octo" {
		t.Errorf("pr.view result: %v", res)
	}
	st, body, _ = g.ask(readerTok, OpPRDiff, n, map[string]any{"expected_head_sha": head})
	if res := result(t, body); st != 200 || !strings.Contains(str(res, "diff"), "+b\n") || res["head_sha"] != head {
		t.Fatalf("pr.diff: %d %v", st, body)
	}
	st, body, _ = g.ask(readerTok, OpPRChecks, n, map[string]any{})
	if res := result(t, body); st != 200 || res["summary"].(map[string]any)["passed"] != float64(1) {
		t.Fatalf("pr.checks: %d %v", st, body)
	}
	st, body, _ = g.ask(readerTok, OpPRFiles, n, map[string]any{"page": 1, "per_page": 10})
	if res := result(t, body); st != 200 || res["total"] != float64(1) || len(res["files"].([]any)) != 1 {
		t.Fatalf("pr.files: %d %v", st, body)
	}

	// Ledger: per op one op.request and one op.result from the orchestrator, with no run id and no result body
	// (the fake ledger validates each event against the spec schema).
	reqs, results := g.led.rows(t, g.db, "op.request"), g.led.rows(t, g.db, "op.result")
	if len(reqs) != 4 || len(results) != 4 || len(g.led.rows(t, g.db, "denial")) != 0 {
		t.Fatalf("ledger: %d op.request, %d op.result, want 4 and 4: %v", len(reqs), len(results), g.led.rows(t, g.db, ""))
	}
	for i, op := range PRReadOps {
		for _, e := range []map[string]any{reqs[i], results[i]} {
			a := e["attrs"].(map[string]any)
			if a["factory.requester.kind"] != KindOrchestrator || e["run_id"] != "" || e["orch"] != "dashboard" || e["project"] != "storefront" {
				t.Errorf("event %v of %s: %v", e["name"], op, e)
			}
			if strings.Contains(strings.ToLower(e["body"].(string)+" "+strings.Join(attrStrings(a), " ")), "the body.") {
				t.Errorf("%s: the ledger carries the pull request's text: %v", op, e)
			}
		}
		ra, sa := reqs[i]["attrs"].(map[string]any), results[i]["attrs"].(map[string]any)
		if ra["factory.op"] != op || ra["factory.reversibility"] != "reversible" || sa["factory.request_id"] != ra["factory.request_id"] || sa["factory.outcome"] != "succeeded" {
			t.Errorf("%s: request event %v, result event %v", op, ra, sa)
		}
	}
	if n := g.s.LiveTokens(); n != 0 {
		t.Errorf("%d GitHub tokens left live", n)
	}
	for _, r := range g.s.Requests() {
		if r.Method != "GET" && !strings.Contains(r.Path, "installation/token") && !strings.Contains(r.Path, "access_tokens") {
			t.Errorf("a read op sent %s %s", r.Method, r.Path)
		}
	}
}

func attrStrings(a map[string]any) []string {
	var out []string
	for _, v := range a {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// A read is never replayed from an earlier op: each ask reads GitHub again.
func TestPRReadIsFreshEveryTime(t *testing.T) {
	g := newReadRig(t, OpPRView)
	n, _ := g.openPR("agent/a", ghtest.PROptions{})
	_, body, _ := g.ask(readerTok, OpPRView, n, map[string]any{})
	first := str(body, "id")
	if result(t, body)["mergeable"] != true {
		t.Fatalf("%v", body)
	}
	g.r.SetConflict(n, true)
	_, body, _ = g.ask(readerTok, OpPRView, n, map[string]any{})
	if str(body, "id") == first || result(t, body)["mergeable"] != false {
		t.Errorf("the second read is the first one again: %v", body)
	}
}

func TestPRReadDryRunTouchesNothing(t *testing.T) {
	g := newReadRig(t, PRReadOps...)
	n, _ := g.openPR("agent/a", ghtest.PROptions{})
	st, body, _ := g.call("POST", "/v0/ops", readerTok, map[string]any{
		"op": OpPRDiff, "project": "storefront", "dry_run": true,
		"target": map[string]any{"adapter": "github", "ref": readRepo + "#" + strconv.Itoa(n)}, "params": map[string]any{},
	})
	if st != 200 || body["type"] != "dry_run" || body["would_allow"] != true || body["class"] != "routine" {
		t.Fatalf("dry run: %d %v", st, body)
	}
	if len(g.s.Requests()) != 0 {
		t.Errorf("a dry run reached GitHub: %v", g.s.Requests())
	}
	if n := opCount(t, g.db, "op = ?", OpPRDiff); n != 0 {
		t.Errorf("a dry run left %d op rows", n)
	}
}

func TestPRReadOpsPolicyDenials(t *testing.T) {
	g := newReadRig(t, PRReadOps...)
	n, _ := g.openPR("agent/a", ghtest.PROptions{})
	before := len(g.led.rows(t, g.db, "denial"))

	st, body, _ := g.ask(readerTok, OpPRView, n, map[string]any{})
	if st != 200 {
		t.Fatal(body)
	}
	// Another repository of the same installation: refused before GitHub is asked.
	st, body, _ = g.call("POST", "/v0/ops", readerTok, map[string]any{
		"op": OpPRView, "project": "storefront", "target": map[string]any{"adapter": "github", "ref": "example-org/other#1"}, "params": map[string]any{},
	})
	if st != http.StatusForbidden {
		t.Fatalf("other repo: %d %v", st, body)
	}
	mustDenial(t, body, "SCOPE_PATH")
	// Unknown param, bad head.
	st, body, _ = g.ask(readerTok, OpPRDiff, n, map[string]any{"patch": true})
	mustDenial(t, body, "OP_PARAMS_INVALID")
	st, body, _ = g.ask(readerTok, OpPRDiff, n, map[string]any{"expected_head_sha": "main"})
	mustDenial(t, body, "OP_PARAMS_INVALID")
	// Outside the token: a token that holds only pr.view has no pr.diff; another project is not its project.
	g.ver.orchs[readerTok].ScopeOps = []string{OpPRView}
	st, body, _ = g.ask(readerTok, OpPRDiff, n, map[string]any{})
	mustDenial(t, body, "OP_NOT_IN_TOKEN")
	st, body, _ = g.call("POST", "/v0/ops", readerTok, map[string]any{
		"op": OpPRView, "project": "acme-shop", "target": map[string]any{"adapter": "github", "ref": "acme/shop#1"}, "params": map[string]any{},
	})
	mustDenial(t, body, "OP_NOT_IN_TOKEN")
	// Not for a run, even one whose token names the op: no profile ceiling lists them.
	for _, op := range PRReadOps {
		g.ver.runs[runTok].TokenOps = append(g.ver.runs[runTok].TokenOps, op)
		st, body, _ = g.call("POST", "/v0/ops", runTok, map[string]any{
			"op": op, "target": map[string]any{"adapter": "github", "ref": "acme/shop#1"}, "params": map[string]any{},
		})
		mustDenial(t, body, "OP_NOT_IN_TOKEN")
	}
	// Not for the main orchestrator unless its scope says so.
	st, body, _ = g.call("POST", "/v0/ops", orchTok, map[string]any{
		"op": OpPRView, "project": "acme-shop", "target": map[string]any{"adapter": "github", "ref": "acme/shop#1"}, "params": map[string]any{},
	})
	mustDenial(t, body, "OP_NOT_IN_TOKEN")
	_ = st

	if got := len(g.led.rows(t, g.db, "denial")) - before; got != 10 {
		t.Errorf("%d denials ledgered, want 10", got)
	}
	if n := g.s.Count("GET", "/pulls/"); n != 1 {
		t.Errorf("%d reads of a pull request: only the allowed pr.view may have read", n)
	}
}

func TestPRReadRateLimits(t *testing.T) {
	g := newReadRig(t, PRReadOps...)
	eff := g.engine.For("storefront")
	n, _ := g.openPR("agent/a", ghtest.PROptions{})
	for _, op := range PRReadOps {
		if eff.Rate(op) < 1 || eff.RateHour(op) < eff.Rate(op) {
			t.Errorf("%s: %d per minute, %d per hour", op, eff.Rate(op), eff.RateHour(op))
		}
	}
	// The diff is the dearest read (two GitHub calls and up to 256 KiB): its minute rate is the smallest.
	perMin := eff.Rate(OpPRDiff)
	for i := range perMin {
		if st, body, _ := g.ask(readerTok, OpPRDiff, n, map[string]any{}); st != 200 {
			t.Fatalf("call %d: %d %v", i+1, st, body)
		}
	}
	st, body, hdr := g.ask(readerTok, OpPRDiff, n, map[string]any{})
	if st != http.StatusTooManyRequests || hdr.Get("Retry-After") == "" || !strings.Contains(str(body, "why"), "per minute") {
		t.Fatalf("over the minute rate: %d %v", st, body)
	}
	mustDenial(t, body, "OP_POLICY_REFUSED")
	// The cap is per op: another op of the same caller still passes.
	if st, body, _ := g.ask(readerTok, OpPRView, n, map[string]any{}); st != 200 {
		t.Errorf("pr.view after the diff limit: %d %v", st, body)
	}
	g.advance(61e9)
	if st, body, _ := g.ask(readerTok, OpPRDiff, n, map[string]any{}); st != 200 {
		t.Errorf("a minute later: %d %v", st, body)
	}
}

// What a person wrote in a pull request may hold a secret: chapd stores no result that does, and nothing of it
// reaches the caller, the op row or the ledger.
func TestPRReadNeverReturnsASecret(t *testing.T) {
	g := newReadRig(t, PRReadOps...)
	g.svc.redactor = redact.NewRegistry()
	secret := "ghp_" + strings.Repeat("a1B2", 10)
	n, head := g.openPR("agent/a", ghtest.PROptions{Title: "x", Body: "my token is " + secret})
	g.r.SetFiles(n, ghtest.File{Filename: ".env", Patch: "@@ -0,0 +1 @@\n+TOKEN=" + secret})

	for _, op := range []string{OpPRView, OpPRDiff} {
		st, body, _ := g.ask(readerTok, op, n, map[string]any{})
		res := result(t, body)
		if st != 200 || res["blocked"] != "REDACTION_BLOCKED" || len(res) != 1 {
			t.Errorf("%s: %d %v", op, st, body)
		}
		// Read back through the op route too.
		_, again, _ := g.call("GET", "/v0/ops/"+str(body, "id"), readerTok, nil)
		if result(t, again)["blocked"] != "REDACTION_BLOCKED" {
			t.Errorf("%s stored: %v", op, again)
		}
	}
	// Files and checks hold names, not file contents: this one has no secret in it and passes.
	if st, body, _ := g.ask(readerTok, OpPRFiles, n, map[string]any{}); st != 200 || result(t, body)["blocked"] != nil {
		t.Errorf("pr.files: %d %v", st, body)
	}
	if st, body, _ := g.ask(readerTok, OpPRChecks, n, map[string]any{"expected_head_sha": head}); st != 200 || result(t, body)["blocked"] != nil {
		t.Errorf("pr.checks: %d %v", st, body)
	}
	var stored string
	if err := g.db.SQL().QueryRow(`SELECT group_concat(COALESCE(result_json,''), ' ') FROM ops`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, secret) {
		t.Error("the ops table holds the secret")
	}
	for _, e := range g.led.rows(t, g.db, "") {
		if strings.Contains(e["body"].(string), secret) || strings.Contains(strings.Join(attrStrings(e["attrs"].(map[string]any)), " "), secret) {
			t.Errorf("the ledger holds the secret: %v", e)
		}
	}
}
