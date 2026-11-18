package console

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/runtoken"
)

// ---- access ----

func TestScreensNeedASession(t *testing.T) {
	sr := newScrRig(t)
	b := sr.browser(pcOrigin)
	for _, p := range []string{"/", "/catalog", "/ledger", "/runs", "/secrets"} {
		if rec := b.do("GET", p, nil, nil); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
			t.Errorf("GET %s signed out: %d %q", p, rec.Code, rec.Header().Get("Location"))
		}
	}
	for _, p := range []string{"/stop-all", "/runs/r-aaaa1/revoke", "/orchestrators/main/revoke", "/ledger/verify", "/secrets/request", "/secrets/a-x/commit", "/secrets/a-x/cancel"} {
		rec := b.do("POST", p, nil, map[string]string{"X-CSRF-Token": b.csrf(), "HX-Request": "true"})
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("HX-Redirect") != "/login" {
			t.Errorf("POST %s signed out: %d %q", p, rec.Code, rec.Header().Get("HX-Redirect"))
		}
	}
	// A POST without the CSRF token never reaches a handler.
	signed, _ := sr.signedIn()
	if rec := signed.do("POST", "/stop-all", nil, map[string]string{"X-CSRF-Token": "wrong"}); rec.Code != http.StatusForbidden {
		t.Errorf("stop-all with a wrong CSRF token: %d", rec.Code)
	}
	if rec := signed.do("GET", "/stop-all", nil, nil); rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotFound {
		t.Errorf("GET /stop-all: %d", rec.Code)
	}
}

func TestScreensRefuseHostAndOriginTricks(t *testing.T) {
	sr := newScrRig(t)
	b, _ := sr.signedIn()
	sr.seedRun("r-aaaa1", "acme-shop")
	for _, host := range []string{"evil.example", "127.0.0.1:55398"} {
		b2 := *b
		b2.host = host
		if rec := b2.do("POST", "/stop-all", nil, map[string]string{"X-CSRF-Token": b.csrf()}); rec.Code != http.StatusForbidden {
			t.Errorf("Host %s: %d", host, rec.Code)
		}
	}
	if st, _ := sr.runState("r-aaaa1"); st != "active" {
		t.Fatalf("a refused request revoked the run")
	}
}

// ---- home ----

func TestHomeScreen(t *testing.T) {
	sr := newScrRig(t)
	b, _ := sr.signedIn()
	sr.seedRun("r-aaaa1", "acme-shop")
	sr.seedRun("r-aaaa2", "acme-shop")
	card := sr.request(nil)
	sr.seedDenial("r-aaaa1", "acme-shop", "OP_DISABLED", "deploy pilot: OP_DISABLED <script>alert(1)</script>")
	sr.seedDenial("r-aaaa2", "acme-shop", "TOKEN_EXPIRED", "pr.merge acme/shop#4: TOKEN_EXPIRED")
	sr.seedOrchDenial("main", "acme-shop", "TOKEN_EXPIRED", "health: TOKEN_EXPIRED")
	sr.seedDenial("r-aaaa1", "acme-shop", "TOKEN_REVOKED", "pr.merge acme/shop#5: TOKEN_REVOKED")
	sr.seedOrchDenial("main", "acme-shop", "TOKEN_REVOKED", "health: TOKEN_REVOKED")
	sr.issueOrch("main")

	page := get(t, b, "/")
	mustHave(t, "home", page,
		"Signed in as operator", "Hello", // existing console behaviour
		`id="stop-all"`, `hx-post="/stop-all"`, "Stop all", "2 active", "hx-confirm=",
		"Pending approvals", "Agent r-7f3a (host-interim) wants to deploy commit", "acme-shop", card.Request.ExpiresAt[:4],
		"Recent denials", "OP_DISABLED", "run r-aaaa1",
		// plain words from the table the chap command line shares, not the bare code repeated as the "what"
		"the token has expired", "Next: the run&#39;s token has expired: stop and report to the orchestrator",
		"Next: the operator issues a new token: chapd orch issue -id main -project &lt;p&gt; -ops &lt;op,...&gt;", "pr.merge acme/shop#4",
		"Health", "Ledger", "Database", "Orchestrator token", "1 live", "Vault", "0 secrets", "test-1.2.3",
		`href="/approvals">Review and decide</a>`,
	)
	// The reason text of an agent never becomes markup.
	mustNotHave(t, "home", page, "<script>alert(1)</script>")
	// A revoked token says it was revoked or its run ended, with no re-issue step and no claim about the operator: a
	// run reports to the orchestrator, the orchestrator asks the operator.
	mustHave(t, "home", page,
		"Next: the token was revoked or its run has ended: stop and report to the orchestrator; do not re-issue or work around it",
		"Next: the token was revoked or its run has ended: stop; do not re-issue or work around it; ask the operator")
	mustNotHave(t, "home", page, "stopped by the operator", "starting the run again")
	mustHave(t, "home", page, "&lt;script&gt;alert(1)&lt;/script&gt;")
	// Health says OK in words.
	mustHave(t, "health row", rowWith(t, page, "Ledger"), "OK", "chain chaperone.test")
}

func TestHomeHealthShowsWhatIsBroken(t *testing.T) {
	sr := newScrRigOptsProjects(t)
	b, _ := sr.signedIn()
	page := get(t, b, "/")
	mustHave(t, "orchestrator", rowWith(t, page, "Orchestrator token"), "WARN", "no live token")
	mustHave(t, "policy", rowWith(t, page, "Policy"), "FAIL", "broken-proj")
	mustHave(t, "empty denials", page, "No denials have been recorded.", "Nothing is waiting for a decision.")

	nv := newScrRigOpts(t, false)
	nb, _ := nv.signedIn()
	mustHave(t, "no vault", rowWith(t, get(t, nb, "/"), "Vault"), "WARN", "not configured")
}

// newScrRigOptsProjects is a rig whose policy dir holds one invalid project file.
func newScrRigOptsProjects(t *testing.T) *scrRig {
	t.Helper()
	sr := newScrRig(t)
	if err := os.WriteFile(sr.polDir+"/broken-proj.yaml", []byte("project: broken-proj\nops: {health: {enabled: true}\nthis is not yaml"), 0o644); err != nil {
		t.Fatal(err)
	}
	sr.con.scr.cfg.Projects = append(sr.con.scr.cfg.Projects, "broken-proj")
	return sr
}

// ---- stop all ----

func TestStopAllRevokesEveryRunAndLogsOperatorStopAll(t *testing.T) {
	sr := newScrRig(t)
	b, _ := sr.signedIn()
	orchToken := sr.issueOrch("main")
	for _, id := range []string{"r-aaaa1", "r-aaaa2", "r-aaaa3"} {
		sr.seedRun(id, "acme-shop")
	}
	rec := hxPost(b, "/stop-all", url.Values{})
	if rec.Code != 200 {
		t.Fatalf("stop all: %d %s", rec.Code, rec.Body)
	}
	mustHave(t, "stop-all", rec.Body.String(), "All runs stopped", "3 run(s) revoked", "OPERATOR_STOP_ALL", `role="status"`)
	for _, id := range []string{"r-aaaa1", "r-aaaa2", "r-aaaa3"} {
		if st, cause := sr.runState(id); st != "ended" || cause != runtoken.StopOperatorStopAll {
			t.Errorf("run %s: state %s cause %s", id, st, cause)
		}
	}
	// The ledger says OPERATOR_STOP_ALL for each run, and the revoke is the operator's.
	var ends int
	for _, e := range sr.events("run.end") {
		if attrString(e, "factory.cause_code") == "OPERATOR_STOP_ALL" && attrString(e, "factory.outcome") == "killed" {
			ends++
		}
	}
	if ends != 3 {
		t.Errorf("%d run.end events carry OPERATOR_STOP_ALL, want 3", ends)
	}
	for _, e := range sr.events("token.revoke") {
		if attrString(e, "factory.revoke.reason") != "operator" {
			t.Errorf("token.revoke %+v", e.Attributes)
		}
	}
	if !strings.Contains(sr.logs.String(), "operator stop all") {
		t.Error("the operator log does not say that Stop all was pressed")
	}
	// Stop all ends runs, not the orchestrator.
	if _, err := sr.orch.Verify(context.Background(), orchToken); err != nil {
		t.Errorf("the orchestrator token after Stop all: %v", err)
	}
	// Nothing left to stop; and the report on the page agrees.
	rec = hxPost(b, "/stop-all", url.Values{})
	mustHave(t, "second stop", rec.Body.String(), "Nothing to stop")
	mustHave(t, "home after", get(t, b, "/"), "0 active")
	mustHave(t, "ledger shows it", get(t, b, "/ledger?event=run.end"), "OPERATOR_STOP_ALL")
}

// ---- runs ----

func TestRunsScreenListsAndRevokes(t *testing.T) {
	sr := newScrRig(t)
	b, _ := sr.signedIn()
	sr.seedRun("r-aaaa1", "acme-shop")
	sr.seedRun("r-aaaa2", "other-proj")
	page := get(t, b, "/runs")
	mustHave(t, "runs", page, "Active runs", "r-aaaa1", "r-aaaa2", "acme-shop", "other-proj", "code@1",
		`hx-post="/runs/r-aaaa1/revoke"`, `aria-label="Revoke run r-aaaa1"`, "hx-confirm=")
	mustHave(t, "no orchestrators", page, "No orchestrator token has been issued.")

	rec := hxPost(b, "/runs/r-aaaa1/revoke", url.Values{})
	if rec.Code != 200 {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	mustHave(t, "row after revoke", rec.Body.String(), "r-aaaa1", "ended: operator (OPERATOR_STOP_RUN)")
	mustNotHave(t, "row after revoke", rec.Body.String(), "hx-post")
	if st, cause := sr.runState("r-aaaa1"); st != "ended" || cause != "OPERATOR_STOP_RUN" {
		t.Errorf("run 1: %s %s", st, cause)
	}
	if st, _ := sr.runState("r-aaaa2"); st != "active" {
		t.Errorf("the other run was touched: %s", st)
	}
	after := get(t, b, "/runs")
	mustHave(t, "runs after", after, "Recently ended", "OPERATOR_STOP_RUN")
	mustNotHave(t, "runs after", after, `hx-post="/runs/r-aaaa1/revoke"`)

	// Unknown and malformed ids answer with a notice for the status region.
	rec = hxPost(b, "/runs/r-zzzz9/revoke", url.Values{})
	if rec.Code != 404 || rec.Header().Get("HX-Retarget") != "#runs-status" || !strings.Contains(rec.Body.String(), "No such run") {
		t.Errorf("unknown run: %d %q %s", rec.Code, rec.Header().Get("HX-Retarget"), rec.Body)
	}
	if rec = hxPost(b, "/runs/not-a-run/revoke", url.Values{}); rec.Code != 400 {
		t.Errorf("malformed run id: %d", rec.Code)
	}
}

func TestRevokeOrchestrator(t *testing.T) {
	sr := newScrRig(t)
	b, _ := sr.signedIn()
	token := sr.issueOrch("main")
	page := get(t, b, "/runs")
	mustHave(t, "orchestrators", page, "Orchestrator tokens", "main", "acme-shop", "health, pr.*", ">live<",
		`hx-post="/orchestrators/main/revoke"`, "Revoke orchestrator", "hx-confirm=")
	// The page shows the fingerprint, never the token.
	mustNotHave(t, "orchestrators", page, token, strings.TrimPrefix(token, runtoken.OrchPrefix))
	if _, err := sr.orch.Verify(context.Background(), token); err != nil {
		t.Fatal(err)
	}

	rec := hxPost(b, "/orchestrators/main/revoke", url.Values{})
	if rec.Code != 200 {
		t.Fatalf("revoke orchestrator: %d %s", rec.Code, rec.Body)
	}
	mustHave(t, "row after revoke", rec.Body.String(), "revoked", "by console")
	mustNotHave(t, "row after revoke", rec.Body.String(), "hx-post")
	// The very next request with the token is refused.
	if _, err := sr.orch.Verify(context.Background(), token); err == nil || !strings.Contains(err.Error(), "TOKEN_REVOKED") {
		t.Fatalf("the revoked token verified: %v", err)
	}
	if rec = hxPost(b, "/orchestrators/main/revoke", url.Values{}); rec.Code != 404 || !strings.Contains(rec.Body.String(), "has no live token") {
		t.Errorf("second revoke: %d %s", rec.Code, rec.Body)
	}
	if rec = hxPost(b, "/orchestrators/Not%20An%20Id/revoke", url.Values{}); rec.Code != 400 {
		t.Errorf("malformed id: %d", rec.Code)
	}
	mustHave(t, "page after", get(t, b, "/"), "WARN", "no live token")
}

// ---- catalog ----

func TestCatalogScreenIsReadOnly(t *testing.T) {
	sr := newScrRig(t)
	b, _ := sr.signedIn()
	cp, err := os.ReadFile("../../policy/chaperone-sandbox.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sr.polDir+"/chaperone-sandbox.yaml", cp, 0o644); err != nil {
		t.Fatal(err)
	}
	sr.con.scr.cfg.Projects = append(sr.con.scr.cfg.Projects, "chaperone-sandbox")
	// One request in the ops table gives the usage column something to count.
	now := time.Now().Unix()
	if _, err := sr.db.SQL().Exec(`INSERT INTO ops (id, state, op, project, target_adapter, target_ref, params_json, op_hash, requester_kind, requester_key,
		orchestrator_id, class, reversibility, policy_version, requested_at, expires_at, updated_at)
		VALUES ('q-000001', 'denied', 'health', 'acme-shop', 'wsl-host', 'pilot', '{}', 'sha256:00', 'orchestrator', 'orchestrator:main', 'main',
		'routine', 'reversible', 'v', ?, ?, ?)`, now, now+60, now); err != nil {
		t.Fatal(err)
	}

	page := get(t, b, "/catalog")
	mustHave(t, "catalog", html.UnescapeString(page), "Operations catalog", sr.pol.Baseline().BaselineVersion(), "acme-shop", "chaperone-sandbox",
		"secrets.write", "critical", "pr.merge", "gated", "deploy", "high", "Needs approval", "Requests", "Last request")
	// secrets.write is disabled and critical; pr.merge is enabled (6/min) in the baseline.
	mustHave(t, "secrets.write row", rowWith(t, page, "<code>secrets.write</code>"), "critical", "yes", "disabled")
	mustHave(t, "pr.merge row", rowWith(t, page, "<code>pr.merge</code>"), "enabled (6/min)")
	// The plain sentence about an op is under its name, in the row header: no column of its own to be pushed off the
	// right edge at 1440 px (review item 9), and it is the first thing a phone shows for the row.
	mustHave(t, "pr.merge sentence", rowWith(t, page, "<code>pr.merge</code>"), `<span class="op-what" id="op-what-pr.merge">`)
	// The row header's accessible name is only the op name; the sentence and usage line are its description (review P3).
	mustHave(t, "pr.merge header", page, `<th scope="row" aria-labelledby="op-pr.merge" aria-describedby="op-what-pr.merge"><span id="op-pr.merge"><code>pr.merge</code></span>`)
	if th := regexp.MustCompile(`(?s)<span id="op-pr\.merge">(.*?)</span>`).FindStringSubmatch(page); th == nil || th[1] != "<code>pr.merge</code>" {
		t.Fatalf("the name element of the pr.merge row header holds more than the op name: %v", th)
	}
	mustNotHave(t, "catalog", page, `<th scope="col">What it does</th>`)
	mustHave(t, "health row", rowWith(t, page, "<code>health</code>"), `<td data-label="Requests">1</td>`)
	// The project file's version is shown next to the project.
	eff := sr.pol.For("chaperone-sandbox")
	mustHave(t, "project", html.UnescapeString(rowWith(t, page, "chaperone-sandbox")), eff.Version)
	// Read-only: nothing on the page can change anything.
	mustNotHave(t, "catalog", page, "<form", "hx-post", "hx-put", "hx-delete", "<button", "<input", "<textarea")
}

// ---- ledger ----

func TestLedgerScreenSearchesByRunOpAndTime(t *testing.T) {
	sr := newScrRig(t)
	b, _ := sr.signedIn()
	sr.seedRun("r-aaaa1", "acme-shop")
	sr.seedRun("r-aaaa2", "acme-shop")
	sr.seedDenial("r-aaaa1", "acme-shop", "OP_DISABLED", "deploy pilot: OP_DISABLED")
	sr.seedDenial("r-aaaa2", "acme-shop", "OP_NOT_IN_TOKEN", "mail.send x: OP_NOT_IN_TOKEN")
	sr.request(nil) // op.request is not ledgered by the engine itself; the screens' own ops are
	if _, err := sr.runs.RevokeAll(context.Background(), runtoken.StopOperatorStopAll); err != nil {
		t.Fatal(err)
	}

	all := get(t, b, "/ledger")
	mustHave(t, "ledger", all, "Integrity", "Check integrity", `hx-post="/ledger/verify"`, "Search", "Newest events",
		"OP_DISABLED", "OP_NOT_IN_TOKEN", "run.end", "token.revoke", "Chain <code>chaperone.test</code>")
	// Newest first.
	if strings.Index(all, "run.end") > strings.Index(all, ">denial<") {
		t.Error("the newest events are not listed first")
	}

	byRun := get(t, b, "/ledger?run=r-aaaa1")
	mustHave(t, "by run", byRun, "Matching events", "OP_DISABLED")
	mustNotHave(t, "by run", byRun, "OP_NOT_IN_TOKEN")

	byEvent := get(t, b, "/ledger?event=denial")
	mustHave(t, "by event", byEvent, "OP_DISABLED", "OP_NOT_IN_TOKEN")
	mustNotHave(t, "by event", byEvent, "token.revoke")

	// By op: a ledgered operator op carries factory.op.
	if _, err := sr.orch.Issue(context.Background(), runtoken.IssueParams{ID: "main",
		Scope: runtoken.OrchScope{Projects: []string{"acme-shop"}, Ops: []string{"health"}}}); err != nil {
		t.Fatal(err)
	}
	byOp := get(t, b, "/ledger?op=orchestrator.issue")
	mustHave(t, "by op", byOp, "op.request", "orchestrator.issue")
	mustNotHave(t, "by op", byOp, "OP_DISABLED")
	mustHave(t, "by request", get(t, b, "/ledger?request="+attrString(sr.events("op.request")[0], "factory.request_id")), "op.request")

	// By time: the future matches nothing; the past does too.
	future := time.Now().UTC().Add(24 * time.Hour).Format(formTimeLayout)
	mustHave(t, "from future", get(t, b, "/ledger?from="+future), "No event matches.")
	past := time.Now().UTC().Add(-24 * time.Hour).Format(formTimeLayout)
	mustHave(t, "from past", get(t, b, "/ledger?from="+past), "OP_DISABLED")
	mustHave(t, "to past", get(t, b, "/ledger?to="+past), "No event matches.")

	// A bad date is refused with a message, not a crash.
	rec := b.do("GET", "/ledger?from=yesterday", nil, nil)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "From is not a date and time") {
		t.Errorf("bad date: %d %s", rec.Code, rec.Body)
	}
	// Search terms are text, never markup.
	rec = b.do("GET", "/ledger?run="+url.QueryEscape(`"><script>x</script>`), nil, nil)
	mustNotHave(t, "xss", rec.Body.String(), "<script>x</script>")
}

func TestLedgerScreenShowsTheLastAnchor(t *testing.T) {
	sr := newScrRig(t)
	b, _ := sr.signedIn()
	sr.seedDenial("r-aaaa1", "acme-shop", "OP_DISABLED", "x")
	mustHave(t, "no anchor", get(t, b, "/ledger"), "No anchor has been written yet.")
	if _, err := sr.led.Anchor(context.Background(), "offline-copy", "usb-1"); err != nil {
		t.Fatal(err)
	}
	sr.seedDenial("r-aaaa1", "acme-shop", "OP_DISABLED", "y")
	second, err := sr.led.Anchor(context.Background(), "offline-copy", "usb-2")
	if err != nil {
		t.Fatal(err)
	}
	page := get(t, b, "/ledger")
	mustHave(t, "anchor", page, "Last anchor", "usb-2", "offline-copy", second.Hash, "covers seq")
	mustNotHave(t, "anchor", page, "usb-1 ")
}

func TestLedgerIntegrityButton(t *testing.T) {
	sr := newScrRig(t)
	b, _ := sr.signedIn()
	for range 5 {
		sr.seedDenial("r-aaaa1", "acme-shop", "OP_DISABLED", "x")
	}
	rec := hxPost(b, "/ledger/verify", url.Values{})
	if rec.Code != 200 {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body)
	}
	_, hash, _ := sr.led.Head(context.Background())
	mustHave(t, "verify ok", rec.Body.String(), "Ledger verified", "Chain", hash, `role="status"`)

	// With the export: write it, then compare.
	if _, err := sr.led.Export(context.Background()); err != nil {
		t.Fatal(err)
	}
	rec = hxPost(b, "/ledger/verify", url.Values{"against_export": {"1"}})
	if rec.Code != 200 {
		t.Fatalf("verify with export: %d %s", rec.Code, rec.Body)
	}
	mustHave(t, "verify export", rec.Body.String(), "Ledger verified", "Compared with the JSONL export", "0 newer events")

	// Break the chain behind the ledger's back: the button says so, loudly.
	if _, err := sr.db.SQL().Exec(`DROP TRIGGER ledger_events_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := sr.db.SQL().Exec(`UPDATE ledger_events SET hash = 'sha256:` + strings.Repeat("ab", 32) + `' WHERE seq = 2`); err != nil {
		t.Fatal(err)
	}
	rec = hxPost(b, "/ledger/verify", url.Values{})
	if rec.Code != http.StatusConflict {
		t.Fatalf("verify of a tampered ledger: %d %s", rec.Code, rec.Body)
	}
	mustHave(t, "verify failed", rec.Body.String(), "Ledger verification FAILED", `role="alert"`, `data-variant="destructive"`, "<li>")
}
