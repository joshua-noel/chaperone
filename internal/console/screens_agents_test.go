package console

import (
	"bytes"
	"net/url"
	"strings"
	"testing"
)

// Without agent keys the Agents screen says so, and no action does anything.
func TestAgentsScreenWithoutKeysIsOffAndActionsRefuse(t *testing.T) {
	sr := newScrRig(t)
	b, _ := sr.signedIn()
	mustHave(t, "agents page", get(t, b, "/agents"), "without agent keys", `href="/agents"`)
	for _, p := range []string{"/agents/enrol/lookup", "/agents/enrol/approve", "/agents/requests/kr-0123456789abcdef/grant", "/agents/requests/kr-0123456789abcdef/deny", "/agents/keys/k-0123456789abcdef/extend"} {
		rec := hxPost(b, p, url.Values{"code": {"ABCD-EFGH"}})
		if rec.Code != 404 || !strings.Contains(rec.Body.String(), "Agent keys are off") {
			t.Errorf("POST %s: %d %s", p, rec.Code, rec.Body)
		}
	}
	// A post without the CSRF header never reaches the handler.
	if rec := b.do("POST", "/agents/enrol/lookup", []byte("code=x"), map[string]string{"Content-Type": "application/x-www-form-urlencoded"}); rec.Code != 403 {
		t.Errorf("a post without a CSRF token: %d", rec.Code)
	}
}

// The screens render with real data: the agent's words are escaped, every form has labelled fields, the narrowing
// form can only keep what was asked, and the one-tap extend is a button per extendable key.
func TestAgentsTemplatesRenderEscapedAndLabelled(t *testing.T) {
	sr := newScrRig(t)
	s := sr.con.scr
	hostile := `<script>alert(1)</script> "quoted" & more`
	var buf bytes.Buffer
	v := agentsView{
		On: true,
		Pending: []reqView{{ID: "kr-0123456789abcdef", Holder: "scout", Project: "acme-shop", Kind: "new", State: "pending", Ops: "pr.diff, pr.view", Units: "acme/shop",
			For: "1 day", Rate: 300, Reason: hostile, Needed: true, Created: "2026-11-05T12:00:00Z", Expires: "2026-11-06T12:00:00Z"}},
		Keys:   []agentKeyView{{ID: "k-0123456789abcdef", Holder: "scout", Project: "acme-shop", State: "live", Ops: "pr.view", Units: "acme/shop", Expires: "2026-11-06T12:00:00Z", CanExtend: true}},
		Recent: []reqView{{ID: "kr-1", Holder: "scout", Kind: "new", State: "denied", Ops: "pr.view", For: "1 day", DenyReason: hostile, Created: "2026-11-05T12:00:00Z"}},
	}
	if err := s.pages["agents"].ExecuteTemplate(&buf, "layout", v); err != nil {
		t.Fatal(err)
	}
	page := buf.String()
	mustHave(t, "agents page", page, "Waiting for your answer", "needed today", "written by the agent", `hx-post="/agents/keys/k-0123456789abcdef/extend"`,
		`aria-label="Extend the key of scout by 24 hours"`, `for="enrol-code"`, `hx-post="/agents/enrol/lookup"`, "Answer the request of scout")
	mustNotHave(t, "agents page", page, "<script>alert(1)</script>")
	mustHave(t, "escaped", page, "&lt;script&gt;alert(1)&lt;/script&gt;")

	buf.Reset()
	rv := agentRequestView{Request: v.Pending[0], Ops: []string{"pr.diff", "pr.view"}, Units: []string{"acme/shop"}, Hours: hourChoices(24), Rate: 300}
	rv.Request.State = "pending"
	if err := s.pages["agent_request"].ExecuteTemplate(&buf, "layout", rv); err != nil {
		t.Fatal(err)
	}
	dec := buf.String()
	mustHave(t, "decision page", dec, "Grant as asked", "Narrow and grant", "Deny it", `name="op" value="pr.diff" checked`, `name="unit" value="acme/shop" checked`,
		`max="300"`, `for="g-ttl"`, `for="g-rate"`, `for="d-reason"`, "never approves anything")
	mustNotHave(t, "decision page", dec, "<script>alert(1)</script>")
	// The hours offered never exceed what was asked, and the asked value is the selected one.
	if got := hourChoices(24); got[len(got)-1].Hours != 24 || !got[len(got)-1].Selected {
		t.Errorf("hour choices: %+v", got)
	}
	for _, h := range hourChoices(10) {
		if h.Hours > 10 {
			t.Errorf("an hour choice above the ask: %+v", h)
		}
	}

	buf.Reset()
	if err := s.frag.ExecuteTemplate(&buf, "agent-enrol-confirm", agentEnrolView{Code: "ABCD-EFGH", Label: "scout", Project: "acme-shop", Expires: "2026-11-05T12:10:00Z"}); err != nil {
		t.Fatal(err)
	}
	mustHave(t, "enrol confirm", buf.String(), "no access at all", `name="code" value="ABCD-EFGH"`, `hx-post="/agents/enrol/approve"`)
}
