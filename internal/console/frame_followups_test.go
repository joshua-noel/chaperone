package console

import (
	"io/fs"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/web"
)

// Follow-ups to the frame guard review. The console is operator-visible; each test pins one item.

// Item 1: Secrets is never framed, but the console's own link out of a frame ("Secrets: opens in Chaperone") opens it with
// ?from=frame. That page must be as restricted as /approvals: a waiting secret write's card must not carry a live Approve
// (since #78 an Approve stores the value).
func TestFramedSecretsPageShowsNoLiveApprove(t *testing.T) {
	sr := newScrRigCfg(t, withGlass)
	b, _ := sr.signedIn()
	id := sr.requestSecret(b, importForm("gh-app-key", canaryA))

	live := get(t, b, "/secrets")
	mustHave(t, "ordinary /secrets", live, `data-approval="`+id+`"`, `data-action="approve"`, `<details class="approval-fold" open`)
	mustNotHave(t, "ordinary /secrets", live, `data-action="approve" disabled`, "data-restricted")

	for name, hdr := range map[string]map[string]string{
		"same-origin": {"Sec-Fetch-Site": "same-origin"},
		"none":        {"Sec-Fetch-Site": "none"},
		"no metadata": {"Sec-Fetch-Site": ""},
	} {
		rec := b.do("GET", "/secrets?from=frame", nil, hdr)
		body := rec.Body.String()
		if rec.Code != http.StatusOK {
			t.Fatalf("/secrets?from=frame (%s): %d", name, rec.Code)
		}
		mustHave(t, "restricted /secrets ("+name+")", body, `data-approval="`+id+`"`, `data-action="approve" disabled`, `data-action="deny" disabled`, "data-restricted")
		mustNotHave(t, "restricted /secrets ("+name+")", body, `<details class="approval-fold" open`, canaryA)
		if name == "no metadata" {
			mustHave(t, "legacy /secrets", body, "current browser")
			mustNotHave(t, "legacy /secrets", body, "data-reopen")
		} else {
			mustHave(t, "restricted /secrets ("+name+")", body, `<a href="/secrets" data-reopen>Re-open here</a>`)
		}
	}
	// a browser that sends no Sec-Fetch-Site takes the safe side here too, with no query at all
	if body := b.do("GET", "/secrets", nil, map[string]string{"Sec-Fetch-Site": ""}).Body.String(); !strings.Contains(body, `data-action="approve" disabled`) {
		t.Error("/secrets with no Sec-Fetch-Site has a live Approve")
	}
	// "Re-open here" is the same page without the mark: ordinary again
	if body := get(t, b, "/secrets"); !strings.Contains(body, `data-action="approve"`) || strings.Contains(body, "data-restricted") {
		t.Error("the Re-open link does not give the ordinary Secrets page back")
	}
	// with no ancestors listed nothing is restricted
	plain := newScrRig(t)
	pb, _ := plain.signedIn()
	plain.requestSecret(pb, importForm("gh-app-key", canaryA))
	if body := get(t, pb, "/secrets?from=frame"); strings.Contains(body, "data-restricted") {
		t.Error("with no ancestors listed /secrets?from=frame must be the ordinary page")
	}
}

// Item 2: a framer can leave out ?embed=1, so the page must not rely on it: a framed response draws no header and no nav
// (their links lead to ordinary pages, or to pages that are never framed). Same signals as the guard: Sec-Fetch-Dest
// iframe, or ?from=frame, while ancestors are listed.
func TestNavIsNotDrawnForAFramedResponse(t *testing.T) {
	sr := newScrRigCfg(t, withGlass)
	b, _ := sr.signedIn()
	nav := func(body string) bool {
		return strings.Contains(body, `class="shell-nav"`) || strings.Contains(body, `class="brand"`)
	}

	// ordinary: drawn
	for _, p := range []string{"/", "/approvals", "/ledger", "/runs", "/secrets", "/catalog"} {
		if !nav(get(t, b, p)) {
			t.Errorf("ordinary %s has no nav", p)
		}
	}
	// a frame navigation without ?embed=1
	for _, p := range []string{"/approvals", "/ledger", "/runs"} {
		for site, hdr := range map[string]map[string]string{
			"same-site":   frameNav,
			"same-origin": {"Sec-Fetch-Dest": "iframe"},
		} {
			rec := b.do("GET", p, nil, hdr)
			if rec.Code != http.StatusOK || nav(rec.Body.String()) {
				t.Errorf("framed %s (%s, no embed): %d, nav drawn: %v", p, site, rec.Code, nav(rec.Body.String()))
			}
		}
	}
	// the window a frame link opens carries ?from=frame, on any page
	for _, p := range []string{"/", "/approvals", "/ledger", "/runs", "/secrets", "/catalog"} {
		rec := b.do("GET", p+"?from=frame", nil, nil)
		if rec.Code != http.StatusOK || nav(rec.Body.String()) {
			t.Errorf("%s?from=frame: %d, nav drawn: %v", p, rec.Code, nav(rec.Body.String()))
		}
	}
	// no ancestors listed: nothing is framed, the page is the ordinary page
	plain := newScrRig(t)
	pb, _ := plain.signedIn()
	for _, p := range []string{"/runs?from=frame", "/approvals"} {
		if !nav(get(t, pb, p)) {
			t.Errorf("%s with no ancestors listed lost its nav", p)
		}
	}
	if rec := pb.do("GET", "/runs", nil, map[string]string{"Sec-Fetch-Dest": "iframe"}); !nav(rec.Body.String()) {
		t.Error("/runs with no ancestors listed lost its nav")
	}
}

// Item 3: only a document navigation or a POST slides the session. A framed page loads /approvals/approvals.js and .css;
// a frame that keeps reloading must not stay signed in past the 30 minute idle limit.
func TestPageAssetsDoNotSlideTheSession(t *testing.T) {
	sr := newScrRigCfg(t, withGlass)
	b, _ := sr.signedIn()
	expires := func() int64 {
		t.Helper()
		var e int64
		if err := sr.db.SQL().QueryRow(`SELECT expires_unix FROM console_sessions`).Scan(&e); err != nil {
			t.Fatal(err)
		}
		return e
	}
	start := expires()
	assets := []struct {
		name, path string
		hdr        map[string]string
	}{
		{"script", "/approvals/approvals.js", map[string]string{"Sec-Fetch-Dest": "script", "Sec-Fetch-Mode": "no-cors"}},
		{"style", "/approvals/approvals.css", map[string]string{"Sec-Fetch-Dest": "style", "Sec-Fetch-Mode": "no-cors"}},
		{"script, no metadata", "/approvals/approvals.js", nil},
		{"style, no metadata", "/approvals/approvals.css", nil},
	}
	// Reload the assets every 10 minutes for 30: the idle limit must not move.
	for range 3 {
		sr.advance(10 * time.Minute)
		for _, a := range assets {
			if rec := b.do("GET", a.path, nil, a.hdr); rec.Code != http.StatusOK {
				t.Fatalf("%s: %d", a.name, rec.Code)
			}
			if got := expires(); got != start {
				t.Fatalf("%s slid expires_unix from %d to %d", a.name, start, got)
			}
		}
	}
	sr.advance(1 * time.Minute) // 31 minutes since the last document or POST
	if rec := b.do("GET", "/approvals", nil, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("a session kept up only by asset loads was still valid after 31 minutes: %d", rec.Code)
	}

	// A document navigation, a frame navigation from the console itself and a POST still slide.
	for name, do := range map[string]func(b *browser, token string) int{
		"document": func(b *browser, _ string) int {
			return b.do("GET", "/approvals", nil, map[string]string{"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate"}).Code
		},
		"iframe, same-origin": func(b *browser, _ string) int {
			return b.do("GET", "/approvals", nil, map[string]string{"Sec-Fetch-Dest": "iframe", "Sec-Fetch-Mode": "navigate"}).Code
		},
		"post": func(b *browser, token string) int {
			return b.do("POST", "/secrets/q-none/cancel", nil, map[string]string{"X-CSRF-Token": token, "HX-Request": "true"}).Code
		},
		"no metadata": func(b *browser, _ string) int { return b.do("GET", "/approvals", nil, nil).Code },
	} {
		sr := newScrRigCfg(t, withGlass)
		b, _ := sr.signedIn()
		token := b.csrf() // a page load: fetch it before the clock moves
		var e0 int64
		if err := sr.db.SQL().QueryRow(`SELECT expires_unix FROM console_sessions`).Scan(&e0); err != nil {
			t.Fatal(err)
		}
		sr.advance(10 * time.Minute)
		do(b, token)
		var e1 int64
		if err := sr.db.SQL().QueryRow(`SELECT expires_unix FROM console_sessions`).Scan(&e1); err != nil {
			t.Fatal(err)
		}
		if e1 <= e0 {
			t.Errorf("%s did not slide the session (%d, started at %d)", name, e1, e0)
		}
	}
}

// Item 3, the 8 hour cap: documents keep the session alive, assets in between change nothing, and the absolute limit holds.
func TestSessionCapHoldsWithDocumentSlidingAndAssets(t *testing.T) {
	sr := newScrRigCfg(t, withGlass)
	b, _ := sr.signedIn()
	doc := map[string]string{"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate"}
	script := map[string]string{"Sec-Fetch-Dest": "script", "Sec-Fetch-Mode": "no-cors"}
	var elapsed time.Duration
	for elapsed < 8*time.Hour-25*time.Minute {
		sr.advance(25 * time.Minute)
		elapsed += 25 * time.Minute
		if rec := b.do("GET", "/approvals", nil, doc); rec.Code != http.StatusOK {
			t.Fatalf("session ended early at %s: %d", elapsed, rec.Code)
		}
		b.do("GET", "/approvals/approvals.js", nil, script)
	}
	sr.advance(25 * time.Minute)
	b.do("GET", "/approvals/approvals.js", nil, script)
	if rec := b.do("GET", "/approvals", nil, doc); rec.Code != http.StatusSeeOther {
		t.Fatalf("session outlived the 8 hour limit: %d", rec.Code)
	}
}

// Item 4: the runbook says held controls stay grey on a top-level page; frame-guard.js marks them data-held (and
// aria-disabled), so the stylesheet must style exactly that. A held destructive button (Deny, Revoke, Stop all) must look
// like any held button in every state, so the held rule overrides each property Basecoat's variant, hover, focus and ring
// rules set, with !important (no race with their specificity or layer), and keeps a neutral focus ring. What this test
// pins is the text of those rules; that they work is checked in a browser by scripts/held-style/check.cjs (a held destructive
// button compared with a held neutral one in rest, hover, focus-visible and active), which CI does not run.
func TestHeldControlsAreStyledOnTopLevelPages(t *testing.T) {
	cssBytes, err := fs.ReadFile(web.Static(), "console.css")
	if err != nil {
		t.Fatal(err)
	}
	css := strings.ReplaceAll(string(cssBytes), "\r\n", "\n")
	rule := func(selector string) string {
		i := strings.Index(css, selector+" {")
		if i < 0 {
			t.Errorf("console.css has no rule %q: a held control does not look held", selector)
			return ""
		}
		return css[i : i+strings.Index(css[i:], "}")]
	}
	const held = "html[data-framed] [data-frame-visible=\"0\"],\nhtml [data-held=\"1\"][aria-disabled=\"true\"]"
	const heldFocus = "html[data-framed] [data-frame-visible=\"0\"]:focus-visible,\nhtml [data-held=\"1\"][aria-disabled=\"true\"]:focus-visible"
	for _, p := range []string{"color", "background-color", "border-color", "box-shadow", "outline-color", "--tw-ring-color"} {
		if !strings.Contains(rule(held), p+": ") || !regexp.MustCompile(`(^|[\s;])`+regexp.QuoteMeta(p)+`: [^;]*!important`).MatchString(rule(held)) {
			t.Errorf("the held rule does not set %s with !important: a held button can show a variant's colour", p)
		}
	}
	for _, p := range []string{"border-color", "box-shadow"} {
		if !regexp.MustCompile(`(^|[\s;])`+regexp.QuoteMeta(p)+`: [^;]*!important`).MatchString(rule(heldFocus)) || strings.Contains(rule(heldFocus), "destructive") {
			t.Errorf("the held :focus-visible rule does not set a neutral %s with !important", p)
		}
	}
	if strings.Contains(rule(held), "destructive") {
		t.Error("the held rule names the destructive colour")
	}
	js, err := fs.ReadFile(web.Static(), "frame-guard.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), `el.setAttribute('aria-disabled', 'true'); el.dataset.held = '1';`) {
		t.Error("frame-guard.js no longer marks a held control with aria-disabled=true and data-held=1: the style no longer matches")
	}
}

// ---- a restricted page draws no enabled state-changing control ----

var (
	startTagPat = regexp.MustCompile(`<([a-zA-Z][a-zA-Z0-9-]*)((?:\s+[^\s=/>"']+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'>]+))?)*)\s*/?>`)
	attrPat     = regexp.MustCompile(`([^\s=/>"']+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?`)
	// a form that only reads (GET), by id. A new form on a restricted page fails the test until it is added here on purpose.
	knownGetForms = map[string]bool{"ledger-search": true}
)

// attrsOf reads a start tag's attributes by name (lower case). A name with no value maps to "".
func attrsOf(raw string) map[string]string {
	out := map[string]string{}
	for _, m := range attrPat.FindAllStringSubmatch(raw, -1) {
		out[strings.ToLower(m[1])] = m[2] + m[3] + m[4]
	}
	return out
}

// postControls lists every element in a page that could send a state-changing request. Any start tag counts, not a list of
// tag names:
//   - any form, unless it is a known GET form (knownGetForms), whatever its method (a form with none is posted by a script)
//   - hx-post, hx-put, hx-delete, hx-patch or their data-hx-* aliases
//   - formmethod="post"
//   - data-action or data-number (the approval and phone scripts send a POST for these)
//
// A button, input, select or textarea with the attribute `disabled` is exempt; on any other tag `disabled` means nothing.
func postControls(body string) []string {
	var out []string
	for _, m := range startTagPat.FindAllStringSubmatch(body, -1) {
		tag, a := strings.ToLower(m[1]), attrsOf(m[2])
		writes := false
		for name, val := range a {
			switch {
			case name == "hx-post" || name == "hx-put" || name == "hx-delete" || name == "hx-patch",
				name == "data-hx-post" || name == "data-hx-put" || name == "data-hx-delete" || name == "data-hx-patch",
				name == "formmethod" && strings.EqualFold(val, "post"),
				name == "data-action", name == "data-number":
				writes = true
			}
		}
		if tag == "form" {
			meth := strings.ToLower(a["method"])
			writes = writes || !knownGetForms[a["id"]] || (meth != "" && meth != "get")
		}
		if !writes {
			continue
		}
		if _, off := a["disabled"]; off && (tag == "button" || tag == "input" || tag == "select" || tag == "textarea") {
			continue
		}
		out = append(out, m[0])
	}
	return out
}

// restrictedVariants are the ways a page is drawn restricted: the console's own link out of a frame, and a browser that sends
// no Sec-Fetch-Site.
func restrictedVariants(p string) map[string]struct {
	path string
	hdr  map[string]string
} {
	type v = struct {
		path string
		hdr  map[string]string
	}
	return map[string]v{
		"from=frame, same-origin": {p + "?from=frame", map[string]string{"Sec-Fetch-Site": "same-origin"}},
		"from=frame, none":        {p + "?from=frame", map[string]string{"Sec-Fetch-Site": "none"}},
		"from=frame, no metadata": {p + "?from=frame", map[string]string{"Sec-Fetch-Site": ""}},
		"no Sec-Fetch-Site":       {p, map[string]string{"Sec-Fetch-Site": ""}},
	}
}

// wantRestrictedReadOnly fails unless every restricted variant of p is a 200 restricted page with no enabled POST control.
func wantRestrictedReadOnly(t *testing.T, b *browser, p string) {
	t.Helper()
	for name, c := range restrictedVariants(p) {
		rec := b.do("GET", c.path, nil, c.hdr)
		body := rec.Body.String()
		if rec.Code != http.StatusOK || !strings.Contains(body, "data-restricted") {
			t.Errorf("%s (%s): %d, want the restricted page", p, name, rec.Code)
			continue
		}
		if live := postControls(body); len(live) != 0 {
			t.Errorf("restricted %s (%s) has enabled POST controls: %s", p, name, strings.Join(live, " | "))
		}
	}
}

// A page drawn restricted is a read-only view: no enabled POST-capable control at all (the one way out, "Re-open here",
// is a plain link). The templates keep every write section behind {{if not .Restricted}}; this test reads what comes out,
// so a new button or form on a restricted page cannot slip in.
func TestRestrictedPagesHaveNoEnabledPostControl(t *testing.T) {
	sr := newScrRigCfg(t, withGlass)
	b, _ := sr.signedIn()
	sr.request(nil)                                        // a pending card on /approvals
	sr.requestSecret(b, importForm("gh-app-key", canaryA)) // a waiting secret write on /secrets
	sr.seedRun("r-aaaa1", "acme-shop")                     // a run with Revoke
	sr.issueOrch("main")                                   // an orchestrator with Revoke

	for _, p := range []string{"/approvals", "/secrets", "/runs", "/ledger"} {
		// the ordinary page has them (so the detector is not blind)
		if body := get(t, b, p); len(postControls(body)) == 0 {
			t.Errorf("ordinary %s: found no POST control; the detector is wrong", p)
		}
		wantRestrictedReadOnly(t, b, p)
	}
}

// The same on a console with a phone origin: the phone panel's form (#phone-enroll-form) has no method and no hx-*; a script
// posts it. It is on the ordinary page and on no restricted one (the gate PhoneOn ... && !st.restricted in approvalsPage).
func TestRestrictedApprovalsHasNoPhoneEnrolmentControl(t *testing.T) {
	pr := newPhoneRigCfg(t, withGlass)
	pr.request(nil)
	rec := pr.pc.postH("/phone/enroll", []byte(`{"label":"My phone"}`), pr.pc.csrf(), nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("ask to enrol: %d %s", rec.Code, rec.Body)
	}
	pr.approveOnPC(str(decode(rec)["approval"])) // an approved, unspent enrolment: "Show the enrolment address"

	body := get(t, pr.pc, "/approvals")
	mustHave(t, "ordinary /approvals", body, `id="phone-enroll-form"`, `data-action="enrollment"`)
	if len(postControls(body)) == 0 {
		t.Error("the detector does not see the phone form on the ordinary page")
	}
	wantRestrictedReadOnly(t, pr.pc, "/approvals")
	for name, c := range restrictedVariants("/approvals") {
		if body := pr.pc.do("GET", c.path, nil, c.hdr).Body.String(); strings.Contains(body, "phone-enroll-form") || strings.Contains(body, `data-action="enrollment"`) {
			t.Errorf("restricted /approvals (%s) holds the phone enrolment controls", name)
		}
	}
}

// The console's mark ?from=frame is also the Ledger's "from" date filter. The "Open the console in its own window" link of a
// browser without IntersectionObserver v2 opens /ledger?from=frame: that must be the restricted Ledger, not a 400.
func TestLedgerFromFrameIsTheMarkNotADate(t *testing.T) {
	sr := newScrRigCfg(t, withGlass)
	b, _ := sr.signedIn()
	rec := b.do("GET", "/ledger?from=frame", nil, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "data-restricted") || strings.Contains(rec.Body.String(), "is not a date") {
		t.Errorf("/ledger?from=frame: %d, want the restricted Ledger", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `<a href="/ledger" data-reopen>Re-open here</a>`) {
		t.Error("restricted Ledger has no Re-open here link")
	}
	// a real date still filters, and a bad one is still refused
	if rec := b.do("GET", "/ledger?from=2026-01-02T03:04", nil, nil); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "is not a date") {
		t.Errorf("/ledger with a date: %d", rec.Code)
	}
	if rec := b.do("GET", "/ledger?from=yesterday", nil, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("/ledger?from=yesterday: %d, want 400", rec.Code)
	}
}
