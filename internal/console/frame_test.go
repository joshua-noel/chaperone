package console

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/approvals"
)

// the dashboard (the operator's front end) shows some console pages in a frame. This is opt-in per origin and per page; these
// tests pin what a frame may show, what it may never show, and that the passkey made in a frame is accepted only for
// a listed top origin.

const glassOrigin = "http://localhost:55440"

func withGlass(c *Config) { c.FrameAncestors = []string{glassOrigin} }

var (
	frameNav = map[string]string{"Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "iframe"}
	topNav   = map[string]string{"Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
)

func frameAncestorsOf(csp string) string {
	for _, d := range strings.Split(csp, ";") {
		if d = strings.TrimSpace(d); strings.HasPrefix(d, "frame-ancestors") {
			return d
		}
	}
	return ""
}

// wantDenyFrames fails unless the response forbids every frame, in both headers.
func wantDenyFrames(t *testing.T, what string, h http.Header) {
	t.Helper()
	if got := frameAncestorsOf(h.Get("Content-Security-Policy")); got != "frame-ancestors 'none'" {
		t.Errorf("%s: CSP %q, want frame-ancestors 'none'", what, got)
	}
	if got := h.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("%s: X-Frame-Options %q, want DENY", what, got)
	}
}

// The list of pages a frame may show is explicit, and it is short. A new entry has to be a deliberate edit of this test.
func TestFramingIsAnExplicitAllowList(t *testing.T) {
	want := []string{"/approvals", "/ledger", "/runs"}
	if len(framablePaths) != len(want) {
		t.Fatalf("framablePaths = %v, want exactly %v", framablePaths, want)
	}
	for _, p := range want {
		if !framablePaths[p] {
			t.Errorf("%s is not framable", p)
		}
	}
	// Never framable: typing a secret (no second factor: a page that could overlay a fake field must not frame it),
	// signing in, enrolling, the phone pages, Home (Stop all), Operations.
	for _, p := range []string{"/secrets", "/secrets/request", "/login", "/enroll", "/phone", "/phone/enroll", "/", "/catalog", "/stop-all", "/orchestrators/main/revoke"} {
		if framablePaths[p] {
			t.Errorf("%s must never be framable", p)
		}
	}
	if len(framablePaths) != 3 {
		t.Errorf("framablePaths = %v", framablePaths)
	}
}

func TestFramingIsOffUnlessAnAncestorIsListed(t *testing.T) {
	sr := newScrRig(t) // no FrameAncestors
	b, _ := sr.signedIn()
	for _, p := range []string{"/approvals", "/ledger", "/runs", "/secrets", "/login"} {
		rec := b.do("GET", p, nil, frameNav)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s in a frame, no ancestors listed: %d, want 403 (cross-site fetch refused as before)", p, rec.Code)
		}
		wantDenyFrames(t, p, rec.Header())
		// and as a same-origin load (a page of the console itself): no frame headers are relaxed
		rec = b.do("GET", p, nil, map[string]string{"Sec-Fetch-Dest": "iframe"})
		wantDenyFrames(t, p+" (same-origin)", rec.Header())
	}
	if rec := b.do("GET", "/approvals", nil, topNav); rec.Code != http.StatusForbidden {
		t.Errorf("top-level same-site navigation with no ancestors listed: %d, want 403", rec.Code)
	}
}

func TestListedAncestorMayFrameOnlyTheFramablePages(t *testing.T) {
	sr := newScrRigCfg(t, withGlass)
	b, _ := sr.signedIn()
	sr.seedRun("r-aaaa1", "acme-shop")

	for p := range framablePaths {
		rec := b.do("GET", p, nil, frameNav)
		if rec.Code != 200 {
			t.Fatalf("%s in a frame: %d %s", p, rec.Code, rec.Body)
		}
		if got := frameAncestorsOf(rec.Header().Get("Content-Security-Policy")); got != "frame-ancestors "+glassOrigin {
			t.Errorf("%s: %q, want frame-ancestors %s", p, got, glassOrigin)
		}
		if rec.Header().Get("X-Frame-Options") != "" {
			t.Errorf("%s: X-Frame-Options %q: it has no allow-list form, so it must not be sent when the CSP allows the frame", p, rec.Header().Get("X-Frame-Options"))
		}
		if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'none'") || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "script-src 'self'") {
			t.Errorf("%s: the rest of the CSP changed: %q", p, rec.Header().Get("Content-Security-Policy"))
		}
		// The same page asked for as a top-level load (not a frame) stays DENY.
		wantDenyFrames(t, p+" top-level", b.do("GET", p, nil, topNav).Header())
	}

	// Every other page: never framed, with the opt-in on, even from a same-origin request that would pass the fetch-metadata check.
	for _, p := range []string{"/", "/secrets", "/catalog", "/login", "/enroll", "/phone"} {
		for name, hdr := range map[string]map[string]string{
			"iframe, same-origin": {"Sec-Fetch-Dest": "iframe"},
			"iframe, same-site":   frameNav,
		} {
			rec := b.do("GET", p, nil, hdr)
			wantDenyFrames(t, p+" "+name, rec.Header())
			if name == "iframe, same-site" && rec.Code != http.StatusForbidden {
				t.Errorf("%s framed from a listed ancestor: %d, want 403", p, rec.Code)
			}
		}
	}
}

// Secret entry always sends DENY and frame-ancestors 'none', whatever the request says and whatever is listed.
func TestSecretRoutesAreNeverFramable(t *testing.T) {
	sr := newScrRigCfg(t, withGlass)
	b, _ := sr.signedIn()
	for _, p := range []string{"/secrets", "/secrets?embed=1", "/secrets/request", "/secrets/a-nothere/commit", "/secrets/a-nothere/cancel"} {
		for _, method := range []string{"GET", "POST"} {
			for _, hdr := range []map[string]string{
				nil, frameNav, topNav, {"Sec-Fetch-Dest": "iframe"}, {"Sec-Fetch-Dest": "iframe", "Sec-Fetch-Mode": "navigate"},
			} {
				rec := b.do(method, p, nil, hdr)
				wantDenyFrames(t, method+" "+p, rec.Header())
			}
		}
	}
	// Opened by the operator (its own address, or a link inside the console), the page loads and stays unframed.
	rec := b.do("GET", "/secrets", nil, map[string]string{"Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"})
	if rec.Code != 200 {
		t.Fatalf("/secrets opened by the operator: %d", rec.Code)
	}
	wantDenyFrames(t, "/secrets", rec.Header())
	// A top-level load from another page is refused (it was allowed in the first version of this PR).
	if rec := b.do("GET", "/secrets", nil, topNav); rec.Code != http.StatusForbidden {
		t.Fatalf("top-level /secrets from a same-site page: %d, want 403", rec.Code)
	}
}

func TestCrossSiteIsStillRefusedExceptListedNavigations(t *testing.T) {
	sr := newScrRigCfg(t, withGlass)
	b, _ := sr.signedIn()
	cross := func(mode, dest string) map[string]string {
		return map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": mode, "Sec-Fetch-Dest": dest}
	}
	// refused: pages that are neither framable nor popup pages, a non-navigation (fetch/XHR) to a listed page, anything but GET
	for name, c := range map[string]struct {
		method, path string
		hdr          map[string]string
	}{
		"catalog, top-level":           {"GET", "/catalog", cross("navigate", "document")},
		"home, top-level":              {"GET", "/", topNav},
		"approvals via fetch":          {"GET", "/approvals", cross("cors", "empty")},
		"approvals via script tag":     {"GET", "/approvals", cross("no-cors", "script")},
		"approvals as an object":       {"GET", "/approvals", cross("navigate", "object")},
		"secrets in a frame":           {"GET", "/secrets", cross("navigate", "iframe")},
		"begin, cross-site":            {"POST", "/approvals/a-x/begin", cross("cors", "empty")},
		"finish, same-site navigation": {"POST", "/approvals/a-x/finish", topNav},
		"revoke, same-site navigation": {"POST", "/runs/r-aaaa1/revoke", topNav},
	} {
		if rec := b.do(c.method, c.path, nil, c.hdr); rec.Code != http.StatusForbidden {
			t.Errorf("%s: %d, want 403", name, rec.Code)
		}
	}
	// allowed: GET navigations to the listed pages in a frame, from a page of another site too (the cookie is SameSite=Strict, so it arrives signed out)
	for _, p := range []string{"/approvals", "/ledger", "/runs"} {
		if rec := b.do("GET", p, nil, cross("navigate", "iframe")); rec.Code != 200 {
			t.Errorf("framed %s from another site: %d", p, rec.Code)
		}
	}
	// refused (review of #75): a top-level load of ANY console page from another page, listed page or not, from the same
	// site or another one. Such a load would carry the session and no frame guard (the DoubleClickjacking swap).
	for _, p := range []string{"/approvals", "/ledger", "/runs", "/secrets", "/", "/catalog"} {
		for _, site := range []string{"same-site", "cross-site"} {
			hdr := map[string]string{"Sec-Fetch-Site": site, "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
			if rec := b.do("GET", p, nil, hdr); rec.Code != http.StatusForbidden {
				t.Errorf("top-level %s from a %s page: %d, want 403", p, site, rec.Code)
			}
		}
	}
	// allowed: the operator's own navigation (typed address, bookmark: site none) and a link inside the console (same-origin)
	for _, site := range []string{"none", "same-origin"} {
		hdr := map[string]string{"Sec-Fetch-Site": site, "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
		if rec := b.do("GET", "/secrets", nil, hdr); rec.Code != 200 {
			t.Errorf("/secrets opened with Sec-Fetch-Site %s: %d", site, rec.Code)
		}
	}
}

func TestFrameAncestorsAreValidated(t *testing.T) {
	for _, bad := range []string{
		"", "*", "http://*.example.org", "https://dashboard.example/", "https://dashboard.example/path", "https://dashboard.example?x=1",
		"https://DASHBOARD.example", "http://dashboard.example", "ftp://dashboard.example", "https://user@dashboard.example", "https://dashboard.example'; script-src *",
		"https://dashboard.example other.example", "https://dashboard.example;", "//dashboard.example", "null", "https://",
	} {
		if err := checkFrameAncestors([]string{bad}); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	for _, good := range []string{"http://localhost:55440", "https://dashboard.example", "https://dashboard.example:8443", "http://localhost"} {
		if err := checkFrameAncestors([]string{good}); err != nil {
			t.Errorf("%q refused: %v", good, err)
		}
	}
	if err := checkFrameAncestors([]string{glassOrigin, glassOrigin}); err == nil {
		t.Error("a duplicate was accepted")
	}
}

// ---- the passkey made in a frame ----

func TestApprovalMadeInAFrameNeedsAListedTopOrigin(t *testing.T) {
	framed := func(o opts) opts { o.signCount = &zero; return o }
	cases := []struct {
		name      string
		ancestors []string
		o         opts
		reason    string // "" means approved
	}{
		{"listed top origin", []string{glassOrigin}, framed(opts{crossOrigin: true, topOrigin: glassOrigin}), ""},
		{"another top origin", []string{glassOrigin}, framed(opts{crossOrigin: true, topOrigin: "http://localhost:9999"}), ReasonOrigin},
		{"a look-alike top origin", []string{glassOrigin}, framed(opts{crossOrigin: true, topOrigin: "http://localhost:55440.evil.example"}), ReasonOrigin},
		{"no top origin", []string{glassOrigin}, framed(opts{crossOrigin: true}), ReasonOrigin},
		{"no ancestors listed", nil, framed(opts{crossOrigin: true, topOrigin: glassOrigin}), ReasonOrigin},
		{"a frame whose own origin is not the console's", []string{glassOrigin}, framed(opts{crossOrigin: true, topOrigin: glassOrigin, origin: "http://localhost:55440"}), ReasonOrigin},
		{"not in a frame, a top origin named anyway", []string{glassOrigin}, framed(opts{topOrigin: glassOrigin}), ReasonOrigin},
		{"not in a frame: the ordinary assertion still works", []string{glassOrigin}, framed(opts{}), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ar := newApprRigCfg(t, nil, func(cfg *Config) { cfg.FrameAncestors = c.ancestors })
			b, auth := ar.signedIn()
			card := ar.request(nil)
			bg := ar.begin(b, card.ID)
			rec := ar.finish(b, card.ID, bg, auth.get(bg.options, pcOrigin.URL, c.o))
			if c.reason == "" {
				if rec.Code != 200 || ar.state(card.ID) != approvals.StateApproved {
					t.Fatalf("approve: %d %s (state %s)", rec.Code, rec.Body, ar.state(card.ID))
				}
				return
			}
			out := wantCode(t, rec, http.StatusForbidden, approvals.CodeAssertion)
			if str(out["why"]) != c.reason {
				t.Fatalf("why %s, want %s (%s)", out["why"], c.reason, rec.Body)
			}
			if ar.state(card.ID) != approvals.StatePending || len(ar.led.named("op.approve")) != 0 {
				t.Fatal("a refused assertion changed something")
			}
		})
	}
}

// A passkey made in a frame signs nobody in and enrols nobody: only the approval verifier takes it.
func TestSignInAndEnrolmentRefuseAFramedPasskey(t *testing.T) {
	r := newRigCfg(t, withGlass)
	b := r.browser(pcOrigin)
	a := mustEnrolled(t, r, b)
	framed := opts{signCount: &zero, crossOrigin: true, topOrigin: glassOrigin}
	if code, out := b.login(a, framed); code == 200 {
		t.Fatalf("a passkey made in a frame signed in: %v", out)
	}
	if rec := b.do("GET", "/approvals", nil, nil); rec.Code == 200 {
		t.Fatal("a session exists after the refused sign-in")
	}
}

// Review of the frame guard (head 1aa60e8): a framed request with no session says so, with a link to sign in at the console's own
// window, and a frame navigation from another origin does not keep a session alive.

func TestSignedOutFramedRequestSaysSoAndLinksToSignIn(t *testing.T) {
	sr := newScrRigCfg(t, withGlass)
	out := sr.browser(pcOrigin) // never signed in: no session cookie
	for _, p := range []string{"/approvals", "/ledger", "/runs"} {
		rec := out.do("GET", p, nil, frameNav)
		if rec.Code != http.StatusOK {
			t.Fatalf("signed-out framed %s: %d, want 200 and a page that says so", p, rec.Code)
		}
		body := rec.Body.String()
		for _, want := range []string{"Signed out: sign in at Chaperone", `href="/login"`, `target="_blank"`, `rel="noopener"`, "/static/frame-guard.js"} {
			if !strings.Contains(body, want) {
				t.Errorf("signed-out framed %s lacks %q", p, want)
			}
		}
		// Still framable only by the listed origin, still no cached copy.
		if got := frameAncestorsOf(rec.Header().Get("Content-Security-Policy")); got != "frame-ancestors "+glassOrigin {
			t.Errorf("signed-out framed %s: frame-ancestors %q, want the listed origin", p, got)
		}
		if rec.Header().Get("X-Frame-Options") != "" || rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("signed-out framed %s: X-Frame-Options %q, Cache-Control %q", p, rec.Header().Get("X-Frame-Options"), rec.Header().Get("Cache-Control"))
		}
		if strings.Contains(body, "article") || strings.Contains(body, "hx-post") {
			t.Errorf("signed-out framed %s leaks page content", p)
		}
	}
	// A signed-out request that is not a frame navigation is unchanged: the redirect to sign-in.
	if rec := out.do("GET", "/approvals", nil, nil); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Errorf("signed-out top-level /approvals: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	// With no ancestors listed a frame navigation is not special at all.
	plain := newScrRig(t).browser(pcOrigin)
	if rec := plain.do("GET", "/approvals", nil, map[string]string{"Sec-Fetch-Dest": "iframe"}); rec.Code != http.StatusSeeOther {
		t.Errorf("no ancestors listed, signed out, framed: %d, want the ordinary redirect", rec.Code)
	}
}

func TestFrameNavigationDoesNotSlideTheSession(t *testing.T) {
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

	// Another origin's frame navigation (same-site or cross-site) reads the page but must not extend the idle time.
	sr.advance(10 * time.Minute)
	for _, site := range []string{"same-site", "cross-site"} {
		hdr := map[string]string{"Sec-Fetch-Site": site, "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "iframe"}
		if rec := b.do("GET", "/approvals", nil, hdr); rec.Code != http.StatusOK {
			t.Fatalf("framed /approvals from a %s page: %d", site, rec.Code)
		}
		if got := expires(); got != start {
			t.Fatalf("a %s frame navigation slid expires_unix from %d to %d", site, start, got)
		}
	}

	// A request that is the console's own (same-origin, or the operator's typed address) still slides it.
	if rec := b.do("GET", "/approvals", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("same-origin /approvals: %d", rec.Code)
	}
	if got := expires(); got <= start {
		t.Fatalf("a same-origin request did not slide expires_unix (%d, started at %d)", got, start)
	}

	// And a session that only ever saw frame navigations ends at its idle time: the frame then shows the signed-out page.
	sr.advance(31 * time.Minute)
	rec := b.do("GET", "/approvals", nil, frameNav)
	if !strings.Contains(rec.Body.String(), "Signed out: sign in at Chaperone") {
		t.Errorf("idle session in a frame: %d, want the signed-out page", rec.Code)
	}
}

// Round 3 of the frame guard review: what a top-level load of a framable page does, by Sec-Fetch-Site. A page that frames the console (or any
// page on another localhost port) cannot open a console page as a window and have the operator click twice on a live
// button: the cross-origin load is refused (403), and a load the console itself opens out of a frame, or one from a browser
// that sends no fetch metadata, is drawn restricted (no live Approve, Deny or Revoke, every card folded).

func TestTopLevelLoadDecisionBySecFetchSite(t *testing.T) {
	sr := newScrRigCfg(t, withGlass)
	b, _ := sr.signedIn()
	sr.request(nil) // one pending card: the single card is unfolded on an ordinary page
	sr.seedRun("r-aaaa1", "acme-shop")
	doc := func(site string) map[string]string {
		return map[string]string{"Sec-Fetch-Site": site, "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
	}
	live := func(body string) bool {
		return strings.Contains(body, `data-action="approve"`) && !strings.Contains(body, `data-action="approve" disabled`) &&
			!strings.Contains(body, `data-action="deny" disabled`) && !strings.Contains(body, "data-restricted")
	}
	restricted := func(body string) bool {
		return strings.Contains(body, `data-action="approve" disabled`) && strings.Contains(body, `data-action="deny" disabled`) &&
			strings.Contains(body, "data-restricted") && !strings.Contains(body, `<details class="approval-fold" open`)
	}
	// a restricted page names its way out: a link to the page without any query or hash, or (no Sec-Fetch-Site) no link at all
	reopenLink := func(body, path string) bool {
		return strings.Contains(body, `<a href="`+path+`" data-reopen>Re-open here</a>`)
	}
	legacyNote := func(body string) bool {
		return strings.Contains(body, "current browser") && !strings.Contains(body, "data-reopen") && !strings.Contains(body, "Re-open here")
	}

	// window.open (or a link, or a redirect) of any other page: refused, so never reaches a render. A listed ancestor's
	// origin is cross-origin to the console like any other localhost port: Sec-Fetch-Site same-site for http://localhost:55440,
	// cross-site for another host.
	for _, site := range []string{"same-site", "cross-site"} {
		for _, p := range []string{"/approvals", "/approvals?from=frame", "/runs", "/ledger", "/secrets", "/secrets?from=frame"} {
			if rec := b.do("GET", p, nil, doc(site)); rec.Code != http.StatusForbidden {
				t.Errorf("top-level %s from a %s page: %d, want 403", p, site, rec.Code)
			}
		}
	}
	// the operator's own: a typed address or bookmark (none), a link in the console (same-origin)
	for _, site := range []string{"none", "same-origin"} {
		rec := b.do("GET", "/approvals", nil, doc(site))
		if rec.Code != http.StatusOK || !live(rec.Body.String()) || !strings.Contains(rec.Body.String(), `<details class="approval-fold" open`) {
			t.Errorf("/approvals with Sec-Fetch-Site %s: %d, want the ordinary page with a live Approve and the card unfolded", site, rec.Code)
		}
	}
	// no Sec-Fetch-Site at all: the safe side, and no query value lifts it (an opener could add any): no way out on the page
	for _, p := range []string{"/approvals", "/approvals?reopen=1", "/approvals?reopen=1&x=y"} {
		rec := b.do("GET", p, nil, map[string]string{"Sec-Fetch-Site": ""})
		if rec.Code != http.StatusOK || !restricted(rec.Body.String()) || !legacyNote(rec.Body.String()) {
			t.Errorf("%s with no Sec-Fetch-Site: %d, want the restricted page with the 'current browser' note and no link", p, rec.Code)
		}
	}
	// /secrets is never framed but is opened by the console's own link out of a frame: the same decision as /approvals
	// (its card is covered in TestFramedSecretsPageShowsNoLiveApprove)
	for _, site := range []string{"same-origin", "none"} {
		if rec := b.do("GET", "/secrets?from=frame", nil, map[string]string{"Sec-Fetch-Site": site}); rec.Code != http.StatusOK ||
			!strings.Contains(rec.Body.String(), "data-restricted") || !reopenLink(rec.Body.String(), "/secrets") {
			t.Errorf("/secrets?from=frame with Sec-Fetch-Site %q: %d, want the restricted page with Re-open here", site, rec.Code)
		}
		if body := b.do("GET", "/secrets", nil, doc(site)).Body.String(); strings.Contains(body, "data-restricted") {
			t.Errorf("/secrets with Sec-Fetch-Site %q is restricted", site)
		}
	}
	if body := b.do("GET", "/secrets", nil, map[string]string{"Sec-Fetch-Site": ""}).Body.String(); !strings.Contains(body, "data-restricted") || !legacyNote(body) {
		t.Error("/secrets with no Sec-Fetch-Site must be restricted with no way out")
	}
	// the console's own link out of a frame carries ?from=frame, whatever the browser says about the site
	for _, site := range []string{"same-origin", "none"} {
		rec := b.do("GET", "/approvals?from=frame", nil, map[string]string{"Sec-Fetch-Site": site})
		if rec.Code != http.StatusOK || !restricted(rec.Body.String()) || !reopenLink(rec.Body.String(), "/approvals") {
			t.Errorf("/approvals?from=frame with Sec-Fetch-Site %q: %d, want the restricted page with Re-open here", site, rec.Code)
		}
	}
	if rec := b.do("GET", "/approvals?from=frame", nil, map[string]string{"Sec-Fetch-Site": ""}); !restricted(rec.Body.String()) || !legacyNote(rec.Body.String()) {
		t.Error("/approvals?from=frame with no Sec-Fetch-Site must be restricted with no way out")
	}
	// ...and "Re-open here" is the same page without the mark: ordinary again (the address hash is not carried)
	if rec := b.do("GET", "/approvals", nil, nil); !live(rec.Body.String()) {
		t.Error("the Re-open link does not give the ordinary page back")
	}

	// /runs: no Revoke button on a restricted page, a note instead; the ordinary page keeps both buttons
	if body := b.do("GET", "/runs", nil, nil).Body.String(); !strings.Contains(body, `hx-post="/runs/r-aaaa1/revoke"`) || strings.Contains(body, "data-restricted") {
		t.Error("ordinary /runs lost Revoke or shows the note")
	}
	for _, hdr := range []map[string]string{{}, {"Sec-Fetch-Site": ""}} {
		rec := b.do("GET", "/runs?from=frame", nil, hdr)
		body := rec.Body.String()
		// no Revoke, and no link in the Revoke cell at all (a link there would open an ordinary /runs): plain text
		if rec.Code != 200 || strings.Contains(body, "hx-post") || !strings.Contains(body, "data-restricted") ||
			strings.Contains(body, `target="_blank"`) || strings.Contains(body, "Revoke opens in Chaperone") || strings.Count(body, "Re-open to revoke") < 1 {
			t.Errorf("restricted /runs (%v): %d, want no Revoke button, no frame link and 'Re-open to revoke' text", hdr, rec.Code)
		}
	}
	if body := b.do("GET", "/runs?from=frame", nil, nil).Body.String(); !reopenLink(body, "/runs") {
		t.Error("restricted /runs has no Re-open here link")
	}
	// the frame links themselves carry the mark, so a context-menu open or a drag arrives restricted too
	if body := b.do("GET", "/runs", nil, frameNav).Body.String(); !strings.Contains(body, `href="/runs?from=frame" target="_blank"`) || strings.Contains(body, `href="/runs" target="_blank"`) {
		t.Error("the framed Revoke link does not carry ?from=frame")
	}
	if body := b.do("GET", "/runs", nil, map[string]string{"Sec-Fetch-Site": ""}).Body.String(); strings.Contains(body, "hx-post") {
		t.Error("/runs with no Sec-Fetch-Site still carries Revoke")
	}

	// a frame navigation is the visibility guard's business, not restricted; with no ancestors listed nothing is restricted
	if body := b.do("GET", "/approvals?from=frame", nil, frameNav).Body.String(); strings.Contains(body, "data-restricted") {
		t.Error("a frame navigation is drawn restricted")
	}
	plain := newScrRig(t)
	pb, _ := plain.signedIn()
	plain.request(nil)
	if body := pb.do("GET", "/approvals?from=frame", nil, nil).Body.String(); strings.Contains(body, "data-restricted") {
		t.Error("with no ancestors listed the page must be the ordinary page")
	}
	if body := pb.do("GET", "/approvals", nil, map[string]string{"Sec-Fetch-Site": ""}).Body.String(); strings.Contains(body, "data-restricted") {
		t.Error("with no ancestors listed a missing Sec-Fetch-Site must not restrict")
	}
}
