package console

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/web"
)

// Review of the frame guard: in a frame there is no Revoke (it is not Hello-signed), the phone panel is not drawn, and the framed
// WebAuthn verifier exists only for the server's own origin.

func TestNoRevokeButtonInAFrame(t *testing.T) {
	sr := newScrRigCfg(t, withGlass)
	b, _ := sr.signedIn()
	sr.seedRun("r-aaaa1", "acme-shop")
	sr.issueOrch("main")

	framed := b.do("GET", "/runs", nil, frameNav)
	if framed.Code != 200 {
		t.Fatalf("framed /runs: %d", framed.Code)
	}
	body := framed.Body.String()
	for _, bad := range []string{"/runs/r-aaaa1/revoke", "/orchestrators/main/revoke", "Revoke orchestrator", ">Revoke</button>", "hx-post"} {
		if strings.Contains(body, bad) {
			t.Errorf("a framed /runs page holds %q: there must be no revoke control in a frame", bad)
		}
	}
	if n := strings.Count(body, "Revoke opens in Chaperone"); n != 2 {
		t.Errorf("framed /runs says \"Revoke opens in Chaperone\" %d times, want 2 (the run and the orchestrator)", n)
	}
	if !strings.Contains(body, `target="_blank" rel="noopener"`) {
		t.Error("the revoke notice is not a link to a top-level window")
	}

	// The same page as a top-level load keeps both buttons, and the guard of the request is by Sec-Fetch-Dest, not by the query.
	top := b.do("GET", "/runs", nil, nil).Body.String()
	for _, want := range []string{`hx-post="/runs/r-aaaa1/revoke"`, `hx-post="/orchestrators/main/revoke"`} {
		if !strings.Contains(top, want) {
			t.Errorf("the top-level /runs page lost %q", want)
		}
	}
	if q := b.do("GET", "/runs?embed=1", nil, nil).Body.String(); !strings.Contains(q, `hx-post="/runs/r-aaaa1/revoke"`) {
		t.Error("?embed=1 on a top-level load must not remove Revoke: only a frame navigation does")
	}
	// A rig without ancestors never treats anything as framed.
	plain := newScrRig(t)
	pb, _ := plain.signedIn()
	plain.seedRun("r-aaaa1", "acme-shop")
	if body := pb.do("GET", "/runs", nil, map[string]string{"Sec-Fetch-Dest": "iframe"}).Body.String(); !strings.Contains(body, "/runs/r-aaaa1/revoke") {
		t.Error("with no ancestors listed the page must be the ordinary page")
	}
}

func TestPhonePanelIsNotDrawnInAFrame(t *testing.T) {
	pr := newPhoneRigCfg(t, withGlass)
	top := pr.pc.do("GET", "/approvals", nil, nil)
	if top.Code != 200 || !strings.Contains(top.Body.String(), `id="phone-panel"`) {
		t.Fatalf("the phone panel is missing from the ordinary page: %d", top.Code)
	}
	framed := pr.pc.do("GET", "/approvals", nil, frameNav)
	if framed.Code != 200 {
		t.Fatalf("framed /approvals: %d", framed.Code)
	}
	for _, bad := range []string{`id="phone-panel"`, "phone-enroll-form", "Ask to add a phone", "Show the enrolment address"} {
		if strings.Contains(framed.Body.String(), bad) {
			t.Errorf("a framed /approvals page holds %q: enrolment is never framed", bad)
		}
	}
}

func TestFramedVerifierIsBuiltForTheServerOriginOnly(t *testing.T) {
	r := newRigCfg(t, withGlass, pcOrigin, phoneOrigin)
	pc, phone := r.con.rps[strings.ToLower(pcOrigin.URL[len("http://"):])], r.con.relyingPartyAt(phoneOrigin.URL)
	if pc == nil || pc.waFramed == nil {
		t.Fatal("the server origin has no framed verifier")
	}
	if phone == nil || phone.waFramed != nil {
		t.Fatalf("the phone origin must have no framed verifier: %+v", phone)
	}
}

// The guard runs in a browser; these pin the rules the review asked for in its source, so a rewrite cannot drop one
// without this test saying so. The behaviour itself is checked in a real browser (see the PR).
func TestFrameGuardSourceKeepsTheReviewedRules(t *testing.T) {
	b, err := fs.ReadFile(web.Static(), "frame-guard.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for rule, needle := range map[string]string{
		"only when framed":                                            "window.top === window.self",
		"the whole card is watched":                                   "article.approval",
		"IntersectionObserver v2 on the card":                         "trackVisibility: true",
		"threshold at full visibility":                                "intersectionRatio >= 0.99",
		"a minimum continuous visible time":                           "const MIN_MS = 800",
		"armed only after that time":                                  "now() - s.since >= MIN_MS",
		"click-time re-check applies queued reports":                  "takeRecords()",
		"scroll disarms":                                              "['scroll', 'resize']",
		"hiding the tab disarms":                                      "visibilitychange",
		"no support means no control":                                 "'isVisible' in IntersectionObserverEntry.prototype",
		"a click on a held control is stopped":                        "e.stopImmediatePropagation()",
		"links are held like buttons":                                 "a[href], [hx-post]",
		"a link is judged on its own visibility":                      "el.matches('a') ? null : el.closest(CARD)",
		"the click listeners come before the observers":               "Registered FIRST, before any observer exists",
		"no observer means held":                                      "cannot judge: held",
		"what is still not in view is looked at again after a scroll": "function retryLater()",
		"the link in the frame is held":                               "scan(links)",
		"the note is after the card, not above the block":             "c.el.appendChild(c.note)",
		"the signed text is watched":                                  ".approval-text",
		"the buttons are watched":                                     ".approval-actions",
		"a long card sends the operator to Chaperone":                 "This card is long: approve it in Chaperone",
		"the note is outside the signed text":                         "It is outside .approval-text",
		"a changed visibility report restarts the visible period":     "if (s.sig !== undefined && s.sig !== sig) s.since = 0",
		"a held control is aria-disabled, not disabled (Basecoat dims a disabled button, IOv2 then calls it not visible)": "Not the disabled attribute",
		"the card entry exists before anything reads it":                                                                  "The card entry exists before anything reads it",
		"a control that cannot be judged stays held":                                                                      "fail closed",
		"the second click of a fast pair is ignored":                                                                      "fast = fast || e.detail >= 2 || now() - lastClick < FAST_MS",
		"dblclick is ignored": "e.type === 'dblclick'",
	} {
		if !strings.Contains(src, needle) {
			t.Errorf("frame-guard.js lost the rule %q (looking for %q)", rule, needle)
		}
	}
	if strings.Contains(src, "embed") && strings.Contains(src, "location.search") {
		t.Error("the guard must not read the ?embed query")
	}
}

// Review of the frame guard (head 1aa60e8): the guard's second round.

func TestFrameGuardSourceKeepsTheSecondRoundRules(t *testing.T) {
	b, err := fs.ReadFile(web.Static(), "frame-guard.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for rule, needle := range map[string]string{
		"only the window's own blur disarms (a blur of an element must not)":        "if (e.target === window) disarmAll()",
		"scroll and resize still disarm":                                            "['scroll', 'resize'].forEach",
		"a new tab is opened by the page, not the browser":                          "window.open(url.href, '_blank', 'noopener')",
		"the open waits for the fast-pair window":                                   "FAST_MS + 50",
		"a click while an open is pending is a fast pair":                           "let fast = pending;",
		"a click anywhere cancels the pending open":                                 "const pending = clicky && pendingOpen !== 0",
		"a disarm cancels the pending open":                                         "cancelOpen(); // a pending new tab",
		"target=_blank links are delayed":                                           `el.matches('[target="_blank"]')`,
		"only a middle click (not a right click) takes the delayed open":            "if (e.type === 'auxclick' && e.button !== 1) return",
		"a click with a modifier key is delayed too":                                "e.ctrlKey || e.shiftKey || e.metaKey || e.altKey",
		"auxclick is listened to":                                                   "['click', 'auxclick', 'dblclick'",
		"the opened tab is marked, so the server draws it restricted":               "url.searchParams.set('from', 'frame')",
		"the frame links carry the mark themselves (secrets)":                       "a.href = '/secrets?from=frame'",
		"the frame links carry the mark themselves (open card)":                     "a.href = '/approvals?from=frame#title-'",
		"the frame links carry the mark themselves (unsupported note)":              "open.href = window.location.pathname + '?from=frame'",
		"the unsupported-browser note has a working link":                           "data-frame-free",
		"an unheld link still goes through the fast-pair rule and the delayed open": "el.dataset.frameFree === '1' || allowed(el)",
	} {
		if !strings.Contains(src, needle) {
			t.Errorf("frame-guard.js lost the rule %q (looking for %q)", rule, needle)
		}
	}
	if strings.Contains(src, "['scroll', 'resize', 'blur']") {
		t.Error("blur must not be a capture listener on window next to scroll and resize: it fires for every element")
	}

	// The top window: acting controls are held until the page has been visible and focused for a second and a person acted.
	for rule, needle := range map[string]string{
		"the top window holds its acting controls":                       "function holdTopLevel()",
		"a second of visible and focused time":                           "const HOLD_MS = 1000",
		"released only when a person acted and the time has passed":      "return moved && since > 0 && t() - since >= HOLD_MS",
		"blur of the window resets the timer, not blur of elements":      "if (e.target === window) { since = 0; paint(); }",
		"hiding the tab resets the timer":                                "document.addEventListener('visibilitychange', restart)",
		"a move needs a distance (synthetic moves have none)":            "(e.movementX || 0) !== 0 || (e.movementY || 0) !== 0",
		"a mouse press that moves focus is not a person's focus":         "t() - lastDown > 400",
		"keyboard and assistive tech are not locked out":                 "Move the pointer or press Tab, then try again.",
		"sign-in, enrolment and the phone's number buttons are not held": "const EXEMPT = '[data-passkey], [data-number], #enroll'",
		"Re-open is held like a button":                                  "[hx-delete], a[data-reopen]'",
		"a middle click on a held link is stopped too":                   "['click', 'auxclick'].forEach(function (type) {",
	} {
		if !strings.Contains(src, needle) {
			t.Errorf("frame-guard.js lost the rule %q (looking for %q)", rule, needle)
		}
	}
	js := string(approvalsJS)
	if !strings.Contains(js, "document.querySelector('[data-restricted]')") {
		t.Error("approvals.js unfolds a card from the address hash on a restricted page")
	}
	if strings.Contains(js, "held") {
		t.Error("approvals.js must not carry its own hold any more: it lives in frame-guard.js (holdTopLevel)")
	}
}
