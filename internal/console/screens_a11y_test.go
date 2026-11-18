package console

import (
	"context"
	"regexp"
	"strings"
	"testing"
)

// Accessibility basics for the screens (ticket L1-20: labels and keyboard).
// These are checks on the markup, not a browser run: every control is a
// native element a keyboard reaches, has an accessible name, and every status
// that changes is in a live region. The page has the landmarks a screen reader
// jumps by, and nothing needs script the CSP forbids.

var (
	controlRe = regexp.MustCompile(`(?s)<(input|textarea|select)\b([^>]*)>`)
	buttonRe  = regexp.MustCompile(`(?s)<button\b([^>]*)>(.*?)</button>`)
	anchorRe  = regexp.MustCompile(`(?s)<a\b([^>]*)>(.*?)</a>`)
	tagRe     = regexp.MustCompile(`(?s)<[^>]*>`)
	attrIDRe  = regexp.MustCompile(`\bid="([^"]+)"`)
	hxPostRe  = regexp.MustCompile(`<(\w+)\b[^>]*\bhx-post=`)
	thRe      = regexp.MustCompile(`<th\b([^>]*)>`)
)

func hasAttr(attrs, name string) bool {
	return regexp.MustCompile(`(^|\s)` + name + `(=|\s|$)`).MatchString(attrs)
}

func checkPage(t *testing.T, name, page string) {
	t.Helper()
	errf := func(format string, args ...any) { t.Helper(); t.Errorf(name+": "+format, args...) }

	// Landmarks and the way in.
	for _, want := range []string{`<html lang="en">`, `<a class="skip-link" href="#main">`, `<nav class="shell-nav" aria-label="Console">`, `<main class="shell-main" id="main"`} {
		if !strings.Contains(page, want) {
			errf("missing %s", want)
		}
	}
	if n := strings.Count(page, "<h1"); n != 1 {
		errf("%d <h1>, want 1", n)
	}
	if !regexp.MustCompile(`<title>[^<]+ - Chaperone</title>`).MatchString(page) {
		errf("no page title")
	}

	// Every field has a label: for= on its id, a wrapping <label>, or aria-label.
	for _, m := range controlRe.FindAllStringSubmatchIndex(page, -1) {
		tag, attrs := page[m[2]:m[3]], page[m[4]:m[5]]
		typ := regexp.MustCompile(`\btype="([^"]+)"`).FindStringSubmatch(attrs)
		if tag == "input" && typ != nil && (typ[1] == "hidden" || typ[1] == "submit" || typ[1] == "button") {
			continue
		}
		switch {
		case hasAttr(attrs, "aria-label") || hasAttr(attrs, "aria-labelledby"):
		case attrIDRe.MatchString(attrs) && strings.Contains(page, `for="`+attrIDRe.FindStringSubmatch(attrs)[1]+`"`):
		default:
			before := page[:m[0]]
			open := strings.LastIndex(before, "<label")
			if open < 0 || strings.Contains(before[open:], "</label>") {
				errf("field without a label: <%s %s>", tag, attrs)
			}
		}
	}

	// Every button and link has a name.
	for _, m := range buttonRe.FindAllStringSubmatch(page, -1) {
		if strings.TrimSpace(tagRe.ReplaceAllString(m[2], "")) == "" && !hasAttr(m[1], "aria-label") {
			errf("button without a name: %s", m[0])
		}
		if !hasAttr(m[1], "type") {
			errf("button without a type (it would submit a form): %s", m[0])
		}
	}
	for _, m := range anchorRe.FindAllStringSubmatch(page, -1) {
		if strings.TrimSpace(tagRe.ReplaceAllString(m[2], "")) == "" && !hasAttr(m[1], "aria-label") {
			errf("link without a name: %s", m[0])
		}
	}

	// Keyboard: actions are native buttons or forms, nothing steals the tab order.
	for _, m := range hxPostRe.FindAllStringSubmatch(page, -1) {
		if m[1] != "button" && m[1] != "form" {
			errf("hx-post on <%s>: not reachable by keyboard", m[1])
		}
	}
	if regexp.MustCompile(`tabindex="[1-9]`).MatchString(page) {
		errf("a positive tabindex reorders the keyboard path")
	}
	for _, m := range regexp.MustCompile(`<(\w+)\b[^>]*\btabindex="0"`).FindAllStringSubmatch(page, -1) {
		if m[1] != "pre" { // the card text scrolls, so a keyboard must be able to focus it
			errf("tabindex=0 on <%s>", m[1])
		}
	}
	// Taking authority away asks first; the destructive buttons all do.
	for _, m := range buttonRe.FindAllStringSubmatch(page, -1) {
		if strings.Contains(m[1], `data-variant="destructive"`) && strings.Contains(m[1], "hx-post") && !strings.Contains(m[1], "hx-confirm") {
			errf("a destructive button acts without asking: %s", m[0])
		}
	}

	// Tables: a caption, and header cells that say which way they head.
	if strings.Count(page, "<table") != strings.Count(page, "<caption") {
		errf("%d tables, %d captions", strings.Count(page, "<table"), strings.Count(page, "<caption"))
	}
	for _, m := range thRe.FindAllStringSubmatch(page, -1) {
		if !hasAttr(m[1], "scope") {
			errf("<th> without scope: <th%s>", m[1])
		}
	}

	// Live regions: whatever an action answers with lands in one.
	for _, id := range []string{"stop-all-result", "verify-result", "secrets-status", "secret-form-status", "runs-status"} {
		re := regexp.MustCompile(`<div id="` + id + `"[^>]*aria-live="polite"`)
		if strings.Contains(page, `id="`+id+`"`) && !re.MatchString(page) {
			errf("#%s is not a live region", id)
		}
	}

	// The CSP allows no inline script, handler or style: so none may be used.
	for _, bad := range []string{" onclick=", " onchange=", " onsubmit=", ` style="`, "javascript:"} {
		if strings.Contains(page, bad) {
			errf("inline %q", bad)
		}
	}
	for _, m := range regexp.MustCompile(`<script\b([^>]*)>`).FindAllStringSubmatch(page, -1) {
		if !strings.Contains(m[1], "src=") {
			errf("inline <script>")
		}
	}
	// Basecoat 1.0.2 styles .btn with data-variant; it has no .btn-destructive or .btn-outline.
	if m := regexp.MustCompile(`class="[^"]*\bbtn-[a-z]+`).FindString(page); m != "" {
		errf("a class Basecoat 1.0.2 does not define (use class=\"btn\" data-variant=...): %s", m)
	}
	if strings.Count(page, "<button") != strings.Count(page, "</button>") {
		errf("unbalanced <button>")
	}
}

func TestScreensAccessibilityBasics(t *testing.T) {
	sr := newScrRig(t)
	b, _ := sr.signedIn()
	ctx := context.Background()
	// Give every screen something to show: runs, an orchestrator, a card, a
	// waiting secret write, a denial, an anchor, a vault secret.
	sr.seedRun("r-aaaa1", "acme-shop")
	sr.seedRun("r-aaaa2", "acme-shop")
	sr.issueOrch("main")
	sr.request(nil)
	sr.seedDenial("r-aaaa1", "acme-shop", "OP_DISABLED", "deploy pilot: OP_DISABLED")
	if _, err := sr.led.Anchor(ctx, "offline-copy", "usb-1"); err != nil {
		t.Fatal(err)
	}
	if err := sr.runs.Revoke(ctx, "r-aaaa2", "OPERATOR_STOP_RUN"); err != nil { // an ended run to list
		t.Fatal(err)
	}
	sr.requestSecret(b, importForm("gh-app-key", "a-value-for-a11y"))

	for _, p := range []string{"/", "/approvals", "/catalog", "/ledger", "/ledger?event=denial", "/runs", "/secrets"} {
		page := get(t, b, p)
		checkPage(t, p, page)
		// The checker must be looking at something.
		switch p {
		case "/secrets":
			if n := len(controlRe.FindAllString(page, -1)); n < 6 {
				t.Errorf("%s: the checker found %d form controls", p, n)
			}
		case "/ledger":
			if n := len(controlRe.FindAllString(page, -1)); n < 7 {
				t.Errorf("%s: the checker found %d form controls", p, n)
			}
		case "/runs":
			if n := len(buttonRe.FindAllString(page, -1)); n < 2 {
				t.Errorf("%s: the checker found %d buttons", p, n)
			}
		}
	}
	// The fragments the actions answer with name their state in words.
	for _, p := range []string{"/stop-all"} {
		rec := hxPost(b, p, nil)
		mustHave(t, p, rec.Body.String(), "<h2>")
	}
	// The stylesheet gives keyboard focus a visible ring, and the skip link a place to land.
	css := get(t, b, "/static/console.css")
	mustHave(t, "css", css, ":focus-visible", ".skip-link:focus")
	// And console.js reaches the nav's current page and the confirm/clear hooks without eval.
	js := get(t, b, "/static/console.js")
	mustHave(t, "js", js, "aria-current", "htmx:beforeSwap", "data-clear-on-success")
	mustNotHave(t, "js", js, "eval(", "new Function")
}
