package console

import (
	"context"
	"crypto/hmac"
	"io/fs"
	"net/http"
	"strings"

	"github.com/joshua-noel/chaperone/web"
)

const (
	sessionCookie = "chap_session"
	csrfCookie    = "chap_csrf"
	csrfHeader    = "X-CSRF-Token"
)

// framablePaths is the whole list of pages a listed frame ancestor may show in a frame (GET only). Anything not here is
// never framed, with or without the opt-in: sign-in, enrolment, the phone pages, Home (it holds Stop all), Operations,
// and Secrets (typing a secret has no second factor, so a page that could overlay a fake field must never frame it).
// Adding a path here widens what a compromised ancestor can show; the test TestFramingIsAnExplicitAllowList pins it.
var framablePaths = map[string]bool{
	"/approvals": true, // the cards, Approve and Deny (the page script also holds every button until it is plainly visible)
	"/ledger":    true, // the log, read only
	"/runs":      true, // active runs and tokens, and Revoke
}

// framable says whether this request is a frame navigation to a framablePath and frame ancestors are configured.
func (c *Console) framable(r *http.Request) bool {
	return len(c.frameAncestors) > 0 && r.Method == http.MethodGet && framablePaths[r.URL.Path] && r.Header.Get("Sec-Fetch-Dest") == "iframe"
}

// navigation says whether fetch metadata would refuse this request as same-site or cross-site but it is only a GET
// frame navigation (Sec-Fetch-Dest: iframe) to a framablePath. A GET reads and changes nothing; the session cookie is
// SameSite=Strict, so from another site the page arrives signed out; and the browser shows the page only inside a listed
// ancestor (the CSP frame-ancestors of framable). A top-level navigation from another page is NOT relaxed: it is refused
// as before, so no other page can load a console page as a document, with the session and without the frame guard (the
// "DoubleClickjacking" swap). The operator opens a top-level page by its own address, or from a link inside a frame
// (that navigation is same-origin). Without ancestors configured nothing is relaxed.
func (c *Console) navigation(r *http.Request, site string) bool {
	if len(c.frameAncestors) == 0 || r.Method != http.MethodGet || r.Header.Get("Sec-Fetch-Mode") != "navigate" {
		return false
	}
	if site != "same-site" && site != "cross-site" {
		return false
	}
	return r.Header.Get("Sec-Fetch-Dest") == "iframe" && framablePaths[r.URL.Path]
}

// restricts is whether restricted applies to a path: every framablePath, and Secrets. Secrets is never framed, but the
// console's own link out of a frame ("Secrets: opens in Chaperone") opens it, and since a secret write's card is on that page
// (Approve stores the value) it must not hand over a live Approve any more than /approvals does.
func restricts(path string) bool { return framablePaths[path] || path == "/secrets" }

// restricted says whether this load of a framablePath or of /secrets is shown disarmed: every card folded, no unfold from the address
// hash, no Approve, Deny or Revoke, and a note with a "Re-open here" link. It applies to a document load, not a frame
// navigation (the visibility guard owns that), and only while frame ancestors are configured. Two cases:
//   - the console's own link out of a frame carries ?from=frame. Whoever opened it, it is the page a frame lure sends the
//     operator to; it must not hand him a live Approve at a predictable place after two clicks.
//   - a browser that sends no Sec-Fetch-Site cannot be told from another site, so it takes the safe side, and no query
//     value lifts it (an opener could add any value): the page says so and points to a supported browser. Every browser
//     the console supports sends the header.
//
// A top-level load from another page is not "restricted": navigation() already refuses it with 403 for Sec-Fetch-Site
// same-site and cross-site (a window.open or a link or a redirect of any other page, a listed ancestor included). The
// header values same-origin and none (a link in the console, the typed address) are the operator's own and are unrestricted.
func (c *Console) restricted(r *http.Request) bool {
	if len(c.frameAncestors) == 0 || r.Method != http.MethodGet || !restricts(r.URL.Path) || r.Header.Get("Sec-Fetch-Dest") == "iframe" {
		return false
	}
	q := r.URL.Query()
	if q.Get("from") == "frame" {
		return true
	}
	return r.Header.Get("Sec-Fetch-Site") == ""
}

// framed says whether the response is one a frame shows, or the window a frame link opens, while frame ancestors are
// configured: Sec-Fetch-Dest iframe, or ?from=frame. Those are the guard's own signals; ?embed=1 is not one (a framer can
// leave it out). Such a page draws no header and no nav: their links lead to ordinary pages that carry no ?from=frame, or
// to pages that are never framed. Without ancestors nothing is framed and every page is the ordinary page.
func (c *Console) framed(r *http.Request) bool {
	return len(c.frameAncestors) > 0 && (r.Header.Get("Sec-Fetch-Dest") == "iframe" || r.URL.Query().Get("from") == "frame")
}

// assetPaths are the console's own routes that serve a page's script and style, not a page. Only a browser that sends no
// Sec-Fetch-Dest needs this list: otherwise the destination says it.
var assetPaths = map[string]bool{"/approvals/approvals.js": true, "/approvals/approvals.css": true}

// slidesSession says whether this request counts as the operator using the console, so that it extends the session's idle
// time: a POST, or a document navigation (Sec-Fetch-Dest document or iframe). A page's script or style, an htmx or fetch
// GET (destination empty) and the like do not: a frame that keeps reloading its assets must not stay signed in past the
// idle limit. A browser that sends no Sec-Fetch-Dest is not told apart except by the asset routes.
func slidesSession(r *http.Request) bool {
	if r.Method == http.MethodPost {
		return true
	}
	switch r.Header.Get("Sec-Fetch-Dest") {
	case "document", "iframe":
		return true
	case "":
		return !assetPaths[r.URL.Path]
	}
	return false
}

// csp: script and style only from this origin; htmx's inline styles and
// eval are switched off in the page (see web/VENDOR.md). img-src data: is for
// Basecoat's inline SVG icons.
const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

type ctxKey struct{}

// reqState is what the guard learned about a request.
type reqState struct {
	rp         *relyingParty
	csrfCookie string
	sess       *session
	user       *approver
	restricted bool // see Console.restricted
	legacy     bool // restricted because the browser sent no Sec-Fetch-Site: nothing on the page lifts it
	framed     bool // a framed response or the window a frame link opened (see Console.framed): the page draws no header or nav
}

func stateOf(r *http.Request) *reqState { return r.Context().Value(ctxKey{}).(*reqState) }

func refuse(w http.ResponseWriter, status int, why string) {
	http.Error(w, why, status)
}

// guard is the DNS-rebinding, cross-origin, CSRF and cache gate in front of
// every console route.
func (c *Console) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		if c.framable(r) {
			// A frame navigation to one of the framablePaths, with ancestors configured: shown only inside the listed
			// origins. No X-Frame-Options: it has no allow-list form, and the CSP frame-ancestors below decides.
			h.Set("Content-Security-Policy", strings.Replace(csp, "frame-ancestors 'none'", "frame-ancestors "+strings.Join(c.frameAncestors, " "), 1))
		} else {
			h.Set("Content-Security-Policy", csp)
			h.Set("X-Frame-Options", "DENY")
		}
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "publickey-credentials-get=(self), publickey-credentials-create=(self)")

		// 1. Host: exactly the host of a configured origin. This is what stops
		// DNS rebinding: the attacker's page is served from the browser's
		// point of view at evil.example, so Host says so.
		rp := c.rps[strings.ToLower(r.Host)]
		if rp == nil {
			c.log.Warn("refused: host not allowed", "host", r.Host, "remote", r.RemoteAddr)
			refuse(w, http.StatusForbidden, "host not allowed")
			return
		}

		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodPost:
		default:
			h.Set("Allow", "GET, HEAD, POST")
			refuse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		unsafe := r.Method == http.MethodPost

		// 2. Origin: when sent it must be this origin; a POST must send it.
		switch origin, sent := r.Header["Origin"]; {
		case sent && (len(origin) != 1 || origin[0] != rp.URL):
			c.log.Warn("refused: origin mismatch", "origin", origin, "want", rp.URL)
			refuse(w, http.StatusForbidden, "origin not allowed")
			return
		case unsafe && !sent:
			refuse(w, http.StatusForbidden, "origin required")
			return
		}
		// 3. Fetch metadata, when the browser sends it. A request that gets through only because navigation() relaxed
		// it (a frame navigation from another origin) must not keep the session alive: slide stays false for it. Nor
		// does a request for a page asset (slidesSession).
		slide := slidesSession(r)
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
			if !c.navigation(r, site) {
				c.log.Warn("refused: sec-fetch-site", "site", site)
				refuse(w, http.StatusForbidden, "cross-site request refused")
				return
			}
			slide = false
		}

		// Static files carry no session and set no cookie; they passed the
		// host, origin and fetch-metadata checks above.
		if !unsafe && strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}

		st := &reqState{rp: rp, restricted: c.restricted(r), framed: c.framed(r)}
		st.legacy = st.restricted && r.Header.Get("Sec-Fetch-Site") == ""
		// 4. CSRF cookie: issue one if the browser has none.
		if ck, err := r.Cookie(c.cookieName(rp, csrfCookie)); err == nil && len(ck.Value) == 43 {
			st.csrfCookie = ck.Value
		} else {
			st.csrfCookie = b64.EncodeToString(randBytes(32))
			http.SetCookie(w, c.cookie(rp, csrfCookie, st.csrfCookie, 0))
		}

		// 5. Session.
		if ck, err := r.Cookie(c.cookieName(rp, sessionCookie)); err == nil {
			sess, user, err := c.lookupSession(r.Context(), ck.Value, slide)
			if err != nil {
				c.log.Error("session lookup", "err", err)
				refuse(w, http.StatusInternalServerError, "internal error")
				return
			}
			if sess != nil && sess.Origin == rp.URL {
				st.sess, st.user = sess, user
			}
		}

		// 6. CSRF token on every POST.
		if unsafe {
			got := r.Header.Get(csrfHeader)
			if !hmac.Equal([]byte(got), []byte(c.csrfToken(st))) {
				c.log.Warn("refused: csrf token")
				refuse(w, http.StatusForbidden, "csrf token missing or wrong")
				return
			}
		}

		r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, st))
		if st.user == nil && c.framable(r) {
			// Signed out (idle 30 minutes, or the 8-hour cap): every framable page would redirect to /login, which is
			// never framable, so the frame would show the browser's "refused to connect" page with no words. Say
			// what happened instead, with a link that opens the sign-in page in the console's own window.
			c.render(w, r, http.StatusOK, "signedout", page{Title: "Signed out"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// cookieName adds the __Host- prefix on https origins, which makes the
// browser refuse a Domain attribute or a cookie set from a sibling subdomain.
// It cannot be used on plain-http localhost (the prefix needs Secure).
func (c *Console) cookieName(rp *relyingParty, name string) string {
	if rp.secure() {
		return "__Host-" + name
	}
	return name
}

// cookie builds a host-only, HttpOnly, SameSite=Strict cookie. maxAge 0 makes
// a browser-session cookie; a negative value deletes it.
func (c *Console) cookie(rp *relyingParty, name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     c.cookieName(rp, name),
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   rp.secure(),
		SameSite: http.SameSiteStrictMode,
	}
}

// staticHandler serves web/static. No directory listings; cacheable, unlike
// everything else the guard covers.
func staticHandler() http.Handler {
	files := http.StripPrefix("/static/", http.FileServerFS(web.Static()))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/static/")
		if st, err := fs.Stat(web.Static(), p); err != nil || st.IsDir() {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=300")
		files.ServeHTTP(w, r)
	})
}
