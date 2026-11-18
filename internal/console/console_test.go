package console

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func wantRefused(t *testing.T, r *rig, code int, out map[string]json.RawMessage, reason string) {
	t.Helper()
	if code < 400 {
		t.Fatalf("expected a refusal, got %d %v", code, out)
	}
	if got := str(out["error"]); got != reason {
		t.Fatalf("error code = %q, want %q (events %+v)", got, reason, r.events())
	}
	if e := r.last(); e.Name != EventRefused || e.Reason != reason {
		t.Fatalf("last event = %+v, want refusal %q", e, reason)
	}
}

func countRows(t *testing.T, r *rig, table string) int {
	t.Helper()
	var n int
	if err := r.db.SQL().QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// ---- the happy path, end to end ----

func TestEnrolAndLogin(t *testing.T) {
	r := newRig(t)
	b := r.browser(pcOrigin)

	// Before enrolment the login page says so and begin is refused.
	if rec := b.do("GET", "/login", nil, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "No approver is enrolled") {
		t.Fatalf("GET /login before enrolment: %d", rec.Code)
	}
	if code, out := b.post("/login/begin", nil, ""); code != http.StatusConflict || str(out["error"]) != "no_approver" {
		t.Fatalf("login/begin with no approver: %d %v", code, out)
	}

	a := mustEnrolled(t, r, b)
	if e := r.last(); e.Name != EventEnrolled || !e.Bootstrap || !e.UserVerified || e.RPID != "localhost" || e.Origin != "http://localhost:55398" {
		t.Fatalf("enrol event = %+v", e)
	}
	var rp, origin string
	var uv int
	if err := r.db.SQL().QueryRow(`SELECT rp_id, origin, user_verified FROM credentials`).Scan(&rp, &origin, &uv); err != nil {
		t.Fatal(err)
	}
	if rp != "localhost" || origin != "http://localhost:55398" || uv != 1 {
		t.Fatalf("stored credential rp_id=%q origin=%q uv=%d", rp, origin, uv)
	}

	// No session yet: / bounces to /login.
	if rec := b.do("GET", "/", nil, nil); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("GET / signed out: %d %q", rec.Code, rec.Header().Get("Location"))
	}

	code, out := b.login(a, opts{})
	if code != 200 {
		t.Fatalf("login: %d %v events=%+v", code, out, r.events())
	}
	if e := r.last(); e.Name != EventLogin || !e.UserVerified || e.SignCount != 1 {
		t.Fatalf("login event = %+v", e)
	}
	rec := b.do("GET", "/", nil, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Signed in as operator") || !strings.Contains(rec.Body.String(), "Hello") {
		t.Fatalf("GET / signed in: %d %s", rec.Code, rec.Body.String())
	}
	if rec := b.do("GET", "/login", nil, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("GET /login when signed in: %d", rec.Code)
	}

	// Logout ends the session server-side, not just in the browser.
	cookies := map[string]string{}
	for k, v := range b.cookies {
		cookies[k] = v
	}
	if rec := b.do("POST", "/logout", nil, map[string]string{"X-CSRF-Token": b.csrf()}); rec.Code != http.StatusNoContent || rec.Header().Get("HX-Redirect") != "/login" {
		t.Fatalf("logout: %d", rec.Code)
	}
	b.cookies = cookies // the old cookie, replayed
	if rec := b.do("GET", "/", nil, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("session still valid after logout: %d", rec.Code)
	}
}

func TestSessionExpiry(t *testing.T) {
	r := newRig(t)
	b := r.browser(pcOrigin)
	a := mustEnrolled(t, r, b)
	if code, out := b.login(a, opts{}); code != 200 {
		t.Fatal(code, out)
	}
	r.advance(20 * time.Minute) // inside the 30 minute idle window: slides
	if rec := b.do("GET", "/", nil, nil); rec.Code != 200 {
		t.Fatalf("20 min: %d", rec.Code)
	}
	r.advance(20 * time.Minute) // 20 more since the last request
	if rec := b.do("GET", "/", nil, nil); rec.Code != 200 {
		t.Fatalf("40 min total, active: %d", rec.Code)
	}
	r.advance(31 * time.Minute) // idle too long
	if rec := b.do("GET", "/", nil, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("idle session accepted: %d", rec.Code)
	}
}

func TestSessionAbsoluteLimit(t *testing.T) {
	r := newRig(t)
	b := r.browser(pcOrigin)
	a := mustEnrolled(t, r, b)
	if code, out := b.login(a, opts{}); code != 200 {
		t.Fatal(code, out)
	}
	start := r.now
	// Busy the whole time: a request every 25 minutes keeps the idle timer fresh.
	for r.now.Sub(start) < 8*time.Hour-25*time.Minute {
		r.advance(25 * time.Minute)
		if rec := b.do("GET", "/", nil, nil); rec.Code != 200 {
			t.Fatalf("session ended early at %s: %d", r.now.Sub(start), rec.Code)
		}
	}
	r.advance(25 * time.Minute) // now past 8 hours since sign-in
	if rec := b.do("GET", "/", nil, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("session outlived the absolute limit (%s): %d", r.now.Sub(start), rec.Code)
	}
}

func TestDisabledApproverLosesSession(t *testing.T) {
	r := newRig(t)
	b := r.browser(pcOrigin)
	a := mustEnrolled(t, r, b)
	if code, out := b.login(a, opts{}); code != 200 {
		t.Fatal(code, out)
	}
	if _, err := r.db.SQL().Exec(`UPDATE approvers SET disabled_at = ?`, "2026-10-24T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if rec := b.do("GET", "/", nil, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("disabled approver kept the session: %d", rec.Code)
	}
	b2 := r.browser(pcOrigin)
	code, out := b2.login(a, opts{})
	wantRefused(t, r, code, out, ReasonCredential)
}

// ---- acceptance: refusals ----

func TestWrongOriginRefused(t *testing.T) {
	t.Run("assertion", func(t *testing.T) {
		r := newRig(t)
		b := r.browser(pcOrigin)
		a := mustEnrolled(t, r, b)
		// A look-alike page reports its own origin in clientDataJSON.
		code, out := b.login(a, opts{origin: "http://localhost:55399"})
		wantRefused(t, r, code, out, ReasonOrigin)
		code, out = b.login(a, opts{origin: "https://evil.example"})
		wantRefused(t, r, code, out, ReasonOrigin)
		if countRows(t, r, "console_sessions") != 0 {
			t.Fatal("a session was created")
		}
	})
	t.Run("registration", func(t *testing.T) {
		r := newRig(t)
		b := r.browser(pcOrigin)
		_, code, out := b.enrol(r, r.token(), opts{origin: "https://evil.example"})
		wantRefused(t, r, code, out, ReasonOrigin)
		if countRows(t, r, "approvers") != 0 || countRows(t, r, "credentials") != 0 {
			t.Fatal("a credential was stored")
		}
	})
}

func TestWrongChallengeRefused(t *testing.T) {
	bad := b64.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	t.Run("assertion", func(t *testing.T) {
		r := newRig(t)
		b := r.browser(pcOrigin)
		a := mustEnrolled(t, r, b)
		code, out := b.login(a, opts{challenge: bad})
		wantRefused(t, r, code, out, ReasonChallenge)
	})
	t.Run("registration", func(t *testing.T) {
		r := newRig(t)
		b := r.browser(pcOrigin)
		_, code, out := b.enrol(r, r.token(), opts{challenge: bad})
		wantRefused(t, r, code, out, ReasonChallenge)
		if countRows(t, r, "approvers") != 0 {
			t.Fatal("an approver was stored")
		}
	})
}

func TestReplayRefused(t *testing.T) {
	t.Run("same ceremony", func(t *testing.T) {
		r := newRig(t)
		b := r.browser(pcOrigin)
		a := mustEnrolled(t, r, b)
		cer, options := b.begin("/login/begin", nil)
		body := a.get(options, b.origin, opts{})
		if code, out := b.post("/login/finish", body, cer); code != 200 {
			t.Fatal(code, out)
		}
		// The same bytes again, from the same browser, with the same ceremony.
		code, out := b.post("/login/finish", body, cer)
		wantRefused(t, r, code, out, ReasonCeremony)
	})
	t.Run("old assertion on a new ceremony", func(t *testing.T) {
		r := newRig(t)
		b := r.browser(pcOrigin)
		a := mustEnrolled(t, r, b)
		cer, options := b.begin("/login/begin", nil)
		old := a.get(options, b.origin, opts{})
		if code, out := b.post("/login/finish", old, cer); code != 200 {
			t.Fatal(code, out)
		}
		// An attacker who captured `old` waits for the next sign-in and sends it.
		cer2, _ := b.begin("/login/begin", nil)
		code, out := b.post("/login/finish", old, cer2)
		wantRefused(t, r, code, out, ReasonChallenge)
	})
	t.Run("registration", func(t *testing.T) {
		r := newRig(t)
		b := r.browser(pcOrigin)
		req, _ := json.Marshal(map[string]string{"token": r.token(), "name": "operator", "label": "Hello"})
		cer, options := b.begin("/enroll/begin", req)
		a := newAuthenticator(t, "localhost")
		body := a.create(options, b.origin, opts{})
		if code, out := b.post("/enroll/finish", body, cer); code != 200 {
			t.Fatal(code, out)
		}
		code, out := b.post("/enroll/finish", body, cer)
		wantRefused(t, r, code, out, ReasonCeremony)
		if n := countRows(t, r, "credentials"); n != 1 {
			t.Fatalf("credentials = %d", n)
		}
	})
	t.Run("failed attempt burns the ceremony", func(t *testing.T) {
		r := newRig(t)
		b := r.browser(pcOrigin)
		a := mustEnrolled(t, r, b)
		cer, options := b.begin("/login/begin", nil)
		if code, out := b.post("/login/finish", a.get(options, b.origin, opts{noUV: true}), cer); code != http.StatusForbidden {
			t.Fatal(code, out)
		}
		// The right answer to the same ceremony is too late.
		code, out := b.post("/login/finish", a.get(options, b.origin, opts{}), cer)
		wantRefused(t, r, code, out, ReasonCeremony)
	})
}

func TestUserVerificationRequired(t *testing.T) {
	t.Run("assertion with UV false", func(t *testing.T) {
		r := newRig(t)
		b := r.browser(pcOrigin)
		a := mustEnrolled(t, r, b)
		code, out := b.login(a, opts{noUV: true})
		wantRefused(t, r, code, out, ReasonUV)
		if countRows(t, r, "console_sessions") != 0 {
			t.Fatal("a session was created")
		}
	})
	t.Run("assertion with UP false", func(t *testing.T) {
		r := newRig(t)
		b := r.browser(pcOrigin)
		a := mustEnrolled(t, r, b)
		code, out := b.login(a, opts{noUP: true})
		wantRefused(t, r, code, out, ReasonUP)
	})
	t.Run("registration with UV false", func(t *testing.T) {
		r := newRig(t)
		b := r.browser(pcOrigin)
		_, code, out := b.enrol(r, r.token(), opts{noUV: true})
		wantRefused(t, r, code, out, ReasonUV)
		if countRows(t, r, "approvers") != 0 || countRows(t, r, "credentials") != 0 {
			t.Fatal("a credential without user verification was stored")
		}
	})
	t.Run("the table refuses user_verified = 0", func(t *testing.T) {
		r := newRig(t)
		b := r.browser(pcOrigin)
		mustEnrolled(t, r, b)
		if _, err := r.db.SQL().Exec(`UPDATE credentials SET user_verified = 0`); err == nil {
			t.Fatal("CHECK constraint did not fire")
		}
	})
}

func TestHostRebindingRefused(t *testing.T) {
	r := newRig(t)
	good := r.browser(pcOrigin)
	a := mustEnrolled(t, r, good)
	if code, out := good.login(a, opts{}); code != 200 {
		t.Fatal(code, out)
	}
	h := r.con.Handler()
	for _, host := range []string{
		"evil.example", "evil.example:55398", "127.0.0.1:55398", "[::1]:55398",
		"localhost", "localhost:55399", "localhost.:55398", "localhost.evil.example:55398", "LOCALHOST.evil.example",
	} {
		for _, path := range []string{"/", "/login", "/enroll", "/static/console.js"} {
			b := &browser{t: t, h: h, host: host, origin: "http://" + host, cookies: map[string]string{}}
			for k, v := range good.cookies { // even a browser holding a live session cookie
				b.cookies[k] = v
			}
			rec := b.do("GET", path, nil, nil)
			if rec.Code != http.StatusForbidden {
				t.Errorf("Host %q GET %s = %d, want 403", host, path, rec.Code)
			}
			if strings.Contains(rec.Body.String(), "Signed in") || len(rec.Result().Cookies()) != 0 {
				t.Errorf("Host %q GET %s leaked content or set a cookie", host, path)
			}
		}
		// A rebinding page can also POST; the guard answers before any handler.
		b := &browser{t: t, h: h, host: host, origin: "http://" + host, cookies: good.cookies}
		if rec := b.do("POST", "/login/begin", nil, map[string]string{"X-CSRF-Token": good.csrf()}); rec.Code != http.StatusForbidden {
			t.Errorf("Host %q POST = %d, want 403", host, rec.Code)
		}
	}
	if n := countRows(t, r, "console_ceremonies"); n != 0 {
		t.Fatalf("a refused request left %d ceremonies", n)
	}
}

func TestOriginAndFetchMetadataRefused(t *testing.T) {
	r := newRig(t)
	b := r.browser(pcOrigin)
	tok := b.csrf()
	post := func(h map[string]string) int {
		h["X-CSRF-Token"] = tok
		return b.do("POST", "/login/begin", nil, h).Code
	}
	if c := post(map[string]string{"Origin": "https://evil.example"}); c != 403 {
		t.Errorf("foreign Origin on POST = %d", c)
	}
	if c := post(map[string]string{"Origin": "null"}); c != 403 {
		t.Errorf("null Origin on POST = %d", c)
	}
	if c := post(map[string]string{"Origin": "http://localhost:55398/"}); c != 403 {
		t.Errorf("Origin with a path = %d", c)
	}
	if c := post(map[string]string{"Origin": ""}); c != 403 {
		t.Errorf("POST without Origin = %d", c)
	}
	if c := post(map[string]string{"Sec-Fetch-Site": "cross-site"}); c != 403 {
		t.Errorf("cross-site POST = %d", c)
	}
	if c := post(map[string]string{"Sec-Fetch-Site": "same-site"}); c != 403 {
		t.Errorf("same-site POST = %d", c)
	}
	if c := b.do("GET", "/login", nil, map[string]string{"Origin": "https://evil.example"}).Code; c != 403 {
		t.Errorf("GET with a foreign Origin = %d", c)
	}
	if c := b.do("GET", "/login", nil, map[string]string{"Sec-Fetch-Site": "cross-site"}).Code; c != 403 {
		t.Errorf("cross-site GET = %d", c)
	}
	for _, m := range []string{"PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"} {
		if c := b.do(m, "/login", nil, nil).Code; c != http.StatusMethodNotAllowed {
			t.Errorf("%s = %d, want 405", m, c)
		}
	}
}

func TestCSRF(t *testing.T) {
	r := newRig(t)
	b := r.browser(pcOrigin)
	good := b.csrf()
	for name, hdr := range map[string]map[string]string{
		"missing":                  {},
		"empty":                    {"X-CSRF-Token": ""},
		"garbage":                  {"X-CSRF-Token": "AAAA"},
		"truncated":                {"X-CSRF-Token": good[:len(good)-2]},
		"form field is not enough": {},
	} {
		if rec := b.do("POST", "/login/begin", nil, hdr); rec.Code != 403 {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
	// A token minted for another browser (another csrf cookie) is no use here.
	other := r.browser(pcOrigin)
	if rec := b.do("POST", "/login/begin", nil, map[string]string{"X-CSRF-Token": other.csrf()}); rec.Code != 403 {
		t.Errorf("token from another browser: %d", rec.Code)
	}
	// A token from before sign-in stops working once there is a session.
	a := mustEnrolled(t, r, b)
	pre := b.csrf()
	if code, out := b.login(a, opts{}); code != 200 {
		t.Fatal(code, out)
	}
	if rec := b.do("POST", "/logout", nil, map[string]string{"X-CSRF-Token": pre}); rec.Code != 403 {
		t.Errorf("pre-session token accepted for logout: %d", rec.Code)
	}
	if rec := b.do("POST", "/logout", nil, map[string]string{"X-CSRF-Token": b.csrf()}); rec.Code != 204 {
		t.Errorf("logout with the right token: %d", rec.Code)
	}
}

func TestCeremonyBoundToBrowser(t *testing.T) {
	r := newRig(t)
	b := r.browser(pcOrigin)
	a := mustEnrolled(t, r, b)
	cer, options := b.begin("/login/begin", nil)
	other := r.browser(pcOrigin) // another browser got hold of the ceremony id
	code, out := other.post("/login/finish", a.get(options, b.origin, opts{}), cer)
	wantRefused(t, r, code, out, ReasonCeremony)
}

func TestCeremonyKindAndExpiry(t *testing.T) {
	r := newRig(t)
	b := r.browser(pcOrigin)
	a := mustEnrolled(t, r, b)
	// A login ceremony cannot finish an enrolment and vice versa.
	cer, options := b.begin("/login/begin", nil)
	code, out := b.post("/enroll/finish", a.get(options, b.origin, opts{}), cer)
	wantRefused(t, r, code, out, ReasonCeremony)
	// An old ceremony is dead.
	cer, options = b.begin("/login/begin", nil)
	r.advance(6 * time.Minute)
	code, out = b.post("/login/finish", a.get(options, b.origin, opts{}), cer)
	wantRefused(t, r, code, out, ReasonCeremony)
	// Garbage ids.
	for _, id := range []string{"", "x", strings.Repeat("A", 22)} {
		code, out = b.post("/login/finish", []byte("{}"), id)
		wantRefused(t, r, code, out, ReasonCeremony)
	}
}

func TestUnknownCredentialAndBadSignature(t *testing.T) {
	r := newRig(t)
	b := r.browser(pcOrigin)
	good := mustEnrolled(t, r, b)

	// A device the server never enrolled, with the right user handle.
	stranger := newAuthenticator(t, "localhost")
	stranger.userHandle = good.userHandle
	code, out := b.login(stranger, opts{})
	wantRefused(t, r, code, out, ReasonCredential)

	// The enrolled credential id, signed by another key.
	code, out = b.login(good, opts{wrongKey: true})
	wantRefused(t, r, code, out, ReasonSignature)

	// The enrolled credential with someone else's user handle.
	imposter := *good
	imposter.userHandle = make([]byte, 32)
	code, out = b.login(&imposter, opts{})
	wantRefused(t, r, code, out, ReasonCredential)
}

func TestClonedAuthenticatorRefused(t *testing.T) {
	r := newRig(t)
	b := r.browser(pcOrigin)
	a := mustEnrolled(t, r, b)
	five, three := uint32(5), uint32(3)
	if code, out := b.login(a, opts{signCount: &five}); code != 200 {
		t.Fatal(code, out)
	}
	code, out := b.login(a, opts{signCount: &three}) // counter went backwards
	wantRefused(t, r, code, out, ReasonClone)
}

func TestZeroCounterIsNotAClone(t *testing.T) {
	// Platform authenticators may always report 0 (ADR-004).
	r := newRig(t)
	b := r.browser(pcOrigin)
	a := mustEnrolled(t, r, b)
	zero := uint32(0)
	for i := range 3 {
		if code, out := b.login(a, opts{signCount: &zero}); code != 200 {
			t.Fatalf("login %d: %d %v", i, code, out)
		}
	}
}

func TestConcurrentFinishConsumesOnce(t *testing.T) {
	r := newRig(t)
	b := r.browser(pcOrigin)
	a := mustEnrolled(t, r, b)
	cer, options := b.begin("/login/begin", nil)
	body := a.get(options, b.origin, opts{})
	tok := b.csrf()
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &browser{t: t, h: b.h, host: b.host, origin: b.origin, cookies: map[string]string{}}
			for k, v := range b.cookies {
				c.cookies[k] = v
			}
			rec := c.do("POST", "/login/finish", body, map[string]string{"X-CSRF-Token": tok, "X-Ceremony-ID": cer})
			if rec.Code == 200 {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("%d of 8 concurrent finishes succeeded, want exactly 1", ok)
	}
}

// ---- enrolment tokens ----

func TestEnrolmentTokens(t *testing.T) {
	ctx := context.Background()
	t.Run("one use", func(t *testing.T) {
		r := newRig(t)
		tok := r.token()
		b := r.browser(pcOrigin)
		if _, code, out := b.enrol(r, tok, opts{}); code != 200 {
			t.Fatal(code, out)
		}
		req, _ := json.Marshal(map[string]string{"token": tok, "name": "x", "label": "y"})
		code, out := b.post("/enroll/begin", req, "")
		wantRefused(t, r, code, out, ReasonEnrolment)
	})
	t.Run("wrong and empty", func(t *testing.T) {
		r := newRig(t)
		r.token()
		b := r.browser(pcOrigin)
		for _, tok := range []string{"", "nope", strings.Repeat("x", 200)} {
			req, _ := json.Marshal(map[string]string{"token": tok})
			code, out := b.post("/enroll/begin", req, "")
			if code < 400 {
				t.Fatalf("token %q accepted: %d %v", tok, code, out)
			}
		}
		if n := countRows(t, r, "console_ceremonies"); n != 0 {
			t.Fatalf("%d ceremonies after refused tokens", n)
		}
	})
	t.Run("expired", func(t *testing.T) {
		r := newRig(t)
		tok := r.token()
		r.advance(11 * time.Minute)
		b := r.browser(pcOrigin)
		req, _ := json.Marshal(map[string]string{"token": tok})
		code, out := b.post("/enroll/begin", req, "")
		wantRefused(t, r, code, out, ReasonEnrolment)
	})
	t.Run("expires between begin and finish", func(t *testing.T) {
		r := newRig(t)
		tok := r.token()
		b := r.browser(pcOrigin)
		req, _ := json.Marshal(map[string]string{"token": tok})
		cer, options := b.begin("/enroll/begin", req)
		r.advance(11 * time.Minute)
		a := newAuthenticator(t, "localhost")
		code, out := b.post("/enroll/finish", a.create(options, b.origin, opts{}), cer)
		// The ceremony itself (5 minutes) is gone first; either way, nothing is stored.
		if code < 400 || countRows(t, r, "credentials") != 0 {
			t.Fatalf("%d %v", code, out)
		}
	})
	t.Run("two ceremonies, one token", func(t *testing.T) {
		r := newRig(t)
		tok := r.token()
		b1, b2 := r.browser(pcOrigin), r.browser(pcOrigin)
		req, _ := json.Marshal(map[string]string{"token": tok})
		cer1, opt1 := b1.begin("/enroll/begin", req)
		cer2, opt2 := b2.begin("/enroll/begin", req)
		a1, a2 := newAuthenticator(t, "localhost"), newAuthenticator(t, "localhost")
		c1, o1 := b1.post("/enroll/finish", a1.create(opt1, b1.origin, opts{}), cer1)
		c2, o2 := b2.post("/enroll/finish", a2.create(opt2, b2.origin, opts{}), cer2)
		if (c1 == 200) == (c2 == 200) {
			t.Fatalf("both or neither enrolled: %d %v / %d %v", c1, o1, c2, o2)
		}
		if n := countRows(t, r, "approvers"); n != 1 {
			t.Fatalf("approvers = %d", n)
		}
	})
	t.Run("not once an approver exists", func(t *testing.T) {
		r := newRig(t)
		mustEnrolled(t, r, r.browser(pcOrigin))
		if _, err := IssueEnrollment(ctx, r.db, nil, time.Minute, r.now); err == nil {
			t.Fatal("a first-approver token was issued while an approver exists")
		}
		// A token issued earlier is useless too.
		r2 := newRig(t)
		tok := r2.token()
		mustEnrolled(t, r2, r2.browser(pcOrigin))
		req, _ := json.Marshal(map[string]string{"token": tok})
		code, out := r2.browser(pcOrigin).post("/enroll/begin", req, "")
		wantRefused(t, r2, code, out, ReasonEnrolment)
	})
	t.Run("only the hash is stored", func(t *testing.T) {
		r := newRig(t)
		tok := r.token()
		var n int
		if err := r.db.SQL().QueryRow(`SELECT count(*) FROM console_enrollments WHERE hex(token_sha256) = upper(?) OR token_sha256 = ?`, tok, tok).Scan(&n); err != nil || n != 0 {
			t.Fatal(n, err)
		}
		if err := r.db.SQL().QueryRow(`SELECT count(*) FROM console_enrollments WHERE token_sha256 = ?`, sum([]byte(tok))).Scan(&n); err != nil || n != 1 {
			t.Fatal(n, err)
		}
	})
}

// ---- a second origin: the phone shape (ADR-004 section 5) ----

func TestCredentialsAreBoundToTheirOrigin(t *testing.T) {
	r := newRig(t, pcOrigin, phoneOrigin)
	pc := r.browser(pcOrigin)
	hello := mustEnrolled(t, r, pc)

	// Add a phone passkey to the same approver, at the phone origin.
	ctx := context.Background()
	var id int64
	if err := r.db.SQL().QueryRow(`SELECT id FROM approvers`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	tok, err := IssueEnrollment(ctx, r.db, &id, time.Minute, r.now)
	if err != nil {
		t.Fatal(err)
	}
	phone := r.browser(phoneOrigin)
	req, _ := json.Marshal(map[string]string{"token": tok, "label": "Phone"})
	cer, options := phone.begin("/enroll/begin", req)
	pa := newAuthenticator(t, phoneOrigin.RPID)
	if code, out := phone.post("/enroll/finish", pa.create(options, phoneOrigin.URL, opts{}), cer); code != 200 {
		t.Fatal(code, out, r.events())
	}
	if e := r.last(); e.Name != EventEnrolled || e.Bootstrap {
		t.Fatalf("a second device is not the bootstrap enrolment: %+v", e)
	}
	if n := countRows(t, r, "approvers"); n != 1 {
		t.Fatalf("approvers = %d, want the phone added to the same one", n)
	}
	rows, err := r.db.SQL().Query(`SELECT rp_id, origin FROM credentials ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var rp, o string
		_ = rows.Scan(&rp, &o)
		got = append(got, rp+" "+o)
	}
	rows.Close()
	if strings.Join(got, "|") != "localhost http://localhost:55398|pc.tail1234.ts.net https://pc.tail1234.ts.net" {
		t.Fatalf("credentials = %v", got)
	}

	// Each device signs in at its own origin...
	if code, out := phone.login(pa, opts{}); code != 200 {
		t.Fatal(code, out, r.events())
	}
	if e := r.last(); e.RPID != phoneOrigin.RPID || e.Origin != phoneOrigin.URL {
		t.Fatalf("login event %+v", e)
	}
	if code, out := pc.login(hello, opts{}); code != 200 {
		t.Fatal(code, out)
	}
	// ...and not at the other's. The phone passkey, asked for at the PC.
	pc2 := r.browser(pcOrigin)
	pa.rpID = "localhost" // a malicious page at the PC origin could ask for it, but the authenticator only signs for its own RP ID
	code, out := pc2.login(pa, opts{})
	if code < 400 {
		t.Fatalf("phone passkey accepted at the PC origin: %v", out)
	}
	// The Hello credential, replayed at the phone origin with an honest clientData origin.
	phone2 := r.browser(phoneOrigin)
	hello.rpID = phoneOrigin.RPID
	code, out = phone2.login(hello, opts{})
	if code < 400 {
		t.Fatalf("Hello credential accepted at the phone origin: %v", out)
	}
	// Cookies do not travel either: a PC session is no session at the phone origin.
	phone3 := r.browser(phoneOrigin)
	for k, v := range pc.cookies {
		phone3.cookies[k] = v
	}
	if rec := phone3.do("GET", "/", nil, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("PC session accepted at the phone origin: %d", rec.Code)
	}
}

// ---- headers, cookies, static files ----

func TestResponseHeadersAndCookies(t *testing.T) {
	r := newRig(t, pcOrigin, phoneOrigin)
	for _, o := range []Origin{pcOrigin, phoneOrigin} {
		b := r.browser(o)
		rec := b.do("GET", "/login", nil, nil)
		h := rec.Header()
		if h.Get("Cache-Control") != "no-store" {
			t.Errorf("%s Cache-Control = %q", o.URL, h.Get("Cache-Control"))
		}
		csp := h.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "script-src 'self'", "style-src 'self'", "frame-ancestors 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("CSP lacks %q: %s", want, csp)
			}
		}
		if strings.Contains(csp, "unsafe") {
			t.Errorf("CSP has unsafe-*: %s", csp)
		}
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "no-referrer" || h.Get("X-Frame-Options") != "DENY" {
			t.Errorf("security headers: %v", h)
		}
		cookies := rec.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatalf("%s: %d cookies", o.URL, len(cookies))
		}
		c := cookies[0]
		if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" {
			t.Errorf("%s cookie %+v", o.URL, c)
		}
		wantSecure := strings.HasPrefix(o.URL, "https://")
		if c.Secure != wantSecure || strings.HasPrefix(c.Name, "__Host-") != wantSecure {
			t.Errorf("%s cookie secure=%v name=%q", o.URL, c.Secure, c.Name)
		}
	}
	// Every dynamic response is no-store, errors included.
	b := r.browser(pcOrigin)
	for _, rec := range []*struct {
		code int
		cc   string
	}{
		{b.do("GET", "/nope", nil, nil).Code, b.do("GET", "/nope", nil, nil).Header().Get("Cache-Control")},
		{b.do("POST", "/login/begin", nil, nil).Code, b.do("POST", "/login/begin", nil, nil).Header().Get("Cache-Control")},
	} {
		if rec.cc != "no-store" {
			t.Errorf("status %d Cache-Control = %q", rec.code, rec.cc)
		}
	}
}

func TestSessionAndCSRFCookiesAfterLogin(t *testing.T) {
	r := newRig(t)
	b := r.browser(pcOrigin)
	a := mustEnrolled(t, r, b)
	cer, options := b.begin("/login/begin", nil)
	rec := b.do("POST", "/login/finish", a.get(options, b.origin, opts{}),
		map[string]string{"X-CSRF-Token": b.csrf(), "X-Ceremony-ID": cer})
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	var sess *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			sess = c
		}
	}
	if sess == nil || !sess.HttpOnly || sess.SameSite != http.SameSiteStrictMode || sess.MaxAge != 0 {
		t.Fatalf("session cookie %+v", sess)
	}
	// Only a hash of it is stored.
	var n int
	if err := r.db.SQL().QueryRow(`SELECT count(*) FROM console_sessions WHERE token_sha256 = ?`, sum([]byte(sess.Value))).Scan(&n); err != nil || n != 1 {
		t.Fatal(n, err)
	}
}

func TestStaticFiles(t *testing.T) {
	r := newRig(t)
	b := r.browser(pcOrigin)
	for _, p := range []string{"/static/vendor/htmx.min.js", "/static/vendor/basecoat.min.css", "/static/vendor/basecoat.min.js", "/static/console.js", "/static/console.css"} {
		rec := b.do("GET", p, nil, nil)
		if rec.Code != 200 || rec.Body.Len() == 0 {
			t.Errorf("%s: %d", p, rec.Code)
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Errorf("%s set a cookie", p)
		}
	}
	for _, p := range []string{"/static/", "/static", "/static/vendor/", "/static/vendor", "/static/nope.js", "/static/../templates/layout.html", "/static/%2e%2e/templates/layout.html", "/static/.gitattributes"} {
		if rec := b.do("GET", p, nil, nil); rec.Code == 200 {
			t.Errorf("%s served: %q", p, rec.Body.String())
		}
	}
}

func TestPagesLoadOnlyLocalScript(t *testing.T) {
	r := newRig(t)
	b := r.browser(pcOrigin)
	for _, p := range []string{"/login", "/enroll"} {
		body := b.do("GET", p, nil, nil).Body.String()
		for _, bad := range []string{`src="http`, `href="http`, "<script>", "onclick=", "javascript:", "style="} {
			if strings.Contains(body, bad) {
				t.Errorf("%s contains %q", p, bad)
			}
		}
		if !strings.Contains(body, `src="/static/vendor/htmx.min.js"`) || !strings.Contains(body, `"allowEval":false`) {
			t.Errorf("%s does not load htmx locally with eval off", p)
		}
	}
}

// ---- configuration ----

func TestConfigValidation(t *testing.T) {
	r := newRig(t)
	bad := map[string][]Origin{
		"none":                 nil,
		"http off localhost":   {{RPID: "pc.ts.net", URL: "http://pc.ts.net"}},
		"rpid is not the host": {{RPID: "ts.net", URL: "https://pc.ts.net"}},
		"path":                 {{RPID: "localhost", URL: "http://localhost:55398/console"}},
		"trailing slash":       {{RPID: "localhost", URL: "http://localhost:55398/"}},
		"ip address":           {{RPID: "127.0.0.1", URL: "http://127.0.0.1:55398"}},
		"upper case":           {{RPID: "Localhost", URL: "http://Localhost:55398"}},
		"scheme":               {{RPID: "localhost", URL: "ftp://localhost"}},
		"duplicate host":       {pcOrigin, pcOrigin},
	}
	for name, origins := range bad {
		if _, err := New(Config{DB: r.db, Origins: origins}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := New(Config{Origins: []Origin{pcOrigin}}); err == nil {
		t.Error("nil DB accepted")
	}
}

// TestOptionsDemandUserVerification pins what the browser is told: platform
// authenticator, discoverable key, user verification required, no attestation,
// and the right RP ID. These are the options Edge hands to Windows Hello.
func TestOptionsDemandUserVerification(t *testing.T) {
	r := newRig(t)
	b := r.browser(pcOrigin)

	req, _ := json.Marshal(map[string]string{"token": r.token()})
	_, options := b.begin("/enroll/begin", req)
	var reg struct {
		PublicKey struct {
			RP     struct{ ID, Name string } `json:"rp"`
			User   struct{ ID string }       `json:"user"`
			Params []struct {
				Alg  int
				Type string
			} `json:"pubKeyCredParams"`
			AuthenticatorSelection struct {
				AuthenticatorAttachment string
				ResidentKey             string
				RequireResidentKey      bool
				UserVerification        string
			} `json:"authenticatorSelection"`
			Attestation string
			Timeout     int
			Challenge   string
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &reg); err != nil {
		t.Fatal(err)
	}
	pk, sel := reg.PublicKey, reg.PublicKey.AuthenticatorSelection
	if pk.RP.ID != "localhost" || pk.RP.Name != "Chaperone" || pk.Attestation != "none" ||
		sel.AuthenticatorAttachment != "platform" || sel.ResidentKey != "required" || !sel.RequireResidentKey ||
		sel.UserVerification != "required" || pk.Timeout != 300000 || len(pk.Challenge) < 43 || len(pk.User.ID) < 43 {
		t.Fatalf("registration options: %s", options)
	}
	es256 := false
	for _, p := range pk.Params {
		es256 = es256 || (p.Alg == -7 && p.Type == "public-key")
	}
	if !es256 {
		t.Fatalf("no ES256 in %s", options)
	}

	r2 := newRig(t)
	b2 := r2.browser(pcOrigin)
	mustEnrolled(t, r2, b2)
	_, options = b2.begin("/login/begin", nil)
	var login struct {
		PublicKey struct {
			RPID             string `json:"rpId"`
			UserVerification string `json:"userVerification"`
			Allow            []any  `json:"allowCredentials"`
			Timeout          int    `json:"timeout"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &login); err != nil {
		t.Fatal(err)
	}
	if p := login.PublicKey; p.RPID != "localhost" || p.UserVerification != "required" || len(p.Allow) != 0 || p.Timeout != 300000 {
		t.Fatalf("login options: %s", options)
	}
}

func TestPendingCeremoniesAreCapped(t *testing.T) {
	r := newRig(t)
	b := r.browser(pcOrigin)
	mustEnrolled(t, r, b)
	for i := range maxCeremonies {
		if code, out := b.post("/login/begin", nil, ""); code != 200 {
			t.Fatalf("begin %d: %d %v", i, code, out)
		}
	}
	if code, out := b.post("/login/begin", nil, ""); code != http.StatusTooManyRequests || str(out["error"]) != "busy" {
		t.Fatalf("begin past the cap: %d %v", code, out)
	}
	// Expired ceremonies make room again.
	r.advance(6 * time.Minute)
	if code, out := b.post("/login/begin", nil, ""); code != 200 {
		t.Fatalf("begin after expiry: %d %v", code, out)
	}
}
