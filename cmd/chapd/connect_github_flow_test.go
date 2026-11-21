package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The local callback is hostile input. These tests play a web page in the operator's browser, a page on another
// name that resolves to this computer, and a program that sends garbage, against the real server of the flow.

const reflectMarker = "REFLECTME-9f3a"

func newTestFlow(t *testing.T, mut func(*flowConfig)) *manifestFlow {
	t.Helper()
	cfg := flowConfig{WebBase: "https://github.com", Permissions: map[string]string{"contents": "write", "metadata": "read"}, Timeout: 30 * time.Second}
	if mut != nil {
		mut(&cfg)
	}
	f, err := startManifestFlow(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Close)
	return f
}

func (f *manifestFlow) port() int { return f.lns[0].Addr().(*net.TCPAddr).Port }

// hit sends one request to the flow's IPv4 listener as a browser would, with the Host header given ("" means the
// flow's own). It returns the status, the body and the response headers.
func (f *manifestFlow) hit(t *testing.T, method, path, host string, hdr map[string]string) (int, string, http.Header) {
	t.Helper()
	req, err := http.NewRequest(method, "http://127.0.0.1:"+strconv.Itoa(f.port())+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if host == "" {
		host = f.host
	}
	req.Host = host
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	hc := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(b), resp.Header
}

var (
	browserStart    = map[string]string{"Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
	browserCallback = map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
)

func (f *manifestFlow) callbackPath(code string) string {
	return "/callback?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(f.state)
}

// finish plays the operator: open the start page, then follow GitHub's redirect to the callback. It returns the code
// the flow delivers.
func finishFlow(t *testing.T, f *manifestFlow, code string) string {
	t.Helper()
	if st, _, _ := f.hit(t, "GET", "/start/"+f.startKey, "", browserStart); st != 200 {
		t.Fatalf("the start page answered %d after the refusals", st)
	}
	if st, body, _ := f.hit(t, "GET", f.callbackPath(code), "", browserCallback); st != 200 {
		t.Fatalf("the callback answered %d after the refusals: %s", st, body)
	}
	got, err := f.Wait(context.Background())
	if err != nil || got != code {
		t.Fatalf("Wait: %q %v", got, err)
	}
	return got
}

func TestFlowServesTheStartPage(t *testing.T) {
	f := newTestFlow(t, func(c *flowConfig) { c.Org = "my-org" })
	st, body, h := f.hit(t, "GET", "/start/"+f.startKey, "", browserStart)
	if st != 200 {
		t.Fatalf("status %d: %s", st, body)
	}
	wantAction := `action="https://github.com/organizations/my-org/settings/apps/new?state=` + f.state + `"`
	if !strings.Contains(body, wantAction) {
		t.Errorf("the form does not post to GitHub with the state:\n%s", body)
	}
	if !strings.Contains(body, `redirect_url&#34;:&#34;http://localhost:`+strconv.Itoa(f.port())+`/callback&#34;`) {
		t.Errorf("the page does not carry the manifest with this flow's callback:\n%s", body)
	}
	if strings.Contains(body, "<script") {
		t.Error("the page has a script")
	}
	for k, want := range map[string]string{
		"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
	} {
		if h.Get(k) != want {
			t.Errorf("%s: %q, want %q", k, h.Get(k), want)
		}
	}
	csp := h.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "form-action https://github.com", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
}

// What the page says about the account comes from the command line, so it must be escaped, whatever it holds.
func TestFlowEscapesWhatItWritesIntoThePage(t *testing.T) {
	f := newTestFlow(t, func(c *flowConfig) { c.Org = `"><script>alert(1)</script>` })
	_, body, _ := f.hit(t, "GET", "/start/"+f.startKey, "", browserStart)
	if strings.Contains(body, "<script>") || strings.Contains(body, "><script") {
		t.Errorf("unescaped text in the page:\n%s", body)
	}
}

// The redirect URL in the manifest and the address the Host check and the listeners serve are one value.
func TestFlowManifestRedirectIsTheCallbackAddress(t *testing.T) {
	f := newTestFlow(t, nil)
	var m struct {
		RedirectURL string `json:"redirect_url"`
		Public      bool   `json:"public"`
	}
	if err := json.Unmarshal(f.manifest, &m); err != nil {
		t.Fatal(err)
	}
	want := "http://localhost:" + strconv.Itoa(f.port()) + "/callback"
	if m.RedirectURL != want || f.Spec().RedirectURL != want || f.origin+"/callback" != want {
		t.Fatalf("redirect %q, spec %q, origin %q, want %q", m.RedirectURL, f.Spec().RedirectURL, f.origin, want)
	}
	u, _ := url.Parse(m.RedirectURL)
	if u.Host != f.host {
		t.Errorf("the redirect names host %s, the Host check wants %s", u.Host, f.host)
	}
	if !strings.HasPrefix(f.StartURL(), f.origin+"/start/") {
		t.Errorf("start URL %s", f.StartURL())
	}
	// The address the browser is sent to (localhost) reaches the flow: the callback arrives exactly there.
	resp, err := http.Get(f.origin + "/nothing")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("localhost:%d answered %d", f.port(), resp.StatusCode)
	}
}

func TestFlowOnlyListensOnLoopback(t *testing.T) {
	f := newTestFlow(t, nil)
	for _, ln := range f.lns {
		if ip := ln.Addr().(*net.TCPAddr).IP; !ip.IsLoopback() {
			t.Errorf("listening on %s", ln.Addr())
		}
	}
}

func TestFlowHoldsBothLoopbackAddresses(t *testing.T) {
	f := newTestFlow(t, nil)
	if len(f.lns) != 2 {
		t.Skip("this machine has no IPv6 loopback address, so only 127.0.0.1 is held")
	}
	conn, err := net.DialTimeout("tcp6", net.JoinHostPort("::1", strconv.Itoa(f.port())), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestFlowRefusesToStartWhenIPv6LoopbackIsTakenByAnother(t *testing.T) {
	var mu sync.Mutex
	var v4 []net.Listener
	listen := func(network, addr string) (net.Listener, error) {
		if network == "tcp6" {
			return nil, errors.New("bind: address already in use")
		}
		ln, err := net.Listen(network, addr)
		mu.Lock()
		v4 = append(v4, ln)
		mu.Unlock()
		return ln, err
	}
	_, err := startManifestFlow(flowConfig{WebBase: "https://github.com", Permissions: map[string]string{"contents": "read"}, Listen: listen})
	if err == nil || !strings.Contains(err.Error(), "[::1]") {
		t.Fatalf("started although another program may hold ::1: %v", err)
	}
	if len(v4) != flowBindTries {
		t.Errorf("tried %d ports, want %d", len(v4), flowBindTries)
	}
	for _, ln := range v4 {
		if c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second); err == nil {
			c.Close()
			t.Fatalf("the IPv4 listener %s was left open", ln.Addr())
		}
	}
}

type flowCase struct {
	name   string
	method string
	path   func(f *manifestFlow) string
	host   func(f *manifestFlow) string
	hdr    map[string]string
	want   int
}

func (c flowCase) merge(base map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range c.hdr {
		out[k] = v
	}
	return out
}

func TestFlowRefusals(t *testing.T) {
	start := func(f *manifestFlow) string { return "/start/" + f.startKey }
	cb := func(extra string) func(f *manifestFlow) string {
		return func(f *manifestFlow) string { return f.callbackPath("0123456789abcdef0123") + extra }
	}
	rawCb := func(q string) func(f *manifestFlow) string {
		return func(*manifestFlow) string { return "/callback?" + q }
	}
	host := func(h string) func(f *manifestFlow) string {
		return func(f *manifestFlow) string { return strings.ReplaceAll(h, "PORT", strconv.Itoa(f.port())) }
	}
	hdr := func(kv ...string) map[string]string {
		m := map[string]string{}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	cases := []flowCase{
		// A page on another name that resolves here (DNS rebinding), or a client that names another host.
		{"start, rebound host", "GET", start, host("evil.example:PORT"), nil, 403},
		{"start, host without port", "GET", start, host("localhost"), nil, 403},
		{"start, host 127.0.0.1", "GET", start, host("127.0.0.1:PORT"), nil, 403},
		{"start, host [::1]", "GET", start, host("[::1]:PORT"), nil, 403},
		{"start, another port", "GET", start, host("localhost:1"), nil, 403},
		{"callback, rebound host", "GET", cb(""), host("evil.example:PORT"), nil, 403},
		{"callback, host 127.0.0.1", "GET", cb(""), host("127.0.0.1:PORT"), nil, 403},
		// A request another origin made.
		{"start, foreign origin", "GET", start, nil, hdr("Origin", "https://evil.example"), 403},
		{"start, null origin", "GET", start, nil, hdr("Origin", "null"), 403},
		{"start, GitHub's origin", "GET", start, nil, hdr("Origin", "https://github.com"), 403},
		{"callback, foreign origin", "GET", cb(""), nil, hdr("Origin", "https://evil.example"), 403},
		{"callback, null origin", "GET", cb(""), nil, hdr("Origin", "null"), 403},
		{"callback, look-alike origin", "GET", cb(""), nil, hdr("Origin", "https://github.com.evil.example"), 403},
		// A web page that starts the flow: a link, a form or a window.open from another site.
		{"start, from another site", "GET", start, nil, hdr("Sec-Fetch-Site", "cross-site"), 403},
		{"start, from a sibling site", "GET", start, nil, hdr("Sec-Fetch-Site", "same-site"), 403},
		// Not a page load: fetch, XHR, an image, a frame, a script.
		{"start, by fetch", "GET", start, nil, hdr("Sec-Fetch-Mode", "cors"), 403},
		{"start, in a frame", "GET", start, nil, hdr("Sec-Fetch-Dest", "iframe"), 403},
		{"start, as an image", "GET", start, nil, hdr("Sec-Fetch-Dest", "image"), 403},
		{"callback, by fetch", "GET", cb(""), nil, hdr("Sec-Fetch-Mode", "no-cors"), 403},
		{"callback, in a frame", "GET", cb(""), nil, hdr("Sec-Fetch-Dest", "iframe"), 403},
		// The start key.
		{"start, wrong key", "GET", func(*manifestFlow) string { return "/start/" + strings.Repeat("A", 43) }, nil, nil, 404},
		{"start, no key", "GET", func(*manifestFlow) string { return "/start/" }, nil, nil, 404},
		{"start, key with a tail", "GET", func(f *manifestFlow) string { return "/start/" + f.startKey + "x" }, nil, nil, 404},
		{"start, key prefix", "GET", func(f *manifestFlow) string { return "/start/" + f.startKey[:20] }, nil, nil, 404},
		{"start, the state instead of the key", "GET", func(f *manifestFlow) string { return "/start/" + f.state }, nil, nil, 404},
		// The state.
		{"callback, wrong state", "GET", rawCb("code=0123456789abcdef0123&state=" + strings.Repeat("A", 43)), nil, nil, 400},
		{"callback, no state", "GET", rawCb("code=0123456789abcdef0123"), nil, nil, 400},
		{"callback, empty state", "GET", rawCb("code=0123456789abcdef0123&state="), nil, nil, 400},
		{"callback, the start key as the state", "GET", func(f *manifestFlow) string { return "/callback?code=0123456789abcdef0123&state=" + f.startKey }, nil, nil, 400},
		{"callback, a prefix of the state", "GET", func(f *manifestFlow) string { return "/callback?code=0123456789abcdef0123&state=" + f.state[:42] }, nil, nil, 400},
		{"callback, two states", "GET", func(f *manifestFlow) string {
			return f.callbackPath("0123456789abcdef0123") + "&state=" + strings.Repeat("A", 43)
		}, nil, nil, 400},
		{"callback, the state twice", "GET", func(f *manifestFlow) string { return f.callbackPath("0123456789abcdef0123") + "&state=" + f.state }, nil, nil, 400},
		// The code, with the right state: still refused, and still not used up.
		{"callback, no code", "GET", func(f *manifestFlow) string { return "/callback?state=" + f.state }, nil, nil, 400},
		{"callback, short code", "GET", func(f *manifestFlow) string { return "/callback?code=abc&state=" + f.state }, nil, nil, 400},
		{"callback, long code", "GET", func(f *manifestFlow) string {
			return "/callback?code=" + strings.Repeat("a", 200) + "&state=" + f.state
		}, nil, nil, 400},
		{"callback, code with markup", "GET", func(f *manifestFlow) string {
			return "/callback?code=%3Cscript%3E" + reflectMarker + "&state=" + f.state
		}, nil, nil, 400},
		{"callback, code with a slash", "GET", func(f *manifestFlow) string { return "/callback?code=../../etc/passwd&state=" + f.state }, nil, nil, 400},
		{"callback, two codes", "GET", func(f *manifestFlow) string {
			return f.callbackPath("0123456789abcdef0123") + "&code=0123456789abcdef9999"
		}, nil, nil, 400},
		// Methods and paths.
		{"start, POST", "POST", start, nil, nil, 405},
		{"start, HEAD", "HEAD", start, nil, nil, 405},
		{"callback, POST", "POST", cb(""), nil, nil, 405},
		{"callback, PUT", "PUT", cb(""), nil, nil, 405},
		{"root", "GET", func(*manifestFlow) string { return "/" }, nil, nil, 404},
		{"start without slash", "GET", func(*manifestFlow) string { return "/start" }, nil, nil, 404},
		{"callback with a tail", "GET", func(f *manifestFlow) string { return "/callback/x?state=" + f.state }, nil, nil, 404},
		{"favicon", "GET", func(*manifestFlow) string { return "/favicon.ico?" + reflectMarker }, nil, nil, 404},
		{"reflection probe in the path", "GET", func(*manifestFlow) string { return "/" + reflectMarker }, nil, nil, 404},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newTestFlow(t, func(cfg *flowConfig) { cfg.Note = func(string) {} })
			h := ""
			if c.host != nil {
				h = c.host(f)
			}
			base := browserStart
			if strings.HasPrefix(c.name, "callback") {
				base = browserCallback
				// A callback is only taken after the start page was opened; open it, as the operator did.
				if st, _, _ := f.hit(t, "GET", "/start/"+f.startKey, "", browserStart); st != 200 {
					t.Fatalf("start page: %d", st)
				}
			}
			st, body, _ := f.hit(t, c.method, c.path(f), h, c.merge(base))
			if st != c.want {
				t.Fatalf("status %d, want %d (%s)", st, c.want, body)
			}
			// Nothing a request sent comes back in the answer.
			for _, bad := range []string{reflectMarker, "<script", f.state, f.startKey, "evil.example"} {
				if strings.Contains(body, bad) {
					t.Errorf("the answer reflects %q: %s", bad, body)
				}
			}
			// The refusal spent nothing: the real operator can still finish.
			if strings.HasPrefix(c.name, "callback") {
				if st, body, _ := f.hit(t, "GET", f.callbackPath("0123456789abcdef0123"), "", browserCallback); st != 200 {
					t.Fatalf("after the refusal the real callback answered %d: %s", st, body)
				}
				if got, err := f.Wait(context.Background()); err != nil || got != "0123456789abcdef0123" {
					t.Fatalf("Wait: %q %v", got, err)
				}
				return
			}
			finishFlow(t, f, "0123456789abcdef0123")
		})
	}
}

// A hostile page cannot spoil the real callback by guessing: wrong states are refused, never counted as the single use.
func TestFlowWrongStatesDoNotUseUpTheSingleChance(t *testing.T) {
	f := newTestFlow(t, func(c *flowConfig) { c.Note = func(string) {} })
	f.hit(t, "GET", "/start/"+f.startKey, "", browserStart)
	for i := range 200 {
		q := "/callback?code=0123456789abcdef0123&state=" + strconv.Itoa(i)
		if st, _, _ := f.hit(t, "GET", q, "", browserCallback); st != 400 {
			t.Fatalf("guess %d: %d", i, st)
		}
	}
	if st, _, _ := f.hit(t, "GET", f.callbackPath("0123456789abcdef0123"), "", browserCallback); st != 200 {
		t.Fatalf("the real callback was refused after 200 guesses: %d", st)
	}
}

func TestFlowStartPageOpensOnce(t *testing.T) {
	f := newTestFlow(t, nil)
	if st, _, _ := f.hit(t, "GET", "/start/"+f.startKey, "", browserStart); st != 200 {
		t.Fatalf("first: %d", st)
	}
	st, body, _ := f.hit(t, "GET", "/start/"+f.startKey, "", browserStart)
	if st != 410 || !strings.Contains(body, "already opened") {
		t.Errorf("second: %d %q", st, body)
	}
	// The first page is the one that can finish: its state is still good.
	if st, _, _ := f.hit(t, "GET", f.callbackPath("0123456789abcdef0123"), "", browserCallback); st != 200 {
		t.Fatalf("callback: %d", st)
	}
	if got, err := f.Wait(context.Background()); err != nil || got != "0123456789abcdef0123" {
		t.Fatalf("Wait: %q %v", got, err)
	}
}

func TestFlowCallbackBeforeTheStartPageIsRefused(t *testing.T) {
	f := newTestFlow(t, func(c *flowConfig) { c.Note = func(string) {} })
	// Even with the right state, which only the start page shows.
	if st, _, _ := f.hit(t, "GET", f.callbackPath("0123456789abcdef0123"), "", browserCallback); st != 400 {
		t.Fatalf("a callback before the start page: %d", st)
	}
	finishFlow(t, f, "0123456789abcdef0123")
}

func TestFlowAcceptsOneCallbackAndThenCloses(t *testing.T) {
	f := newTestFlow(t, func(c *flowConfig) { c.Note = func(string) {} })
	f.hit(t, "GET", "/start/"+f.startKey, "", browserStart)
	st, body, h := f.hit(t, "GET", f.callbackPath("0123456789abcdef0123"), "", browserCallback)
	if st != 200 || strings.Contains(body, "0123456789abcdef0123") || strings.Contains(body, f.state) {
		t.Fatalf("first callback: %d %q", st, body)
	}
	if h.Get("Referrer-Policy") != "no-referrer" || h.Get("Cache-Control") != "no-store" {
		t.Errorf("the answer to the callback lacks its privacy headers: %v", h)
	}
	// A second good-looking callback (a reload, a replay, another code with the same state) is refused.
	if st, _, _ := f.hit(t, "GET", f.callbackPath("9999999999abcdef0123"), "", browserCallback); st != 410 {
		t.Errorf("second callback: %d", st)
	}
	code, err := f.Wait(context.Background())
	if err != nil || code != "0123456789abcdef0123" {
		t.Fatalf("Wait: %q %v (the second code must not replace the first)", code, err)
	}
	for _, ln := range f.lns {
		if c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second); err == nil {
			c.Close()
			t.Errorf("%s still accepts connections after the callback", ln.Addr())
		}
	}
}

func TestFlowDeadline(t *testing.T) {
	f := newTestFlow(t, func(c *flowConfig) { c.Timeout = 200 * time.Millisecond })
	begin := time.Now()
	_, err := f.Wait(context.Background())
	if !errors.Is(err, errFlowTimeout) || time.Since(begin) > 5*time.Second {
		t.Fatalf("Wait: %v after %s", err, time.Since(begin))
	}
	for _, ln := range f.lns {
		if c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second); err == nil {
			c.Close()
			t.Errorf("%s still accepts connections after the deadline", ln.Addr())
		}
	}
	if _, err := startManifestFlow(flowConfig{WebBase: "https://github.com", Permissions: map[string]string{"contents": "read"}, Timeout: flowMaxTimeout + time.Second}); err == nil {
		t.Error("a deadline above the limit was accepted")
	}
}

func TestFlowEndsWhenTheCommandIsInterrupted(t *testing.T) {
	f := newTestFlow(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait: %v", err)
	}
	for _, ln := range f.lns {
		if c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second); err == nil {
			c.Close()
			t.Errorf("%s still accepts connections", ln.Addr())
		}
	}
}

func TestFlowReportsRefusalsWithAFixedPhraseAndAtMostTwentyTimes(t *testing.T) {
	var mu sync.Mutex
	var notes []string
	f := newTestFlow(t, func(c *flowConfig) {
		c.Note = func(r string) { mu.Lock(); notes = append(notes, r); mu.Unlock() }
	})
	for range 100 {
		f.hit(t, "GET", "/start/"+f.startKey+reflectMarker, "evil.example:1", nil)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(notes) != flowMaxNotes {
		t.Errorf("%d notes, want %d", len(notes), flowMaxNotes)
	}
	for _, n := range notes {
		if strings.Contains(n, reflectMarker) || strings.Contains(n, "evil.example") {
			t.Errorf("a note repeats what the request sent: %q", n)
		}
	}
}

func TestFlowManifestDoesNotChangeWithTheRequest(t *testing.T) {
	f := newTestFlow(t, nil)
	_, a, _ := f.hit(t, "GET", "/start/"+f.startKey+"?redirect_url=https://evil.example/x&name=evil&manifest=%7B%7D", "", browserStart)
	if strings.Contains(a, "evil.example") || strings.Contains(a, `value="{}"`) {
		t.Errorf("a query parameter changed the page:\n%s", a)
	}
	if !strings.Contains(a, "localhost:"+strconv.Itoa(f.port())+"/callback") {
		t.Errorf("the page has no callback address:\n%s", a)
	}
	var m map[string]any
	if err := json.Unmarshal(f.manifest, &m); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Spec().JSON(); err != nil {
		t.Fatal(err)
	}
}
