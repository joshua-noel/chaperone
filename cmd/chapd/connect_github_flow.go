package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/loopback"
)

// This file is the local half of `chapd connect github`: a short-lived web
// server on the loopback addresses that serves one page, which posts the
// manifest to GitHub, and receives the one redirect GitHub sends back.
//
// Everything the server receives is hostile input. A web page in the operator's
// browser can ask this server for anything, so the rules are narrow:
//
//   - Only the exact host `localhost:PORT` is answered (a page on another name
//     that resolves to this computer is refused, which stops DNS rebinding), and
//     an Origin header, when the browser sends one, must be this origin (or
//     GitHub's, on the callback). A browser that sends fetch metadata must be
//     making a top-level navigation; the start page also refuses a navigation
//     that another site started.
//   - The start page is at an address with a random key and works once. It is
//     the only place the `state` value is shown. Nothing else is served.
//   - The callback needs that `state` (compared in constant time), and it is
//     accepted once. A wrong state never uses up the one chance, so a hostile
//     page cannot spoil the real callback by guessing.
//   - The manifest is fixed when the server starts. No request changes it, and
//     its redirect URL is the same string the Host check uses, so GitHub can
//     only send the code to the address that checks it.
//   - Nothing from a request is written into a page.

// errFlowTimeout: the browser did not come back in time.
var errFlowTimeout = errors.New("the browser did not come back in time")

const (
	flowDefaultTimeout = 10 * time.Minute
	flowMaxTimeout     = 30 * time.Minute
	flowMaxNotes       = 20 // refusals reported to the operator; the rest are counted
	flowBindTries      = 5
)

// flowCodeRE is the shape of the temporary code (GitHub's example is 40 hex
// digits). Anything else is refused before it can reach GitHub's API or a path.
var flowCodeRE = regexp.MustCompile(`^[A-Za-z0-9._-]{8,128}$`)

type flowConfig struct {
	// WebBase is GitHub's web address, no trailing slash (https://github.com).
	WebBase string
	// Org is the organisation that will own the App, empty for the signed-in user.
	Org string
	// Permissions are the App's default permissions.
	Permissions map[string]string
	// Timeout is how long the flow lives.
	Timeout time.Duration
	// Listen is loopback.Listen; tests may pass another.
	Listen loopback.ListenFunc
	// Note is told, with a fixed phrase, about each refused request. It may be nil.
	Note func(reason string)
}

type manifestFlow struct {
	cfg      flowConfig
	spec     gh.ManifestSpec
	manifest []byte
	lns      []net.Listener
	srv      *http.Server

	origin    string // http://localhost:PORT
	host      string // localhost:PORT
	webOrigin string // https://github.com
	action    string // where the form posts

	state    string
	startKey string

	started atomic.Bool
	used    atomic.Bool
	code    chan string

	noteMu sync.Mutex
	notes  int

	closeOnce sync.Once
}

func flowToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// startManifestFlow takes a port on both loopback addresses, builds the
// manifest and starts serving. It returns before any browser has come.
func startManifestFlow(cfg flowConfig) (*manifestFlow, error) {
	if cfg.Listen == nil {
		cfg.Listen = loopback.Listen
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = flowDefaultTimeout
	}
	if cfg.Timeout > flowMaxTimeout {
		return nil, fmt.Errorf("the timeout is at most %s", flowMaxTimeout)
	}
	wb, err := url.Parse(cfg.WebBase)
	if err != nil || wb.Host == "" || wb.Path != "" || wb.RawQuery != "" || (wb.Scheme != "https" && wb.Scheme != "http") {
		return nil, errors.New("bad GitHub web address")
	}
	f := &manifestFlow{cfg: cfg, code: make(chan string, 1), webOrigin: wb.Scheme + "://" + wb.Host}

	// A port the system picks, on 127.0.0.1 and on ::1 (internal/loopback). If somebody else holds the same
	// number on ::1, try another port: nothing may listen where the browser could be sent.
	var bindErr error
	for range flowBindTries {
		if f.lns, bindErr = loopback.Bind("127.0.0.1:0", cfg.Listen, ""); bindErr == nil {
			break
		}
	}
	if bindErr != nil {
		return nil, bindErr
	}
	fail := func(err error) (*manifestFlow, error) { loopback.CloseAll(f.lns); return nil, err }
	port := f.lns[0].Addr().(*net.TCPAddr).Port
	f.host = fmt.Sprintf("localhost:%d", port)
	f.origin = "http://" + f.host

	if f.state, err = flowToken(); err != nil {
		return fail(err)
	}
	if f.startKey, err = flowToken(); err != nil {
		return fail(err)
	}
	nonce, name := make([]byte, 16), make([]byte, 3)
	if _, err = rand.Read(nonce); err == nil {
		_, err = rand.Read(name)
	}
	if err != nil {
		return fail(err)
	}
	// The one address this flow knows: the manifest's redirect URL and the Host check both come from f.origin.
	f.spec = gh.ManifestSpec{
		Name: "chaperone-" + hex.EncodeToString(name), Nonce: hex.EncodeToString(nonce),
		RedirectURL: f.origin + "/callback", Permissions: cfg.Permissions,
	}
	if f.manifest, err = f.spec.JSON(); err != nil {
		return fail(err)
	}
	f.action = f.webOrigin + "/settings/apps/new"
	if cfg.Org != "" {
		f.action = f.webOrigin + "/organizations/" + url.PathEscape(cfg.Org) + "/settings/apps/new"
	}
	f.action += "?state=" + url.QueryEscape(f.state)

	f.srv = &http.Server{
		Handler:           http.HandlerFunc(f.serve),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	for _, ln := range f.lns {
		go func() { _ = f.srv.Serve(ln) }()
	}
	return f, nil
}

// Spec is the manifest that was sent, for checking what GitHub made from it.
func (f *manifestFlow) Spec() gh.ManifestSpec { return f.spec }

// StartURL is the one address the operator opens.
func (f *manifestFlow) StartURL() string { return f.origin + "/start/" + f.startKey }

// Wait blocks until the callback has delivered a code, the timeout passes or
// ctx ends. The listeners are closed before it returns, whatever the outcome.
func (f *manifestFlow) Wait(ctx context.Context) (string, error) {
	defer f.Close()
	t := time.NewTimer(f.cfg.Timeout)
	defer t.Stop()
	select {
	case code := <-f.code:
		return code, nil
	case <-t.C:
		return "", errFlowTimeout
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// Close stops the server and releases both addresses. It is safe to call twice.
func (f *manifestFlow) Close() {
	f.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = f.srv.Shutdown(ctx)
		_ = f.srv.Close()
		loopback.CloseAll(f.lns)
	})
}

// note reports a refused request to the operator, with a fixed phrase. At most
// flowMaxNotes are shown, so a page that floods the port cannot flood the terminal.
func (f *manifestFlow) note(reason string) {
	if f.cfg.Note == nil {
		return
	}
	f.noteMu.Lock()
	f.notes++
	n := f.notes
	f.noteMu.Unlock()
	switch {
	case n < flowMaxNotes:
		f.cfg.Note(reason)
	case n == flowMaxNotes:
		f.cfg.Note("more refused requests, not shown")
	}
}

func (f *manifestFlow) deny(w http.ResponseWriter, status int, reason, body string) {
	f.note(reason)
	http.Error(w, body, status)
}

func (f *manifestFlow) serve(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Content-Security-Policy", "default-src 'none'; form-action "+f.webOrigin+"; base-uri 'none'; frame-ancestors 'none'")

	// 1. Host: exactly this address. A page that reaches this server through another name is refused.
	if !strings.EqualFold(r.Host, f.host) {
		f.deny(w, http.StatusForbidden, "wrong host name", "host not allowed")
		return
	}
	path := r.URL.Path
	isCallback := path == "/callback"
	// 2. Origin: when the browser sends one it must be this origin. The callback may also come from GitHub's own page.
	if origin, sent := r.Header["Origin"]; sent {
		ok := len(origin) == 1 && (origin[0] == f.origin || (isCallback && origin[0] == f.webOrigin))
		if !ok {
			f.deny(w, http.StatusForbidden, "wrong origin", "origin not allowed")
			return
		}
	}
	// 3. Fetch metadata, when the browser sends it: a top-level page load, nothing else (no fetch, no frame).
	if m := r.Header.Get("Sec-Fetch-Mode"); m != "" && m != "navigate" {
		f.deny(w, http.StatusForbidden, "not a page load", "not allowed")
		return
	}
	if d := r.Header.Get("Sec-Fetch-Dest"); d != "" && d != "document" {
		f.deny(w, http.StatusForbidden, "not a page load", "not allowed")
		return
	}
	if r.Method != http.MethodGet {
		h.Set("Allow", "GET")
		f.deny(w, http.StatusMethodNotAllowed, "wrong method", "method not allowed")
		return
	}
	switch {
	case isCallback:
		f.callback(w, r)
	case strings.HasPrefix(path, "/start/"):
		f.start(w, r, strings.TrimPrefix(path, "/start/"))
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

var startPage = template.Must(template.New("start").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>Chaperone: create your GitHub App</title></head>
<body>
<h1>Create your GitHub App</h1>
<p>This creates a GitHub App in {{.Account}}. The App is private to that account. Chaperone uses it to act on GitHub with its own key, which is kept in the vault on this computer.</p>
<p>The App asks for these permissions and no others. It has no webhook.</p>
<ul>{{range .Permissions}}<li>{{.}}</li>{{end}}</ul>
<p>Press the button. GitHub shows its own page: check the name, then press "Create GitHub App". GitHub then sends this browser back to this computer. You can close this tab after that.</p>
<form method="post" action="{{.Action}}">
<input type="hidden" name="manifest" value="{{.Manifest}}">
<button type="submit">Continue to GitHub</button>
</form>
<details><summary>The manifest that is sent</summary><pre>{{.Manifest}}</pre></details>
</body></html>
`))

// start serves the page that posts the manifest, once.
func (f *manifestFlow) start(w http.ResponseWriter, r *http.Request, key string) {
	// A page on another site must not be able to start the flow, even with the address: the operator's own
	// address bar sends "none", a link inside this origin "same-origin".
	if s := r.Header.Get("Sec-Fetch-Site"); s != "" && s != "none" && s != "same-origin" {
		f.deny(w, http.StatusForbidden, "started from another site", "not allowed")
		return
	}
	if subtle.ConstantTimeCompare([]byte(key), []byte(f.startKey)) != 1 {
		f.deny(w, http.StatusNotFound, "wrong start key", "not found")
		return
	}
	if !f.started.CompareAndSwap(false, true) {
		f.deny(w, http.StatusGone, "start page opened twice", "This page was already opened. Run the command again for a new address.")
		return
	}
	perms := make([]string, 0, len(f.cfg.Permissions))
	for k, v := range f.cfg.Permissions {
		perms = append(perms, k+": "+v)
	}
	sort.Strings(perms)
	account := "your own GitHub account"
	if f.cfg.Org != "" {
		account = "the GitHub organization " + f.cfg.Org
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = startPage.Execute(w, struct {
		Account, Action, Manifest string
		Permissions               []string
	}{account, f.action, string(f.manifest), perms})
}

// callback receives the redirect from GitHub: ?code=...&state=...
func (f *manifestFlow) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	states, codes := q["state"], q["code"]
	// The state first, and in constant time. A wrong or missing one never uses up the single chance.
	if len(states) != 1 || subtle.ConstantTimeCompare([]byte(states[0]), []byte(f.state)) != 1 || !f.started.Load() {
		f.deny(w, http.StatusBadRequest, "callback with the wrong state", "This request was not started by Chaperone.")
		return
	}
	if len(codes) != 1 || !flowCodeRE.MatchString(codes[0]) {
		f.deny(w, http.StatusBadRequest, "callback without a usable code", "This request has no usable code.")
		return
	}
	if !f.used.CompareAndSwap(false, true) {
		f.deny(w, http.StatusGone, "second callback", "This address was already used.")
		return
	}
	f.code <- codes[0]
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>Chaperone</title></head>`+
		`<body><p>Chaperone has what it needs from GitHub. You can close this tab and go back to the terminal.</p></body></html>`)
}
