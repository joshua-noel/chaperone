package main

import (
	"bytes"
	"context"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
	"github.com/joshua-noel/chaperone/internal/store"
	"github.com/joshua-noel/chaperone/internal/vault"
)

// These tests run the whole command against the fake GitHub (internal/gh/ghtest). A Go HTTP client plays the
// operator's browser: it opens the address the command printed, posts the manifest to the fake's github.com side,
// and follows the redirect back to the command's loopback port. Nothing here reaches the real GitHub.

func useFakeGitHub(t *testing.T) *ghtest.Server {
	t.Helper()
	s := ghtest.New(t)
	web, api, clock := githubWebBase, githubAPIBase, githubClock
	githubWebBase, githubAPIBase, githubClock = s.URL(), s.URL(), s.Now
	t.Cleanup(func() { githubWebBase, githubAPIBase, githubClock = web, api, clock })
	return s
}

type ghEnv struct {
	t    *testing.T
	dir  string
	db   string
	fake *ghtest.Server
}

// newGHEnv is a folder with a database and an initialised vault, and the fake GitHub.
func newGHEnv(t *testing.T) *ghEnv {
	t.Helper()
	e := newGHEnvNoVault(t)
	if code, _, stderr := runVault(t, "init", "-db", e.db); code != 0 {
		t.Fatalf("vault init: %d %s", code, stderr)
	}
	return e
}

func newGHEnvNoVault(t *testing.T) *ghEnv {
	t.Helper()
	useTestWrapper(t)
	dir := t.TempDir()
	return &ghEnv{t: t, dir: dir, db: filepath.Join(dir, "state.db"), fake: useFakeGitHub(t)}
}

type connectRun struct {
	out, err *syncBuf
	done     chan int
	code     int
	finished bool
}

var startAddrRE = regexp.MustCompile(`http://localhost:(\d+)/start/\S+`)

// connect starts `chapd connect github` in the background.
func (e *ghEnv) connect(args ...string) *connectRun {
	r := &connectRun{out: &syncBuf{}, err: &syncBuf{}, done: make(chan int, 1)}
	full := append([]string{"connect", "github", "-db", e.db}, withOwner(args)...)
	go func() { r.done <- run(full, r.out, r.err) }()
	return r
}

// withOwner adds the account the command needs to know, unless the test names one. The case differs from the fake's
// login on purpose: the owner is compared without regard to case.
func withOwner(args []string) []string {
	for _, a := range args {
		if a == "-org" || a == "-user" {
			return args
		}
	}
	return append([]string{"-user", "Example-User"}, args...)
}

// startURL waits for the address the command prints.
func (r *connectRun) startURL(t *testing.T) string {
	t.Helper()
	for range 800 {
		if m := startAddrRE.FindString(r.out.String()); m != "" {
			return m
		}
		select {
		case code := <-r.done:
			r.code, r.finished = code, true
			t.Fatalf("the command ended (%d) before it printed an address:\n%s\n%s", code, r.out.String(), r.err.String())
		default:
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("no address printed:\n%s\n%s", r.out.String(), r.err.String())
	return ""
}

func (r *connectRun) wait(t *testing.T) int {
	t.Helper()
	if r.finished {
		return r.code
	}
	select {
	case r.code = <-r.done:
		r.finished = true
		return r.code
	case <-time.After(60 * time.Second):
		t.Fatalf("the command did not end:\n%s\n%s", r.out.String(), r.err.String())
		return -1
	}
}

// both is everything the command showed the operator.
func (r *connectRun) both() string { return r.out.String() + "\n" + r.err.String() }

// runConnect runs the command to its end with no browser (refusals before the flow starts).
func (e *ghEnv) runConnect(args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = run(append([]string{"connect", "github", "-db", e.db}, withOwner(args)...), &out, &errb)
	return code, out.String(), errb.String()
}

// ---- the operator's browser ----

type fakeBrowser struct {
	t  *testing.T
	hc *http.Client
}

func newBrowser(t *testing.T) *fakeBrowser {
	return &fakeBrowser{t: t, hc: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (b *fakeBrowser) do(req *http.Request, hdr map[string]string) (int, string, http.Header) {
	b.t.Helper()
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := b.hc.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(body), resp.Header
}

func (b *fakeBrowser) get(u string, hdr map[string]string) (int, string, http.Header) {
	b.t.Helper()
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		b.t.Fatal(err)
	}
	return b.do(req, hdr)
}

var (
	formActionRE   = regexp.MustCompile(`<form method="post" action="([^"]*)">`)
	formManifestRE = regexp.MustCompile(`name="manifest" value="([^"]*)"`)
)

// openStart opens the page the command's address leads to and reads its form: where it posts, and the manifest.
func (b *fakeBrowser) openStart(startURL string) (action, manifest string) {
	b.t.Helper()
	st, body, _ := b.get(startURL, browserStart)
	if st != 200 {
		b.t.Fatalf("the start page answered %d: %s", st, body)
	}
	a, m := formActionRE.FindStringSubmatch(body), formManifestRE.FindStringSubmatch(body)
	if a == nil || m == nil {
		b.t.Fatalf("no form in the start page:\n%s", body)
	}
	return html.UnescapeString(a[1]), html.UnescapeString(m[1])
}

// postManifest is what GitHub's page does when the operator presses "Create GitHub App": it makes the App and
// redirects the browser. It returns the address of the redirect.
func (b *fakeBrowser) postManifest(action, manifest string) string {
	b.t.Helper()
	req, err := http.NewRequest("POST", action, strings.NewReader(url.Values{"manifest": {manifest}}.Encode()))
	if err != nil {
		b.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	st, body, h := b.do(req, nil)
	if st != http.StatusFound {
		b.t.Fatalf("GitHub answered %d: %s", st, body)
	}
	return h.Get("Location")
}

// operator plays the operator through the whole flow and returns the callback's status and body.
func (b *fakeBrowser) operator(startURL string) (int, string) {
	b.t.Helper()
	action, manifest := b.openStart(startURL)
	loc := b.postManifest(action, manifest)
	st, body, _ := b.get(loc, browserCallback)
	return st, body
}

// ---- looking at what was stored ----

func (e *ghEnv) openVault() *vault.Vault {
	e.t.Helper()
	ctx := context.Background()
	d, err := store.Open(ctx, e.db)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { d.Close() })
	v, err := vault.Open(ctx, vault.Config{Dir: filepath.Join(e.dir, "vault"), KeyDir: filepath.Join(e.dir, "vault-keys"), DB: d, Wrapper: newWrapper()})
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(v.Close)
	return v
}

func (e *ghEnv) hasKey() bool {
	e.t.Helper()
	_, err := e.openVault().Info(context.Background(), gh.AppKeySecretID)
	return err == nil
}

func (e *ghEnv) hasRecord() bool {
	_, err := os.Lstat(githubAppPath(e.db))
	return err == nil
}

// secretsOf are the values of an App that must never be in output or on disk in the clear: two lines of the key,
// the client secret and the webhook secret.
func secretsOf(a *ghtest.App) []string {
	lines := strings.Split(string(a.PEM()), "\n")
	return []string{lines[1], lines[2], a.ClientSecret(), a.WebhookSecret()}
}

func assertNoSecrets(t *testing.T, what, text string, secrets []string) {
	t.Helper()
	for _, s := range secrets {
		if strings.Contains(text, s) {
			t.Errorf("%s holds a secret (%.8s...)", what, s)
		}
	}
	if strings.Contains(text, "PRIVATE KEY") {
		t.Errorf("%s holds a key header", what)
	}
}

// assertNoSecretsOnDisk reads every file under dir. The vault's files are encrypted, so a key, a client secret or a
// webhook secret in the clear can only be a leak.
func assertNoSecretsOnDisk(t *testing.T, dir string, secrets []string) {
	t.Helper()
	n := 0
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		n++
		assertNoSecrets(t, p, string(b), secrets)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 3 {
		t.Fatalf("scanned only %d files under %s", n, dir)
	}
}

func portOf(t *testing.T, startURL string) string {
	t.Helper()
	m := startAddrRE.FindStringSubmatch(startURL)
	if m == nil {
		t.Fatalf("not a start address: %s", startURL)
	}
	return m[1]
}

func assertPortClosed(t *testing.T, port string) {
	t.Helper()
	for _, host := range []string{"127.0.0.1", "::1"} {
		if c, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), time.Second); err == nil {
			c.Close()
			t.Errorf("%s:%s still accepts connections", host, port)
		}
	}
}

var corePermsWanted = map[string]string{"contents": "write", "pull_requests": "write", "checks": "read", "metadata": "read"}

// ---- the happy path ----

func TestConnectGitHubHappyPath(t *testing.T) {
	e := newGHEnv(t)
	r := e.connect("-timeout", "2m")
	u := r.startURL(t)
	port := portOf(t, u)
	if st, body := newBrowser(t).operator(u); st != 200 || strings.Contains(body, "code=") {
		t.Fatalf("callback answered %d: %s", st, body)
	}
	if code := r.wait(t); code != 0 {
		t.Fatalf("exit %d:\n%s", code, r.both())
	}
	assertPortClosed(t, port) // closed after the one good callback

	apps := e.fake.Apps()
	if len(apps) != 1 {
		t.Fatalf("%d Apps made", len(apps))
	}
	app := apps[0]

	// What was asked of GitHub.
	reqs := e.fake.ManifestRequests()
	if len(reqs) != 1 {
		t.Fatalf("%d manifests", len(reqs))
	}
	m := reqs[0].Manifest
	if reqs[0].Org != "" || len(reqs[0].State) != 43 {
		t.Errorf("org %q, state %q", reqs[0].Org, reqs[0].State)
	}
	if m.RedirectURL != "http://localhost:"+port+"/callback" {
		t.Errorf("redirect %q", m.RedirectURL)
	}
	if m.HookAttrs != nil || m.Public || len(m.DefaultEvents) != 0 || len(m.CallbackURLs) != 0 || m.SetupURL != "" {
		t.Errorf("the manifest asks for more than a private App with no webhook: %+v", m)
	}
	if !reflect.DeepEqual(m.DefaultPermissions, corePermsWanted) {
		t.Errorf("permissions %v", m.DefaultPermissions)
	}
	if !strings.HasPrefix(m.Name, "chaperone-") || m.URL != gh.ManifestHomepage {
		t.Errorf("name %q, url %q", m.Name, m.URL)
	}

	// Where the key went: into the vault, and nowhere else.
	v := e.openVault()
	ks, _ := gh.NewVaultKey(v, "")
	got, err := ks.AppKey(context.Background())
	if err != nil || !got.Equal(app.Key()) {
		t.Fatalf("the vault does not hold the App's key: %v", err)
	}
	info, err := v.Info(context.Background(), gh.AppKeySecretID)
	if err != nil || info.Kind != gh.AppKeySecretID || !strings.Contains(r.out.String(), info.Fingerprint) {
		t.Errorf("vault entry %+v: %v", info, err)
	}

	// Where chapd reads the App.
	rec, err := readGitHubAppRecord(e.db)
	if err != nil || rec == nil {
		t.Fatalf("record: %v %v", rec, err)
	}
	if rec.AppID != app.ID() || rec.ClientID != app.ClientID() || rec.Slug != app.Slug() || rec.Owner != "example-user" || rec.Version != 1 {
		t.Errorf("record %+v", rec)
	}

	// What the operator saw.
	out := r.out.String()
	for _, want := range []string{app.Slug(), "example-user", "/apps/" + app.Slug() + "/installations/new", "Only select repositories", "installation id", "chapd connect github status", "contents: write", "Checked with GitHub"} {
		if !strings.Contains(out, want) {
			t.Errorf("the output lacks %q:\n%s", want, out)
		}
	}
	secrets := secretsOf(app)
	assertNoSecrets(t, "the output", r.both(), secrets)
	if strings.Contains(r.both(), reqs[0].Code) {
		t.Error("the temporary code was printed")
	}
	assertNoSecretsOnDisk(t, e.dir, secrets)

	// A second run is refused: this is a first setup.
	code, _, stderr := e.runConnect()
	if code != 1 || !strings.Contains(stderr, "already holds github-app-key") {
		t.Errorf("second run: %d %q", code, stderr)
	}

	// Before the install, status says so.
	var so, se bytes.Buffer
	if code := run([]string{"connect", "github", "status", "-db", e.db}, &so, &se); code != 1 || !strings.Contains(so.String(), "nowhere yet") || !strings.Contains(so.String(), app.Slug()) {
		t.Errorf("status before the install: %d %q %q", code, so.String(), se.String())
	}

	// The operator installs the App. Nobody tells chapd the installation id: it finds it with the App's key.
	in := app.Install("example-user")
	in.AddRepo("storefront", "main")
	so.Reset()
	se.Reset()
	if code := run([]string{"connect", "github", "status", "-db", e.db}, &so, &se); code != 0 {
		t.Fatalf("status after the install: %d %q %q", code, so.String(), se.String())
	}
	for _, want := range []string{app.Slug(), "example-user", "selected repositories", "checks: read", "contents: write", "signs in as"} {
		if !strings.Contains(so.String(), want) {
			t.Errorf("status lacks %q:\n%s", want, so.String())
		}
	}
	assertNoSecrets(t, "status", so.String()+se.String(), secrets)

	client, err := githubClient(v, rec.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := client.FindInstallation(context.Background(), gh.Repo{Owner: "example-user", Name: "storefront"})
	if err != nil || inst.ID != in.ID {
		t.Fatalf("chapd cannot find the installation with the recorded App and the stored key: %+v %v", inst, err)
	}
	tok, err := client.MintToken(context.Background(), inst.ID, gh.TokenRequest{Repositories: []string{"storefront"}, Permissions: gh.PermsMerge()})
	if err != nil {
		t.Fatalf("a token for pr.merge: %v", err)
	}
	tok.Wipe()
	if _, err := client.MintToken(context.Background(), inst.ID, gh.TokenRequest{Repositories: []string{"storefront"}, Permissions: gh.PermsDeploy()}); err == nil {
		t.Error("the App can mint a deployments token without having asked for it")
	}
}

func TestConnectGitHubInAnOrganisationWithExtraGroups(t *testing.T) {
	e := newGHEnv(t)
	r := e.connect("-org", "my-org", "-with", "issues, deploy,ci-report")
	u := r.startURL(t)
	if st, _ := newBrowser(t).operator(u); st != 200 {
		t.Fatalf("callback %d", st)
	}
	if code := r.wait(t); code != 0 {
		t.Fatalf("exit %d:\n%s", code, r.both())
	}
	req := e.fake.ManifestRequests()[0]
	want := map[string]string{"contents": "write", "pull_requests": "write", "checks": "write", "metadata": "read", "issues": "write", "deployments": "write"}
	if req.Org != "my-org" || !reflect.DeepEqual(req.Manifest.DefaultPermissions, want) {
		t.Errorf("org %q permissions %v", req.Org, req.Manifest.DefaultPermissions)
	}
	if rec, _ := readGitHubAppRecord(e.db); rec == nil || rec.Owner != "my-org" {
		t.Errorf("record %+v", rec)
	}
	if !strings.Contains(r.out.String(), "organization my-org") {
		t.Errorf("the output does not name the organization:\n%s", r.out.String())
	}
}

// ---- the hostile cases, through the whole command ----

// A code from somebody else's App reaches the callback. This is the worst case: the attacker even knows the state.
// The flow accepts a well-formed callback, but the App behind the code is not the one the manifest asked for, so
// nothing is stored.
func TestConnectGitHubRefusesACodeFromAnotherAppEvenWithTheRightState(t *testing.T) {
	e := newGHEnv(t)
	r := e.connect()
	u := r.startURL(t)
	b := newBrowser(t)
	action, _ := b.openStart(u)
	state, _ := url.Parse(action)

	// The attacker makes an App of their own through GitHub's real flow, with their own manifest.
	atk := gh.ManifestSpec{Name: "attacker-app", Nonce: strings.Repeat("ab", 16), RedirectURL: "http://localhost:9/callback", Permissions: corePermsWanted}
	body, _ := atk.JSON()
	loc := b.postManifest(e.fake.URL()+"/settings/apps/new", string(body))
	atkCode := mustQuery(t, loc, "code")

	// The browser is sent to the callback with the attacker's code.
	cb := strings.Split(u, "/start/")[0] + "/callback?code=" + atkCode + "&state=" + state.Query().Get("state")
	if st, _, _ := b.get(cb, browserCallback); st != 200 {
		t.Fatalf("callback %d", st)
	}
	if code := r.wait(t); code != 1 {
		t.Fatalf("exit %d, want 1:\n%s", code, r.both())
	}
	if !strings.Contains(r.err.String(), "Nothing was stored") || !strings.Contains(r.err.String(), "not made from the manifest") || !strings.Contains(r.err.String(), "/settings/apps/attacker-app/advanced") {
		t.Errorf("stderr:\n%s", r.err.String())
	}
	if e.hasKey() || e.hasRecord() {
		t.Error("something was stored")
	}
	assertNoSecrets(t, "the output", r.both(), secretsOf(e.fake.Apps()[0]))
	assertNoSecretsOnDisk(t, e.dir, secretsOf(e.fake.Apps()[0]))
}

func mustQuery(t *testing.T, loc, key string) string {
	t.Helper()
	u, err := url.Parse(loc)
	if err != nil || u.Query().Get(key) == "" {
		t.Fatalf("no %s in %q", key, loc)
	}
	return u.Query().Get(key)
}

// Anything GitHub's answer holds that the manifest did not ask for, or that is not a usable key, stores nothing.
func TestConnectGitHubStoresNothingFromAnAppThatIsNotWhatWasAsked(t *testing.T) {
	cases := map[string]struct {
		args    []string
		tamper  func(map[string]any)
		wantErr string
	}{
		"a wider permission": {nil, func(a map[string]any) { a["permissions"].(map[string]string)["administration"] = "write" }, "permissions are not the ones"},
		"a higher level":     {nil, func(a map[string]any) { a["permissions"].(map[string]string)["checks"] = "write" }, "permissions are not the ones"},
		"a missing one":      {nil, func(a map[string]any) { delete(a["permissions"].(map[string]string), "checks") }, "permissions are not the ones"},
		"an event":           {nil, func(a map[string]any) { a["events"] = []string{"push"} }, "subscribes to events"},
		"another owner":      {[]string{"-org", "my-org"}, func(a map[string]any) { a["owner"] = map[string]any{"login": "someone-else"} }, "belongs to the account someone-else, not to my-org"},
		"a key that is not RSA": {nil, func(a map[string]any) {
			a["pem"] = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"
		}, "not a usable RSA key"},
		"an owner with no login (an Enterprise)": {nil, func(a map[string]any) { a["owner"] = map[string]any{"name": "Some Enterprise"} }, "owner of an unexpected shape"},
		"no description of ours":                 {nil, func(a map[string]any) { a["description"] = nil }, "not made from the manifest"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newGHEnv(t)
			r := e.connect(c.args...)
			u := r.startURL(t)
			e.fake.TamperConversion(c.tamper)
			if st, _ := newBrowser(t).operator(u); st != 200 {
				t.Fatalf("callback %d", st)
			}
			if code := r.wait(t); code != 1 {
				t.Fatalf("exit %d, want 1:\n%s", code, r.both())
			}
			if !strings.Contains(r.err.String(), c.wantErr) || !strings.Contains(r.err.String(), "Nothing was stored") || !strings.Contains(r.err.String(), "/settings/apps") {
				t.Errorf("stderr:\n%s", r.err.String())
			}
			if e.hasKey() || e.hasRecord() {
				t.Error("something was stored")
			}
			app := e.fake.Apps()[0]
			assertNoSecrets(t, "the output", r.both(), []string{app.ClientSecret(), app.WebhookSecret(), strings.Split(string(app.PEM()), "\n")[1]})
		})
	}
}

func TestConnectGitHubWhenGitHubRefusesTheCode(t *testing.T) {
	e := newGHEnv(t)
	e.fake.Inject("POST", "/conversions", ghtest.Fault{Status: 404, Message: "Not Found"})
	r := e.connect()
	u := r.startURL(t)
	if st, _ := newBrowser(t).operator(u); st != 200 {
		t.Fatalf("callback %d", st)
	}
	if code := r.wait(t); code != 1 || !strings.Contains(r.err.String(), "did not give the App over") || !strings.Contains(r.err.String(), "Nothing was stored") {
		t.Fatalf("exit %d:\n%s", code, r.both())
	}
	if e.hasKey() || e.hasRecord() {
		t.Error("something was stored")
	}
}

// ---- refusals before the flow starts, and the deadline ----

func TestConnectGitHubRefusesBeforeItStartsAnything(t *testing.T) {
	_, pemBytes, _ := writePEM(t, t.TempDir())
	cases := []struct {
		name    string
		prep    func(e *ghEnv)
		args    []string
		noVault bool
		want    string
	}{
		{"an unknown group", nil, []string{"-with", "everything"}, false, "unknown permission group"},
		{"a bad organization", nil, []string{"-org", "not an org!"}, false, "-org is not a GitHub organization"},
		{"an organization with a slash", nil, []string{"-org", "a/b"}, false, "-org is not a GitHub organization"},
		{"a timeout over the limit", nil, []string{"-timeout", "2h"}, false, "-timeout must be"},
		{"a zero timeout", nil, []string{"-timeout", "0s"}, false, "-timeout must be"},
		{"an extra argument", nil, []string{"extra"}, false, "usage: chapd connect github"},
		{"no vault", nil, nil, true, "no vault yet"},
		{"a key already in the vault", func(e *ghEnv) {
			p := filepath.Join(e.dir, "k.pem")
			if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			if code, _, se := runVault(t, "import", "--name", "github-app-key", "--file", p, "-db", e.db); code != 0 {
				t.Fatal(se)
			}
		}, nil, false, "already holds github-app-key"},
		{"a record already there", func(e *ghEnv) {
			if err := writeGitHubAppRecord(e.db, githubAppRecord{Version: 1, AppID: 1, ClientID: "Iv1.x", Slug: "old", Owner: "me", Created: "2026-01-01T00:00:00Z"}); err != nil {
				t.Fatal(err)
			}
		}, nil, false, "github-app.json already exists"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var e *ghEnv
			if c.noVault {
				e = newGHEnvNoVault(t)
			} else {
				e = newGHEnv(t)
			}
			if c.prep != nil {
				c.prep(e)
			}
			code, stdout, stderr := e.runConnect(c.args...)
			if code == 0 || !strings.Contains(stderr, c.want) {
				t.Fatalf("exit %d, want a refusal with %q:\n%s\n%s", code, c.want, stdout, stderr)
			}
			if strings.Contains(stdout, "/start/") {
				t.Error("it started the flow before it refused")
			}
			if n := len(e.fake.ManifestRequests()) + len(e.fake.Apps()); n != 0 {
				t.Errorf("GitHub was asked for %d things", n)
			}
		})
	}
}

func TestConnectGitHubGivesUpAtTheDeadline(t *testing.T) {
	e := newGHEnv(t)
	r := e.connect("-timeout", "400ms")
	u := r.startURL(t)
	if code := r.wait(t); code != 1 || !strings.Contains(r.err.String(), "did not come back in time") || !strings.Contains(r.err.String(), "Nothing was stored") {
		t.Fatalf("exit %d:\n%s", code, r.both())
	}
	assertPortClosed(t, portOf(t, u))
	if e.hasKey() || e.hasRecord() {
		t.Error("something was stored")
	}
	// The address is dead: a late browser gets nothing.
	if _, err := (&http.Client{Timeout: time.Second}).Get(u); err == nil {
		t.Error("the start address still answers after the deadline")
	}
}

// ---- status ----

func TestConnectGitHubStatusWithoutASetup(t *testing.T) {
	e := newGHEnv(t)
	var so, se bytes.Buffer
	code := run([]string{"connect", "github", "status", "-db", e.db}, &so, &se)
	if code != 1 || !strings.Contains(so.String(), "No GitHub App is set up here") {
		t.Fatalf("%d %q %q", code, so.String(), se.String())
	}
	if code := run([]string{"connect", "github", "status", "-org", "x", "-db", e.db}, &so, &se); code != 2 {
		t.Errorf("status with -org: %d", code)
	}
}

func TestConnectGitHubStatusSaysWhenGitHubDoesNotKnowTheKey(t *testing.T) {
	e := newGHEnv(t)
	r := e.connect()
	if st, _ := newBrowser(t).operator(r.startURL(t)); st != 200 || r.wait(t) != 0 {
		t.Fatalf("setup failed: %s", r.both())
	}
	// The record names another App than the stored key belongs to.
	p := githubAppPath(e.db)
	b, _ := os.ReadFile(p)
	rec, _ := readGitHubAppRecord(e.db)
	if err := os.WriteFile(p, bytes.ReplaceAll(b, []byte(rec.ClientID), []byte("Iv1.unknown")), 0o600); err != nil {
		t.Fatal(err)
	}
	var so, se bytes.Buffer
	if code := run([]string{"connect", "github", "status", "-db", e.db}, &so, &se); code != 1 || !strings.Contains(so.String(), "PROBLEM") {
		t.Fatalf("%d %q %q", code, so.String(), se.String())
	}
}

// ---- chapd run reads the record ----

func TestRunReadsTheAppRecord(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "state.db")
	parse := func(args ...string) (Config, int, string) {
		var errb bytes.Buffer
		cfg, code := parseRunFlags("chapd run", append([]string{"-db", db}, args...), &errb, false)
		return cfg, code, errb.String()
	}
	// No record: nothing changes.
	if cfg, code, _ := parse(); code != 0 || cfg.GitHubAppID != "" {
		t.Fatalf("no record: %d %q", code, cfg.GitHubAppID)
	}
	if err := writeGitHubAppRecord(db, githubAppRecord{Version: 1, AppID: 77, ClientID: "Iv23liABC", Slug: "chaperone-abc", Owner: "me", Created: "2026-01-01T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	// A record needs the vault.
	if _, code, msg := parse(); code != 2 || !strings.Contains(msg, "-vault-dir") || !strings.Contains(msg, "chaperone-abc") {
		t.Fatalf("record without the vault: %d %q", code, msg)
	}
	if cfg, code, msg := parse("-vault-dir", filepath.Join(dir, "vault")); code != 0 || cfg.GitHubAppID != "Iv23liABC" {
		t.Fatalf("record with the vault: %d %q %q", code, cfg.GitHubAppID, msg)
	}
	// An explicit flag wins, and then the record is not even read.
	if cfg, code, _ := parse("-github-app-id", "12345"); code != 0 || cfg.GitHubAppID != "12345" {
		t.Fatalf("explicit flag: %d %q", code, cfg.GitHubAppID)
	}
	// A record that is not what connect writes stops chapd.
	for name, content := range map[string]string{
		"an unknown field": `{"version":1,"app_id":1,"client_id":"x","slug":"s","owner":"o","created":"c","extra":1}`,
		"a bad slug":       `{"version":1,"app_id":1,"client_id":"x","slug":"../s","owner":"o","created":"c"}`,
		"a bad version":    `{"version":2,"app_id":1,"client_id":"x","slug":"s","owner":"o","created":"c"}`,
		"no id":            `{"version":1,"client_id":"x","slug":"s","owner":"o","created":"c"}`,
		"two documents":    `{"version":1,"app_id":1,"client_id":"x","slug":"s","owner":"o","created":"c"} {}`,
		"not json":         `hello`,
	} {
		if err := os.WriteFile(githubAppPath(db), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, code, msg := parse("-vault-dir", "v"); code != 2 || !strings.Contains(msg, "github-app.json") {
			t.Errorf("%s: %d %q", name, code, msg)
		}
	}
	// Not a plain file.
	_ = os.Remove(githubAppPath(db))
	if err := os.Mkdir(githubAppPath(db), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, code, _ := parse("-vault-dir", "v"); code != 2 {
		t.Errorf("a folder in place of the record: %d", code)
	}
}

func TestGitHubAppRecordIsNeverReplaced(t *testing.T) {
	db := filepath.Join(t.TempDir(), "state.db")
	rec := githubAppRecord{Version: 1, AppID: 1, ClientID: "Iv1.x", Slug: "a", Owner: "o", Created: "2026-01-01T00:00:00Z"}
	if err := writeGitHubAppRecord(db, rec); err != nil {
		t.Fatal(err)
	}
	rec.Slug = "b"
	if err := writeGitHubAppRecord(db, rec); err == nil {
		t.Error("a second write replaced the record")
	}
	if got, _ := readGitHubAppRecord(db); got == nil || got.Slug != "a" {
		t.Errorf("record %+v", got)
	}
}

// ---- from the quickstart to the real GitHub ----

// The documented path (docs/runbooks/github-app-setup.md, "From the quickstart"): stop the quickstart, make the
// folder's vault, run the command against the folder's database, then start chapd on the folder.
func TestQuickstartFolderMovesToTheRealGitHub(t *testing.T) {
	useTestWrapper(t)
	fake := useFakeGitHub(t)
	dir := filepath.Join(qsTemp(t), "qs")
	r := startQuickstart(t, quickstartOptions{Dir: dir, Addr: qsFreeAddr(t)})
	r.ready()
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	before := map[string][]byte{quickstartMarker: read(quickstartMarker), "run-keys.json": read("run-keys.json"), quickstartTokenFile: read(quickstartTokenFile), "policy/playground.yaml": read("policy/playground.yaml")}
	db := filepath.Join(dir, "state.db")

	if code, _, se := runVault(t, "init", "-db", db); code != 0 {
		t.Fatalf("vault init: %s", se)
	}
	e := &ghEnv{t: t, dir: dir, db: db, fake: fake}
	c := e.connect()
	if st, _ := newBrowser(t).operator(c.startURL(t)); st != 200 || c.wait(t) != 0 {
		t.Fatalf("connect failed:\n%s", c.both())
	}
	app := fake.Apps()[0]
	secrets := secretsOf(app)

	// What changed in the folder: a vault, its keys and the record. What did not: everything the quickstart made.
	for _, name := range []string{"vault", "vault-keys", githubAppFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, was := range before {
		if !bytes.Equal(was, read(name)) {
			t.Errorf("%s changed", name)
		}
	}

	// The playground itself does not move to GitHub: it refuses a folder that now holds a vault and a record.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := runQuickstart(ctx, quickstartOptions{Dir: dir, Playground: true}, io.Discard); err == nil || !strings.Contains(err.Error(), "did not make") {
		t.Errorf("the quickstart on a folder with a vault and a record: %v", err)
	}

	// `chapd run` on the folder, as the runbook writes it, picks up the App.
	var errb bytes.Buffer
	qs, err := readQuickstartState(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg, code := parseRunFlags("chapd run", []string{
		"-db", db, "-keys", filepath.Join(dir, "run-keys.json"), "-policy-dir", filepath.Join(dir, "policy"), "-instance", "quickstart",
		"-addr", qs.Addr, "-vault-dir", filepath.Join(dir, "vault"), "-vault-key-dir", filepath.Join(dir, "vault-keys"), "-log-dir", filepath.Join(dir, "logs"),
	}, &errb, false)
	if code != 0 || cfg.GitHubAppID != app.ClientID() {
		t.Fatalf("parse: %d %q %s", code, cfg.GitHubAppID, errb.String())
	}
	var logbuf syncBuf
	cfg.Log = slog.New(slog.NewTextHandler(&logbuf, nil))
	built, err := Build(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if built.git == nil {
		t.Error("chapd built from the record has no GitHub App")
	}
	if err := built.Start(ctx); err != nil {
		t.Fatal(err)
	}
	built.Close()
	assertNoSecrets(t, "chapd's log", logbuf.String(), secrets)

	// The App is installed on the repositories the operator chose; chapd finds the installation itself.
	in := app.Install("example-user")
	in.AddRepo("storefront", "main")
	var so, se bytes.Buffer
	if code := run([]string{"connect", "github", "status", "-db", db}, &so, &se); code != 0 || !strings.Contains(so.String(), "example-user") {
		t.Errorf("status: %d %q %q", code, so.String(), se.String())
	}
	assertNoSecretsOnDisk(t, dir, secrets) // the database, the ledger and the log folder included
}

// ---- whose App is it ----

func TestConnectGitHubNeedsToKnowWhoseAppItMakes(t *testing.T) {
	e := newGHEnv(t)
	for name, args := range map[string][]string{
		"neither":          nil,
		"both":             {"-org", "my-org", "-user", "me"},
		"a bad user":       {"-user", "a/b"},
		"a bad user again": {"-user", "not a user!"},
	} {
		var out, errb bytes.Buffer
		code := run(append([]string{"connect", "github", "-db", e.db}, args...), &out, &errb)
		if code != 2 || strings.Contains(out.String(), "/start/") {
			t.Errorf("%s: exit %d, out %q", name, code, out.String())
		}
		if name == "neither" || name == "both" {
			if !strings.Contains(errb.String(), "exactly one of -org ORG or -user LOGIN") || !strings.Contains(errb.String(), "whose App") {
				t.Errorf("%s: the message does not say why: %q", name, errb.String())
			}
		}
	}
	var out, errb bytes.Buffer
	if code := run([]string{"connect", "github", "status", "-user", "me", "-db", e.db}, &out, &errb); code != 2 {
		t.Errorf("status with -user: %d", code)
	}
	if n := len(e.fake.ManifestRequests()) + len(e.fake.Apps()); n != 0 {
		t.Errorf("GitHub was asked for %d things", n)
	}
}

// The reviewer's experiment. Somebody who has seen the start page posts the same manifest, with the same state, from
// THEIR account, and sends the code to the callback. The owner GitHub reports is not the account the operator named,
// so nothing is stored, and the message does not tell the operator to delete an App they cannot delete.
func TestConnectGitHubRefusesAnAppMadeInSomebodyElsesAccount(t *testing.T) {
	e := newGHEnv(t)
	r := e.connect("-user", "example-user")
	u := r.startURL(t)
	b := newBrowser(t)
	action, manifest := b.openStart(u)
	state := mustQuery(t, action, "state")

	e.fake.SetWebUser("mallory")
	loc := b.postManifest(action, manifest) // the attacker posts the very same form from their own account
	cb := strings.Split(u, "/start/")[0] + "/callback?code=" + mustQuery(t, loc, "code") + "&state=" + state
	if st, _, _ := b.get(cb, browserCallback); st != 200 {
		t.Fatalf("callback %d", st)
	}
	if code := r.wait(t); code != 1 {
		t.Fatalf("exit %d, want 1:\n%s", code, r.both())
	}
	for _, want := range []string{"belongs to the account mallory, not to example-user", "Nothing was stored", "cannot delete"} {
		if !strings.Contains(r.err.String(), want) {
			t.Errorf("stderr lacks %q:\n%s", want, r.err.String())
		}
	}
	if strings.Contains(r.both(), "Check that") || strings.Contains(r.out.String(), "GitHub created the App") {
		t.Errorf("the command spoke as if it had stored the App:\n%s", r.both())
	}
	if e.hasKey() || e.hasRecord() {
		t.Error("something was stored")
	}
	app := e.fake.Apps()[0]
	assertNoSecrets(t, "the output", r.both(), secretsOf(app))
	assertNoSecretsOnDisk(t, e.dir, secretsOf(app))
}

func TestConnectGitHubOwnerIsComparedWithoutRegardToCase(t *testing.T) {
	e := newGHEnv(t)
	r := e.connect("-user", "EXAMPLE-user")
	if st, _ := newBrowser(t).operator(r.startURL(t)); st != 200 || r.wait(t) != 0 {
		t.Fatalf("exit %d:\n%s", r.code, r.both())
	}
	if !e.hasKey() {
		t.Error("nothing stored")
	}
}

// The addresses the messages point to are the organization's own when -org is given.
func TestConnectGitHubMessagesPointToTheRightSettingsPage(t *testing.T) {
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"user": {[]string{"-user", "example-user"}, "/settings/apps"},
		"org":  {[]string{"-org", "my-org"}, "/organizations/my-org/settings/apps"},
	} {
		t.Run(name+" timeout", func(t *testing.T) {
			e := newGHEnv(t)
			r := e.connect(append(c.args, "-timeout", "300ms")...)
			r.startURL(t)
			if r.wait(t) != 1 {
				t.Fatal(r.both())
			}
			want := e.fake.URL() + c.want
			if !strings.Contains(r.err.String(), want+"\n") || (name == "org" && strings.Contains(r.err.String(), e.fake.URL()+"/settings/apps")) {
				t.Errorf("want %q (and no other settings page):\n%s", want, r.err.String())
			}
		})
		t.Run(name+" exchange failure", func(t *testing.T) {
			e := newGHEnv(t)
			e.fake.Inject("POST", "/conversions", ghtest.Fault{Status: 404, Message: "Not Found"})
			r := e.connect(c.args...)
			if st, _ := newBrowser(t).operator(r.startURL(t)); st != 200 || r.wait(t) != 1 {
				t.Fatal(r.both())
			}
			want := e.fake.URL() + c.want + " and run this again"
			if !strings.Contains(r.err.String(), want) || (name == "org" && strings.Contains(r.err.String(), e.fake.URL()+"/settings/apps")) {
				t.Errorf("want %q:\n%s", want, r.err.String())
			}
		})
	}
}

// Starting over needs two things to go, and the refusals name both.
func TestConnectGitHubRefusalsNameWhatToRemoveToStartOver(t *testing.T) {
	e := newGHEnv(t)
	r := e.connect("-user", "example-user")
	if st, _ := newBrowser(t).operator(r.startURL(t)); st != 200 || r.wait(t) != 0 {
		t.Fatal(r.both())
	}
	code, _, stderr := e.runConnect()
	for _, want := range []string{gh.AppKeySecretID, githubAppFile, "start over", "Starting over"} {
		if code != 1 || !strings.Contains(stderr, want) {
			t.Errorf("the refusal (exit %d) lacks %q: %s", code, want, stderr)
		}
	}
	// Only the vault secret is left: the record case.
	if err := os.Remove(githubAppPath(e.db)); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := e.runConnect(); code != 1 || !strings.Contains(stderr, gh.AppKeySecretID) {
		t.Errorf("exit %d: %s", code, stderr)
	}
}
