package gh_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
)

// ---- the permissions ----

var corePerms = map[string]string{"contents": "write", "pull_requests": "write", "checks": "read", "metadata": "read"}

func TestManifestPermissionsAreTheSmallestSetTheShippedOpsNeed(t *testing.T) {
	got, err := gh.ManifestPermissions()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, corePerms) {
		t.Fatalf("core permissions: %v, want %v", got, corePerms)
	}
	for _, bad := range []string{"workflows", "administration", "members", "actions", "secrets", "statuses"} {
		if _, ok := got[bad]; ok {
			t.Errorf("the core set holds %s", bad)
		}
	}
	for extra, want := range map[string]map[string]string{
		gh.ExtraDeploy:   {"deployments": "write"},
		gh.ExtraIssues:   {"issues": "write"},
		gh.ExtraCIReport: {"checks": "write"},
	} {
		got, err := gh.ManifestPermissions(extra)
		if err != nil {
			t.Fatalf("%s: %v", extra, err)
		}
		exp := map[string]string{}
		for k, v := range corePerms {
			exp[k] = v
		}
		for k, v := range want {
			exp[k] = v
		}
		if !reflect.DeepEqual(got, exp) {
			t.Errorf("with %s: %v, want %v", extra, got, exp)
		}
	}
	if _, err := gh.ManifestPermissions("everything"); !errors.Is(err, gh.ErrInvalidArgument) {
		t.Errorf("an unknown group: %v", err)
	}
}

// opPerms is every permission set of gh (the functions named Perms...), and whether the operations that use it are
// on in the baseline (so the core App must serve it) or off or opt-in (so a group serves it).
var opPerms = map[string]struct {
	set   func() map[string]string
	group string // "" for the core set
}{
	"PermsEvaluateMerge":  {gh.PermsEvaluateMerge, ""},
	"PermsOpenPull":       {gh.PermsOpenPull, ""},
	"PermsFetch":          {gh.PermsFetch, ""},
	"PermsPush":           {gh.PermsPush, ""},
	"PermsMerge":          {gh.PermsMerge, ""},
	"PermsReadPull":       {gh.PermsReadPull, ""},
	"PermsReadPullChecks": {gh.PermsReadPullChecks, ""},
	"PermsDeployRead":     {gh.PermsDeployRead, gh.ExtraDeploy},
	"PermsDeploy":         {gh.PermsDeploy, gh.ExtraDeploy},
	"PermsIssueRead":      {gh.PermsIssueRead, gh.ExtraIssues},
	"PermsIssueWrite":     {gh.PermsIssueWrite, gh.ExtraIssues},
	"PermsReportCI":       {gh.PermsReportCI, gh.ExtraCIReport},
}

// A new Perms function must be placed in a group on purpose: this test finds it in the source.
func TestEveryPermsFunctionIsPlacedInAGroup(t *testing.T) {
	fset := token.NewFileSet()
	files, err := parser.ParseDir(fset, ".", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	sources := 0
	for _, pkg := range files {
		for fname, f := range pkg.Files {
			if strings.HasSuffix(fname, "_test.go") {
				continue
			}
			sources++
			for _, d := range f.Decls {
				if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Perms") {
					found = append(found, fn.Name.Name)
				}
			}
		}
	}
	if sources == 0 {
		t.Skip("the source of package gh is not in the working folder (a test binary built elsewhere); this check reads it")
	}
	var known []string
	for n := range opPerms {
		known = append(known, n)
	}
	sort.Strings(found)
	sort.Strings(known)
	if !reflect.DeepEqual(found, known) {
		t.Fatalf("permission sets in the source: %v\nplaced in a manifest group: %v\nPlace the new one in internal/gh/manifest.go and in opPerms", found, known)
	}
}

// Each permission set the operations mint with can be minted on an installation that holds exactly the manifest's
// permissions: the core sets always, and each group's sets only when the group was asked for.
func TestManifestPermissionsServeTheOps(t *testing.T) {
	for _, withGroup := range []bool{false, true} {
		for name, op := range opPerms {
			if withGroup && op.group == "" {
				continue // the core sets do not depend on a group
			}
			var extras []string
			if withGroup && op.group != "" {
				extras = []string{op.group}
			}
			granted, err := gh.ManifestPermissions(extras...)
			if err != nil {
				t.Fatal(err)
			}
			s := ghtest.New(t)
			app := convertedApp(t, s, gh.ManifestSpec{Name: "chaperone-t", Nonce: strings.Repeat("a1", 8), RedirectURL: "http://localhost:1/callback", Permissions: granted})
			in := app.Install("example-user")
			in.AddRepo("storefront", "main")
			c := appClient(t, s, app)
			_, err = c.MintToken(context.Background(), in.ID, gh.TokenRequest{Repositories: []string{"storefront"}, Permissions: op.set()})
			switch {
			case op.group == "" && err != nil:
				t.Errorf("%s: the core App cannot serve it: %v", name, err)
			case op.group != "" && withGroup && err != nil:
				t.Errorf("%s: the App with %q cannot serve it: %v", name, op.group, err)
			case op.group != "" && !withGroup && err == nil:
				// a read-only set of a group may be inside the core (deploy read, issue read need issues read)
				if reflect.DeepEqual(mergeLevels(op.set(), corePerms), corePerms) {
					continue
				}
				t.Errorf("%s: served without its group, so the core set is wider than it needs to be", name)
			}
		}
	}
}

// mergeLevels is the highest level of each permission of a and b.
func mergeLevels(a, b map[string]string) map[string]string {
	rank := map[string]int{"": 0, "read": 1, "write": 2, "admin": 3}
	out := map[string]string{}
	for _, m := range []map[string]string{a, b} {
		for k, v := range m {
			if rank[v] > rank[out[k]] {
				out[k] = v
			}
		}
	}
	return out
}

// ---- the manifest ----

func spec(perms map[string]string) gh.ManifestSpec {
	return gh.ManifestSpec{Name: "chaperone-0a1b2c", Nonce: "0123456789abcdef0123456789abcdef", RedirectURL: "http://localhost:51234/callback", Permissions: perms}
}

func TestManifestJSON(t *testing.T) {
	b, err := spec(corePerms).JSON()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["redirect_url"] != "http://localhost:51234/callback" || m["name"] != "chaperone-0a1b2c" || m["url"] != gh.ManifestHomepage {
		t.Errorf("manifest: %s", b)
	}
	if m["public"] != false {
		t.Error("the App must be private to the owner")
	}
	if ev, ok := m["default_events"].([]any); !ok || len(ev) != 0 {
		t.Errorf("default_events must be an empty list: %v", m["default_events"])
	}
	for _, key := range []string{"hook_attributes", "callback_urls", "setup_url", "request_oauth_on_install", "setup_on_update"} {
		if _, ok := m[key]; ok {
			t.Errorf("the manifest names %s, which chapd does not need", key)
		}
	}
	if !strings.Contains(m["description"].(string), spec(nil).Nonce) {
		t.Errorf("the description does not carry the nonce: %v", m["description"])
	}
	if !reflect.DeepEqual(m["default_permissions"], map[string]any{"contents": "write", "pull_requests": "write", "checks": "read", "metadata": "read"}) {
		t.Errorf("permissions: %v", m["default_permissions"])
	}

	for name, mut := range map[string]func(*gh.ManifestSpec){
		"redirect with a query":       func(s *gh.ManifestSpec) { s.RedirectURL = "http://localhost:1/callback?x=1" },
		"redirect with a fragment":    func(s *gh.ManifestSpec) { s.RedirectURL = "http://localhost:1/callback#x" },
		"redirect with a login":       func(s *gh.ManifestSpec) { s.RedirectURL = "http://u:p@localhost:1/callback" },
		"redirect that is not http":   func(s *gh.ManifestSpec) { s.RedirectURL = "javascript:alert(1)" },
		"short nonce":                 func(s *gh.ManifestSpec) { s.Nonce = "abc" },
		"nonce with other characters": func(s *gh.ManifestSpec) { s.Nonce = strings.Repeat("G", 32) },
		"no permissions":              func(s *gh.ManifestSpec) { s.Permissions = nil },
		"a permission level":          func(s *gh.ManifestSpec) { s.Permissions = map[string]string{"contents": "owner"} },
		"a permission name":           func(s *gh.ManifestSpec) { s.Permissions = map[string]string{"Contents!": "read"} },
		"empty name":                  func(s *gh.ManifestSpec) { s.Name = "" },
		"long name":                   func(s *gh.ManifestSpec) { s.Name = strings.Repeat("n", 35) },
	} {
		s := spec(corePerms)
		mut(&s)
		if _, err := s.JSON(); !errors.Is(err, gh.ErrInvalidArgument) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// ---- the exchange ----

// submit plays the operator's browser at GitHub: post the manifest, read the redirect, return its query.
func submit(t *testing.T, s *ghtest.Server, sp gh.ManifestSpec, org, state string) url.Values {
	t.Helper()
	body, err := sp.JSON()
	if err != nil {
		t.Fatal(err)
	}
	path := "/settings/apps/new"
	if org != "" {
		path = "/organizations/" + org + "/settings/apps/new"
	}
	if state != "" {
		path += "?state=" + url.QueryEscape(state)
	}
	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := hc.PostForm(s.URL()+path, url.Values{"manifest": {string(body)}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GitHub answered %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != sp.RedirectURL {
		t.Fatalf("GitHub redirected to %s, the manifest said %s", got, sp.RedirectURL)
	}
	return loc.Query()
}

func anon(t *testing.T, s *ghtest.Server, rt http.RoundTripper) *gh.Client {
	t.Helper()
	cfg := gh.Config{BaseURL: s.URL(), Now: s.Now}
	if rt != nil {
		cfg.HTTPClient = &http.Client{Transport: rt, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	c, err := gh.NewAnonymous(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// convertedApp runs the whole exchange for sp and returns the fake's record of the App.
func convertedApp(t *testing.T, s *ghtest.Server, sp gh.ManifestSpec) *ghtest.App {
	t.Helper()
	q := submit(t, s, sp, "", "state-"+sp.Nonce)
	app, err := anon(t, s, nil).ConvertManifest(context.Background(), q.Get("code"))
	if err != nil {
		t.Fatal(err)
	}
	defer app.Wipe()
	for _, a := range s.Apps() {
		if a.ID() == app.ID {
			return a
		}
	}
	t.Fatal("the fake does not know the App")
	return nil
}

func appClient(t *testing.T, s *ghtest.Server, a *ghtest.App) *gh.Client {
	t.Helper()
	c, err := gh.New(gh.Config{AppID: a.ClientID(), Keys: gh.StaticKey{Key: a.Key()}, BaseURL: s.URL(), Now: s.Now})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type recordAuth struct {
	rt   http.RoundTripper
	auth []string
	path []string
}

func (r *recordAuth) RoundTrip(req *http.Request) (*http.Response, error) {
	r.auth = append(r.auth, req.Header.Get("Authorization"))
	r.path = append(r.path, req.Method+" "+req.URL.Path)
	return r.rt.RoundTrip(req)
}

func TestConvertManifestHappyPath(t *testing.T) {
	s := ghtest.New(t)
	sp := spec(corePerms)
	q := submit(t, s, sp, "", "the-state")
	if q.Get("state") != "the-state" || len(q.Get("code")) != 40 {
		t.Fatalf("redirect query %v", q)
	}
	rec := &recordAuth{rt: http.DefaultTransport}
	app, err := anon(t, s, rec).ConvertManifest(context.Background(), q.Get("code"))
	if err != nil {
		t.Fatal(err)
	}
	defer app.Wipe()
	fake := s.Apps()[0]
	if app.ID != fake.ID() || app.Slug != fake.Slug() || app.ClientID != fake.ClientID() || app.OwnerLogin != "example-user" {
		t.Errorf("app: %+v", app)
	}
	if !bytes.Equal(app.PEM, fake.PEM()) {
		t.Error("the key is not the one GitHub made")
	}
	if _, err := gh.ParsePrivateKeyPEM(app.PEM); err != nil {
		t.Errorf("the key does not parse: %v", err)
	}
	if err := app.Check(sp); err != nil {
		t.Errorf("the App GitHub made from this manifest does not check out: %v", err)
	}
	if len(rec.path) != 1 || rec.path[0] != "POST /app-manifests/"+q.Get("code")+"/conversions" || rec.auth[0] != "" {
		t.Errorf("the exchange must be one POST with no credential: %v %q", rec.path, rec.auth)
	}
	// The client secret and the webhook secret are not kept anywhere in what is returned.
	dump, _ := json.Marshal(app)
	for _, secret := range []string{fake.ClientSecret(), fake.WebhookSecret()} {
		if strings.Contains(string(dump), secret) {
			t.Error("a secret other than the key is kept in the result")
		}
	}
	// What the fake was sent, and by whom.
	reqs := s.ManifestRequests()
	if len(reqs) != 1 || reqs[0].State != "the-state" || reqs[0].Manifest.HookAttrs != nil || reqs[0].Manifest.Public {
		t.Errorf("manifest requests: %+v", reqs)
	}
	app.Wipe()
	if app.PEM != nil {
		t.Error("Wipe left the key")
	}
}

func TestConvertManifestForAnOrganisation(t *testing.T) {
	s := ghtest.New(t)
	q := submit(t, s, spec(corePerms), "my-org", "")
	app, err := anon(t, s, nil).ConvertManifest(context.Background(), q.Get("code"))
	if err != nil {
		t.Fatal(err)
	}
	defer app.Wipe()
	if app.OwnerLogin != "my-org" || q.Has("state") {
		t.Errorf("owner %q, query %v", app.OwnerLogin, q)
	}
}

func TestConvertManifestCodeIsSingleUseAndShortLived(t *testing.T) {
	s := ghtest.New(t)
	c := anon(t, s, nil)
	q := submit(t, s, spec(corePerms), "", "")
	app, err := c.ConvertManifest(context.Background(), q.Get("code"))
	if err != nil {
		t.Fatal(err)
	}
	app.Wipe()
	var ae *gh.APIError
	if _, err := c.ConvertManifest(context.Background(), q.Get("code")); !errors.As(err, &ae) || ae.Status != 404 {
		t.Errorf("a second use of the code: %v", err)
	}

	sp := spec(corePerms)
	sp.Name = "chaperone-other"
	q2 := submit(t, s, sp, "", "")
	s.Advance(61 * time.Minute)
	if _, err := c.ConvertManifest(context.Background(), q2.Get("code")); !errors.As(err, &ae) || ae.Status != 404 {
		t.Errorf("an expired code: %v", err)
	}
	if _, err := c.ConvertManifest(context.Background(), "0123456789abcdef0123"); !errors.As(err, &ae) || ae.Status != 404 {
		t.Errorf("an unknown code: %v", err)
	}
	// A code of a shape GitHub never sends is refused here, before any request.
	n := len(s.Requests())
	for _, bad := range []string{"", "../x", "abc", "a b c d e f g h", strings.Repeat("a", 200), "a/b/c/d/e/f/g/h"} {
		if _, err := c.ConvertManifest(context.Background(), bad); !errors.Is(err, gh.ErrInvalidArgument) {
			t.Errorf("code %q: %v", bad, err)
		}
	}
	if len(s.Requests()) != n {
		t.Error("a malformed code was sent to GitHub")
	}
	s.Inject("POST", "/conversions", ghtest.Fault{Status: 422, Message: "Validation Failed: the endpoint has been spammed"})
	if _, err := c.ConvertManifest(context.Background(), "0123456789abcdef0123"); !errors.As(err, &ae) || ae.Status != 422 {
		t.Errorf("a 422: %v", err)
	}
}

func TestConvertManifestAnswersThatAreNotTheExpectedApp(t *testing.T) {
	cases := map[string]func(map[string]any){
		"no key":                 func(a map[string]any) { delete(a, "pem") },
		"a null key":             func(a map[string]any) { a["pem"] = nil },
		"a key that is a number": func(a map[string]any) { a["pem"] = 7 },
		"an empty key":           func(a map[string]any) { a["pem"] = "" },
		"no id":                  func(a map[string]any) { delete(a, "id") },
		"a slug with a slash":    func(a map[string]any) { a["slug"] = "../evil" },
		"an upper-case slug":     func(a map[string]any) { a["slug"] = "Evil" },
		"a client id with space": func(a map[string]any) { a["client_id"] = "Iv 1" },
		"no owner":               func(a map[string]any) { a["owner"] = map[string]any{} },
		"an owner with markup":   func(a map[string]any) { a["owner"] = map[string]any{"login": "<script>"} },
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			s := ghtest.New(t)
			q := submit(t, s, spec(corePerms), "", "")
			s.TamperConversion(tamper)
			app, err := anon(t, s, nil).ConvertManifest(context.Background(), q.Get("code"))
			if err == nil {
				app.Wipe()
				t.Fatal("accepted")
			}
			fake := s.Apps()[0]
			for _, secret := range []string{fake.ClientSecret(), fake.WebhookSecret(), string(fake.PEM()[40:100])} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("the error holds a secret: %v", err)
				}
			}
		})
	}
}

func TestConvertManifestUnescapesTheKeyWithoutAString(t *testing.T) {
	s := ghtest.New(t)
	q := submit(t, s, spec(corePerms), "", "")
	want := "-----BEGIN X-----\r\n<&>\u00e9\\\t\"/\n-----END X-----\n"
	s.TamperConversion(func(a map[string]any) { a["pem"] = want })
	app, err := anon(t, s, nil).ConvertManifest(context.Background(), q.Get("code"))
	if err != nil {
		t.Fatal(err)
	}
	defer app.Wipe()
	if string(app.PEM) != want {
		t.Errorf("key bytes %q, want %q", app.PEM, want)
	}
}

func TestManifestAppCheck(t *testing.T) {
	sp := spec(corePerms)
	good := func() *gh.ManifestApp {
		return &gh.ManifestApp{Description: sp.Description(), Permissions: map[string]string{"contents": "write", "pull_requests": "write", "checks": "read", "metadata": "read"}}
	}
	if err := good().Check(sp); err != nil {
		t.Fatalf("a good App: %v", err)
	}
	for name, mut := range map[string]func(*gh.ManifestApp){
		"another description": func(a *gh.ManifestApp) { a.Description = "an attacker's App" },
		"another nonce": func(a *gh.ManifestApp) {
			a.Description = strings.Replace(a.Description, sp.Nonce, strings.Repeat("0", 32), 1)
		},
		"a wider permission":   func(a *gh.ManifestApp) { a.Permissions["administration"] = "write" },
		"a higher level":       func(a *gh.ManifestApp) { a.Permissions["checks"] = "write" },
		"a missing permission": func(a *gh.ManifestApp) { delete(a.Permissions, "checks") },
		"a swapped permission": func(a *gh.ManifestApp) { delete(a.Permissions, "checks"); a.Permissions["issues"] = "read" },
		"an event":             func(a *gh.ManifestApp) { a.Events = []string{"push"} },
	} {
		a := good()
		mut(a)
		if err := a.Check(sp); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// ---- the calls that show the new App works ----

func TestGetAppAndListInstallationsAsTheNewApp(t *testing.T) {
	s := ghtest.New(t)
	app := convertedApp(t, s, spec(corePerms))
	c := appClient(t, s, app)
	got, err := c.GetApp(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != app.ID() || got.Slug != app.Slug() || got.ClientID != app.ClientID() || got.OwnerLogin != "example-user" || !reflect.DeepEqual(got.Permissions, corePerms) || got.InstallationsCount != 0 {
		t.Errorf("app info: %+v", got)
	}
	if ins, err := c.ListInstallations(context.Background()); err != nil || len(ins) != 0 {
		t.Fatalf("before the install: %v %v", ins, err)
	}

	// The operator installs the App on the repositories they choose. chapd is not told the installation id:
	// it finds it with the App's own key, per repository.
	in := app.Install("example-user")
	in.AddRepo("storefront", "main")
	inst, err := c.FindInstallation(context.Background(), gh.Repo{Owner: "example-user", Name: "storefront"})
	if err != nil {
		t.Fatalf("the installation cannot be found with the new App's key: %v", err)
	}
	if inst.ID != in.ID || inst.AppID != app.ID() {
		t.Errorf("installation %+v, want id %d app %d", inst, in.ID, app.ID())
	}
	tok, err := c.MintToken(context.Background(), inst.ID, gh.TokenRequest{Repositories: []string{"storefront"}, Permissions: gh.PermsMerge()})
	if err != nil {
		t.Fatalf("the discovered installation does not mint: %v", err)
	}
	tok.Wipe()
	ins, err := c.ListInstallations(context.Background())
	if err != nil || len(ins) != 1 || ins[0].ID != in.ID || ins[0].Account != "example-user" || ins[0].Selection != "selected" {
		t.Fatalf("installations: %v %v", ins, err)
	}
	if got, _ := c.GetApp(context.Background()); got.InstallationsCount != 1 {
		t.Errorf("installations_count %d", got.InstallationsCount)
	}
}

func TestListInstallationsPages(t *testing.T) {
	s := ghtest.New(t)
	app := convertedApp(t, s, spec(corePerms))
	for i := range 230 {
		app.Install("acct-" + strconv.Itoa(i))
	}
	ins, err := appClient(t, s, app).ListInstallations(context.Background())
	if err != nil || len(ins) != 230 {
		t.Fatalf("%d installations: %v", len(ins), err)
	}
}

func TestANewAppsKeyIsNotAnotherAppsKey(t *testing.T) {
	s := ghtest.New(t)
	sp1, sp2 := spec(corePerms), spec(corePerms)
	sp2.Name = "chaperone-second"
	a1, a2 := convertedApp(t, s, sp1), convertedApp(t, s, sp2)
	// App 2's id signed with App 1's key.
	c, err := gh.New(gh.Config{AppID: a2.ClientID(), Keys: gh.StaticKey{Key: a1.Key()}, BaseURL: s.URL(), Now: s.Now})
	if err != nil {
		t.Fatal(err)
	}
	var ae *gh.APIError
	if _, err := c.GetApp(context.Background()); !errors.As(err, &ae) || ae.Status != 401 {
		t.Errorf("another App's key was accepted: %v", err)
	}
	// An installation of App 1 is not visible to App 2.
	a1.Install("example-user").AddRepo("storefront", "main")
	if _, err := appClient(t, s, a2).FindInstallation(context.Background(), gh.Repo{Owner: "example-user", Name: "storefront"}); !errors.As(err, &ae) || ae.Status != 404 {
		t.Errorf("App 2 sees App 1's installation: %v", err)
	}
}

func TestAnAnonymousClientHasNoApp(t *testing.T) {
	s := ghtest.New(t)
	c := anon(t, s, nil)
	if _, err := c.GetApp(context.Background()); err == nil {
		t.Error("an anonymous client called GET /app")
	}
	if _, err := c.FindInstallation(context.Background(), gh.Repo{Owner: "a", Name: "b"}); err == nil {
		t.Error("an anonymous client found an installation")
	}
	if _, err := gh.NewAnonymous(gh.Config{AppID: "1", Keys: gh.StaticKey{Key: s.Key()}, BaseURL: s.URL()}); err == nil {
		t.Error("an anonymous client with a key")
	}
}
