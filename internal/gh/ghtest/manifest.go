package ghtest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// This file fakes the two GitHub endpoints of the app-manifest flow and the two
// App calls that show a new App works:
//
//	POST /settings/apps/new                      (github.com, the operator's browser)
//	POST /organizations/{org}/settings/apps/new  (the same, for an organisation)
//	POST /app-manifests/{code}/conversions       (the REST API, no credential)
//	GET  /app, GET /app/installations            (the REST API, App JWT)
//
// They sit on the same fake server as the rest of the REST API; a test passes
// [Server.URL] as both the web base and the API base. The App that the flow
// creates has its own RSA key, so a JWT signed with the key the conversion
// returned is the only one the fake accepts for it.
//
// What is modelled, from GitHub's documentation ("Registering a GitHub App from
// a manifest"): the manifest is a JSON string in a form field `manifest`; an
// optional `state` in the query string comes back unchanged next to `code`; the
// code is temporary (one hour) and a second use of it is a 404; the answer
// carries id, slug, node_id, client_id, client_secret, webhook_secret, pem,
// owner, name, description, external_url, html_url, permissions and events.
//
// [INFERENCE] Simplification: the real flow shows a page where the operator may
// rename the App and presses "Create GitHub App". Here the POST creates the App
// at once and answers 302 to `redirect_url` with the code, which is what the
// browser ends up doing. A manifest GitHub would reject (no url, a webhook
// without a url, an unknown permission) is answered 422 here as well.

// App is an App made through the manifest flow.
type App struct {
	s             *Server
	id            int64
	slug          string
	clientID      string
	name          string
	description   string
	externalURL   string
	owner         string
	perms         map[string]string
	events        []string
	key           *rsa.PrivateKey
	clientSecret  string
	webhookSecret string
}

// ID is the App's numeric id.
func (a *App) ID() int64 { return a.id }

// Slug is the App's URL name.
func (a *App) Slug() string { return a.slug }

// ClientID is the App's client id.
func (a *App) ClientID() string { return a.clientID }

// Owner is the login of the account the App was created under.
func (a *App) Owner() string { return a.owner }

// Description is the description the manifest gave.
func (a *App) Description() string { return a.description }

// Permissions are the permissions the manifest asked for, which the App holds.
func (a *App) Permissions() map[string]string {
	out := make(map[string]string, len(a.perms))
	for k, v := range a.perms {
		out[k] = v
	}
	return out
}

// Key is the App's private key.
func (a *App) Key() *rsa.PrivateKey { return a.key }

// PEM is the private key as GitHub hands it over: PKCS#1, "RSA PRIVATE KEY".
func (a *App) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(a.key)})
}

// ClientSecret and WebhookSecret are the two other secrets the conversion
// returns. They exist so that a test can look for them in output.
func (a *App) ClientSecret() string  { return a.clientSecret }
func (a *App) WebhookSecret() string { return a.webhookSecret }

// Install installs the App on account, with the permissions it holds. Add the
// repositories the operator chose with [Installation.AddRepo].
func (a *App) Install(account string) *Installation {
	in := &Installation{Account: account, Granted: a.Permissions(), s: a.s, repos: map[string]*Repo{}, app: a}
	a.s.mu.Lock()
	in.ID = 5000 + a.s.nextID()
	a.s.installs[in.ID] = in
	a.s.mu.Unlock()
	return in
}

// appNumericID is the `app_id` a call made as app reports.
func appNumericID(app *App) int64 {
	if app == nil {
		return OwnAppID
	}
	return app.id
}

// ManifestDoc is the manifest GitHub received, decoded.
type ManifestDoc struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	Description string `json:"description"`
	RedirectURL string `json:"redirect_url"`
	Public      bool   `json:"public"`
	HookAttrs   *struct {
		URL    string `json:"url"`
		Active *bool  `json:"active"`
	} `json:"hook_attributes"`
	CallbackURLs       []string          `json:"callback_urls"`
	SetupURL           string            `json:"setup_url"`
	DefaultEvents      []string          `json:"default_events"`
	DefaultPermissions map[string]string `json:"default_permissions"`
}

// ManifestRequest is one accepted POST of a manifest.
type ManifestRequest struct {
	// Org is the organisation of the address, empty for a personal account.
	Org string
	// State is the `state` of the query string, empty when none was sent.
	State string
	// Raw is the manifest field as sent.
	Raw      string
	Manifest ManifestDoc
	// Code is the temporary code that was issued, and App the App it makes.
	Code string
	App  *App
}

type manifestCode struct {
	app     *App
	created time.Time
	used    bool
}

type manifestState struct {
	apps     []*App
	codes    map[string]*manifestCode
	requests []ManifestRequest
	user     string
	tamper   func(answer map[string]any)
}

// SetWebUser sets the login of the personal account that "the operator" is
// signed in as on the fake's github.com side. The default is example-user.
func (s *Server) SetWebUser(login string) {
	s.mu.Lock()
	s.web.user = login
	s.mu.Unlock()
}

// TamperConversion lets a test change the answer of the next conversions
// before it is sent, to model a service that answers something unexpected.
func (s *Server) TamperConversion(fn func(answer map[string]any)) {
	s.mu.Lock()
	s.web.tamper = fn
	s.mu.Unlock()
}

// Apps returns the Apps the manifest flow has made, oldest first.
func (s *Server) Apps() []*App {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*App(nil), s.web.apps...)
}

// ManifestRequests returns the manifests the fake accepted, oldest first.
func (s *Server) ManifestRequests() []ManifestRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ManifestRequest(nil), s.web.requests...)
}

func (s *Server) appByIss(iss string) *App {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.web.apps {
		if iss == strconv.FormatInt(a.id, 10) || iss == a.clientID {
			return a
		}
	}
	return nil
}

var (
	slugBad  = regexp.MustCompile(`[^a-z0-9]+`)
	permName = regexp.MustCompile(`^[a-z][a-z_]{0,63}$`)
)

func webPage(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, "<!doctype html><title>GitHub</title><p>%s", html.EscapeString(msg))
}

// newAppPage is the POST of the manifest form.
func (s *Server) newAppPage(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		webPage(w, http.StatusBadRequest, "Bad request")
		return
	}
	raw := r.PostForm.Get("manifest")
	var m ManifestDoc
	if raw == "" || json.Unmarshal([]byte(raw), &m) != nil {
		webPage(w, http.StatusUnprocessableEntity, "Invalid GitHub App manifest: the manifest is not valid JSON")
		return
	}
	if m.URL == "" {
		webPage(w, http.StatusUnprocessableEntity, "Invalid GitHub App manifest: url can't be blank")
		return
	}
	if m.HookAttrs != nil && m.HookAttrs.URL == "" {
		webPage(w, http.StatusUnprocessableEntity, "Invalid GitHub App manifest: hook_attributes url can't be blank")
		return
	}
	for k, v := range m.DefaultPermissions {
		if !permName.MatchString(k) || permLevel(v) == 0 {
			webPage(w, http.StatusUnprocessableEntity, "Invalid GitHub App manifest: unknown permission "+k)
			return
		}
	}
	var redirect *url.URL
	if m.RedirectURL != "" {
		u, err := url.Parse(m.RedirectURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			webPage(w, http.StatusUnprocessableEntity, "Invalid GitHub App manifest: redirect_url is not a URL")
			return
		}
		redirect = u
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		webPage(w, http.StatusInternalServerError, "key generation failed")
		return
	}
	org := r.PathValue("org")

	s.mu.Lock()
	owner := org
	if owner == "" {
		owner = s.web.user
	}
	if owner == "" {
		owner = "example-user"
	}
	name := m.Name
	if name == "" {
		name = "app-" + strconv.Itoa(len(s.web.apps)+1)
	}
	slug := strings.Trim(slugBad.ReplaceAllString(strings.ToLower(name), "-"), "-")
	for _, a := range s.web.apps {
		if a.slug == slug {
			s.mu.Unlock()
			webPage(w, http.StatusUnprocessableEntity, "Name is already in use")
			return
		}
	}
	id := 900000 + int64(len(s.web.apps)) + 1
	a := &App{
		s: s, id: id, slug: slug, clientID: "Iv23li" + hex.EncodeToString(randBytes(7)), name: name,
		description: m.Description, externalURL: m.URL, owner: owner, perms: m.DefaultPermissions, events: m.DefaultEvents,
		key: key, clientSecret: hex.EncodeToString(randBytes(20)), webhookSecret: hex.EncodeToString(randBytes(16)),
	}
	if a.perms == nil {
		a.perms = map[string]string{}
	}
	if a.events == nil {
		a.events = []string{}
	}
	if s.web.codes == nil {
		s.web.codes = map[string]*manifestCode{}
	}
	code := hex.EncodeToString(randBytes(20))
	s.web.codes[code] = &manifestCode{app: a, created: s.now}
	s.web.apps = append(s.web.apps, a)
	state := r.URL.Query().Get("state")
	s.web.requests = append(s.web.requests, ManifestRequest{Org: org, State: state, Raw: raw, Manifest: m, Code: code, App: a})
	s.mu.Unlock()

	if redirect == nil {
		webPage(w, http.StatusOK, "Registered GitHub App "+name)
		return
	}
	q := redirect.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	redirect.RawQuery = q.Encode()
	w.Header().Set("Location", redirect.String())
	w.WriteHeader(http.StatusFound)
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// convertManifest is POST /app-manifests/{code}/conversions. It takes no
// credential, answers 201 once per code, and 404 for an unknown, used or
// expired (over one hour, by the fake's clock) code.
func (s *Server) convertManifest(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	rec := s.web.codes[r.PathValue("code")]
	if rec == nil || rec.used || s.now.Sub(rec.created) > time.Hour {
		s.mu.Unlock()
		refuse(w, http.StatusNotFound, "Not Found")
		return
	}
	rec.used = true
	a, tamper := rec.app, s.web.tamper
	s.mu.Unlock()

	answer := a.json()
	answer["client_secret"] = a.clientSecret
	answer["webhook_secret"] = a.webhookSecret
	answer["pem"] = string(a.PEM())
	if tamper != nil {
		tamper(answer)
	}
	jsonOut(w, http.StatusCreated, answer)
}

// json is the App as GitHub's "GitHub app" schema shows it.
func (a *App) json() map[string]any {
	now := a.s.Now().UTC().Format(time.RFC3339)
	return map[string]any{
		"id": a.id, "slug": a.slug, "node_id": "A_" + a.slug, "client_id": a.clientID,
		"owner":        map[string]any{"login": a.owner, "id": 1, "type": "User"},
		"name":         a.name,
		"description":  a.description,
		"external_url": a.externalURL,
		"html_url":     "https://github.test/apps/" + a.slug,
		"created_at":   now, "updated_at": now,
		"permissions": a.Permissions(), "events": a.events,
	}
}

// getApp is GET /app.
func (s *Server) getApp(w http.ResponseWriter, r *http.Request) {
	app, msg := s.verifyApp(bearer(r))
	if msg != "" {
		refuse(w, http.StatusUnauthorized, msg)
		return
	}
	if app == nil { // the fake's own App
		jsonOut(w, http.StatusOK, map[string]any{
			"id": OwnAppID, "slug": "chaperone-app", "client_id": "Iv1.fakeown", "owner": map[string]any{"login": "example-org"},
			"permissions": map[string]string{}, "events": []string{},
		})
		return
	}
	out := app.json()
	s.mu.Lock()
	n := 0
	for _, in := range s.installs {
		if in.app == app {
			n++
		}
	}
	s.mu.Unlock()
	out["installations_count"] = n
	jsonOut(w, http.StatusOK, out)
}

// listAppInstallations is GET /app/installations: the calling App's own
// installations, 100 a page at most.
func (s *Server) listAppInstallations(w http.ResponseWriter, r *http.Request) {
	app, msg := s.verifyApp(bearer(r))
	if msg != "" {
		refuse(w, http.StatusUnauthorized, msg)
		return
	}
	per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if per <= 0 || per > 100 {
		per = 30
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page <= 0 {
		page = 1
	}
	s.mu.Lock()
	var ins []*Installation
	for _, in := range s.installs {
		if in.app == app {
			ins = append(ins, in)
		}
	}
	s.mu.Unlock()
	sort.Slice(ins, func(i, j int) bool { return ins[i].ID < ins[j].ID })
	lo := min((page-1)*per, len(ins))
	hi := min(lo+per, len(ins))
	out := []map[string]any{}
	for _, in := range ins[lo:hi] {
		out = append(out, map[string]any{
			"id": in.ID, "app_id": appNumericID(app), "account": map[string]any{"login": in.Account},
			"repository_selection": "selected", "permissions": in.Granted,
		})
	}
	jsonOut(w, http.StatusOK, out)
}
