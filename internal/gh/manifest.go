package gh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// This file is the client side of GitHub's app-manifest flow ("Registering a
// GitHub App from a manifest", docs.github.com): the manifest Chaperone asks
// GitHub to turn into an App, the exchange of the temporary code for the App's
// settings and private key, and the two calls that show the new App works.
//
// The flow, as GitHub documents it:
//
//  1. The operator's browser POSTs a form with one field, `manifest` (JSON), to
//     https://github.com/settings/apps/new (a personal account) or
//     https://github.com/organizations/ORG/settings/apps/new, with an optional
//     `state` in the query string.
//  2. The operator names the App and presses "Create GitHub App". GitHub
//     redirects the browser to the manifest's `redirect_url` with `code` (and
//     `state`, when one was sent) in the query string.
//  3. The code is exchanged with POST /app-manifests/{code}/conversions, which
//     takes no credential. The answer (201) holds the App's id, slug, node_id,
//     client_id, client_secret, webhook_secret, pem, owner, name, description,
//     external_url, html_url, permissions and events.
//
// GitHub says all three steps must finish within one hour. It does not say in
// words that a code works only once; this code treats it as single use anyway.

// ManifestHomepage is the `url` of the manifest. GitHub requires one; this is
// the project's own page.
const ManifestHomepage = "https://github.com/joshua-noel/chaperone"

// Optional groups of permissions, each for operations that are off or opt-in.
const (
	// ExtraDeploy is for the `deploy` op: deployments write.
	ExtraDeploy = "deploy"
	// ExtraIssues is for issue.open, issue.comment and issue.reopen: issues write.
	ExtraIssues = "issues"
	// ExtraCIReport is for ci.report: checks write instead of read.
	ExtraCIReport = "ci-report"
)

// ManifestPermissions is the smallest permission set of an App that can serve
// the GitHub operations Chaperone ships, taken from the same functions the
// operations mint their tokens with (so it cannot drift from the code): the
// highest level asked for each permission by the pull request ops, the git
// proxy's fetch and push, and the read ops. With no extras that is
// contents write, pull_requests write, checks read and metadata read. Each
// extra adds the permissions of one opt-in operation group. Never `workflows`,
// `administration` or anything on an account or organisation.
func ManifestPermissions(extras ...string) (map[string]string, error) {
	sets := []map[string]string{
		PermsEvaluateMerge(), PermsOpenPull(), PermsFetch(), PermsPush(), PermsMerge(), PermsReadPull(), PermsReadPullChecks(),
	}
	for _, e := range extras {
		switch e {
		case ExtraDeploy:
			sets = append(sets, PermsDeployRead(), PermsDeploy())
		case ExtraIssues:
			sets = append(sets, PermsIssueRead(), PermsIssueWrite())
		case ExtraCIReport:
			sets = append(sets, PermsReportCI())
		default:
			return nil, fmt.Errorf("%w: unknown permission group %q", ErrInvalidArgument, e)
		}
	}
	out := map[string]string{}
	for _, set := range sets {
		for k, v := range set {
			if level(v) > level(out[k]) {
				out[k] = v
			}
		}
	}
	return out, nil
}

// ManifestSpec is what Chaperone asks GitHub to create.
type ManifestSpec struct {
	// Name is the App's name, shown on the registration page, where the
	// operator may change it. GitHub keeps names unique.
	Name string
	// Nonce is a random value, unique to this setup. It is put in the App's
	// description, and [ManifestApp.Check] looks for it in what GitHub returns.
	Nonce string
	// RedirectURL is where GitHub sends the browser with the temporary code.
	RedirectURL string
	// Permissions are the App's default permissions (see [ManifestPermissions]).
	Permissions map[string]string
}

// Description is the App's description, with the nonce in it.
func (m ManifestSpec) Description() string {
	return "Chaperone access broker, set up by chapd connect github. Setup " + m.Nonce + "."
}

func (m ManifestSpec) validate() error {
	switch {
	case m.Name == "" || len(m.Name) > 34 || !validPlainText(m.Name):
		return fmt.Errorf("%w: manifest name", ErrInvalidArgument)
	case len(m.Nonce) < 16 || !nonceRE.MatchString(m.Nonce):
		return fmt.Errorf("%w: manifest nonce", ErrInvalidArgument)
	case len(m.Permissions) == 0:
		return fmt.Errorf("%w: manifest permissions", ErrInvalidArgument)
	}
	u, err := url.Parse(m.RedirectURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%w: manifest redirect URL", ErrInvalidArgument)
	}
	for k, v := range m.Permissions {
		if !permNameRE.MatchString(k) || level(v) == 0 {
			return fmt.Errorf("%w: manifest permission %q: %q", ErrInvalidArgument, k, v)
		}
	}
	return nil
}

var nonceRE = regexp.MustCompile(`^[a-f0-9]{16,64}$`)

func validPlainText(s string) bool {
	for _, r := range s {
		if r < ' ' || r == 0x7f || r == utf8.RuneError {
			return false
		}
	}
	return true
}

// JSON is the manifest GitHub takes in the `manifest` field. It names no
// webhook (so none is created), no event, no callback or setup URL, and the App
// is private to the account that creates it.
func (m ManifestSpec) JSON() ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Name               string            `json:"name"`
		URL                string            `json:"url"`
		Description        string            `json:"description"`
		RedirectURL        string            `json:"redirect_url"`
		Public             bool              `json:"public"`
		DefaultEvents      []string          `json:"default_events"`
		DefaultPermissions map[string]string `json:"default_permissions"`
	}{m.Name, ManifestHomepage, m.Description(), m.RedirectURL, false, []string{}, m.Permissions})
}

// ManifestApp is GitHub's answer to the exchange of a manifest code. PEM is the
// App's private key: the only copy there will ever be. Call [ManifestApp.Wipe]
// when done with it.
type ManifestApp struct {
	ID          int64
	Slug        string
	ClientID    string
	Name        string
	Description string
	HTMLURL     string
	OwnerLogin  string
	Permissions map[string]string
	Events      []string
	// PEM is the private key as GitHub sent it. The client secret and the
	// webhook secret are read and discarded: nothing in Chaperone uses them.
	PEM []byte
}

// Wipe overwrites the private key in memory.
func (a *ManifestApp) Wipe() {
	if a != nil {
		clear(a.PEM)
		a.PEM = nil
	}
}

var (
	codeRE   = regexp.MustCompile(`^[A-Za-z0-9._-]{8,128}$`)
	slugRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	clientRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	loginRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)
)

// ConvertManifest exchanges the temporary code (POST /app-manifests/{code}/
// conversions, no credential) for the App GitHub created. Call it on a client
// from [NewAnonymous].
//
// The private key is copied out of the answer into [ManifestApp.PEM] and the
// copies this function made are overwritten. The client secret and the webhook
// secret are never kept. No error holds any of them.
func (c *Client) ConvertManifest(ctx context.Context, code string) (*ManifestApp, error) {
	if !codeRE.MatchString(code) {
		return nil, fmt.Errorf("%w: manifest code", ErrInvalidArgument)
	}
	var raw []byte
	if err := c.do(ctx, call{method: http.MethodPost, path: "/app-manifests/" + url.PathEscape(code) + "/conversions"}, &raw); err != nil {
		return nil, err
	}
	defer clear(raw)
	var doc struct {
		ID          int64             `json:"id"`
		Slug        string            `json:"slug"`
		ClientID    string            `json:"client_id"`
		Name        string            `json:"name"`
		Description string            `json:"description"`
		HTMLURL     string            `json:"html_url"`
		Permissions map[string]string `json:"permissions"`
		Events      []string          `json:"events"`
		Owner       struct {
			Login string `json:"login"`
		} `json:"owner"`
		PEM           json.RawMessage `json:"pem"`
		ClientSecret  json.RawMessage `json:"client_secret"`
		WebhookSecret json.RawMessage `json:"webhook_secret"`
	}
	err := json.Unmarshal(raw, &doc)
	clear(doc.ClientSecret)
	clear(doc.WebhookSecret)
	defer clear(doc.PEM)
	if err != nil {
		return nil, errors.New("gh: the manifest exchange answered something that is not the expected JSON")
	}
	pem, err := jsonStringBytes(doc.PEM)
	if err != nil {
		return nil, errors.New("gh: the manifest exchange returned no private key")
	}
	app := &ManifestApp{
		ID: doc.ID, Slug: doc.Slug, ClientID: doc.ClientID, Name: doc.Name, Description: doc.Description,
		HTMLURL: doc.HTMLURL, OwnerLogin: doc.Owner.Login, Permissions: doc.Permissions, Events: doc.Events, PEM: pem,
	}
	if err := app.wellFormed(); err != nil {
		app.Wipe()
		return nil, err
	}
	return app, nil
}

// wellFormed accepts only the shapes GitHub uses for these fields. The values
// come from a remote service: they decide nothing until they match a narrow
// pattern, and callers that print them clean them first.
func (a *ManifestApp) wellFormed() error {
	switch {
	case a.ID <= 0:
		return errors.New("gh: the manifest exchange returned no App id")
	case !slugRE.MatchString(a.Slug):
		return errors.New("gh: the manifest exchange returned an App slug of an unexpected shape")
	case !clientRE.MatchString(a.ClientID):
		return errors.New("gh: the manifest exchange returned a client id of an unexpected shape")
	case !loginRE.MatchString(a.OwnerLogin):
		return errors.New("gh: the manifest exchange returned an owner of an unexpected shape")
	case len(a.PEM) == 0:
		return errors.New("gh: the manifest exchange returned no private key")
	}
	return nil
}

// Check says whether this is the App that spec asked for: the nonce is in its
// description, its permissions are exactly the permissions asked for (no more,
// no fewer) and it subscribes to no event. An App created from some other
// manifest fails at least one of the three.
func (a *ManifestApp) Check(spec ManifestSpec) error {
	if !strings.Contains(a.Description, spec.Nonce) {
		return errors.New("this App was not made from the manifest chapd sent (its description does not carry this setup's value)")
	}
	if len(a.Events) != 0 {
		return errors.New("this App subscribes to events; the manifest asked for none")
	}
	if len(a.Permissions) != len(spec.Permissions) {
		return errors.New("this App's permissions are not the ones the manifest asked for")
	}
	for k, v := range spec.Permissions {
		if a.Permissions[k] != v {
			return errors.New("this App's permissions are not the ones the manifest asked for")
		}
	}
	return nil
}

// jsonStringBytes decodes a JSON string into a fresh byte slice, without making
// a Go string (which cannot be wiped). It accepts the escapes JSON defines,
// except a surrogate half, which no PEM holds.
func jsonStringBytes(raw json.RawMessage) ([]byte, error) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, errors.New("not a JSON string")
	}
	in := raw[1 : len(raw)-1]
	out := make([]byte, 0, len(in))
	fail := func() ([]byte, error) { clear(out); return nil, errors.New("bad JSON string") }
	for i := 0; i < len(in); i++ {
		c := in[i]
		if c != '\\' {
			out = append(out, c)
			continue
		}
		i++
		if i >= len(in) {
			return fail()
		}
		switch e := in[i]; e {
		case '"', '\\', '/':
			out = append(out, e)
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'u':
			if i+4 >= len(in) {
				return fail()
			}
			n, err := strconv.ParseUint(string(in[i+1:i+5]), 16, 16)
			if err != nil || (n >= 0xD800 && n <= 0xDFFF) {
				return fail()
			}
			out = utf8.AppendRune(out, rune(n))
			i += 4
		default:
			return fail()
		}
	}
	return out, nil
}

// AppInfo is the App as GitHub reports it to its own JWT (GET /app).
type AppInfo struct {
	ID                 int64
	Slug               string
	ClientID           string
	OwnerLogin         string
	Permissions        map[string]string
	Events             []string
	InstallationsCount int
}

// GetApp reads the App the client's key belongs to (GET /app, App JWT). It
// proves the key and the App id agree.
func (c *Client) GetApp(ctx context.Context) (AppInfo, error) {
	jwt, err := c.asApp(ctx)
	if err != nil {
		return AppInfo{}, err
	}
	var out struct {
		ID                 int64             `json:"id"`
		Slug               string            `json:"slug"`
		ClientID           string            `json:"client_id"`
		Permissions        map[string]string `json:"permissions"`
		Events             []string          `json:"events"`
		InstallationsCount int               `json:"installations_count"`
		Owner              struct {
			Login string `json:"login"`
		} `json:"owner"`
	}
	if err := c.do(ctx, call{method: http.MethodGet, path: "/app", secret: jwt}, &out); err != nil {
		return AppInfo{}, err
	}
	return AppInfo{ID: out.ID, Slug: out.Slug, ClientID: out.ClientID, OwnerLogin: out.Owner.Login,
		Permissions: out.Permissions, Events: out.Events, InstallationsCount: out.InstallationsCount}, nil
}

// maxInstallationPages bounds [Client.ListInstallations]: 1000 installations.
const maxInstallationPages = 10

// ListInstallations lists the App's installations (GET /app/installations,
// App JWT). Chaperone does not need the list to work: it finds the installation
// of each repository itself ([Client.FindInstallation]). The list is for
// `chapd connect github status`.
func (c *Client) ListInstallations(ctx context.Context) ([]Installation, error) {
	var all []Installation
	for page := 1; page <= maxInstallationPages; page++ {
		jwt, err := c.asApp(ctx)
		if err != nil {
			return nil, err
		}
		var out []struct {
			ID      int64 `json:"id"`
			AppID   int64 `json:"app_id"`
			Account struct {
				Login string `json:"login"`
			} `json:"account"`
			Selection string `json:"repository_selection"`
		}
		q := url.Values{"per_page": {strconv.Itoa(perPage)}, "page": {strconv.Itoa(page)}}
		if err := c.do(ctx, call{method: http.MethodGet, path: "/app/installations", query: q, secret: jwt}, &out); err != nil {
			return nil, err
		}
		for _, in := range out {
			all = append(all, Installation{ID: in.ID, AppID: in.AppID, Account: in.Account.Login, Selection: in.Selection})
		}
		if len(out) < perPage {
			return slices.Clip(all), nil
		}
	}
	return all, nil
}
