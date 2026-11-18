package gh

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// DefaultBaseURL is the public GitHub REST API.
	DefaultBaseURL = "https://api.github.com"
	// APIVersion is sent in X-GitHub-Api-Version. The temporary stateless-token
	// format override header (ends 2026-11-30, ADR-002) is deliberately not sent.
	APIVersion = "2022-11-28"

	maxBody        = 32 << 20 // largest response body read; a compare of 250 commits is well below
	maxMessage     = 512      // bytes of GitHub's error message kept in an APIError
	maxFieldErrors = 5        // entries of a 422's errors[] kept in an APIError
	maxFieldPart   = 60       // bytes of a resource, field or code in one of them
	perPage        = 100
)

// Config configures a [Client].
type Config struct {
	// AppID is the `iss` of the App JWT: the App's numeric ID or its client ID.
	AppID string
	// Keys supplies the App private key for each JWT.
	Keys KeySource
	// BaseURL defaults to [DefaultBaseURL]. It must be https, except for a
	// loopback address (the fake server).
	BaseURL string
	// HTTPClient defaults to a client with a 30 s timeout that does not follow
	// redirects. A supplied client is used as is.
	HTTPClient *http.Client
	// Now defaults to time.Now. Tests pass the fake server's clock.
	Now func() time.Time
	// UserAgent defaults to "chaperone-gh".
	UserAgent string
}

// Client talks to the GitHub REST API as one GitHub App. It holds no token; the
// caller passes the installation [Token] to each call. It never retries.
type Client struct {
	base  string
	appID string
	keys  KeySource
	hc    *http.Client
	now   func() time.Time
	agent string
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	if cfg.AppID == "" || strings.ContainsAny(cfg.AppID, " \t\r\n") {
		return nil, fmt.Errorf("%w: AppID", ErrInvalidArgument)
	}
	if cfg.Keys == nil {
		return nil, fmt.Errorf("%w: Keys", ErrInvalidArgument)
	}
	base := cfg.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, fmt.Errorf("%w: BaseURL", ErrInvalidArgument)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if ip := net.ParseIP(u.Hostname()); (ip == nil || !ip.IsLoopback()) && u.Hostname() != "localhost" {
			return nil, fmt.Errorf("%w: BaseURL must be https (plain http only for loopback)", ErrInvalidArgument)
		}
	default:
		return nil, fmt.Errorf("%w: BaseURL scheme", ErrInvalidArgument)
	}
	c := &Client{base: strings.TrimRight(u.String(), "/"), appID: cfg.AppID, keys: cfg.Keys,
		hc: cfg.HTTPClient, now: cfg.Now, agent: cfg.UserAgent}
	if c.hc == nil {
		c.hc = &http.Client{
			Timeout:       30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.agent == "" {
		c.agent = "chaperone-gh"
	}
	return c, nil
}

// Repo names a repository.
type Repo struct{ Owner, Name string }

var nameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)

func validName(s string) bool { return nameRE.MatchString(s) && s != "." && s != ".." }

// ParseRepo parses "owner/name".
func ParseRepo(s string) (Repo, error) {
	o, n, ok := strings.Cut(s, "/")
	r := Repo{o, n}
	if !ok || r.validate() != nil {
		return Repo{}, fmt.Errorf("%w: repository %q", ErrInvalidArgument, s)
	}
	return r, nil
}

func (r Repo) String() string { return r.Owner + "/" + r.Name }

func (r Repo) validate() error {
	if !validName(r.Owner) || !validName(r.Name) {
		return fmt.Errorf("%w: repository %q", ErrInvalidArgument, r.String())
	}
	return nil
}

func (r Repo) path(rest string) string {
	return "/repos/" + url.PathEscape(r.Owner) + "/" + url.PathEscape(r.Name) + rest
}

var shaRE = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

// validSHA accepts a full lowercase SHA-1 or SHA-256 object name. Abbreviated
// SHAs are refused on purpose: every exact-head rule needs the full value.
func validSHA(s string) error {
	if !shaRE.MatchString(s) {
		return fmt.Errorf("%w: %q is not a full commit SHA", ErrInvalidArgument, s)
	}
	return nil
}

// validRef accepts a branch name or a commit SHA for use in a URL path or body.
// It applies git's own ref-name rules conservatively; "owner:branch" is not a
// ref (callers that need it say so).
func validRef(s string) error {
	bad := s == "" || len(s) > 255 || strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") ||
		strings.HasSuffix(s, ".") || strings.HasSuffix(s, ".lock") || strings.HasPrefix(s, "-") ||
		strings.Contains(s, "..") || strings.Contains(s, "//") || strings.Contains(s, "@{") ||
		strings.ContainsAny(s, " ~^:?*[\\%#\x7f") || !utf8.ValidString(s)
	for _, r := range s {
		if r < 0x20 {
			bad = true
		}
	}
	if bad {
		return fmt.Errorf("%w: ref %q", ErrInvalidArgument, s)
	}
	return nil
}

// refPath escapes a validated ref segment by segment, keeping "/" (GitHub
// resolves "feat/x" in path position; "%2F" is not guaranteed to work).
func refPath(ref string) string {
	parts := strings.Split(ref, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

// call describes one request.
type call struct {
	method string
	path   string // escaped, begins with "/"
	query  url.Values
	body   any
	secret string // bearer credential
	accept string // Accept header; empty for GitHub's JSON media type
}

// do sends one request, once. Any non-2xx answer becomes an *APIError. out may be nil.
func (c *Client) do(ctx context.Context, k call, out any) error {
	u := c.base + k.path
	if len(k.query) > 0 {
		u += "?" + k.query.Encode()
	}
	var body io.Reader
	if k.body != nil {
		b, err := json.Marshal(k.body)
		if err != nil {
			return fmt.Errorf("gh: encode request: %w", err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, k.method, u, body)
	if err != nil {
		return fmt.Errorf("gh: build request: %w", err)
	}
	accept := k.accept
	if accept == "" {
		accept = "application/vnd.github+json"
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", APIVersion)
	req.Header.Set("User-Agent", c.agent)
	req.Header.Set("Authorization", "Bearer "+k.secret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		// url.Error carries the URL (no credential in it) and the cause.
		return fmt.Errorf("gh: %s %s: %w", k.method, req.URL.EscapedPath(), scrub(err, k.secret))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("gh: %s %s: read response: %w", k.method, req.URL.EscapedPath(), scrub(err, k.secret))
	}
	if len(raw) > maxBody {
		return fmt.Errorf("gh: %s %s: response larger than %d bytes", k.method, req.URL.EscapedPath(), maxBody)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return c.apiError(k, req.URL.EscapedPath(), resp, raw)
	}
	if rb, ok := out.(*[]byte); ok { // a non-JSON answer (the diff media type): hand the bytes over as they are
		*rb = raw
		return nil
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("gh: %s %s: decode response: %w", k.method, req.URL.EscapedPath(), err)
	}
	return nil
}

func (c *Client) apiError(k call, path string, resp *http.Response, raw []byte) error {
	var eb struct {
		Message string            `json:"message"`
		DocURL  string            `json:"documentation_url"`
		Errors  []json.RawMessage `json:"errors"`
	}
	_ = json.Unmarshal(raw, &eb) // non-JSON bodies (HTML from a proxy) leave Message empty
	return &APIError{
		Method:    k.method,
		Path:      path,
		Status:    resp.StatusCode,
		Message:   clipText(eb.Message, k.secret, maxMessage),
		Errors:    fieldErrors(eb.Errors, k.secret),
		DocURL:    eb.DocURL,
		RequestID: resp.Header.Get("X-GitHub-Request-Id"),
		RateLimit: rateLimitOf(resp.StatusCode, resp.Header, eb.Message, c.now()),
	}
}

// fieldErrors reads GitHub's `errors` array of a 422: objects with resource,
// field, code and message, or (older answers) plain strings. At most
// maxFieldErrors are kept, each clipped, credentials scrubbed.
func fieldErrors(raw []json.RawMessage, secret string) []FieldError {
	var out []FieldError
	for _, r := range raw {
		if len(out) == maxFieldErrors {
			break
		}
		var o struct {
			Resource string `json:"resource"`
			Field    string `json:"field"`
			Code     string `json:"code"`
			Message  string `json:"message"`
		}
		var str string
		switch {
		case json.Unmarshal(r, &o) == nil:
		case json.Unmarshal(r, &str) == nil:
			o.Message = str
		default:
			continue
		}
		e := FieldError{
			Resource: clipText(o.Resource, secret, maxFieldPart), Field: clipText(o.Field, secret, maxFieldPart),
			Code: clipText(o.Code, secret, maxFieldPart), Message: clipText(o.Message, secret, maxMessage),
		}
		if e != (FieldError{}) {
			out = append(out, e)
		}
	}
	return out
}

// clipText makes GitHub-supplied text safe to show: the credential replaced,
// invalid UTF-8 and control characters removed, at most max bytes.
func clipText(s, secret string, max int) string {
	if secret != "" {
		s = strings.ReplaceAll(s, secret, "[redacted]")
	}
	s = strings.ToValidUTF8(s, "?")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > max {
		s = strings.ToValidUTF8(s[:max], "") + "..."
	}
	return s
}

// scrub removes a credential from a transport error's text, defensively. The
// cause stays reachable with errors.Is and errors.As.
func scrub(err error, secret string) error {
	if secret == "" || !strings.Contains(err.Error(), secret) {
		return err
	}
	return scrubbed{strings.ReplaceAll(err.Error(), secret, "[redacted]"), err}
}

type scrubbed struct {
	msg string
	err error
}

func (s scrubbed) Error() string { return s.msg }
func (s scrubbed) Unwrap() error { return s.err }

// asToken returns the call credential for an installation token.
func (c *Client) asToken(t *Token) (string, error) { return t.bearer(c.now()) }

// asApp signs a fresh App JWT.
func (c *Client) asApp(ctx context.Context) (string, error) {
	return appJWT(ctx, c.keys, c.appID, c.now())
}
