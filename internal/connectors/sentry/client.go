package sentry

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/connectors/sentry/sentryspec"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/redact"
)

// maxResponse is the most bytes of one answer the client reads. An event with a
// long stack and many breadcrumbs is a few hundred kilobytes.
const maxResponse = 4 << 20

const apiPrefix = "/api/0"

var (
	issueIDRE = regexp.MustCompile(sentryspec.IssueRefPattern)
	slugRE    = policy.SentrySlugRE()
)

// ErrNotFound is Sentry's "no such thing", also what it answers for an object
// that the token cannot see.
var ErrNotFound = errors.New("sentry: Sentry has no such item that the token can see")

// errUnreadable is a success answer that is not the JSON the client expects.
var errUnreadable = errors.New("sentry: the answer is not the expected JSON")

// ServiceError is an answer that is not a success. It holds the status and
// nothing Sentry wrote: an error text from outside could hold anything,
// including what the client sent.
type ServiceError struct{ Status int }

func (e *ServiceError) Error() string {
	if e.Status >= 300 && e.Status < 400 {
		return fmt.Sprintf("sentry: the server answered HTTP %d, a redirect; chapd does not follow redirects, so check base_url in the project's sentry block (docs/runbooks/sentry.md)", e.Status)
	}
	return fmt.Sprintf("sentry: the server answered HTTP %d", e.Status)
}

// AuthError is Sentry's refusal of the token (401) or of the request for lack of
// a scope or a role (403).
type AuthError struct{ Status int }

func (e *AuthError) Error() string {
	return fmt.Sprintf("sentry: the server refused the auth token (HTTP %d); check the vault secret and its scopes (docs/runbooks/sentry.md)", e.Status)
}

// RateLimitError means Sentry refused a call because a rate limit is used up.
// It had no effect.
type RateLimitError struct{ RetryAfter time.Duration }

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("sentry: the server's rate limit is used up; retry in %d s", int(e.RetryAfter.Round(time.Second)/time.Second))
}

// notSentError wraps a failure before any byte of the request left chapd.
type notSentError struct{ error }

func (e *notSentError) Unwrap() error { return e.error }

// Definite reports whether err certainly means Sentry did not act: the request
// was never sent, or Sentry refused it (a redirect, a 4xx, a rate limit). A
// timeout, a cut connection, a 5xx or an unreadable answer is not definite: for
// a write the outcome is unknown.
func Definite(err error) bool {
	var ns *notSentError
	var se *ServiceError
	var ae *AuthError
	var rl *RateLimitError
	switch {
	case errors.As(err, &ns), errors.As(err, &ae), errors.As(err, &rl), errors.Is(err, ErrNotFound), errors.Is(err, ErrNotConnected):
		return true
	case errors.As(err, &se):
		return se.Status >= 300 && se.Status < 500 && se.Status != http.StatusRequestTimeout
	}
	return false
}

// Scope is where a request goes: the Sentry server and the organisation. It is
// resolved once from the project's policy and used for every call of one
// request, so a read and the write after it go to the same place.
type Scope struct {
	BaseURL string
	Org     string
}

// ClientConfig builds a [Client].
type ClientConfig struct {
	// Credential returns the auth token. It is called on every request, so a
	// rotated secret is picked up, and the client keeps no copy. [VaultCredential]
	// reads it from the vault.
	Credential func(ctx context.Context) (string, error)
	// Registry, when set, learns the token the client uses, so the redaction
	// check masks it wherever it would appear.
	Registry *redact.Registry
	// HTTP defaults to a client with a 20 s timeout. It never follows a
	// redirect, whatever the client given.
	HTTP *http.Client
}

// Client sends the connector's fixed requests. It has no method that takes a
// URL, a path or a query from outside this package: each method takes values
// that the adapter has checked, and checks their shape again.
type Client struct {
	cfg ClientConfig
	hc  *http.Client
}

// NewClient validates cfg and returns a Client.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Credential == nil {
		return nil, errors.New("sentry: the client needs a Credential")
	}
	hc := cfg.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	// Never follow a redirect: it could carry the bearer token to another host.
	c := *hc
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{cfg: cfg, hc: &c}, nil
}

// base checks the scope and returns the base URL. The base URL must pass the
// policy's own rule: an https origin with an exact DNS host name. There is no
// exception for a test: a test client reaches a fake by its HTTP client.
func (c *Client) base(s Scope) (string, error) {
	if !slugRE.MatchString(s.Org) {
		return "", &notSentError{errors.New("sentry: the organisation is not a slug")}
	}
	if err := policy.CheckSentryBaseURL(s.BaseURL); err != nil {
		return "", &notSentError{errors.New("sentry: the base URL is not an https origin with an exact host name")}
	}
	return s.BaseURL, nil
}

// do sends one request. The token goes in the Authorization header and nowhere
// else. Every error is a fixed sentence: none holds the token, the URL or text
// Sentry wrote. On success it decodes the JSON answer into out (when set) and
// returns the answer's headers.
func (c *Client) do(ctx context.Context, method string, s Scope, path string, q url.Values, body, out any) (http.Header, error) {
	base, err := c.base(s)
	if err != nil {
		return nil, err
	}
	u := base + apiPrefix + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, &notSentError{errors.New("sentry: the request body could not be built")}
		}
		rd = bytes.NewReader(b)
	}
	tok, err := c.cfg.Credential(ctx)
	if err != nil {
		if errors.Is(err, ErrNotConnected) {
			return nil, &notSentError{ErrNotConnected}
		}
		return nil, &notSentError{errors.New("sentry: the auth token could not be read from the vault")}
	}
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return nil, &notSentError{ErrNotConnected}
	}
	if c.cfg.Registry != nil {
		// Every call: the registry may have been cleared since, and a token that is not
		// registered would reach a log unmasked.
		if err := c.cfg.Registry.Set(redactID, []byte(tok)); err != nil {
			return nil, &notSentError{errors.New("sentry: the auth token cannot be registered with the redaction check")}
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, &notSentError{errors.New("sentry: the request could not be built")}
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "chapd-sentry")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, transportError(err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode <= 299:
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return nil, &AuthError{Status: resp.StatusCode}
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrNotFound
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, &RateLimitError{RetryAfter: retryAfter(resp.Header)}
	default:
		return nil, &ServiceError{Status: resp.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil || len(data) > maxResponse {
		return resp.Header, errTooLarge(err)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.Header, errUnreadable
		}
	}
	return resp.Header, nil
}

// errTooLarge is the error of an answer that was cut short or is too big.
func errTooLarge(read error) error {
	if read != nil {
		return errors.New("sentry: the answer could not be read in full")
	}
	return ErrTooLarge
}

// ErrTooLarge means an answer was bigger than the client reads.
var ErrTooLarge = errors.New("sentry: the answer is too large to read")

// transportError turns a failure of the HTTP round trip into a fixed sentence. A
// failure before the request was written (no connection, a certificate that does
// not verify) is not sent; anything else leaves a write unknown.
func transportError(err error) error {
	var op *net.OpError
	var cert *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	switch {
	case errors.As(err, &cert), errors.As(err, &unknown):
		return &notSentError{errors.New("sentry: the server's certificate does not verify")}
	case errors.As(err, &op) && op.Op == "dial":
		return &notSentError{errors.New("sentry: the server could not be reached")}
	}
	return errors.New("sentry: the server could not be reached, or did not answer in time")
}

func retryAfter(h http.Header) time.Duration {
	if s, err := strconv.Atoi(strings.TrimSpace(h.Get("Retry-After"))); err == nil && s > 0 && s <= 3600 {
		return time.Duration(s) * time.Second
	}
	return time.Minute
}

// ---- what Sentry sends back --------------------------------------------------
//
// Each type below lists the fields chapd reads and no others. encoding/json
// drops every field that is not listed, so what an event or an issue carries
// beyond them (request bodies, cookies, headers, user data, local variables,
// tags, breadcrumbs, the exception's message) is not kept. The answer itself is
// read into memory whole, up to the cap, while it is decoded.

// numString reads a JSON string or number as text.
type numString string

func (n *numString) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch x := v.(type) {
	case string:
		*n = numString(x)
	case float64:
		*n = numString(strconv.FormatFloat(x, 'f', -1, 64))
	case nil:
	default:
		return errors.New("not a string or a number")
	}
	return nil
}

// Issue is the part of a Sentry issue the connector reads.
type Issue struct {
	ID        string    `json:"id"`
	ShortID   string    `json:"shortId"`
	Title     string    `json:"title"`
	Culprit   string    `json:"culprit"`
	Level     string    `json:"level"`
	Status    string    `json:"status"`
	Count     numString `json:"count"`
	FirstSeen string    `json:"firstSeen"`
	LastSeen  string    `json:"lastSeen"`
	Project   struct {
		Slug string `json:"slug"`
	} `json:"project"`
	AssignedTo *struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"assignedTo"`
}

// ListParams are the filters of ListIssues. Each value was checked against a
// closed pattern by the adapter.
type ListParams struct {
	Status, Level, Cursor string
	Limit                 int
}

// IssuePage is one page of issues and the cursor of the next, when Sentry says
// there is one.
type IssuePage struct {
	Issues []Issue
	Next   string
}

var nextCursorRE = regexp.MustCompile(`rel="next";\s*results="true";\s*cursor="([^"]{1,64})"`)

// ListIssues reads one page of a project's issues. The search query is built
// from the closed words of the params; no caller text is in it.
func (c *Client) ListIssues(ctx context.Context, s Scope, project string, p ListParams) (IssuePage, error) {
	if !slugRE.MatchString(project) {
		return IssuePage{}, &notSentError{errors.New("sentry: the project is not a slug")}
	}
	query := "is:" + p.Status
	if p.Level != "" {
		query += " level:" + p.Level
	}
	q := url.Values{"query": {query}, "limit": {strconv.Itoa(p.Limit)}}
	if p.Cursor != "" {
		q.Set("cursor", p.Cursor)
	}
	var issues []Issue
	h, err := c.do(ctx, http.MethodGet, s, "/projects/"+url.PathEscape(s.Org)+"/"+url.PathEscape(project)+"/issues/", q, nil, &issues)
	if err != nil {
		return IssuePage{}, err
	}
	page := IssuePage{Issues: issues}
	if m := nextCursorRE.FindStringSubmatch(strings.Join(h.Values("Link"), ", ")); m != nil {
		page.Next = m[1]
	}
	return page, nil
}

func issuePath(s Scope, id string) (string, error) {
	if !issueIDRE.MatchString(id) {
		return "", &notSentError{errors.New("sentry: the issue id is not a number")}
	}
	return "/organizations/" + url.PathEscape(s.Org) + "/issues/" + id + "/", nil
}

// GetIssue reads one issue.
func (c *Client) GetIssue(ctx context.Context, s Scope, id string) (Issue, error) {
	path, err := issuePath(s, id)
	if err != nil {
		return Issue{}, err
	}
	var is Issue
	_, err = c.do(ctx, http.MethodGet, s, path, nil, nil, &is)
	return is, err
}

// Frame is one stack frame, as much of it as the connector reads: where, not
// what the variables held.
type Frame struct {
	File     string
	Function string
	Line     int
	InApp    bool
}

// EventSummary is the essentials of an issue's latest event. The rest of the
// event is not kept.
type EventSummary struct {
	ID            string
	Date          string
	ExceptionType string
	// Frames are the frames of the exception that was raised, innermost first.
	Frames []Frame
}

// excData is the part of an exception entry the connector reads. The exception's
// message ("value") is not in it.
type excData struct {
	Values []struct {
		Type       string `json:"type"`
		Stacktrace *struct {
			Frames []struct {
				Filename string `json:"filename"`
				Function string `json:"function"`
				LineNo   *int   `json:"lineNo"`
				InApp    bool   `json:"inApp"`
			} `json:"frames"`
		} `json:"stacktrace"`
	} `json:"values"`
}

// eventEntry is one element of an event's entries. Only an exception entry is
// kept; for any other kind (request, breadcrumbs, and the rest) the decoder reads
// the type, sees that it is not an exception, and keeps nothing of the entry.
type eventEntry struct{ exc *excData }

func (e *eventEntry) UnmarshalJSON(b []byte) error {
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return err
	}
	if head.Type != "exception" {
		return nil
	}
	var full struct {
		Data excData `json:"data"`
	}
	if err := json.Unmarshal(b, &full); err != nil {
		return err
	}
	e.exc = &full.Data
	return nil
}

// LatestEvent reads the issue's latest event and keeps its essentials: the id,
// the time, and the type and stack frames of the exception. ErrNotFound means
// the issue has no event. The answer is read into memory whole, up to the cap,
// while it is decoded, and dropped after; what is kept is the listed fields.
func (c *Client) LatestEvent(ctx context.Context, s Scope, id string) (EventSummary, error) {
	path, err := issuePath(s, id)
	if err != nil {
		return EventSummary{}, err
	}
	var ev struct {
		EventID     string       `json:"eventID"`
		DateCreated string       `json:"dateCreated"`
		Entries     []eventEntry `json:"entries"`
	}
	if _, err := c.do(ctx, http.MethodGet, s, path+"events/latest/", nil, nil, &ev); err != nil {
		return EventSummary{}, err
	}
	sum := EventSummary{ID: ev.EventID, Date: ev.DateCreated}
	for _, e := range ev.Entries {
		if e.exc == nil || len(e.exc.Values) == 0 {
			continue
		}
		// The values run from the oldest exception to the one that was raised.
		raised := e.exc.Values[len(e.exc.Values)-1]
		sum.ExceptionType = raised.Type
		if raised.Stacktrace != nil {
			// The frames run from the outermost call to the innermost.
			fr := raised.Stacktrace.Frames
			for i := len(fr) - 1; i >= 0 && len(sum.Frames) < maxFramesRead; i-- {
				f := Frame{File: fr[i].Filename, Function: fr[i].Function, InApp: fr[i].InApp}
				if fr[i].LineNo != nil {
					f.Line = *fr[i].LineNo
				}
				sum.Frames = append(sum.Frames, f)
			}
		}
		break
	}
	return sum, nil
}

// maxFramesRead is how many frames the client keeps of an event: one more than
// the adapter shows, so the adapter can say that the stack was cut.
const maxFramesRead = maxFrames + 1

// SetStatus sets an issue's status to "resolved" or "unresolved" and returns the
// issue as Sentry answers.
func (c *Client) SetStatus(ctx context.Context, s Scope, id, status string) (Issue, error) {
	if status != "resolved" && status != "unresolved" {
		return Issue{}, &notSentError{errors.New("sentry: the status is not one the connector sets")}
	}
	return c.put(ctx, s, id, map[string]any{"status": status})
}

// Assign sets an issue's assignee. to is a member of the policy's list.
func (c *Client) Assign(ctx context.Context, s Scope, id, to string) (Issue, error) {
	return c.put(ctx, s, id, map[string]any{"assignedTo": to})
}

func (c *Client) put(ctx context.Context, s Scope, id string, body map[string]any) (Issue, error) {
	path, err := issuePath(s, id)
	if err != nil {
		return Issue{}, err
	}
	var is Issue
	_, err = c.do(ctx, http.MethodPut, s, path, nil, body, &is)
	return is, err
}

// Note is what Sentry answers for a new note.
type Note struct {
	ID numString `json:"id"`
}

// Comment adds a note to an issue. Sentry has no key that makes a repeat safe:
// the caller sends this once.
func (c *Client) Comment(ctx context.Context, s Scope, id, text string) (Note, error) {
	path, err := issuePath(s, id)
	if err != nil {
		return Note{}, err
	}
	var n Note
	_, err = c.do(ctx, http.MethodPost, s, path+"comments/", nil, map[string]any{"text": text}, &n)
	return n, err
}
