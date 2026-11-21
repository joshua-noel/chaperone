package resend

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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/connectors/resend/resendspec"
	"github.com/joshua-noel/chaperone/internal/redact"
)

// APIBase is the one address the connector sends to. It is fixed: no policy
// file, no flag and no test sets another. A test reaches its fake through the
// HTTP client it gives the connector, which trusts the fake's certificate and
// sends every request to the fake, whatever host the URL names. Resend's
// documentation: "All requests contain the following base URL:
// https://api.resend.com" (API reference, Introduction).
const APIBase = "https://api.resend.com"

const (
	// userAgent is sent on every request: Resend rejects a request without a
	// User-Agent header with a 403 (API reference, Introduction).
	userAgent = "chapd-resend"
	// maxResponse is the most bytes of one answer the client reads.
	maxResponse = 1 << 20
	// maxErrorBody is the most bytes of an error answer the client reads. Only the
	// error's type word is taken from it.
	maxErrorBody = 16 << 10
	// IdempotencyPrefix goes before the execution id in the Idempotency-Key
	// header, so the key cannot meet a key that another program uses on the same
	// Resend account.
	IdempotencyPrefix = "chaperone-mail-send/"
	// maxIdempotencyKey is Resend's limit: a key has 1 to 256 characters
	// (API reference, Send Email, and Errors: invalid_idempotency_key).
	maxIdempotencyKey = 256
)

var (
	idemRE    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,200}$`)
	statusRE  = regexp.MustCompile(resendspec.StatusRefPattern)
	errCodeRE = regexp.MustCompile(`^[a-z][a-z_]{0,60}$`)
)

// IdempotencyKey returns the Idempotency-Key header for an execution id, or ""
// when the id is not one that makes a safe key. The key is derived from the
// execution id and from nothing else, so a repeat of one execution is the same
// key and two executions never are.
func IdempotencyKey(executionID string) string {
	if !idemRE.MatchString(executionID) {
		return ""
	}
	k := IdempotencyPrefix + executionID
	if len(k) > maxIdempotencyKey {
		return ""
	}
	return k
}

// Message is the one document the connector sends to POST /emails. It has the
// fields of a plain-text message and no others: no html, no attachments, no
// reply_to, no scheduled_at, no template, no tags and no headers. The adapter
// hashes [Message.JSON] for the approval card and the client sends the same
// bytes.
type Message struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Cc      []string `json:"cc,omitempty"`
	Bcc     []string `json:"bcc,omitempty"`
	Subject string   `json:"subject"`
	Text    string   `json:"text"`
}

// JSON returns the request body.
func (m Message) JSON() ([]byte, error) { return json.Marshal(m) }

// Email is what the client keeps of a retrieved email: four fields. Resend's
// answer also holds the subject, the body, the addresses and the tags; the
// client decodes none of them, so none can reach a result.
type Email struct {
	ID        string `json:"id"`
	From      string `json:"from"`
	LastEvent string `json:"last_event"`
	CreatedAt string `json:"created_at"`
}

// ErrNoSendKey and ErrNoStatusKey mean the vault holds no such secret.
var (
	ErrNoSendKey   = errors.New("resend: not connected; the vault has no resend-api-key (docs/runbooks/resend.md)")
	ErrNoStatusKey = errors.New("resend: mail.status is not available; the vault has no resend-status-key, which is optional and needs Resend's full_access permission (docs/runbooks/resend.md)")
)

// errUnreadable is a success answer that is not the JSON the client expects.
var errUnreadable = errors.New("resend: the answer is not the expected JSON")

// ErrTooLarge means an answer was bigger than the client reads.
var ErrTooLarge = errors.New("resend: the answer is too large to read")

// errorCodes is the closed list of error types Resend documents (API reference,
// Errors) that the connector tells apart. An error type that is not in it
// becomes "other": text from outside never reaches an error as it is.
var errorCodes = map[string]bool{
	"validation_error": true, "invalid_idempotency_key": true, "missing_api_key": true,
	"restricted_api_key": true, "invalid_permission": true, "suspended_api_key": true,
	"not_found": true, "method_not_allowed": true,
	"concurrent_idempotent_requests": true, "invalid_idempotent_request": true,
	"invalid_attachment": true, "invalid_parameter": true,
	"missing_required_field": true, "missing_required_parameter": true,
	"daily_quota_exceeded": true, "monthly_quota_exceeded": true, "rate_limit_exceeded": true,
	"email_above_quota": true, "application_error": true, "service_unavailable": true,
}

// APIError is an answer that is not a success. It holds the status, a word from
// the closed list [errorCodes] and, for a 429, the seconds to wait. It holds
// nothing Resend wrote: an error text from outside could hold anything,
// including what the client sent.
type APIError struct {
	Status     int
	Code       string
	RetryAfter int
}

func (e *APIError) Error() string {
	return fmt.Sprintf("resend: Resend answered HTTP %d (%s)", e.Status, e.Code)
}

// notSentError wraps a failure before any byte of the request left chapd.
type notSentError struct{ error }

func (e *notSentError) Unwrap() error { return e.error }

// Definite reports whether err certainly means Resend did not act: the request
// was never sent, or Resend refused it (a redirect, a client error, a rate limit).
// A timeout, a cut connection, a 5xx, an unreadable answer and a 409 are not
// definite. A 409 is Resend's idempotency answer: it says an earlier request
// with the same key is, or was, in the system, so a message may have gone.
func Definite(err error) bool {
	var ns *notSentError
	var ae *APIError
	switch {
	case errors.As(err, &ns), errors.Is(err, ErrNoSendKey), errors.Is(err, ErrNoStatusKey):
		return true
	case errors.As(err, &ae):
		return ae.Status >= 300 && ae.Status < 500 && ae.Status != http.StatusRequestTimeout && ae.Status != http.StatusConflict
	}
	return false
}

// ClientConfig builds a [Client].
type ClientConfig struct {
	// SendKey returns the API key that sends mail. It should be a key with
	// Resend's sending_access permission, restricted to one domain. It is
	// called on every send, so a rotated secret is picked up, and the client
	// keeps no copy. [VaultCredential] reads it from the vault.
	SendKey func(ctx context.Context) (string, error)
	// StatusKey returns the optional API key that reads one email. Resend gives
	// a sending_access key no read at all, so this key needs full_access. nil
	// means mail.status is not available. It is never used to send.
	StatusKey func(ctx context.Context) (string, error)
	// Registry, when set, learns each key the client uses, so the redaction
	// check masks it wherever it would appear.
	Registry *redact.Registry
	// HTTP defaults to a client with a 30 s timeout. It never follows a
	// redirect, whatever the client given: a redirect could carry a key to
	// another host.
	HTTP *http.Client
}

// Client sends the connector's fixed requests to [APIBase]. It has no method
// that takes a URL, a path or a header from outside this package.
type Client struct {
	cfg ClientConfig
	hc  *http.Client
}

// NewClient validates cfg and returns a Client.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.SendKey == nil {
		return nil, errors.New("resend: the client needs a SendKey")
	}
	hc := cfg.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	// Never follow a redirect: it could carry the key to another host.
	c := *hc
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{cfg: cfg, hc: &c}, nil
}

// HasStatusKey reports whether the client was given a way to read the status
// key. It says nothing about the vault.
func (c *Client) HasStatusKey() bool { return c.cfg.StatusKey != nil }

// key reads one key, trimmed, and registers it with the redaction check.
func (c *Client) key(ctx context.Context, read func(context.Context) (string, error), redactID string, missing error) (string, error) {
	if read == nil {
		return "", &notSentError{missing}
	}
	tok, err := read(ctx)
	if err != nil {
		if errors.Is(err, missing) {
			return "", &notSentError{missing}
		}
		return "", &notSentError{errors.New("resend: the API key could not be read from the vault")}
	}
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return "", &notSentError{missing}
	}
	if c.cfg.Registry != nil {
		// Every call: the registry may have been cleared since, and a key that is
		// not registered would reach a log unmasked.
		if err := c.cfg.Registry.Set(redactID, []byte(tok)); err != nil {
			return "", &notSentError{errors.New("resend: the API key cannot be registered with the redaction check")}
		}
	}
	return tok, nil
}

// SendReady reads the sending key and nothing else, so Check can refuse before a
// card is made when the vault has none. It sends nothing.
func (c *Client) SendReady(ctx context.Context) error {
	_, err := c.key(ctx, c.cfg.SendKey, redactSendKey, ErrNoSendKey)
	return err
}

// StatusReady is [Client.SendReady] for the status key.
func (c *Client) StatusReady(ctx context.Context) error {
	_, err := c.key(ctx, c.cfg.StatusKey, redactStatusKey, ErrNoStatusKey)
	return err
}

// Send posts one message. key is the Idempotency-Key header: use
// [IdempotencyKey] of the execution id. It returns the id Resend gave the
// message, as Resend wrote it: the adapter cleans it. The message is sent at
// most once by this method; it never retries.
//
// Resend keeps an idempotency key for 24 hours (API reference, Send Email; Idempotency
// Keys). Within that time a second request with the same key and the same body
// returns the first answer and sends nothing. After it the key is forgotten and a
// second request would send again.
func (c *Client) Send(ctx context.Context, m Message, key string) (string, error) {
	if key == "" {
		return "", &notSentError{errors.New("resend: there is no idempotency key")}
	}
	body, err := m.JSON()
	if err != nil {
		return "", &notSentError{errors.New("resend: the request body could not be built")}
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, "/emails", c.cfg.SendKey, redactSendKey, ErrNoSendKey, body, key, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// Email reads one email with the status key.
func (c *Client) Email(ctx context.Context, id string) (Email, error) {
	if !statusRE.MatchString(id) {
		return Email{}, &notSentError{errors.New("resend: the email id is not a UUID")}
	}
	var e Email
	err := c.do(ctx, http.MethodGet, "/emails/"+id, c.cfg.StatusKey, redactStatusKey, ErrNoStatusKey, nil, "", &e)
	return e, err
}

// do sends one request. The key goes in the Authorization header and nowhere
// else. Every error is a fixed sentence or an [APIError]: none holds the key, the
// URL or text Resend wrote. On success it decodes the JSON answer into out.
func (c *Client) do(ctx context.Context, method, path string, read func(context.Context) (string, error), redactID string, missing error, body []byte, idemKey string, out any) error {
	tok, err := c.key(ctx, read, redactID, missing)
	if err != nil {
		return err
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, APIBase+path, rd)
	if err != nil {
		return &notSentError{errors.New("resend: the request could not be built")}
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if idemKey != "" {
		req.Header.Set("Idempotency-Key", idemKey)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return transportError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return apiError(resp)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return errors.New("resend: the answer could not be read in full")
	}
	if len(data) > maxResponse {
		return ErrTooLarge
	}
	if err := json.Unmarshal(data, out); err != nil {
		return errUnreadable
	}
	return nil
}

// apiError makes the error of a non-success answer. It reads the type word of
// Resend's error body, and only that, and keeps it only when it is on the closed
// list.
func apiError(resp *http.Response) error {
	e := &APIError{Status: resp.StatusCode, Code: "other"}
	var b struct {
		Name string `json:"name"`
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	if json.Unmarshal(data, &b) == nil && errCodeRE.MatchString(b.Name) && errorCodes[b.Name] {
		e.Code = b.Name
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		if s, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && s > 0 && s <= 86400 {
			e.RetryAfter = s
		}
	}
	return e
}

// transportError turns a failure of the HTTP round trip into a fixed sentence. A
// failure before the request was written (no connection, a certificate that does
// not verify) is not sent; anything else leaves a write unknown.
func transportError(err error) error {
	var op *net.OpError
	var cert *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	switch {
	case errors.As(err, &cert), errors.As(err, &unknown):
		return &notSentError{errors.New("resend: the server's certificate does not verify")}
	case errors.As(err, &op) && op.Op == "dial":
		return &notSentError{errors.New("resend: the server could not be reached")}
	}
	return errors.New("resend: the server could not be reached, or did not answer in time")
}
