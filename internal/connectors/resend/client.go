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

// ErrMalformedKey means the stored key holds a byte that no API key holds.
var ErrMalformedKey = errors.New("resend: the stored API key is malformed (it holds a character outside printable ASCII, such as a line break); import resend-api-key again (docs/runbooks/resend.md)")

// ErrNoSendKey means the vault holds no sending key.
var ErrNoSendKey = errors.New("resend: not connected; the vault has no resend-api-key (docs/runbooks/resend.md)")

// errUnreadable is a success answer that is not the JSON the client expects.
var errUnreadable = errors.New("resend: the answer is not the expected JSON")

// ErrTooLarge means an answer was bigger than the client reads.
var ErrTooLarge = errors.New("resend: the answer is too large to read")

var errorCodes = map[string]bool{
	"validation_error": true, "invalid_idempotency_key": true, "missing_api_key": true,
	"restricted_api_key": true, "invalid_permission": true, "suspended_api_key": true,
	"not_found": true, "method_not_allowed": true,
	"concurrent_idempotent_requests": true, "invalid_idempotent_request": true,
	"invalid_attachment": true, "invalid_parameter": true,
	"missing_required_field": true, "missing_required_parameter": true,
	"daily_quota_exceeded": true, "monthly_quota_exceeded": true, "rate_limit_exceeded": true,
	"email_above_quota": true, "application_error": true, "service_unavailable": true,
	"resource_locked": true, "dns_lookup_failed": true, "invalid_api_key": true, "invalid_from_address": true,
	"invalid_access": true, "invalid_region": true, "security_error": true, "internal_server_error": true,
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
	case errors.As(err, &ns), errors.Is(err, ErrNoSendKey):
		return true
	case errors.As(err, &ae):
		return ae.Status >= 300 && ae.Status < 500 && ae.Status != http.StatusRequestTimeout && ae.Status != http.StatusConflict
	}
	return false
}

// ClientConfig builds a [Client].
type ClientConfig struct {
	// SendKey returns the API key that sends mail: a key with Resend's
	// sending_access permission, restricted to one domain. It is the only secret the
	// connector reads. It is called on every send, so a rotated secret is picked up,
	// and the client keeps no copy. [VaultCredential] reads it from the vault.
	SendKey func(ctx context.Context) (string, error)

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

// key reads the sending key, trimmed, and registers it with the redaction check.
func (c *Client) key(ctx context.Context) (string, error) {
	tok, err := c.cfg.SendKey(ctx)
	if err != nil {
		if errors.Is(err, ErrNoSendKey) {
			return "", &notSentError{ErrNoSendKey}
		}
		return "", &notSentError{errors.New("resend: the API key could not be read from the vault")}
	}
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return "", &notSentError{ErrNoSendKey}
	}
	// A key is printable ASCII, `!` to `~`, and nothing else: a newline, a NUL or any
	// other byte in a header value is refused by Go before anything is written, which
	// would otherwise read as a send that may have gone. Refuse it here, as not sent.
	for i := 0; i < len(tok); i++ {
		if tok[i] < '!' || tok[i] > '~' {
			return "", &notSentError{ErrMalformedKey}
		}
	}
	if c.cfg.Registry != nil {
		// Every call: the registry may have been cleared since, and a key that is
		// not registered would reach a log unmasked.
		if err := c.cfg.Registry.Set(redactSendKey, []byte(tok)); err != nil {
			return "", &notSentError{errors.New("resend: the API key cannot be registered with the redaction check")}
		}
	}
	return tok, nil
}

// SendReady reads the sending key and nothing else, so Check can refuse before a
// card is made when the vault has none. It sends nothing.
func (c *Client) SendReady(ctx context.Context) error {
	_, err := c.key(ctx)
	return err
}

// sendPath is the one route the client calls: POST /emails. There is no other
// request in this file, and no method takes a path.
const sendPath = "/emails"

// Send posts one message. key is the Idempotency-Key header: use
// [IdempotencyKey] of the execution id. It returns the id Resend gave the
// message, as Resend wrote it: the adapter cleans it. This method makes one call and
// does not retry. Go's HTTP transport, below it, may replay the identical request
// (same body, same Idempotency-Key) once if a warm keep-alive connection drops after
// the server took the message; Resend then sees one key and sends one message. That is
// why the key is sent on every send: it is what makes the replay safe.
//
// Resend keeps an idempotency key for 24 hours (API reference, Send Email; Idempotency
// Keys). Within that time a second request with the same key and the same body
// returns the first answer and sends nothing. After it the key is forgotten and a
// second request would send again.
//
// The key goes in the Authorization header and nowhere else. Every error is a fixed
// sentence or an [APIError]: none holds the key, the URL or text Resend wrote.
func (c *Client) Send(ctx context.Context, m Message, idemKey string) (string, error) {
	if idemKey == "" {
		return "", &notSentError{errors.New("resend: there is no idempotency key")}
	}
	body, err := m.JSON()
	if err != nil {
		return "", &notSentError{errors.New("resend: the request body could not be built")}
	}
	tok, err := c.key(ctx)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, APIBase+sendPath, bytes.NewReader(body))
	if err != nil {
		return "", &notSentError{errors.New("resend: the request could not be built")}
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", idemKey)
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", transportError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", apiError(resp)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return "", errors.New("resend: the answer could not be read in full")
	}
	if len(data) > maxResponse {
		return "", ErrTooLarge
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", errUnreadable
	}
	return out.ID, nil
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
