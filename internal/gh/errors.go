package gh

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Sentinels for errors.Is. Every GitHub refusal is an *APIError; match it by
// meaning with these, read the details with errors.As.
var (
	ErrUnauthorized         = errors.New("gh: unauthorized (401)")        // bad, expired or revoked credential
	ErrForbidden            = errors.New("gh: forbidden (403)")           // permission missing; not a rate limit
	ErrNotFound             = errors.New("gh: not found (404)")           // also what GitHub says for a repo the token does not cover
	ErrNotAllowed           = errors.New("gh: method not allowed (405)")  // merge refused: not mergeable, checks, base modified
	ErrConflict             = errors.New("gh: conflict (409)")            // head did not match `sha`, deployment conflict
	ErrUnprocessable        = errors.New("gh: unprocessable (422)")       // validation failed, update-branch head moved
	ErrServer               = errors.New("gh: GitHub server error (5xx)") //
	ErrRateLimited          = errors.New("gh: rate limited")              // primary or secondary; see APIError.RateLimit
	ErrSecondaryRateLimited = errors.New("gh: secondary rate limit")      // abuse / secondary limit only

	// Client-side refusals (no request was sent).
	ErrTokenExpired    = errors.New("gh: installation token expired")
	ErrTokenWiped      = errors.New("gh: token was wiped")
	ErrNotNarrowed     = errors.New("gh: minted token is broader than requested")
	ErrListTruncated   = errors.New("gh: GitHub list is incomplete")
	ErrInvalidArgument = errors.New("gh: invalid argument")
)

// RateLimit describes a refusal for rate limiting. The client never waits or
// retries; the caller owns that decision.
type RateLimit struct {
	// Secondary is true for GitHub's secondary (abuse) limit, false for the
	// primary hourly limit.
	Secondary bool
	// RetryAfter is the Retry-After header; zero if absent.
	RetryAfter time.Duration
	// Reset is X-RateLimit-Reset; zero if absent.
	Reset time.Time
	// Limit and Remaining are X-RateLimit-Limit and -Remaining; -1 if absent.
	Limit, Remaining int
	// Resource is X-RateLimit-Resource ("core", "search", ...); may be empty.
	Resource string
}

// APIError is a non-2xx answer from GitHub.
type APIError struct {
	Method    string
	Path      string // request path without query; never contains a credential
	Status    int
	Message   string       // GitHub's `message`, truncated, credentials scrubbed
	Errors    []FieldError // a 422's `errors[]`: what GitHub found wrong; same clean-up as Message
	DocURL    string
	RequestID string // X-GitHub-Request-Id, for support and the ledger
	RateLimit *RateLimit
}

// FieldError is one entry of the `errors` array GitHub sends with a 422.
type FieldError struct {
	Resource, Field, Code, Message string
}

func (f FieldError) String() string {
	var b strings.Builder
	b.WriteString(f.Resource)
	if f.Field != "" {
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.WriteString(f.Field)
	}
	if f.Code != "" {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(f.Code)
	}
	if f.Message != "" {
		if b.Len() > 0 {
			b.WriteString(": ")
		}
		b.WriteString(f.Message)
	}
	return b.String()
}

// Detail is GitHub's message followed by what it found wrong, for a person to
// read: `Validation Failed (PullRequest custom: not all refs are readable)`.
func (e *APIError) Detail() string {
	if len(e.Errors) == 0 {
		return e.Message
	}
	parts := make([]string, len(e.Errors))
	for i, f := range e.Errors {
		parts[i] = f.String()
	}
	return strings.TrimSpace(e.Message + " (" + strings.Join(parts, "; ") + ")")
}

func (e *APIError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "gh: %s %s: %d", e.Method, e.Path, e.Status)
	if d := e.Detail(); d != "" {
		b.WriteString(" ")
		b.WriteString(d)
	}
	if e.RateLimit != nil {
		kind := "primary"
		if e.RateLimit.Secondary {
			kind = "secondary"
		}
		fmt.Fprintf(&b, " (%s rate limit", kind)
		if e.RateLimit.RetryAfter > 0 {
			fmt.Fprintf(&b, ", retry after %s", e.RateLimit.RetryAfter)
		}
		if !e.RateLimit.Reset.IsZero() {
			fmt.Fprintf(&b, ", resets %s", e.RateLimit.Reset.UTC().Format(time.RFC3339))
		}
		b.WriteString(")")
	}
	if e.RequestID != "" {
		fmt.Fprintf(&b, " [request %s]", e.RequestID)
	}
	return b.String()
}

// Is matches the sentinels above.
func (e *APIError) Is(target error) bool {
	switch target {
	case ErrRateLimited:
		return e.RateLimit != nil
	case ErrSecondaryRateLimited:
		return e.RateLimit != nil && e.RateLimit.Secondary
	}
	if e.RateLimit != nil {
		return false // a 403/429 that is a rate limit is not "forbidden"
	}
	switch target {
	case ErrUnauthorized:
		return e.Status == http.StatusUnauthorized
	case ErrForbidden:
		return e.Status == http.StatusForbidden
	case ErrNotFound:
		return e.Status == http.StatusNotFound
	case ErrNotAllowed:
		return e.Status == http.StatusMethodNotAllowed
	case ErrConflict:
		return e.Status == http.StatusConflict
	case ErrUnprocessable:
		return e.Status == http.StatusUnprocessableEntity
	case ErrServer:
		return e.Status >= 500
	}
	return false
}

// rateLimitOf classifies a refusal. Evidence order: exhausted primary headers,
// then secondary signals (Retry-After, message text), then any 429.
func rateLimitOf(status int, h http.Header, msg string, now time.Time) *RateLimit {
	if status != http.StatusForbidden && status != http.StatusTooManyRequests {
		return nil
	}
	rl := &RateLimit{Limit: headerInt(h, "X-RateLimit-Limit"), Remaining: headerInt(h, "X-RateLimit-Remaining"),
		Resource: h.Get("X-RateLimit-Resource")}
	if v := headerInt(h, "X-RateLimit-Reset"); v >= 0 {
		rl.Reset = time.Unix(int64(v), 0)
	}
	if v := headerInt(h, "Retry-After"); v >= 0 {
		rl.RetryAfter = time.Duration(v) * time.Second
	} else if t, err := http.ParseTime(h.Get("Retry-After")); err == nil {
		rl.RetryAfter = max(0, t.Sub(now))
	}
	lower := strings.ToLower(msg)
	switch {
	case rl.Remaining == 0:
		return rl // primary exhausted
	case strings.Contains(lower, "secondary rate limit") || strings.Contains(lower, "abuse detection") || h.Get("Retry-After") != "":
		rl.Secondary = true
		return rl
	case strings.Contains(lower, "rate limit"):
		return rl
	case status == http.StatusTooManyRequests:
		return rl
	}
	return nil
}

func headerInt(h http.Header, k string) int {
	v := h.Get(k)
	if v == "" {
		return -1
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		return -1
	}
	return n
}
