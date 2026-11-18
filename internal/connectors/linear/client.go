package linear

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxAPIResponse = 4 << 20
	// DefaultHourlyBudget is the most GraphQL calls chapd makes in any 60
	// minutes. Linear allows an OAuth app 5 000 requests an hour; a poll every
	// 15 minutes and a few ops a day use a small part of 300.
	DefaultHourlyBudget = 300
	// lowWater is the number of requests Linear says remain at which chapd stops
	// sending until Linear's window resets.
	lowWater = 20
	// defaultRetryAfter is how long chapd stops after a rate-limit answer that
	// names no time.
	defaultRetryAfter = time.Minute
)

// RateLimitError means a call was not sent, or Linear refused it, because a
// rate limit is used up. Either way it had no effect.
type RateLimitError struct {
	RetryAfter time.Duration
	// Local is true when chapd's own hourly budget stopped the call.
	Local bool
}

func (e *RateLimitError) Error() string {
	who := "Linear's"
	if e.Local {
		who = "chapd's own hourly Linear"
	}
	return fmt.Sprintf("linear: %s rate limit is used up; retry in %d s", who, int(e.RetryAfter.Round(time.Second)/time.Second))
}

// GraphQLError is Linear's refusal of a document: it was understood and not
// carried out. Linear's mutations are atomic, so it had no effect.
type GraphQLError struct {
	Code    string // extensions.code ("INVALID_INPUT")
	Message string // clipped, control characters removed
}

func (e *GraphQLError) Error() string {
	if e.Code == "" {
		return "linear: " + e.Message
	}
	return "linear: " + e.Code + ": " + e.Message
}

// HTTPError is an answer that is not a GraphQL answer.
type HTTPError struct{ Status int }

func (e *HTTPError) Error() string { return fmt.Sprintf("linear: the API answered HTTP %d", e.Status) }

// notSentError wraps a failure before any byte went to Linear.
type notSentError struct{ error }

func (e *notSentError) Unwrap() error { return e.error }

// ErrNotFound is returned when Linear has no such issue.
var ErrNotFound = errors.New("linear: no such issue")

// Definite reports whether err certainly means Linear did not act: the call was
// never sent, Linear refused it (a GraphQL error, a rate limit, a 4xx), or
// chapd's own checks refused it. A timeout, a cut connection or a 5xx is not
// definite: for a mutation the outcome is unknown.
func Definite(err error) bool {
	var ns *notSentError
	var gq *GraphQLError
	var rl *RateLimitError
	var he *HTTPError
	switch {
	case errors.As(err, &ns), errors.As(err, &gq), errors.As(err, &rl), errors.Is(err, ErrNotFound):
		return true
	case errors.As(err, &he):
		return he.Status >= 400 && he.Status < 500 && he.Status != http.StatusRequestTimeout
	}
	return false
}

// ClientConfig builds a [Client].
type ClientConfig struct {
	Endpoints Endpoints
	Tokens    *TokenSource
	HTTP      *http.Client
	// HourlyBudget is the most calls in any 60 minutes; zero means
	// [DefaultHourlyBudget].
	HourlyBudget int
	Now          func() time.Time
}

// Client sends the connector's fixed GraphQL documents. It has no method that
// takes a document from outside this package.
type Client struct {
	cfg ClientConfig

	mu      sync.Mutex
	sent    []time.Time // calls in the last hour, oldest first
	blocked time.Time   // Linear asked us to wait until this time
	calls   int         // total calls sent (tests and status)
}

// NewClient returns a Client.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Tokens == nil {
		return nil, errors.New("linear: the client needs a token source")
	}
	if err := cfg.Endpoints.Validate(); err != nil {
		return nil, err
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	// Never follow a redirect: it could carry the bearer token to another host.
	hc := *cfg.HTTP
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	cfg.HTTP = &hc
	if cfg.HourlyBudget <= 0 {
		cfg.HourlyBudget = DefaultHourlyBudget
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Client{cfg: cfg}, nil
}

// Calls is the number of GraphQL calls sent so far.
func (c *Client) Calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// reserve counts one call against the budget and the pause Linear asked for.
func (c *Client) reserve() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.cfg.Now()
	if now.Before(c.blocked) {
		return &RateLimitError{RetryAfter: c.blocked.Sub(now)}
	}
	cut := now.Add(-time.Hour)
	i := 0
	for i < len(c.sent) && !c.sent[i].After(cut) {
		i++
	}
	c.sent = c.sent[i:]
	if len(c.sent) >= c.cfg.HourlyBudget {
		return &RateLimitError{RetryAfter: c.sent[0].Add(time.Hour).Sub(now), Local: true}
	}
	c.sent = append(c.sent, now)
	c.calls++
	return nil
}

func (c *Client) block(d time.Duration) {
	if d <= 0 {
		d = defaultRetryAfter
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if until := c.cfg.Now().Add(d); until.After(c.blocked) {
		c.blocked = until
	}
}

// noteLimits reads Linear's rate-limit headers: when few requests remain, stop
// sending until the window resets.
func (c *Client) noteLimits(h http.Header) {
	rem, err := strconv.Atoi(strings.TrimSpace(h.Get("X-RateLimit-Requests-Remaining")))
	if err != nil || rem > lowWater {
		return
	}
	wait := defaultRetryAfter
	if ms, err := strconv.ParseInt(strings.TrimSpace(h.Get("X-RateLimit-Requests-Reset")), 10, 64); err == nil && ms > 0 {
		if d := time.UnixMilli(ms).Sub(c.cfg.Now()); d > 0 && d < time.Hour {
			wait = d
		}
	}
	c.block(wait)
}

// do sends one fixed document. name is the GraphQL operation name. vars are
// built by this package from validated values. A 401 (or Linear's
// authentication error) gets one new token and one resend: Linear refused the
// token before doing anything, so the resend is safe even for a mutation.
func (c *Client) do(ctx context.Context, name, query string, vars map[string]any, out any) error {
	payload, err := json.Marshal(map[string]any{"operationName": name, "query": query, "variables": vars})
	if err != nil {
		return err
	}
	for attempt := 0; ; attempt++ {
		if err := c.reserve(); err != nil {
			return &notSentError{err}
		}
		tok, err := c.cfg.Tokens.Token(ctx, attempt > 0)
		if err != nil {
			return &notSentError{err}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Endpoints.API, bytes.NewReader(payload))
		if err != nil {
			return &notSentError{err}
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		resp, err := c.cfg.HTTP.Do(req)
		if err != nil {
			return fmt.Errorf("linear: %s: %w", name, stripURL(err))
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponse+1))
		resp.Body.Close()
		c.noteLimits(resp.Header)

		if resp.StatusCode == http.StatusTooManyRequests {
			after := retryAfter(resp.Header)
			c.block(after)
			return &RateLimitError{RetryAfter: after}
		}
		var env struct {
			Data   json.RawMessage `json:"data"`
			Errors []struct {
				Message    string `json:"message"`
				Extensions struct {
					Code string `json:"code"`
					Type string `json:"type"`
				} `json:"extensions"`
			} `json:"errors"`
		}
		jerr := json.Unmarshal(body, &env)
		if jerr == nil && len(env.Errors) > 0 {
			e := env.Errors[0]
			code := e.Extensions.Code
			switch {
			case code == "RATELIMITED":
				after := retryAfter(resp.Header)
				c.block(after)
				return &RateLimitError{RetryAfter: after}
			case resp.StatusCode == http.StatusUnauthorized || code == "AUTHENTICATION_ERROR" || strings.Contains(strings.ToLower(e.Extensions.Type), "authentication"):
				if attempt == 0 {
					c.cfg.Tokens.Invalidate()
					continue
				}
				return &GraphQLError{Code: "AUTHENTICATION_ERROR", Message: "Linear does not accept the token chapd minted; check the OAuth app and its secrets (docs/runbooks/linear-intake.md)"}
			}
			return &GraphQLError{Code: clip(code, 60), Message: clip(e.Message, 300)}
		}
		if resp.StatusCode == http.StatusUnauthorized {
			if attempt == 0 {
				c.cfg.Tokens.Invalidate()
				continue
			}
			return &HTTPError{Status: resp.StatusCode}
		}
		if resp.StatusCode/100 != 2 {
			return &HTTPError{Status: resp.StatusCode}
		}
		if rerr != nil || len(body) > maxAPIResponse {
			// The call went through; the answer was cut short or is too big.
			return fmt.Errorf("linear: the answer to %s could not be read in full", name)
		}
		if jerr != nil || len(env.Data) == 0 || string(env.Data) == "null" {
			return fmt.Errorf("linear: %s answered something that is not a GraphQL answer", name)
		}
		if out != nil {
			if err := json.Unmarshal(env.Data, out); err != nil {
				return fmt.Errorf("linear: the answer to %s has an unexpected shape", name)
			}
		}
		return nil
	}
}

func retryAfter(h http.Header) time.Duration {
	if s, err := strconv.Atoi(strings.TrimSpace(h.Get("Retry-After"))); err == nil && s > 0 && s <= 3600 {
		return time.Duration(s) * time.Second
	}
	return defaultRetryAfter
}
