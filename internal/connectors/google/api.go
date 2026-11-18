package google

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

const maxAPIResponse = 1 << 20

// APIError is Google's refusal of an API call: the request was understood and
// not carried out (or, for a 5xx, may or may not have been).
type APIError struct {
	Status  int
	Reason  string // Google's short reason ("notFound", "rateLimitExceeded")
	Message string // Google's message, clipped and with control characters removed
}

func (e *APIError) Error() string {
	return fmt.Sprintf("google: HTTP %d %s: %s", e.Status, e.Reason, e.Message)
}

// definite reports whether Google certainly did not carry the call out: a 4xx
// is a refusal before any effect. A 5xx or 408 is not definite.
func (e *APIError) definite() bool { return e.Status >= 400 && e.Status < 500 && e.Status != 408 }

// apiClient makes bearer-authorised JSON calls. A 401 means Google rejected
// the token before doing anything, so one forced refresh and one retry is safe
// even for a send.
type apiClient struct {
	hc  *http.Client
	src *Source
}

// call sends one request. in (may be nil) is JSON-encoded; out (may be nil) is
// decoded. A non-APIError error means the transport failed: for a write, the
// outcome is unknown.
func (c *apiClient) call(ctx context.Context, method, rawURL string, in, out any) error {
	var payload []byte
	if in != nil {
		var err error
		if payload, err = json.Marshal(in); err != nil {
			return err
		}
	}
	for attempt := 0; ; attempt++ {
		access, _, err := c.src.token(ctx, attempt > 0)
		if err != nil {
			return &notSentError{err}
		}
		req, err := http.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+access)
		req.Header.Set("Accept", "application/json")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			return fmt.Errorf("google: %s %s: %w", method, hostOf(rawURL), stripURL(err))
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponse))
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			continue
		}
		if resp.StatusCode/100 != 2 {
			return parseAPIError(resp.StatusCode, body)
		}
		if rerr != nil {
			// The call succeeded; the answer was cut short.
			return fmt.Errorf("google: read the answer of %s: %w", hostOf(rawURL), rerr)
		}
		if out != nil {
			if err := json.Unmarshal(body, out); err != nil {
				return fmt.Errorf("google: %s answered something that is not JSON", hostOf(rawURL))
			}
		}
		return nil
	}
}

func parseAPIError(status int, body []byte) error {
	var e struct {
		Error struct {
			Message string `json:"message"`
			Errors  []struct {
				Reason string `json:"reason"`
			} `json:"errors"`
			Status string `json:"status"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	reason := e.Error.Status
	if len(e.Error.Errors) > 0 && e.Error.Errors[0].Reason != "" {
		reason = e.Error.Errors[0].Reason
	}
	return &APIError{Status: status, Reason: clipText(reason, 60), Message: clipText(e.Error.Message, 200)}
}

// isDefinite reports whether err is a failure that certainly had no effect: a
// 4xx answer, or a failure before any byte went to Google.
func isDefinite(err error) bool {
	var ae *APIError
	var ns *notSentError
	return errors.As(err, &ns) || (errors.As(err, &ae) && ae.definite())
}

// notSentError wraps a failure that happened before the request left.
type notSentError struct{ error }

func (e *notSentError) Unwrap() error { return e.error }
