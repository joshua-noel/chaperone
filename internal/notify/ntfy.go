package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultNtfyURL is the public ntfy server. Self-hosting is a base-URL change.
const DefaultNtfyURL = "https://ntfy.sh"

// ErrPublish is wrapped by every error from a publish that reached ntfy and was
// refused (any status other than 2xx). Match it with errors.Is; read the status
// with errors.As to *PublishError.
var ErrPublish = errors.New("notify: ntfy refused the message")

// PublishError is a non-2xx answer from the ntfy server. It holds only the
// status code: the reply body is not kept, so nothing the server echoes (the
// topic included) can reach a log through it.
type PublishError struct{ Status int }

func (e *PublishError) Error() string { return fmt.Sprintf("notify: ntfy answered HTTP %d", e.Status) }
func (e *PublishError) Unwrap() error { return ErrPublish }

// NtfyConfig configures an [Ntfy] driver.
type NtfyConfig struct {
	// Topic is required; see [InitTopic].
	Topic Topic
	// BaseURL defaults to [DefaultNtfyURL]. It must be https, except for a
	// loopback address (the fake server). It must not carry a path or query:
	// the JSON publish API posts to the server root.
	BaseURL string
	// HTTPClient defaults to a client with a 10 s timeout that does not follow
	// redirects (a redirect would re-send the topic to another host). A supplied
	// client is used as is.
	HTTPClient *http.Client
	// UserAgent defaults to "chaperone-notify".
	UserAgent string
}

// Ntfy is the ntfy driver. It publishes once per Notify and never retries.
//
// It uses ntfy's JSON publish API (POST to the server root), which puts the
// topic in the request body. So the topic is in no URL, and therefore not in the
// errors net/http builds from URLs, in proxy logs of paths, or in any log line
// of this package.
type Ntfy struct {
	endpoint string
	topic    Topic
	hc       *http.Client
	agent    string
}

var _ Notifier = (*Ntfy)(nil)

// NewNtfy validates cfg and returns the driver.
func NewNtfy(cfg NtfyConfig) (*Ntfy, error) {
	if cfg.Topic.IsZero() {
		return nil, errors.New("notify: topic is required")
	}
	base := cfg.BaseURL
	if base == "" {
		base = DefaultNtfyURL
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, errors.New("notify: invalid ntfy base URL")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if ip := net.ParseIP(u.Hostname()); (ip == nil || !ip.IsLoopback()) && u.Hostname() != "localhost" {
			return nil, errors.New("notify: ntfy base URL must be https (plain http only for loopback)")
		}
	default:
		return nil, errors.New("notify: invalid ntfy base URL scheme")
	}
	n := &Ntfy{endpoint: strings.TrimRight(u.String(), "/") + "/", topic: cfg.Topic, hc: cfg.HTTPClient, agent: cfg.UserAgent}
	if n.hc == nil {
		n.hc = &http.Client{
			Timeout:       10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	if n.agent == "" {
		n.agent = "chaperone-notify"
	}
	return n, nil
}

// wire is the JSON body of one publish. Its fields are the whole of what the
// driver may send to ntfy: no click, attach, actions, icon, email, call, delay
// or tags.
type wire struct {
	Topic string `json:"topic"`
	Push
}

// Notify builds the push for w ([Build]) and publishes it. It returns
// [ErrInvalidWake] without any request if w is outside the allowlist.
func (n *Ntfy) Notify(ctx context.Context, w Wake) error {
	p, err := Build(w)
	if err != nil {
		return err
	}
	return n.publish(ctx, p)
}

func (n *Ntfy) publish(ctx context.Context, p Push) error {
	body, err := json.Marshal(wire{Topic: n.topic.Reveal(), Push: p})
	if err != nil {
		return fmt.Errorf("notify: encode message: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", n.agent)
	resp, err := n.hc.Do(req)
	if err != nil {
		// *url.Error holds the method and the endpoint (no topic); keep it.
		return fmt.Errorf("notify: publish: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10)) // let the connection be reused
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &PublishError{Status: resp.StatusCode}
	}
	return nil
}
