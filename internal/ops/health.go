package ops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// This file is `health` (ticket L1-11, the read-only part): one GET of the
// pilot's readiness URL, the same check the house rules and the heartbeat make.
//
// Rules the code keeps:
//
//   - It only reads. The one request is a GET; the client never follows a
//     redirect and the URL must be on the server's loopback, so a bad config
//     cannot make chapd call another machine.
//   - The answer is a closed set of words ("ok", "unavailable", "unreachable",
//     "malformed"). The body of the answer is never echoed to the caller.
//   - It never starts, restarts or probes WSL, Docker or the stack: if the
//     pilot does not answer, the answer is "unreachable".
//   - The rate limit is the policy pack's `rate_per_minute` for `health`,
//     applied per caller by the op pipeline before an adapter is reached.

// Defaults of the pilot readiness check (scripts/pilot-host/README.md, section 3:
// `curl -H "Host: pilot.storefront.net" -H "X-Forwarded-Proto: https"
// http://127.0.0.1:55350/api/health/ready`). WSL forwards the pilot's web port to
// the Windows loopback.
const (
	DefaultPilotReadyURL = "http://127.0.0.1:55350/api/health/ready"
	DefaultPilotHostName = "pilot.storefront.net"

	defaultHealthTimeout = 10 * time.Second
	maxHealthBody        = 64 << 10
	healthAdapterName    = "pilot"
)

// healthTargetRefs are the target refs `health` accepts, on adapter "pilot".
var healthTargetRefs = []string{"health", "readiness"}

// Health answers. HealthOK is the only one that lets a deploy go on.
const (
	HealthOK          = "ok"
	HealthUnavailable = "unavailable" // the pilot answered and said it is not ready
	HealthUnreachable = "unreachable" // no answer (stack down, WSL forwarding off, timeout)
	HealthMalformed   = "malformed"   // an answer that is not the readiness shape
)

// HealthStatus is one reading of the pilot.
type HealthStatus struct {
	Status     string // one of the Health* words
	HTTPStatus int    // 0 when unreachable
	CheckedAt  time.Time
}

// OK reports whether the pilot said `"status":"ok"`.
func (h HealthStatus) OK() bool { return h.Status == HealthOK }

// HealthChecker reads the pilot's readiness. *[PilotHealth] is the production one.
type HealthChecker interface {
	Check(ctx context.Context) HealthStatus
}

// PilotHealthConfig builds a [PilotHealth]. The zero value is the pilot as it
// runs today.
type PilotHealthConfig struct {
	// URL is the readiness URL. It must be http on a loopback address.
	URL string
	// Host is the Host header value the pilot's fence needs.
	Host string
	// Client is optional. Redirects are never followed, whatever it says.
	Client *http.Client
	Now    func() time.Time
}

// PilotHealth is the production [HealthChecker].
type PilotHealth struct {
	url    string
	host   string
	client *http.Client
	now    func() time.Time
}

// NewPilotHealth returns a checker, or an error for a URL that is not plain
// HTTP on loopback.
func NewPilotHealth(cfg PilotHealthConfig) (*PilotHealth, error) {
	if cfg.URL == "" {
		cfg.URL = DefaultPilotReadyURL
	}
	if cfg.Host == "" {
		cfg.Host = DefaultPilotHostName
	}
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("ops: the pilot readiness URL must look like http://127.0.0.1:55350/api/health/ready")
	}
	if h := u.Hostname(); h != "localhost" {
		if ip := net.ParseIP(h); ip == nil || !ip.IsLoopback() {
			return nil, errors.New("ops: the pilot readiness URL must be on a loopback address")
		}
	}
	if strings.ContainsAny(cfg.Host, " \t\r\n/\\") {
		return nil, errors.New("ops: the pilot Host header value is not a host name")
	}
	c := http.Client{Timeout: defaultHealthTimeout}
	if cfg.Client != nil {
		c = *cfg.Client
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &PilotHealth{url: cfg.URL, host: cfg.Host, client: &c, now: now}, nil
}

// Check makes the one GET. It never returns an error: a pilot that cannot be
// read is a status.
func (p *PilotHealth) Check(ctx context.Context) HealthStatus {
	st := HealthStatus{Status: HealthUnreachable, CheckedAt: p.now()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return st
	}
	req.Host = p.host
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return st
	}
	defer resp.Body.Close()
	st.HTTPStatus = resp.StatusCode
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxHealthBody))
	if err != nil {
		st.Status = HealthMalformed
		return st
	}
	st.Status = readyStatus(resp.StatusCode, raw)
	return st
}

// readyStatus maps the HTTP answer to a Health* word. Only a 200 whose JSON
// body says "status":"ok" is ok; `"status":"unavailable"` is the pilot saying
// it is not ready; anything else is malformed.
func readyStatus(code int, body []byte) string {
	// wsl.exe pipes can leave NUL bytes in the text (house rules pipe through tr -d '\0').
	body = bytes.ReplaceAll(body, []byte{0}, nil)
	var v struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(body), &v); err != nil {
		return HealthMalformed
	}
	switch {
	case code == http.StatusOK && v.Status == "ok":
		return HealthOK
	case v.Status == "ok": // a 200 is required for ok: a 5xx that says ok is not trusted
		return HealthMalformed
	case v.Status == "unavailable" || code == http.StatusServiceUnavailable:
		return HealthUnavailable
	}
	return HealthMalformed
}

// ---- the op ----------------------------------------------------------------

type healthAdapter struct{ h HealthChecker }

// NewHealthAdapter returns the `health` adapter.
func NewHealthAdapter(h HealthChecker) Adapter { return &healthAdapter{h: h} }

func (a *healthAdapter) validate(r *Request) error {
	if r.Target.Adapter != healthAdapterName || !slices.Contains(healthTargetRefs, r.Target.Ref) {
		return paramsInvalid("target must be {adapter: %s, ref: %s}", healthAdapterName, healthTargetRefs[0])
	}
	if len(r.Params) != 0 {
		return paramsInvalid("health takes no params")
	}
	return nil
}

// Check validates the shape only. The GET happens in Execute, so a dry run, an
// approval request and a release re-check never touch the pilot.
func (a *healthAdapter) Check(_ context.Context, r *Request) (CheckResult, error) {
	if err := a.validate(r); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{}, nil
}

// Execute reads the pilot once. A pilot that is down is a successful read of
// "not ok", not a failed op: the op's job is to say what it saw.
func (a *healthAdapter) Execute(ctx context.Context, r *Request) (Outcome, error) {
	if err := a.validate(r); err != nil {
		return Outcome{Failed: true, Result: map[string]any{"error": err.Error()}}, nil
	}
	st := a.h.Check(ctx)
	return Outcome{Result: healthResult(st)}, nil
}

func healthResult(st HealthStatus) map[string]any {
	out := map[string]any{
		"status":     st.Status,
		"ok":         st.OK(),
		"checked_at": st.CheckedAt.UTC().Format(time.RFC3339),
	}
	if st.HTTPStatus != 0 {
		out["http_status"] = st.HTTPStatus
	}
	return out
}
