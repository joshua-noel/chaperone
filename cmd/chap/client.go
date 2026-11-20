package main

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
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/joshua-noel/chaperone/internal/redact"
	"github.com/joshua-noel/chaperone/internal/version"
)

const defaultURL = "http://127.0.0.1:55398"

// maxBody bounds what chap reads from chapd (and from --body-file).
const maxBody = 4 << 20

// cliError is a failure already worded for the user, with its exit code.
type cliError struct {
	code int
	msg  string
}

func (e *cliError) Error() string { return e.msg }

func failure(code int, format string, args ...any) *cliError {
	return &cliError{code: code, msg: fmt.Sprintf(format, args...)}
}

// baseURL is chapd's address. Only a loopback address is accepted: the bearer
// token goes there, so an environment that points CHAP_URL elsewhere must not
// be able to collect it.
func (a *app) baseURL() (string, error) {
	raw := strings.TrimSpace(a.getenv("CHAP_URL"))
	if raw == "" {
		return defaultURL, nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", failure(exitUsage, "CHAP_URL must be http://host:port of chapd")
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); !(host == "localhost" || (ip != nil && ip.IsLoopback())) {
		return "", failure(exitUsage, "CHAP_URL must point at the loopback address (127.0.0.1, ::1 or localhost)")
	}
	return u.Scheme + "://" + u.Host, nil
}

// tokenFilePath is where the orchestrator token lives (ADR-007 item 5).
func (a *app) tokenFilePath() string {
	if p := strings.TrimSpace(a.getenv("CHAP_ORCHESTRATOR_TOKEN_FILE")); p != "" {
		return p
	}
	if d := a.getenv("LOCALAPPDATA"); d != "" {
		return filepath.Join(d, "Chaperone", "orchestrator.token")
	}
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "Chaperone", "orchestrator.token")
	}
	return filepath.Join("Chaperone", "orchestrator.token")
}

// loadToken returns the credential: CHAP_RUN_TOKEN first (ADR-007 item 6),
// else the key file named by CHAP_KEY_FILE (ADR-008), else the orchestrator token file. No flag takes a token. Error text never
// contains token bytes.
func (a *app) loadToken() (string, error) {
	a.tokMu.Lock()
	defer a.tokMu.Unlock()
	if a.token != "" {
		return a.token, nil
	}
	tok, from := strings.TrimSpace(a.getenv("CHAP_RUN_TOKEN")), "CHAP_RUN_TOKEN"
	if kf := strings.TrimSpace(a.getenv("CHAP_KEY_FILE")); tok == "" && kf != "" {
		// A key (ADR-008) comes before the orchestrator file: a script or an agent holds a key and nothing else.
		data, err := a.readFile(kf)
		if err != nil {
			return "", failure(exitAuth, "no token: CHAP_KEY_FILE names %s, which cannot be read", clean(kf))
		}
		tok, from = strings.TrimSpace(string(data)), "the key file "+kf
		if tok == "" {
			return "", failure(exitAuth, "no token: the key file %s is empty", clean(kf))
		}
	}
	if tok == "" {
		path := a.tokenFilePath()
		data, err := a.readFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return "", failure(exitAuth, "no token: CHAP_RUN_TOKEN is not set and there is no orchestrator token file at %s", path)
			}
			return "", failure(exitAuth, "no token: CHAP_RUN_TOKEN is not set and the orchestrator token file %s cannot be read", path)
		}
		tok, from = strings.TrimSpace(string(data)), "the orchestrator token file "+path
	}
	if tok == "" {
		return "", failure(exitAuth, "no token: %s is empty", from)
	}
	if len(tok) > 4096 || strings.IndexFunc(tok, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 {
		return "", failure(exitAuth, "the token in %s is not a single printable-ASCII word", from)
	}
	a.token = tok
	if !slices.Contains(a.secrets, tok) {
		a.secrets = append(a.secrets, tok)
	}
	return tok, nil
}

// forgetToken drops the cached credential so the next call reads it again
// (the orchestrator token file is rewritten when the orchestrator's token is reissued; a
// long-lived `chap mcp` must not hold the old one). The old value stays in the
// mask list.
func (a *app) forgetToken() {
	a.tokMu.Lock()
	a.token = ""
	a.tokMu.Unlock()
}

var (
	orchTokenRE = regexp.MustCompile(`chap_orch_[A-Za-z0-9_-]{8,}`)
	jwtRE       = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*`)
	// shapes is chapd's redactor with no registered secrets: only the shape
	// rules (GitHub, Anthropic and Google keys, PEM blocks, JWTs). chap cannot
	// know the vault's values; chapd refuses a request or a denial that holds
	// one, so this only catches what reached chap some other way.
	shapes = redact.NewRegistry()
)

// scrub masks every secret chap knows of, and anything shaped like one, in
// text bound for a terminal or a pipe. It is the last line of defence: no
// command is meant to produce a secret in the first place.
func (a *app) scrub(s string) string {
	a.tokMu.Lock()
	secrets := a.secrets
	a.tokMu.Unlock()
	for _, sec := range secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, "[redacted]")
		}
	}
	s = orchTokenRE.ReplaceAllString(s, "[redacted]")
	s = jwtRE.ReplaceAllString(s, "[redacted]")
	s, _ = shapes.Redact(s)
	return s
}

// reply is chapd's answer.
type reply struct {
	status int
	header http.Header
	body   []byte
	base   string // chapd's address this came from
}

// call sends one request to chapd with the caller's token.
func (a *app) call(method, path string, q url.Values, body any) (*reply, error) {
	return a.callCtx(context.Background(), method, path, q, body)
}

// callCtx is call that stops when ctx is done (`chap mcp` cancels a call the
// client gave up on).
func (a *app) callCtx(ctx context.Context, method, path string, q url.Values, body any) (*reply, error) {
	base, err := a.baseURL()
	if err != nil {
		return nil, err
	}
	tok, err := a.loadToken()
	if err != nil {
		return nil, err
	}
	target := base + path
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, failure(exitFail, "cannot encode the request: %v", err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return nil, failure(exitFail, "cannot build the request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "chap/"+version.Version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, failure(exitUnavailable, "chapd is not reachable at %s (nothing ran): %v", base, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, failure(exitUnavailable, "chapd closed the connection mid-reply (the outcome is unknown; look it up before retrying): %v", err)
	}
	if len(data) > maxBody {
		return nil, failure(exitFail, "chapd's reply is larger than %d bytes", maxBody)
	}
	return &reply{status: resp.StatusCode, header: resp.Header, body: data, base: base}, nil
}

// rendered is what a command shows for a successful reply.
type rendered struct {
	human string
	// json replaces the raw body in --json mode; nil prints the body as is.
	json []byte
	// code is the exit code; exitFail means human is an error message for
	// stderr, whatever the output mode.
	code int
}

// do makes one call and prints the result. render turns a 2xx reply into
// output; everything else goes through the denial and error renderer.
func (a *app) do(asJSON bool, method, path string, q url.Values, body any, render func(*reply) rendered) int {
	r, err := a.call(method, path, q, body)
	if err != nil {
		return a.report(err)
	}
	if r.status >= 200 && r.status < 300 {
		out := render(r)
		if out.code == exitFail {
			a.err(out.human)
			return out.code
		}
		a.welcome(asJSON, r.base)
		if asJSON {
			b := out.json
			if b == nil {
				b = r.body
			}
			a.out(indentJSON(b))
		} else {
			a.out(out.human)
		}
		return out.code
	}
	return a.refused(asJSON, r)
}

func (a *app) report(err error) int {
	var ce *cliError
	if errors.As(err, &ce) {
		return a.fail(ce.code, "%s", ce.msg)
	}
	return a.fail(exitFail, "%v", err)
}

// indentJSON re-indents a JSON body, keeping key order and number text.
func indentJSON(b []byte) string {
	var out bytes.Buffer
	if err := json.Indent(&out, bytes.TrimSpace(b), "", "  "); err != nil {
		return string(b)
	}
	out.WriteByte('\n')
	return out.String()
}

// refused renders a non-2xx reply and returns the exit code.
func (a *app) refused(asJSON bool, r *reply) int {
	var head struct {
		Type      string `json:"type"`
		CauseCode string `json:"cause_code"`
		Why       string `json:"why"`
		Retryable bool   `json:"retryable"`
		State     string `json:"state"`
	}
	isJSON := json.Unmarshal(r.body, &head) == nil
	if asJSON && isJSON {
		a.out(indentJSON(r.body))
	}
	code := exitFail
	var text string
	switch {
	case !isJSON:
		return a.fail(exitFail, "chapd answered %d with a body that is not JSON: %s", r.status, snippet(string(r.body)))
	case head.Type == "denial":
		var d denial
		if err := json.Unmarshal(r.body, &d); err != nil {
			return a.fail(exitFail, "chapd sent a denial chap cannot read: %v", err)
		}
		text = renderDenial(&d)
		if ra := r.header.Get("Retry-After"); ra != "" {
			if n, err := strconv.Atoi(ra); err == nil && n > 0 {
				text += fmt.Sprintf("retry after %d s\n", n)
			}
		}
		switch {
		case r.status == http.StatusServiceUnavailable:
			code = exitUnavailable
		case r.status == http.StatusUnauthorized:
			code = exitAuth
		default:
			code = exitDenied
		}
	case head.Type == "auth_error":
		text = "AUTH FAILED: chapd could not identify the caller\nwhy: " + clean(head.Why) +
			"\nrequest: not possible, policy does not allow asking\n" +
			"check CHAP_RUN_TOKEN or the orchestrator token file\n"
		code = exitAuth
	case head.Type == "unavailable":
		kind := "not retryable as is"
		if head.Retryable {
			kind = "retryable"
		}
		text = "UNAVAILABLE (" + kind + "): chapd failed closed, nothing ran\nwhy: " + clean(head.Why) + "\n"
		code = exitUnavailable
	case head.Type == "not_found":
		text = "NOT FOUND\nwhy: " + clean(head.Why) + "\n"
		code = exitMissing
	case head.Type == "conflict":
		text = "CONFLICT"
		if head.State != "" {
			text += " (state " + clean(head.State) + ")"
		}
		text += "\nwhy: " + clean(head.Why) + "\n"
		code = exitMissing
	default:
		return a.fail(exitFail, "chapd answered %d: %s", r.status, snippet(string(r.body)))
	}
	if !asJSON {
		a.err(text)
	}
	return code
}

func snippet(s string) string {
	s = clean(strings.TrimSpace(s))
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

// clean makes server text safe for a terminal: control characters (escape
// sequences, carriage returns, extra lines) become '?'.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return '?'
		}
		return r
	}, s)
}
