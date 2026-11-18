// Package gitproxy is chapd's smart-HTTP git reverse proxy (ticket L1-09,
// ADR-002 "Push path"). A run's git client talks to chapd with its run token;
// chapd talks to GitHub with an installation token that it mints for one
// repository and one permission set, keeps in memory for the run that uses it
// (see tokens.go) and revokes when the run ends. The run never holds a GitHub
// credential.
//
// The proxy only reads the wire protocol. Every decision is made by the op
// service ([ops.Service]): a fetch is held to the run's repository, a push is
// recorded as a branch.push op and may update exactly one ref, the task branch.
package gitproxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/ops"
)

const (
	// maxHead caps the raw bytes read to find the update-request commands.
	maxHead = 256 << 10
	// maxCommands caps the decoded command section.
	maxCommandBytes = 128 << 10
	// maxReport caps the response bytes kept to read the report-status.
	maxReport = 256 << 10

	requestTimeout = 20 * time.Minute
	revokeTimeout  = 15 * time.Second

	// maxReplay is the largest request body forward holds in memory so it can
	// send it again after a 404 (see [Handler.RetryDelays]). A larger body, or
	// one of unknown length, is streamed once and never retried.
	maxReplay = 1 << 20

	svcUpload  = "git-upload-pack"
	svcReceive = "git-receive-pack"
)

// Gate is the op-service side of the proxy; [ops.Service] implements it.
type Gate interface {
	GitRead(ctx context.Context, c *ops.Caller, repo string) error
	GitPushDiscovery(ctx context.Context, c *ops.Caller, repo string) error
	BeginGitPush(ctx context.Context, c *ops.Caller, p ops.GitPush) (*ops.GitPushOp, error)
}

// Revoker revokes an installation token ([gh.Client] implements it).
type Revoker interface {
	RevokeToken(ctx context.Context, tok *gh.Token) error
}

// Handler is the [ops.GitHandler].
type Handler struct {
	Gate    Gate
	Tokens  ops.TokenMinter
	Revoker Revoker
	// Upstream is the git host, "https://github.com" by default.
	Upstream string
	// Client talks to Upstream. The default has no overall timeout beyond
	// requestTimeout and never follows a redirect (a redirect would carry the
	// token to another host).
	Client *http.Client
	Log    *slog.Logger
	// RetryDelays are the pauses before each repeat of a request GitHub
	// answered 404, with the same token. A just-minted installation token may
	// not have reached all of GitHub's edge caches yet, and GitHub then answers
	// 404 as it does for a private repository the caller cannot see. Nil means
	// 0.5 s, 1 s and 2 s; an empty non-nil slice turns retrying off.
	RetryDelays []time.Duration
	// Wait pauses for d, or returns early with an error when ctx ends. Nil
	// means a timer. Tests replace it to avoid real sleeps.
	Wait func(ctx context.Context, d time.Duration) error
	// Now is the clock that decides whether a cached token is near its end.
	// Nil means time.Now. Tests replace it.
	Now func() time.Time
	// TokenMargin is how long before expires_at a cached token is no longer
	// reused, so a request that starts with it still ends before GitHub stops
	// it. Zero means 5 minutes.
	TokenMargin time.Duration

	// The token cache (tokens.go); the zero value is ready.
	mu      sync.Mutex
	toks    map[tokenKey]*tokenEntry
	retired map[string][]*gh.Token // run -> tokens replaced before the run ended
	ended   map[string]time.Time   // run -> when EndRun ran
	closed  bool
	revokes sync.WaitGroup // revokes EndRun runs in the background
}

// defaultRetryDelays total 3.5 s. GitHub support has advised a few seconds
// for the first retry and up to 30 s for the rare slow case; a git client
// waits on every one of these, so the default is short and RetryDelays can
// grow it.
var defaultRetryDelays = []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second}

func (h *Handler) retryDelays() []time.Duration {
	if h.RetryDelays != nil {
		return h.RetryDelays
	}
	return defaultRetryDelays
}

func (h *Handler) wait(ctx context.Context, d time.Duration) error {
	if h.Wait != nil {
		return h.Wait(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

var _ ops.GitHandler = (*Handler)(nil)

func (h *Handler) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

func (h *Handler) upstream() string {
	if h.Upstream != "" {
		return strings.TrimRight(h.Upstream, "/")
	}
	return "https://github.com"
}

func (h *Handler) client() *http.Client {
	if h.Client != nil {
		return h.Client
	}
	return &http.Client{
		Timeout:       requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type route struct {
	repo    gh.Repo
	service string // svcUpload or svcReceive
	refs    bool   // info/refs (discovery); otherwise the POST
}

var versionRE = regexp.MustCompile(`^version=[012]$`)

// parseRoute reads /git/{owner}/{repo}[.git]/(info/refs|git-upload-pack|git-receive-pack).
func parseRoute(r *http.Request) (route, error) {
	notFound := func(why string) (route, error) { return route{}, &ops.NotFoundError{Why: why} }
	rest := strings.TrimPrefix(r.URL.Path, "/git/")
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) != 3 {
		return notFound("not a git URL")
	}
	repo, err := gh.ParseRepo(parts[0] + "/" + strings.TrimSuffix(parts[1], ".git"))
	if err != nil {
		return notFound("not a git repository URL")
	}
	rt := route{repo: repo}
	switch parts[2] {
	case "info/refs":
		if r.Method != http.MethodGet {
			return notFound("info/refs is read with GET")
		}
		rt.refs = true
		rt.service = r.URL.Query().Get("service")
		if rt.service != svcUpload && rt.service != svcReceive {
			return notFound("only the smart git protocol is served")
		}
	case svcUpload, svcReceive:
		if r.Method != http.MethodPost {
			return notFound(parts[2] + " is called with POST")
		}
		rt.service = parts[2]
	default:
		return notFound("not a git URL")
	}
	return rt, nil
}

// ServeGit implements [ops.GitHandler].
func (h *Handler) ServeGit(w http.ResponseWriter, r *http.Request, c *ops.Caller) error {
	rt, err := parseRoute(r)
	if err != nil {
		return err
	}
	// A pack can take far longer than the server's default deadlines.
	rc := http.NewResponseController(w)
	_ = rc.EnableFullDuplex()
	dl := time.Now().Add(requestTimeout)
	_ = rc.SetReadDeadline(dl)
	_ = rc.SetWriteDeadline(dl)
	defer drainBody(r, rc)

	repo := rt.repo.String()
	switch {
	case rt.service == svcUpload:
		if err := h.Gate.GitRead(r.Context(), c, repo); err != nil {
			return err
		}
		return h.forward(w, r, c, rt, gh.PermsFetch(), r.Body, &reportTee{over: true})
	case rt.refs:
		if err := h.Gate.GitPushDiscovery(r.Context(), c, repo); err != nil {
			return err
		}
		return h.forward(w, r, c, rt, gh.PermsPush(), nil, &reportTee{over: true})
	}
	return h.push(w, r, c, rt)
}

// push serves the receive-pack POST: it reads the update-request head, lets the
// gate decide, then forwards head and the rest of the body untouched.
func (h *Handler) push(w http.ResponseWriter, r *http.Request, c *ops.Caller, rt route) error {
	if ct := r.Header.Get("Content-Type"); ct != "application/x-git-receive-pack-request" {
		return &ops.NotFoundError{Why: "not a git push request"}
	}
	head, p := readPushHead(r.Body, r.Header.Get("Content-Encoding"))
	p.Repo = rt.repo.String()
	if p.Malformed == "" && len(p.Updates) == 0 && !p.PushCert && string(head) == "0000" {
		// git sends a bare flush-pkt before a large push, to test its credentials
		// before it uploads the pack. It carries no update, so it is not an op.
		var extra [1]byte
		n, _ := io.ReadFull(r.Body, extra[:])
		if n == 0 {
			if err := h.Gate.GitPushDiscovery(r.Context(), c, p.Repo); err != nil {
				return err
			}
			return h.forward(w, r, c, rt, gh.PermsPush(), bytes.NewReader(head), &reportTee{over: true})
		}
		head = append(head, extra[0])
	}
	op, err := h.Gate.BeginGitPush(r.Context(), c, p)
	if err != nil {
		return err
	}
	body := io.MultiReader(bytes.NewReader(head), r.Body)
	rep := &reportTee{}
	err = h.forward(w, r, c, rt, gh.PermsPush(), body, rep)
	res := rep.result(err)
	if ferr := op.Finish(r.Context(), res); ferr != nil {
		h.log().Error("gitproxy: could not record the push result", "request", op.ID(), "err", ferr)
	}
	return err
}

// forward sends the request upstream with the run's token for this repository
// and permission set (minted on first use, see [Handler.acquire]) and streams
// the answer. It returns an error only before anything was written to w.
//
// GitHub answers 404 when a token it has not yet replicated to every edge cache
// is used on a private repository. forward repeats such a request with the same
// token, after each pause in [Handler.RetryDelays], as long as it can send the
// request again byte for byte: a request without a body, or a body of known
// length up to maxReplay. A 404 is sent before GitHub applies anything, so the
// repeat of a push cannot apply it twice.
func (h *Handler) forward(w http.ResponseWriter, r *http.Request, c *ops.Caller, rt route, perms map[string]string, body io.Reader, rep *reportTee) error {
	ctx := r.Context()
	var replay []byte // the whole body, when it is held for a repeat
	if body != nil {
		g := &guardedBody{r: body}
		body = g
		// Runs after resp.Body.Close below: the transport may still be reading
		// the client's body in its write goroutine when GitHub answers early.
		defer g.stop(http.NewResponseController(w))
		if n := r.ContentLength; n > 0 && n <= maxReplay {
			replay = make([]byte, n)
			if _, err := io.ReadFull(g, replay); err != nil {
				return &ops.UnavailableError{Why: "chapd could not read the request body; nothing was sent", Err: err}
			}
		}
	}
	replayable := body == nil || replay != nil || r.ContentLength == 0
	tok, done, err := h.acquire(ctx, c, rt.repo, perms)
	if err != nil {
		return err
	}
	refused := false // GitHub answered 401: the token is dead
	defer func() { done(refused) }()

	u := h.upstream() + "/" + url.PathEscape(rt.repo.Owner) + "/" + url.PathEscape(rt.repo.Name) + ".git/"
	if rt.refs {
		u += "info/refs?service=" + rt.service
	} else {
		u += rt.service
	}
	build := func() (*http.Request, error) {
		var b io.Reader
		switch {
		case replay != nil:
			b = bytes.NewReader(replay) // NewRequest sets ContentLength and GetBody
		case body != nil && r.ContentLength != 0:
			b = body
		}
		req, err := http.NewRequestWithContext(ctx, r.Method, u, b)
		if err != nil {
			return nil, err
		}
		if replay == nil && b != nil {
			req.ContentLength = r.ContentLength // -1 (chunked) when the client did not say
		}
		req.SetBasicAuth("x-access-token", tok.Reveal())
		for _, k := range []string{"Content-Type", "Content-Encoding", "Accept"} {
			if v := r.Header.Get(k); v != "" {
				req.Header.Set(k, v)
			}
		}
		if ua := r.Header.Get("User-Agent"); strings.HasPrefix(ua, "git/") && len(ua) <= 100 {
			req.Header.Set("User-Agent", ua)
		} else {
			req.Header.Set("User-Agent", "git/chapd")
		}
		if rt.service == svcUpload {
			if v := r.Header.Get("Git-Protocol"); versionRE.MatchString(v) {
				req.Header.Set("Git-Protocol", v)
			}
		}
		return req, nil
	}

	delays := h.retryDelays()
	var resp *http.Response
	for attempt := 0; ; attempt++ {
		req, err := build()
		if err != nil {
			return &ops.UnavailableError{Why: "chapd could not build the upstream request", Err: err}
		}
		rep.sent = true
		resp, err = h.client().Do(req)
		if err != nil {
			h.log().Warn("gitproxy: upstream request failed", "repo", rt.repo.String(), "err", redactErr(err))
			return &ops.UnavailableError{Why: "GitHub could not be reached; the request may not have completed", Retryable: true}
		}
		if resp.StatusCode != http.StatusNotFound || !replayable || attempt >= len(delays) {
			break
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10)) // lets the connection be reused
		resp.Body.Close()
		h.log().Info("gitproxy: GitHub answered 404; repeating the request with the same token",
			"repo", rt.repo.String(), "service", rt.service, "refs", rt.refs, "attempt", attempt+1, "of", len(delays), "after", delays[attempt])
		if h.wait(ctx, delays[attempt]) != nil {
			// The client is gone: answer with the 404 GitHub gave.
			rep.markStatus(http.StatusNotFound)
			return &ops.NotFoundError{Why: "GitHub does not have this repository for chapd"}
		}
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		rep.markStatus(resp.StatusCode)
		return &ops.NotFoundError{Why: "GitHub does not have this repository for chapd"}
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		refused = resp.StatusCode == http.StatusUnauthorized
		rep.markStatus(resp.StatusCode)
		h.log().Warn("gitproxy: GitHub refused the installation token", "repo", rt.repo.String(), "status", resp.StatusCode)
		return &ops.UnavailableError{Why: fmt.Sprintf("GitHub refused chapd's token (HTTP %d)", resp.StatusCode)}
	case resp.StatusCode >= 500:
		rep.markStatus(resp.StatusCode)
		return &ops.UnavailableError{Why: fmt.Sprintf("GitHub answered HTTP %d", resp.StatusCode), Retryable: true}
	}
	rep.markStatus(resp.StatusCode)

	for _, k := range []string{"Content-Type", "Cache-Control", "Expires", "Pragma"} {
		if v := resp.Header.Get(k); v != "" {
			w.Header().Set(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	rc := http.NewResponseController(w)
	buf := make([]byte, 32<<10)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			rep.add(buf[:n])
			if _, werr := w.Write(buf[:n]); werr != nil {
				rep.broken = true
				return nil
			}
			_ = rc.Flush()
		}
		if rerr != nil {
			if rerr != io.EOF {
				rep.broken = true
			}
			return nil
		}
	}
}

const (
	// maxDrain bounds the request body that is read and thrown away when a
	// request ends before its body was read to the end.
	maxDrain     = 256 << 20
	drainTimeout = time.Minute
)

// drainBody reads what is left of the request body, so a client that is still
// sending sees the answer and not a reset. It is needed because of
// EnableFullDuplex: net/http then no longer discards the unread body before it
// writes, and a body that reaches its end only when the server closes it
// starts a background read nothing stops, which panics on the next request of
// the connection. Past its bounds the connection is cut instead.
func drainBody(r *http.Request, rc *http.ResponseController) {
	_ = rc.SetReadDeadline(time.Now().Add(drainTimeout))
	n, err := io.Copy(io.Discard, io.LimitReader(r.Body, maxDrain))
	if err != nil || n == maxDrain {
		_ = rc.SetReadDeadline(time.Now())
	}
}

// guardedBody lets forward end every read of the client's request body before
// the handler returns: net/http panics when a handler's goroutine still reads
// a body after the server has moved on to the next request on the connection.
type guardedBody struct {
	mu   sync.Mutex
	r    io.Reader
	done bool
}

func (g *guardedBody) Read(p []byte) (int, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.done {
		return 0, io.ErrClosedPipe
	}
	return g.r.Read(p)
}

// stop makes later reads fail and waits for one in flight, which it cuts short
// with a read deadline when it does not end by itself.
func (g *guardedBody) stop(rc *http.ResponseController) {
	if !g.mu.TryLock() {
		_ = rc.SetReadDeadline(time.Now())
		g.mu.Lock()
	}
	g.done = true
	g.mu.Unlock()
}

// revoke ends the token on GitHub, on a context that outlives the request.
func (h *Handler) revoke(tok *gh.Token) {
	defer tok.Wipe()
	if h.Revoker == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), revokeTimeout)
	defer cancel()
	if err := h.Revoker.RevokeToken(ctx, tok); err != nil && !errors.Is(err, gh.ErrUnauthorized) {
		h.log().Warn("gitproxy: could not revoke a token; it expires on its own", "err", redactErr(err))
	}
}

// redactErr keeps a transport error out of the log with its URL: url.Error
// holds the request URL, which has no credential, but the text is shortened
// all the same.
func redactErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	s := err.Error()
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// ---- request head ------------------------------------------------------

// readPushHead reads the update-request commands from body and returns every
// raw byte it consumed (to be sent upstream ahead of the rest of the body)
// together with what it understood. It never reads past the first flush-pkt
// by more than the decompressor's buffer, and the bytes it over-reads are in
// the returned head.
func readPushHead(body io.Reader, encoding string) ([]byte, ops.GitPush) {
	var raw bytes.Buffer
	src := io.TeeReader(io.LimitReader(body, maxHead), &raw)
	var in io.Reader = src
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(src)
		if err != nil {
			return raw.Bytes(), ops.GitPush{Malformed: "the request body is not valid gzip"}
		}
		in = zr
	default:
		return raw.Bytes(), ops.GitPush{Malformed: "unsupported Content-Encoding"}
	}
	p := parseCommands(in)
	return raw.Bytes(), p
}

var (
	hexRE = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
)

// parseCommands reads pkt-lines up to the first flush-pkt, or the second
// command (a second command is already a refusal).
func parseCommands(in io.Reader) ops.GitPush {
	var p ops.GitPush
	total := 0
	var hdr [4]byte
	for first := true; ; first = false {
		if _, err := io.ReadFull(in, hdr[:]); err != nil {
			p.Malformed = "the request ended before its first flush"
			return p
		}
		n, ok := pktLen(hdr)
		if !ok {
			p.Malformed = "bad packet length"
			return p
		}
		if n == 0 { // flush-pkt: end of the command list
			return p
		}
		if n < 4 {
			p.Malformed = "unexpected special packet"
			return p
		}
		n -= 4
		total += n + 4
		if total > maxCommandBytes {
			p.Malformed = "the command list is too long"
			return p
		}
		line := make([]byte, n)
		if _, err := io.ReadFull(in, line); err != nil {
			p.Malformed = "the request ended inside a packet"
			return p
		}
		if bytes.HasPrefix(line, []byte("push-cert")) {
			p.PushCert = true
			return p
		}
		if bytes.HasPrefix(line, []byte("shallow ")) {
			continue
		}
		s := string(bytes.TrimSuffix(line, []byte("\n")))
		if i := strings.IndexByte(s, 0); i >= 0 {
			if !first || len(p.Updates) > 0 {
				p.Malformed = "capabilities outside the first command"
				return p
			}
			s = s[:i]
		}
		f := strings.Split(s, " ")
		if len(f) != 3 || !hexRE.MatchString(f[0]) || !hexRE.MatchString(f[1]) || f[2] == "" || len(f[2]) > 1024 {
			p.Malformed = "a command is not 'old new ref'"
			return p
		}
		p.Updates = append(p.Updates, ops.GitUpdate{Old: f[0], New: f[1], Ref: f[2]})
		if len(p.Updates) == 2 {
			p.More = true
			return p
		}
	}
}

func pktLen(h [4]byte) (int, bool) {
	n := 0
	for _, b := range h {
		switch {
		case b >= '0' && b <= '9':
			n = n<<4 | int(b-'0')
		case b >= 'a' && b <= 'f':
			n = n<<4 | int(b-'a'+10)
		default:
			return 0, false
		}
	}
	return n, true
}

// ---- push report -------------------------------------------------------

// reportTee keeps the head of the receive-pack answer and reads the
// report-status out of it.
type reportTee struct {
	buf    []byte
	over   bool
	status int
	broken bool // the stream to the client or from GitHub broke
	sent   bool // the request went to GitHub
}

func (t *reportTee) markStatus(s int) { t.status = s }

func (t *reportTee) add(b []byte) {
	if t.over {
		return
	}
	if len(t.buf)+len(b) > maxReport {
		t.over = true
		return
	}
	t.buf = append(t.buf, b...)
}

// result turns what happened into the op's outcome. fwdErr is what forward
// returned.
func (t *reportTee) result(fwdErr error) ops.GitPushResult {
	un := func() ops.GitPushResult { return ops.GitPushResult{Outcome: "unconfirmed"} }
	var nf *ops.NotFoundError
	var ue *ops.UnavailableError
	switch {
	case errors.As(fwdErr, &nf):
		return ops.GitPushResult{Outcome: "failed", Detail: "GitHub answered 404 (repository not found for chapd)"}
	case errors.As(fwdErr, &ue):
		if !t.sent {
			return ops.GitPushResult{Outcome: "failed", Detail: "chapd could not send the push to GitHub"}
		}
		if t.status == http.StatusUnauthorized || t.status == http.StatusForbidden {
			return ops.GitPushResult{Outcome: "failed", Detail: fmt.Sprintf("GitHub refused chapd's token (HTTP %d)", t.status)}
		}
		return un() // 5xx or a broken connection: the push may have landed
	case fwdErr != nil:
		return un()
	}
	if t.status < 200 || t.status > 299 {
		return ops.GitPushResult{Outcome: "failed", Detail: fmt.Sprintf("GitHub answered HTTP %d", t.status)}
	}
	if t.over {
		return un()
	}
	unpack, refs, bad := parseReport(t.buf)
	switch {
	case bad != "":
		return ops.GitPushResult{Outcome: "failed", Detail: bad}
	case unpack == "":
		return un()
	case unpack != "ok":
		return ops.GitPushResult{Outcome: "failed", Detail: "unpack failed: " + unpack}
	}
	if len(refs) != 1 {
		return un()
	}
	for _, v := range refs {
		if v == "ok" {
			return ops.GitPushResult{Outcome: "succeeded"}
		}
		return ops.GitPushResult{Outcome: "failed", Detail: "ref refused: " + v}
	}
	return un()
}

// parseReport reads a receive-pack answer, side-band wrapped or plain. unpack
// is the text after "unpack " ("ok" or an error); refs maps a ref to "ok" or
// the ng reason; bad is a fatal message from the server (band 3 or "ERR ...").
func parseReport(b []byte) (unpack string, refs map[string]string, bad string) {
	refs = map[string]string{}
	inner := b
	if len(b) >= 5 {
		var h [4]byte
		copy(h[:], b[:4])
		if n, ok := pktLen(h); ok && n > 4 && n <= len(b) && b[4] >= 1 && b[4] <= 3 {
			inner = nil
			for rest := b; len(rest) >= 4; {
				copy(h[:], rest[:4])
				n, ok := pktLen(h)
				if !ok || n > len(rest) {
					break
				}
				if n == 0 {
					rest = rest[4:]
					continue
				}
				if n < 4 {
					break
				}
				payload := rest[4:n]
				rest = rest[n:]
				if len(payload) == 0 {
					continue
				}
				switch payload[0] {
				case 1:
					inner = append(inner, payload[1:]...)
				case 3:
					return "", nil, "GitHub: " + clamp(strings.TrimSpace(string(payload[1:])), 200)
				}
			}
		}
	}
	return parseInner(inner, refs)
}

// parseInner reads the report-status pkt-lines.
func parseInner(b []byte, refs map[string]string) (string, map[string]string, string) {
	unpack := ""
	for rest := b; len(rest) >= 4; {
		var h [4]byte
		copy(h[:], rest[:4])
		n, ok := pktLen(h)
		if !ok || n > len(rest) {
			break
		}
		if n == 0 {
			rest = rest[4:]
			continue
		}
		if n < 4 {
			break
		}
		line := strings.TrimSuffix(string(rest[4:n]), "\n")
		rest = rest[n:]
		switch {
		case strings.HasPrefix(line, "unpack "):
			unpack = strings.TrimPrefix(line, "unpack ")
		case strings.HasPrefix(line, "ok "):
			refs[strings.TrimPrefix(line, "ok ")] = "ok"
		case strings.HasPrefix(line, "ng "):
			ref, why, _ := strings.Cut(strings.TrimPrefix(line, "ng "), " ")
			refs[ref] = clamp(why, 200)
			if refs[ref] == "" || refs[ref] == "ok" {
				refs[ref] = "ng"
			}
		case strings.HasPrefix(line, "ERR "):
			return "", nil, "GitHub: " + clamp(strings.TrimPrefix(line, "ERR "), 200)
		}
	}
	return unpack, refs, ""
}

func clamp(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
