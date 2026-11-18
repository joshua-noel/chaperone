package ops

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/joshua-noel/chaperone/internal/grant"
)

// This file is chapd's side of `chap-host` (ticket L1-14 built the helper; L1-15
// needs the other end): it signs an execution grant for the fixed `deploy`
// runbook, hands it to the helper over the helper's event stream, and waits
// for the helper to say how the runbook ended.
//
// What chapd decides and what it never does:
//
//   - A grant is signed only inside [HostBus.RunDeploy], which the deploy
//     adapter calls from Execute, that is, only for an op in `executing`
//     whose approval (or policy) allowed it. The grant names the runbook, the
//     SHA from the approved params (40 hex), the op hash, the requester, the
//     SHA-256 of the script the helper must run, a single-use nonce and an
//     expiry at most 5 minutes away. Nothing from an agent's text reaches the
//     host except that SHA.
//   - chapd never runs a script and never talks to WSL. Only the helper does,
//     and only after it verified the signature against the public key it pinned.
//   - The helper's routes accept the host token only. A run token, an
//     orchestrator token or no token is refused, so an agent cannot read a
//     grant off the stream or post a fake result.

const hostPathPrefix = "/v0/host/"

var (
	hostOpIDRe = regexp.MustCompile(`^q-[0-9a-z]{6,32}$`)
	deploySHA  = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// GrantSigner signs an execution grant. chapd's production signer reads the key
// from the vault inside one `vault.Use` call per signature, so the key never
// outlives it.
type GrantSigner interface {
	SignGrant(ctx context.Context, g grant.Grant) (string, error)
}

// StaticGrantSigner signs with a key held in memory. Tests use it; chapd does not.
type StaticGrantSigner ed25519.PrivateKey

// SignGrant implements [GrantSigner].
func (k StaticGrantSigner) SignGrant(_ context.Context, g grant.Grant) (string, error) {
	return grant.Sign(ed25519.PrivateKey(k), g)
}

// DeployRunbook is the name of the runbook in the grant allowlist.
const DeployRunbook = "deploy"

// HostJob is one runbook run chapd asks of the helper.
type HostJob struct {
	OpID   string  // the op's request id; the helper reports back on it
	OpHash string  // "sha256:<hex>" of the approved request
	SHA    string  // the commit to deploy: 40 lowercase hex
	Caller *Caller // who asked; their id goes into the grant
}

// Host outcomes the helper reports.
const (
	HostSucceeded = "succeeded"
	HostFailed    = "failed"
	HostTimeout   = "timeout"
	HostRefused   = "refused"
)

// HostResult is the helper's report.
type HostResult struct {
	Outcome  string // one of the Host* constants
	Code     string // a refusal code when Outcome is HostRefused
	ExitCode int
	// Output is the last part of the redacted output the helper streamed.
	Output string
}

// HostRunner runs the deploy runbook on the host. *[HostBus] is the production one.
type HostRunner interface {
	// RunDeploy returns when the helper reported, or with [ErrHostNotTaken]
	// when the grant ran out before the helper took it (so nothing ran), or
	// with another error when it cannot be known whether the runbook ran.
	RunDeploy(ctx context.Context, job HostJob) (HostResult, error)
}

// ErrHostNotTaken: the grant expired, or the context ended, before the helper
// received it. The runbook certainly did not run.
var ErrHostNotTaken = errors.New("ops: the host helper did not take the grant")

// HostBusConfig builds a [HostBus].
type HostBusConfig struct {
	// Signer signs grants with chapd's grant-signing key.
	Signer GrantSigner
	// Scripts maps a runbook name to the absolute path of the script the helper
	// will run. chapd hashes the file at signing time, so the helper's own copy
	// must have the same bytes (it refuses the grant otherwise).
	Scripts map[string]string
	// TokenFile holds the host token (the helper's credential). It is read on
	// every request so a rotated token takes effect without a restart.
	TokenFile string
	// TTL is how long a grant lives. Default 4 minutes, at most 5.
	TTL time.Duration
	// Redact masks secrets in the helper's output. Nil leaves it as it is.
	Redact func(string) string
	// Pending returns the number of approvals waiting for the operator, for the
	// helper's toast. Nil sends no count.
	Pending func(ctx context.Context) int
	Now     func() time.Time
	// KeepAlive is the period of the stream's comment lines. Default 20 s.
	KeepAlive time.Duration
}

// HostBus is the in-memory exchange between the deploy adapter and the helper.
// Nothing here is persisted: an op in `executing` when chapd stops becomes
// `unconfirmed` on the next start (the op lifecycle), and a grant not yet
// taken is gone.
type HostBus struct {
	cfg HostBusConfig

	mu   sync.Mutex
	jobs map[string]*hostJob
	wake chan struct{} // closed and replaced whenever the set of jobs changes
	conn int           // generation of the newest event stream

	// afterSnapshot, if set, runs in the event stream between picking up the
	// deliverable jobs and marking them taken. A test seam; nil in production.
	afterSnapshot func()
}

type hostJob struct {
	opID      string
	event     []byte // the SSE "grant" event
	exp       time.Time
	mu        sync.Mutex // guards delivered, withdrawn, acked and out
	delivered bool       // the grant was (or is being) written to a helper
	withdrawn bool       // the wait ended "not taken": the grant must never be written
	acked     bool
	result    chan HostResult // capacity 1
	out       tail
}

// NewHostBus returns a bus.
func NewHostBus(cfg HostBusConfig) (*HostBus, error) {
	if cfg.Signer == nil {
		return nil, errors.New("ops: the host bus needs the grant signer")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 4 * time.Minute
	}
	if cfg.TTL > grant.MaxLifetime {
		return nil, fmt.Errorf("ops: grant TTL %v is over the %v limit", cfg.TTL, grant.MaxLifetime)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.KeepAlive <= 0 {
		cfg.KeepAlive = 20 * time.Second
	}
	if cfg.Scripts[DeployRunbook] == "" {
		return nil, errors.New("ops: the host bus needs the path of the deploy script")
	}
	return &HostBus{cfg: cfg, jobs: map[string]*hostJob{}, wake: make(chan struct{})}, nil
}

const maxScriptBytes = 8 << 20

func hashScript(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("the deploy script cannot be opened")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxScriptBytes+1))
	if err != nil || len(b) > maxScriptBytes || len(b) == 0 {
		return "", errors.New("the deploy script cannot be read, is empty or is too large")
	}
	return grant.HashBytes(b), nil
}

// RunDeploy implements [HostRunner].
func (b *HostBus) RunDeploy(ctx context.Context, job HostJob) (HostResult, error) {
	if !hostOpIDRe.MatchString(job.OpID) {
		return HostResult{}, errors.New("ops: the op id has the wrong shape for a host run")
	}
	if !deploySHA.MatchString(job.SHA) {
		return HostResult{}, errors.New("ops: a deploy grant needs a full lower-case commit SHA")
	}
	if job.Caller == nil {
		return HostResult{}, errors.New("ops: a deploy grant needs the requester")
	}

	// A second call for the same op (a retry after a crash reuses the execution)
	// waits on the first run instead of signing a second grant.
	b.mu.Lock()
	j, running := b.jobs[job.OpID]
	b.mu.Unlock()
	if !running {
		var err error
		if j, err = b.sign(ctx, job); err != nil {
			return HostResult{}, err
		}
		b.mu.Lock()
		if prev, dup := b.jobs[job.OpID]; dup {
			j = prev
		} else {
			b.jobs[job.OpID] = j
			b.changedLocked()
		}
		b.mu.Unlock()
	}
	defer b.drop(job.OpID, j)

	expiry := time.NewTimer(j.exp.Sub(b.cfg.Now()))
	defer expiry.Stop()
	for {
		select {
		case r := <-j.result:
			j.mu.Lock()
			r.Output = j.out.String()
			j.mu.Unlock()
			return r, nil
		case <-expiry.C:
			if b.settle(j) {
				expiry.Reset(24 * time.Hour) // taken: now only the result or the context ends the wait
				continue
			}
			return HostResult{}, ErrHostNotTaken
		case <-ctx.Done():
			if b.settle(j) {
				return HostResult{}, fmt.Errorf("ops: waiting for the host was cut short after the helper took the grant: %w", ctx.Err())
			}
			return HostResult{}, ErrHostNotTaken
		}
	}
}

// settle is the wait's verdict on a grant, taken under the job's lock. It
// reports true if the helper has (or may have) the grant. Otherwise it
// withdraws the job, so a stream that already picked it up cannot write it
// afterwards, and "not taken" stays true.
func (b *HostBus) settle(j *hostJob) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.delivered {
		return true
	}
	j.withdrawn = true
	return false
}

func (b *HostBus) drop(opID string, j *hostJob) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.jobs[opID] == j {
		delete(b.jobs, opID)
		b.changedLocked()
	}
}

func (b *HostBus) changedLocked() {
	close(b.wake)
	b.wake = make(chan struct{})
}

func (b *HostBus) sign(ctx context.Context, job HostJob) (*hostJob, error) {
	script, err := hashScript(b.cfg.Scripts[DeployRunbook])
	if err != nil {
		return nil, fmt.Errorf("ops: %w", err)
	}
	nonce, err := grant.NewNonce()
	if err != nil {
		return nil, err
	}
	now := b.cfg.Now()
	g := grant.Grant{
		Op: "deploy", OpHash: job.OpHash, Runbook: DeployRunbook, ScriptSHA256: script,
		Args:  map[string]string{"sha": job.SHA},
		Nonce: nonce, IssuedAt: now.Unix(), ExpiresAt: now.Add(b.cfg.TTL).Unix(),
	}
	if job.Caller.Kind == KindRun {
		g.RunID = job.Caller.RunID
	} else {
		g.OrchestratorID = job.Caller.OrchID
	}
	token, err := b.cfg.Signer.SignGrant(ctx, g)
	if err != nil {
		return nil, err
	}
	ev, err := json.Marshal(map[string]string{"grant": token, "op_id": job.OpID})
	if err != nil {
		return nil, err
	}
	return &hostJob{opID: job.OpID, event: ev, exp: time.Unix(g.ExpiresAt, 0), result: make(chan HostResult, 1)}, nil
}

// ---- tail: the last bytes of a runbook's output ----------------------------

const tailBytes = 4 << 10

type tail struct{ b []byte }

func (t *tail) add(s string) {
	t.b = append(t.b, s...)
	if len(t.b) > tailBytes {
		t.b = append([]byte(nil), t.b[len(t.b)-tailBytes:]...)
	}
}

func (t *tail) String() string { return strings.ToValidUTF8(string(t.b), "") }

// ---- HTTP: the helper's three routes ---------------------------------------

// Handler serves /v0/host/events, /v0/host/runs/{op_id}/output and
// /v0/host/runs/{op_id}/result. Mount it at "/v0/host/". Every request needs
// the host token.
func (b *HostBus) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v0/host/events", b.events)
	mux.HandleFunc("POST /v0/host/runs/{op_id}/output", b.output)
	mux.HandleFunc("POST /v0/host/runs/{op_id}/result", b.report)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !b.authorized(r) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("WWW-Authenticate", `Bearer realm="chapd"`)
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"type": "auth_error", "cause_code": CodeTokenInvalid,
				"why": "this route takes the host token only", "request": map[string]any{"possible": false},
			})
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (b *HostBus) authorized(r *http.Request) bool {
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || got == "" {
		return false
	}
	raw, err := os.ReadFile(b.cfg.TokenFile)
	if err != nil {
		return false
	}
	want := strings.TrimSpace(string(raw))
	return want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func conflict(w http.ResponseWriter, why string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "conflict", "why": why})
}

func (b *HostBus) events(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	// The server's write timeout is for ordinary calls; a stream lives on.
	send := func(s string) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := io.WriteString(w, s); err != nil {
			return false
		}
		return rc.Flush() == nil
	}

	b.mu.Lock()
	b.conn++
	mine := b.conn
	b.mu.Unlock()

	lastPending := -1
	keep := time.NewTicker(b.cfg.KeepAlive)
	defer keep.Stop()
	sent := map[*hostJob]bool{}
	for {
		// Newest stream wins: one helper at a time may hold a grant.
		b.mu.Lock()
		current := b.conn == mine
		wake := b.wake
		b.mu.Unlock()
		if !current {
			return
		}
		if b.cfg.Pending != nil {
			if n := b.cfg.Pending(r.Context()); n != lastPending {
				lastPending = n
				if !send(fmt.Sprintf("event: approvals.pending\ndata: {\"count\":%d}\n\n", n)) {
					return
				}
			}
		}
		snapshot := b.deliverable()
		if b.afterSnapshot != nil {
			b.afterSnapshot()
		}
		for _, j := range snapshot {
			if sent[j] {
				continue // once per stream: a repeat would only draw a replay refusal from the helper
			}
			// Marked taken before the write: once the bytes can reach the
			// helper it may act at once (output, a result) and must be heard,
			// and a wait cut short from here on must not claim the run
			// certainly did not happen. A failed write may still have delivered
			// part of the event, so the job stays taken (unknown). A job whose
			// wait already ended "not taken" is withdrawn: nothing is written.
			if !j.markDelivered() {
				continue
			}
			if !send("event: grant\ndata: " + string(j.event) + "\n\n") {
				return
			}
			sent[j] = true
		}
		select {
		case <-r.Context().Done():
			return
		case <-wake:
		case <-keep.C:
			if !send(": keep-alive\n\n") {
				return
			}
		}
	}
}

// deliverable returns the jobs whose grant the helper has not acknowledged and
// that are still valid. A reconnecting helper gets them again on its new
// stream; the helper's nonce store refuses a grant it already ran.
func (b *HostBus) deliverable() []*hostJob {
	now := b.cfg.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []*hostJob
	for _, j := range b.jobs {
		j.mu.Lock()
		skip := j.acked || j.withdrawn || !now.Before(j.exp)
		j.mu.Unlock()
		if !skip {
			out = append(out, j)
		}
	}
	return out
}

// markDelivered records, under the job's lock, that the grant is being written
// to a helper's stream. It reports false when RunDeploy has already withdrawn
// the job: the grant must then not be written. The mark and the withdrawal
// exclude each other, so the wait's "not taken" verdict is true for good.
func (j *hostJob) markDelivered() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.withdrawn {
		return false
	}
	j.delivered = true
	return true
}

func (b *HostBus) find(w http.ResponseWriter, r *http.Request) *hostJob {
	id := r.PathValue("op_id")
	if !hostOpIDRe.MatchString(id) {
		http.Error(w, "bad op id", http.StatusBadRequest)
		return nil
	}
	b.mu.Lock()
	j := b.jobs[id]
	b.mu.Unlock()
	ok := false
	if j != nil {
		j.mu.Lock()
		ok = j.delivered
		j.mu.Unlock()
	}
	if !ok {
		conflict(w, "the op is not executing on the host")
		return nil
	}
	return j
}

func (b *HostBus) output(w http.ResponseWriter, r *http.Request) {
	j := b.find(w, r)
	if j == nil {
		return
	}
	chunk, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(chunk) > maxBody {
		http.Error(w, "bad chunk", http.StatusBadRequest)
		return
	}
	s := string(bytes.ToValidUTF8(chunk, nil))
	if b.cfg.Redact != nil {
		s = b.cfg.Redact(s)
	}
	j.mu.Lock()
	j.acked = true
	j.out.add(s)
	j.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (b *HostBus) report(w http.ResponseWriter, r *http.Request) {
	j := b.find(w, r)
	if j == nil {
		return
	}
	var body struct {
		ExitCode *int   `json:"exit_code"`
		Outcome  string `json:"outcome"`
		Code     string `json:"code"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || body.ExitCode == nil || len(body.Code) > 48 {
		http.Error(w, "bad result", http.StatusBadRequest)
		return
	}
	switch body.Outcome {
	case HostSucceeded, HostFailed, HostTimeout, HostRefused:
	default:
		http.Error(w, "bad outcome", http.StatusBadRequest)
		return
	}
	j.mu.Lock()
	j.acked = true
	j.mu.Unlock()
	select {
	case j.result <- HostResult{Outcome: body.Outcome, Code: body.Code, ExitCode: *body.ExitCode}:
		w.WriteHeader(http.StatusNoContent)
	default:
		conflict(w, "a result was already recorded")
	}
}
