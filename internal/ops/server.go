package ops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/denialtext"
	"github.com/joshua-noel/chaperone/internal/spec"
)

// ListenAddr is where chapd listens (loopback only; the console shares the port).
const ListenAddr = "127.0.0.1:55398"

const (
	maxBody        = 1 << 20
	defaultSubmitW = 20 * time.Second
)

// RunsBackend is the runs registry (internal/runtoken, L1-04). Values are the
// JSON documents of api/openapi.yaml (Run, RunPage). Errors: *VerifyError for a
// refused control token (answered as an unidentified-caller error), *NotFoundError,
// *ConflictError.
type RunsBackend interface {
	Register(ctx context.Context, control, token string) (any, error)
	End(ctx context.Context, runID string, e RunEnd) (any, error)
	Revoke(ctx context.Context, runID string) (any, error)
	RevokeAll(ctx context.Context) (int, error)
	List(ctx context.Context, state string, limit int, after string) (any, error)
	// Status is GET /v0/runs/{id}: control is a control JWT (act run.status).
	Status(ctx context.Context, control, runID string) (any, error)
}

// RunEnd is the body of POST /v0/runs/{id}/end.
type RunEnd struct {
	Control      string `json:"control"`
	Outcome      string `json:"outcome"`
	CauseCode    string `json:"cause_code"`
	ActualTokens int64  `json:"actual_tokens"`
}

// InterimBackend mints interim run tokens (L1-04). bearer is the caller's own
// orchestrator token, which the minter verifies again.
type InterimBackend interface {
	Mint(ctx context.Context, bearer string, req DevTokenRequest) (any, error)
}

// DevTokenRequest is components.schemas.DevTokenRequest.
type DevTokenRequest struct {
	Project string   `json:"project"`
	Profile string   `json:"profile"`
	Repo    string   `json:"repo"`
	Base    string   `json:"base"`
	Branch  string   `json:"branch"`
	Paths   []string `json:"paths"`
	Ops     []string `json:"ops"`
	Minutes int      `json:"minutes"`
}

// LedgerQuery is the filter of GET /v0/ledger, already narrowed to what the
// caller may read: a run is held to its run_id; the orchestrator reads the
// whole chain, so a read with no filters is gap-free.
type LedgerQuery struct {
	RunID     string
	RequestID string
	EventName string
	From, To  time.Time
	AfterSeq  *int64
	Limit     int
}

// LedgerBackend reads and verifies the ledger (L1-02).
type LedgerBackend interface {
	Query(ctx context.Context, q LedgerQuery) (items []json.RawMessage, nextSeq *int64, err error)
	Verify(ctx context.Context, againstExport bool) (any, error)
}

// Limits on `chap ledger verify --anchor` input.
const (
	MaxAnchorRecords = 2000 // a record is under 600 bytes; the body limit is 1 MiB
	MaxAnchorKeys    = 8
)

// AnchorVerifier is an optional capability of a [LedgerBackend] (L1-21): compare
// the chain with the signed anchor records copied off the server. When the backend
// lacks it, `anchor: true` is answered as unavailable.
type AnchorVerifier interface {
	VerifyAnchors(ctx context.Context, req AnchorVerifyRequest) (any, error)
}

// AnchorVerifyRequest is the body of POST /v0/ledger/verify with `anchor: true`.
type AnchorVerifyRequest struct {
	AgainstExport bool
	// Records are further record lines (a copy restored from the backup, or
	// typed from the phone), besides the file chapd keeps.
	Records []string
	// Keys are extra trusted ledger public keys (after a rotation).
	Keys []string
}

// AnchorInputError is returned by [AnchorVerifier.VerifyAnchors] when a
// supplied record or key is malformed; it is answered as OP_PARAMS_INVALID.
type AnchorInputError struct{ Why string }

func (e *AnchorInputError) Error() string { return e.Why }

// VaultBackend reports vault status without any value (L1-03).
type VaultBackend interface {
	Status(ctx context.Context) (any, error)
}

// ServerConfig wires the HTTP layer.
type ServerConfig struct {
	Svc     *Service
	Auth    *Auth
	Version string
	// AllowInterim reports ADR-005's allow_interim flag. Nil means true.
	AllowInterim func() bool

	// ApproverCredentials counts the live approver (WebAuthn) credentials. It
	// feeds `approver_credentials` in GET /v0/status for orchestrator callers
	// only (`chap doctor` checks that Windows Hello is enrolled). Nil omits it.
	ApproverCredentials func(context.Context) (int, error)

	// Hosts lists the Host header values chapd answers to (DNS-rebinding
	// defence). Empty means 127.0.0.1:55398 and localhost:55398.
	Hosts []string

	Runs    RunsBackend    // optional: /v0/runs routes are unmounted when nil
	Interim InterimBackend // optional
	Ledger  LedgerBackend  // optional
	Vault   VaultBackend   // optional
	Git     GitHandler     // optional: /git/ is unmounted when nil (the git proxy, L1-09)
	Keys    KeyAdmin       // optional: /v0/keys routes are unmounted when nil
	Host    http.Handler   // optional: /v0/host/ is unmounted when nil (chap-host's routes, [HostBus.Handler])
}

// Server is chapd's HTTP handler for the routes of api/openapi.yaml.
type Server struct {
	cfg ServerConfig
	mux *http.ServeMux
}

// NewServer builds the handler. Every route but POST /v0/runs and its /end
// (which carry a control JWT in the body) goes through [Auth].
func NewServer(cfg ServerConfig) *Server {
	s := &Server{cfg: cfg, mux: http.NewServeMux()}
	auth := func(h func(http.ResponseWriter, *http.Request, *Caller)) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := cfg.Auth.Authenticate(r)
			if err != nil {
				s.fail(w, r, err)
				return
			}
			ctx := context.WithValue(r.Context(), callerKey, c)
			if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				ctx = context.WithValue(ctx, bearerKey, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			}
			h(w, r.WithContext(ctx), c)
		})
	}
	m := s.mux
	m.Handle("GET /v0/status", auth(s.status))
	m.Handle("POST /v0/ops", auth(s.submitOp))
	m.Handle("GET /v0/ops", auth(s.listOps))
	m.Handle("GET /v0/ops/{id}", auth(s.getOp))
	m.Handle("POST /v0/ops/{id}/cancel", auth(s.cancelOp))
	m.Handle("POST /v0/approvals", auth(s.requestApproval))
	m.Handle("GET /v0/approvals", auth(s.listApprovals))
	m.Handle("GET /v0/approvals/{id}", auth(s.getApproval))
	m.Handle("GET /v0/catalog", auth(s.catalog))
	if cfg.Runs != nil {
		m.HandleFunc("POST /v0/runs", s.registerRun)
		m.HandleFunc("POST /v0/runs/{id}/end", s.endRun)
		m.Handle("GET /v0/runs", auth(s.listRuns))
		m.HandleFunc("GET /v0/runs/{id}", s.runStatus)
		m.Handle("POST /v0/runs/{id}/revoke", auth(s.revokeRun))
		m.Handle("POST /v0/runs/revoke-all", auth(s.revokeAllRuns))
	}
	if cfg.Keys != nil {
		m.Handle("GET /v0/keys", auth(s.listKeys))
		m.Handle("GET /v0/keys/{id}", auth(s.getKey))
		m.Handle("POST /v0/keys/{id}/claim", auth(s.claimKey))
		m.Handle("POST /v0/keys/{id}/revoke", auth(s.revokeKey))
	}
	if cfg.Interim != nil {
		m.Handle("POST /v0/dev-tokens", auth(s.mintInterim))
	}
	if cfg.Ledger != nil {
		m.Handle("GET /v0/ledger", auth(s.queryLedger))
		m.Handle("POST /v0/ledger/verify", auth(s.verifyLedger))
	}
	if cfg.Vault != nil {
		m.Handle("GET /v0/vault/status", auth(s.vaultStatus))
	}
	if cfg.Git != nil {
		m.Handle("/git/", auth(s.git))
	}
	if cfg.Host != nil {
		// chap-host's three routes. They take the host token only, checked by the
		// handler itself ([HostBus.Handler]); a run or orchestrator token is refused there.
		m.Handle(hostPathPrefix, cfg.Host)
	}
	return s
}

type bearerCtxKey int

const bearerKey bearerCtxKey = 1

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.hostOK(r.Host) {
		http.Error(w, "unknown host", http.StatusMisdirectedRequest)
		return
	}
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	s.mux.ServeHTTP(w, r)
}

func (s *Server) hostOK(host string) bool {
	hosts := s.cfg.Hosts
	if len(hosts) == 0 {
		hosts = []string{"127.0.0.1:55398", "localhost:55398"}
	}
	for _, h := range hosts {
		if strings.EqualFold(host, h) {
			return true
		}
	}
	return false
}

// ---- responses -------------------------------------------------------------

func (s *Server) writeJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		s.fail(w, r, &UnavailableError{Why: "could not encode the response", Err: err})
		return
	}
	s.send(w, r, status, body, string(body))
}

// writeMinted sends the answer to POST /v0/dev-tokens. That answer is the one
// place chapd hands out a secret: the freshly minted run token, which is a JWT
// and so would always trip the redactor. Only the value of the top-level
// "token" field is left out of the scan. Every other field, and a copy of the
// token anywhere else in the body, is scanned as for any response.
func (s *Server) writeMinted(w http.ResponseWriter, r *http.Request, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		s.fail(w, r, &UnavailableError{Why: "could not encode the response", Err: err})
		return
	}
	scan := string(body)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err == nil {
		if tok, ok := fields["token"]; ok {
			var str string
			if json.Unmarshal(tok, &str) == nil {
				fields["token"] = json.RawMessage(`"minted"`)
				if masked, err := json.Marshal(fields); err == nil {
					scan = string(masked)
				}
			}
		}
	}
	s.send(w, r, status, body, scan)
}

// send writes body unless the redactor finds a secret in scan.
func (s *Server) send(w http.ResponseWriter, r *http.Request, status int, body []byte, scan string) {
	if red := s.cfg.Svc.redactor; red != nil {
		if _, res := red.Redact(scan); res.Blocked() {
			// Never send what would leak. This is a denial, ledgered like any.
			c := CallerFrom(r.Context())
			if c != nil {
				err := s.cfg.Svc.deny(r.Context(), c, denial{Project: s.projectOf(c), Surface: "output", Verb: "respond", Target: r.URL.Path, Code: CodeRedactionBlocked, Why: "the response contained a secret and was not sent"})
				s.fail(w, r, err)
				return
			}
			s.fail(w, r, &UnavailableError{Why: "the response contained a secret and was not sent"})
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (s *Server) projectOf(c *Caller) string {
	switch c.Kind {
	case KindRun, KindKey:
		return c.Project
	case KindOrchestrator:
		if len(c.Projects) > 0 {
			return c.Projects[0]
		}
	}
	return "unknown"
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var de *DeniedError
	var ae *authError
	var ue *UnavailableError
	var nf *NotFoundError
	var ce *ConflictError
	w.Header().Set("Content-Type", "application/json")
	switch {
	case errors.As(err, &de):
		if de.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(de.RetryAfter))
		}
		if strings.HasPrefix(r.URL.Path, "/git/") && !strings.Contains(r.Header.Get("Accept"), "application/json") {
			w.Header().Set("X-Chaperone-Denial-Id", de.Denial.DenialID)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(de.Status)
			_, _ = io.WriteString(w, RenderDenial(de.Denial))
			return
		}
		w.WriteHeader(de.Status)
		_ = json.NewEncoder(w).Encode(de.Denial)
	case errors.As(err, &ae):
		challenge := `Bearer realm="chapd"`
		if strings.HasPrefix(r.URL.Path, "/git/") {
			challenge = `Basic realm="chapd"` // libcurl, and so git, answers Basic only
		}
		w.Header().Set("WWW-Authenticate", challenge)
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type": "auth_error", "cause_code": CodeTokenInvalid, "why": clamp(ae.Why, 500),
			"request": map[string]any{"possible": false},
		})
	case errors.As(err, &nf):
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "not_found", "why": clamp(nf.Why, 500)})
	case errors.As(err, &ce):
		w.WriteHeader(http.StatusConflict)
		body := map[string]any{"type": "conflict", "why": clamp(ce.Why, 500)}
		if ce.State != "" {
			body["state"] = string(ce.State)
		}
		_ = json.NewEncoder(w).Encode(body)
	default:
		// Includes *UnavailableError. The cause stays in the log, not the body.
		retry := true
		why := "chapd failed closed; nothing was executed"
		if errors.As(err, &ue) {
			retry, why = ue.Retryable, clamp(ue.Why, 500)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "unavailable", "why": why, "retryable": retry})
	}
}

// RenderDenial is the spec's three-line text form of a denial.
func RenderDenial(d spec.Denial) string {
	var b strings.Builder
	who := "orchestrator " + d.OrchestratorID
	if d.RunID != "" {
		who = "profile " + d.Profile + ", run " + d.RunID
	}
	b.WriteString("DENIED " + d.Action.Verb + " " + d.Action.Target + " (" + who + ")\n")
	b.WriteString("why: " + d.Why + "\n")
	next := denialtext.NextStep(d.CauseCode, d.Why, d.OrchestratorID)
	switch {
	case d.Request.Possible:
		b.WriteString("request: " + d.Request.Command + "\n")
	case next != "":
		b.WriteString("next: " + next + "\n")
	default:
		b.WriteString("request: not possible; policy does not allow asking\n")
	}
	return b.String()
}

// ---- request bodies --------------------------------------------------------

var (
	opKindRe   = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*$`)
	adapterRe  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,38}$`)
	approvalRe = regexp.MustCompile(`^a-[0-9a-z]{6,32}$`)
	hashRe     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	traceRe    = regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)
)

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, string) {
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(strings.ToLower(ct), "application/json") {
		return nil, "Content-Type must be application/json"
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		return nil, "the body is unreadable or larger than 1 MiB"
	}
	return data, ""
}

// parseSubmission validates an op or approval body into a Submission. It
// returns a human reason on failure (answered as OP_PARAMS_INVALID).
func parseSubmission(data []byte, c *Caller, approval bool) (*Submission, string) {
	tree, err := spec.ParseStrict(data)
	if err != nil {
		return nil, "the body is not valid I-JSON: " + err.Error()
	}
	m, ok := tree.(map[string]any)
	if !ok {
		return nil, "the body must be a JSON object"
	}
	allowed := map[string]bool{"op": true, "project": true, "target": true, "params": true, "op_hash": true,
		"reason": true, "approval_id": true, "traceparent": true, "dry_run": true}
	if approval {
		allowed["kind"] = true
	}
	for k := range m {
		if !allowed[k] {
			return nil, "unknown member " + strconv.Quote(clamp(k, 40))
		}
	}
	str := func(k string) (string, bool, string) {
		v, present := m[k]
		if !present {
			return "", false, ""
		}
		sv, ok := v.(string)
		if !ok {
			return "", true, k + " must be a string"
		}
		return sv, true, ""
	}
	sub := &Submission{}
	var present bool
	var bad string
	if sub.Op, present, bad = str("op"); bad != "" || !present || !opKindRe.MatchString(sub.Op) || len(sub.Op) > 64 {
		return nil, "op must be a dotted lowercase op kind"
	}
	if sub.Project, _, bad = str("project"); bad != "" {
		return nil, bad
	}
	if sub.Project != "" && !validProject(sub.Project) {
		return nil, "project is not a project slug"
	}
	if sub.Reason, present, bad = str("reason"); bad != "" || (present && (sub.Reason == "" || len(sub.Reason) > 500)) {
		return nil, "reason must be 1 to 500 characters"
	}
	if approval {
		if k, present, _ := str("kind"); !present || k != "op" {
			return nil, "kind must be \"op\" (net, pkg and scope requests belong to the runner)"
		}
		if sub.Reason == "" {
			return nil, "reason is required for an approval request"
		}
		if dr, ok := m["dry_run"]; ok && dr != false {
			return nil, "dry_run is not allowed on an approval request"
		}
		if _, ok := m["approval_id"]; ok {
			return nil, "approval_id is not allowed on an approval request"
		}
	}
	tg, ok := m["target"].(map[string]any)
	if !ok || len(tg) != 2 {
		return nil, "target must be {adapter, ref}"
	}
	ad, _ := tg["adapter"].(string)
	ref, _ := tg["ref"].(string)
	if !adapterRe.MatchString(ad) || ref == "" || len(ref) > 300 {
		return nil, "target must be {adapter, ref}"
	}
	sub.Target = spec.Target{Adapter: ad, Ref: ref}
	params, ok := m["params"].(map[string]any)
	if !ok {
		return nil, "params must be an object"
	}
	sub.Params = params
	if h, present, bad := str("op_hash"); bad != "" || (present && !hashRe.MatchString(h)) {
		return nil, "op_hash must be sha256:<64 lowercase hex>"
	} else if present {
		sub.OpHash = h
	}
	if sub.ApprovalID, present, bad = str("approval_id"); bad != "" || (present && !approvalRe.MatchString(sub.ApprovalID)) {
		return nil, "approval_id has the wrong shape"
	}
	if sub.Traceparent, present, bad = str("traceparent"); bad != "" || (present && !traceRe.MatchString(sub.Traceparent)) {
		return nil, "traceparent has the wrong shape"
	}
	if v, ok := m["dry_run"]; ok {
		b, isBool := v.(bool)
		if !isBool {
			return nil, "dry_run must be true or false"
		}
		sub.DryRun = b
	}

	// The hash covers the project chapd resolves, never one the body invented.
	project := sub.Project
	if c.Kind == KindRun || c.Kind == KindKey {
		project = c.Project
	}
	sent := sub.OpHash
	if project != "" {
		jcs, err := spec.JCS(params)
		if err != nil {
			return nil, "params cannot be hashed: " + err.Error()
		}
		sub.ParamsJSON = string(jcs)
		h, err := spec.OpHash(map[string]any{
			"spec_version": spec.SpecVersion, "project": project, "op": sub.Op,
			"target": map[string]any{"adapter": ad, "ref": ref}, "params": params,
		})
		if err != nil {
			return nil, "the request cannot be hashed: " + err.Error()
		}
		if sent != "" && sent != h {
			return nil, "op_hash differs from the hash chapd computed for this request"
		}
		sub.OpHash = h
	}
	return sub, ""
}

func parseWait(r *http.Request, def time.Duration) (time.Duration, bool) {
	v := r.URL.Query().Get("wait")
	if v == "" {
		return def, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 55 {
		return 0, false
	}
	return time.Duration(n) * time.Second, true
}

// paramsInvalid refuses a malformed request as OP_PARAMS_INVALID.
func (s *Server) paramsInvalid(w http.ResponseWriter, r *http.Request, c *Caller, why string) {
	s.fail(w, r, s.cfg.Svc.deny(r.Context(), c, denial{
		Project: s.projectOf(c), Verb: "request", Target: r.URL.Path, Code: CodeParamsInvalid, Why: why,
	}))
}

// ---- handlers --------------------------------------------------------------

func (s *Server) submitOp(w http.ResponseWriter, r *http.Request, c *Caller) {
	s.submit(w, r, c, ModeOp)
}
func (s *Server) requestApproval(w http.ResponseWriter, r *http.Request, c *Caller) {
	s.submit(w, r, c, ModeApproval)
}

func (s *Server) submit(w http.ResponseWriter, r *http.Request, c *Caller, mode Mode) {
	data, bad := readBody(w, r)
	if bad != "" {
		s.paramsInvalid(w, r, c, bad)
		return
	}
	sub, bad := parseSubmission(data, c, mode == ModeApproval)
	if bad != "" {
		s.paramsInvalid(w, r, c, bad)
		return
	}
	wait, ok := parseWait(r, defaultSubmitW)
	if !ok {
		s.paramsInvalid(w, r, c, "wait must be 0 to 55 seconds")
		return
	}
	if mode == ModeApproval {
		wait = 0
	}
	res, err := s.cfg.Svc.Submit(r.Context(), c, sub, mode, wait)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if res.Verdict != nil {
		s.writeJSON(w, r, http.StatusOK, res.Verdict)
		return
	}
	s.writeOp(w, r, res.Op)
}

func (s *Server) writeOp(w http.ResponseWriter, r *http.Request, rec *record) {
	status := http.StatusOK
	if !rec.State.Terminal() {
		status = http.StatusAccepted
		w.Header().Set("Location", "/v0/ops/"+rec.ID)
	}
	s.writeJSON(w, r, status, s.view(r.Context(), rec))
}

func (s *Server) view(ctx context.Context, rec *record) opView {
	var info *ApprovalInfo
	if rec.ApprovalID != "" && s.cfg.Svc.appr != nil {
		if a, err := s.cfg.Svc.appr.Lookup(ctx, rec.ApprovalID); err == nil {
			info = &a
		}
	}
	return rec.view(info)
}

func (s *Server) getOp(w http.ResponseWriter, r *http.Request, c *Caller) {
	wait, ok := parseWait(r, 0)
	if !ok {
		s.paramsInvalid(w, r, c, "wait must be 0 to 55 seconds")
		return
	}
	since := State(r.URL.Query().Get("since_state"))
	rec, err := s.cfg.Svc.Get(r.Context(), c, r.PathValue("id"), wait, since)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, s.view(r.Context(), rec))
}

func (s *Server) cancelOp(w http.ResponseWriter, r *http.Request, c *Caller) {
	rec, err := s.cfg.Svc.Cancel(r.Context(), c, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, s.view(r.Context(), rec))
}

func (s *Server) listOps(w http.ResponseWriter, r *http.Request, c *Caller) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	recs, next, err := s.cfg.Svc.List(r.Context(), c, State(r.URL.Query().Get("state")), limit, r.URL.Query().Get("cursor"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]opView, 0, len(recs))
	for _, rec := range recs {
		items = append(items, s.view(r.Context(), rec))
	}
	var nc any
	if next != "" {
		nc = next
	}
	s.writeJSON(w, r, http.StatusOK, map[string]any{"items": items, "next_cursor": nc})
}

func (s *Server) listApprovals(w http.ResponseWriter, r *http.Request, c *Caller) {
	items := []*approvalView{}
	var nc any
	if s.cfg.Svc.appr != nil {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit < 1 || limit > 200 {
			limit = 50
		}
		infos, next, err := s.cfg.Svc.appr.List(r.Context(), c.Key(), r.URL.Query().Get("state"), limit, r.URL.Query().Get("cursor"))
		if err != nil {
			s.fail(w, r, &UnavailableError{Why: "the approval store could not be read", Retryable: true, Err: err})
			return
		}
		for _, a := range infos {
			items = append(items, a.view())
		}
		if next != "" {
			nc = next
		}
	}
	s.writeJSON(w, r, http.StatusOK, map[string]any{"items": items, "next_cursor": nc})
}

func (s *Server) getApproval(w http.ResponseWriter, r *http.Request, c *Caller) {
	nf := &NotFoundError{Why: "no such approval for this caller"}
	if s.cfg.Svc.appr == nil {
		s.fail(w, r, nf)
		return
	}
	info, err := s.cfg.Svc.appr.Lookup(r.Context(), r.PathValue("id"))
	if errors.Is(err, ErrApprovalNotFound) || (err == nil && info.OwnerKey != c.Key()) {
		s.fail(w, r, nf)
		return
	}
	if err != nil {
		s.fail(w, r, &UnavailableError{Why: "the approval store could not be read", Retryable: true, Err: err})
		return
	}
	s.writeJSON(w, r, http.StatusOK, info.view())
}

func (s *Server) status(w http.ResponseWriter, r *http.Request, c *Caller) {
	project := s.projectOf(c)
	eff := s.cfg.Svc.policy.For(project)
	allow := true
	if s.cfg.AllowInterim != nil {
		allow = s.cfg.AllowInterim()
	}
	req := c.requesterView()
	appr := "unavailable"
	if s.cfg.Svc.ApprovalsAvailable() {
		appr = "available"
	}
	body := map[string]any{
		"version": s.cfg.Version, "policy_version": eff.Version, "requester": req, "project": project,
		"approvals": appr, "allow_interim": allow, "git_proxy": "/git/",
	}
	if !c.Expires.IsZero() {
		body["token_expires_at"] = ts(c.Expires)
	} else {
		body["token_expires_at"] = ts(time.Now().Add(time.Hour))
	}
	if c.Kind == KindOrchestrator && s.cfg.ApproverCredentials != nil {
		n, err := s.cfg.ApproverCredentials(r.Context())
		if err != nil {
			s.fail(w, r, &UnavailableError{Why: "the approver credentials could not be counted", Retryable: true, Err: err})
			return
		}
		body["approver_credentials"] = n
	}
	s.writeJSON(w, r, http.StatusOK, body)
}

// catalog serves GET /v0/catalog (and with it the `chap manual` data).
func (s *Server) catalog(w http.ResponseWriter, r *http.Request, c *Caller) {
	q := r.URL.Query()
	svc := s.cfg.Svc
	cat := svc.policy.Catalog()

	project := s.projectOf(c)
	switch c.Kind {
	case KindOrchestrator:
		if p := q.Get("project"); p != "" {
			if !containsString(c.Projects, p) {
				s.fail(w, r, svc.deny(r.Context(), c, denial{Project: project, Verb: "request", Target: "catalog", Code: CodeOpNotInToken, Why: "project " + p + " is not in this orchestrator token's scope"}))
				return
			}
			project = p
		}
	case KindRun, KindKey:
		if p := q.Get("project"); p != "" && p != c.Project {
			s.paramsInvalid(w, r, c, "project differs from the "+c.kindNoun()+"'s project")
			return
		}
	default:
		s.fail(w, r, svc.deny(r.Context(), c, denial{Project: project, Verb: "request", Target: "catalog", Code: CodeOpNotInToken, Why: "this caller's kind is not handled"}))
		return
	}
	all := q.Get("all") == "true"
	if all && c.Kind != KindOrchestrator {
		s.fail(w, r, svc.deny(r.Context(), c, denial{Project: project, Verb: "request", Target: "catalog", Code: CodeOpNotInToken, Why: "only the orchestrator may list disabled ops"}))
		return
	}
	eff := svc.policy.For(project)
	profile := q.Get("profile")

	var ops []string
	switch {
	case profile != "":
		ceiling, ok := eff.ProfileCeiling(profile)
		if !ok {
			s.paramsInvalid(w, r, c, "unknown profile "+strconv.Quote(clamp(profile, 40)))
			return
		}
		ops = ceiling
	case all:
		ops = cat.Ops()
	default:
		for _, op := range cat.Ops() {
			if !spec.OpAllowed(op, c.opPatterns()) {
				continue
			}
			switch c.Kind {
			case KindRun:
				if ceiling, ok := eff.ProfileCeiling(c.Profile); !ok || !containsString(ceiling, op) {
					continue
				}
			case KindKey:
				if svc.keyCeiling(op) != "" {
					continue
				}
			}
			ops = append(ops, op)
		}
	}
	entries := []map[string]any{}
	sort.Strings(ops)
	for _, op := range ops {
		e, ok := cat.Lookup(op)
		if !ok {
			continue
		}
		// An op the baseline turns on but this chapd has no adapter for (no GitHub
		// App configured, say) is refused at request time, so it is not offered.
		_, wired := svc.adapters[op]
		enabled := eff.Enabled(op) && wired
		if !enabled && !all {
			continue
		}
		entries = append(entries, map[string]any{
			"op": op, "class": string(e.Class), "reversibility": e.Reversibility, "surface": e.Surface,
			"enabled": enabled, "needs_approval": e.Class.NeedsApproval(), "summary": e.Summary, "usage": e.Usage,
		})
	}
	body := map[string]any{"policy_version": eff.Version, "project": project, "ops": entries}
	if profile != "" {
		body["profile"] = profile
	}
	s.writeJSON(w, r, http.StatusOK, body)
}

// ---- orchestrator-only routes ---------------------------------------------

// orchOnly refuses a run token on a route only the orchestrator may call.
func (s *Server) orchOnly(w http.ResponseWriter, r *http.Request, c *Caller) bool {
	if c.Kind == KindOrchestrator {
		return true
	}
	s.fail(w, r, s.cfg.Svc.deny(r.Context(), c, denial{
		Project: c.Project, Surface: "token", Verb: "request", Target: r.URL.Path, Code: CodeOpNotInToken,
		Why: "this route is for the orchestrator token only",
	}))
	return false
}

func (s *Server) listRuns(w http.ResponseWriter, r *http.Request, c *Caller) {
	if !s.orchOnly(w, r, c) {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	v, err := s.cfg.Runs.List(r.Context(), r.URL.Query().Get("state"), limit, r.URL.Query().Get("cursor"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, v)
}

func (s *Server) revokeRun(w http.ResponseWriter, r *http.Request, c *Caller) {
	if !s.orchOnly(w, r, c) {
		return
	}
	v, err := s.cfg.Runs.Revoke(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, v)
}

func (s *Server) revokeAllRuns(w http.ResponseWriter, r *http.Request, c *Caller) {
	if !s.orchOnly(w, r, c) {
		return
	}
	n, err := s.cfg.Runs.RevokeAll(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, map[string]any{"revoked": n, "stop_code": "OPERATOR_STOP_ALL"})
}

// controlBody decodes {control[, token]} strictly.
func controlBody(w http.ResponseWriter, r *http.Request, out any) error {
	data, bad := readBody(w, r)
	if bad != "" {
		return &authError{bad}
	}
	if _, err := spec.ParseStrict(data); err != nil {
		return &authError{"the body is not valid I-JSON"}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return &authError{"the body has the wrong shape"}
	}
	return nil
}

func (s *Server) registerRun(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Control string `json:"control"`
		Token   string `json:"token"`
	}
	if err := controlBody(w, r, &b); err != nil {
		s.fail(w, r, err)
		return
	}
	v, err := s.cfg.Runs.Register(r.Context(), b.Control, b.Token)
	if err != nil {
		s.fail(w, r, controlErr(err))
		return
	}
	s.writeJSON(w, r, http.StatusCreated, v)
}

func (s *Server) endRun(w http.ResponseWriter, r *http.Request) {
	var b RunEnd
	if err := controlBody(w, r, &b); err != nil {
		s.fail(w, r, err)
		return
	}
	v, err := s.cfg.Runs.End(r.Context(), r.PathValue("id"), b)
	if err != nil {
		s.fail(w, r, controlErr(err))
		return
	}
	s.writeJSON(w, r, http.StatusOK, v)
}

// runStatus is GET /v0/runs/{id} (LF-2). The caller is a the runner control
// plane, identified by a control JWT in the one Authorization header. A run
// token and the orchestrator token are not control JWTs and are refused here;
// the orchestrator reads runs through GET /v0/runs.
func (s *Server) runStatus(w http.ResponseWriter, r *http.Request) {
	token, err := requestBearer(r)
	if err == nil && strings.HasPrefix(token, OrchPrefix) {
		err = &authError{"the orchestrator token cannot read this route; it takes a the runner control JWT"}
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v, err := s.cfg.Runs.Status(r.Context(), token, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, controlErr(err))
		return
	}
	s.writeJSON(w, r, http.StatusOK, v)
}

// controlErr maps a refused control JWT to the unidentified-caller body.
func controlErr(err error) error {
	var ve *VerifyError
	if errors.As(err, &ve) {
		return &authError{ve.Code + ": " + ve.Detail}
	}
	return err
}

func (s *Server) mintInterim(w http.ResponseWriter, r *http.Request, c *Caller) {
	if !s.orchOnly(w, r, c) {
		return
	}
	data, bad := readBody(w, r)
	if bad != "" {
		s.paramsInvalid(w, r, c, bad)
		return
	}
	var req DevTokenRequest
	if _, err := spec.ParseStrict(data); err != nil {
		s.paramsInvalid(w, r, c, "the body is not valid I-JSON")
		return
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.Profile != "host-interim" || req.Minutes < 1 || req.Minutes > 120 {
		s.paramsInvalid(w, r, c, "the dev-token request has the wrong shape (profile host-interim, minutes 1..120)")
		return
	}
	if !c.MintInterim || !containsString(c.Projects, req.Project) {
		s.fail(w, r, s.cfg.Svc.deny(r.Context(), c, denial{Project: s.projectOf(c), Surface: "token", Verb: "mint", Target: "dev-token", Code: CodeOpNotInToken, Why: "this orchestrator token may not mint interim tokens for " + req.Project}))
		return
	}
	bearer, _ := r.Context().Value(bearerKey).(string)
	v, err := s.cfg.Interim.Mint(r.Context(), bearer, req)
	if err != nil {
		var ve *VerifyError
		if errors.As(err, &ve) {
			s.fail(w, r, s.cfg.Svc.deny(r.Context(), c, denial{Project: s.projectOf(c), Surface: "token", Verb: "mint", Target: "dev-token", Code: ve.Code, Why: ve.Detail}))
			return
		}
		s.fail(w, r, err)
		return
	}
	s.writeMinted(w, r, http.StatusCreated, v)
}

func (s *Server) queryLedger(w http.ResponseWriter, r *http.Request, c *Caller) {
	q := r.URL.Query()
	lq := LedgerQuery{RunID: q.Get("run_id"), RequestID: q.Get("request_id"), EventName: q.Get("event_name")}
	switch c.Kind {
	case KindRun:
		if lq.RunID != "" && lq.RunID != c.RunID {
			s.fail(w, r, s.cfg.Svc.deny(r.Context(), c, denial{Project: c.Project, Verb: "read", Target: "ledger", Code: CodeOpNotInToken, Why: "a run may read only its own ledger events"}))
			return
		}
		lq.RunID = c.RunID
	case KindOrchestrator:
	default:
		s.fail(w, r, s.cfg.Svc.deny(r.Context(), c, denial{Project: s.projectOf(c), Verb: "read", Target: "ledger", Code: CodeOpNotInToken, Why: "only the orchestrator and a run (its own events) may read the ledger"}))
		return
	}
	for k, dst := range map[string]*time.Time{"from": &lq.From, "to": &lq.To} {
		if v := q.Get(k); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				s.paramsInvalid(w, r, c, k+" must be an RFC 3339 instant")
				return
			}
			*dst = t
		}
	}
	if v := q.Get("cursor"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			s.paramsInvalid(w, r, c, "cursor is not a ledger position")
			return
		}
		lq.AfterSeq = &n
	}
	lq.Limit, _ = strconv.Atoi(q.Get("limit"))
	if lq.Limit < 1 || lq.Limit > 200 {
		lq.Limit = 50
	}
	items, next, err := s.cfg.Ledger.Query(r.Context(), lq)
	if err != nil {
		s.fail(w, r, &UnavailableError{Why: "the ledger could not be read", Retryable: true, Err: err})
		return
	}
	if items == nil {
		items = []json.RawMessage{}
	}
	var nc any
	if next != nil {
		nc = strconv.FormatInt(*next, 10)
	}
	s.writeJSON(w, r, http.StatusOK, map[string]any{"items": items, "next_cursor": nc})
}

func (s *Server) verifyLedger(w http.ResponseWriter, r *http.Request, c *Caller) {
	if !s.orchOnly(w, r, c) {
		return
	}
	var b struct {
		AgainstExport bool     `json:"against_export"`
		Anchor        bool     `json:"anchor"`
		AnchorRecords []string `json:"anchor_records"`
		AnchorKeys    []string `json:"anchor_keys"`
	}
	if r.ContentLength != 0 {
		data, bad := readBody(w, r)
		if bad != "" {
			s.paramsInvalid(w, r, c, bad)
			return
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&b); err != nil {
			s.paramsInvalid(w, r, c, "the body has the wrong shape")
			return
		}
	}
	if !b.Anchor {
		if len(b.AnchorRecords) > 0 || len(b.AnchorKeys) > 0 {
			s.paramsInvalid(w, r, c, "anchor_records and anchor_keys need anchor: true")
			return
		}
		v, err := s.cfg.Ledger.Verify(r.Context(), b.AgainstExport)
		if err != nil {
			s.fail(w, r, &UnavailableError{Why: "the ledger could not be verified", Retryable: true, Err: err})
			return
		}
		s.writeJSON(w, r, http.StatusOK, v)
		return
	}
	if len(b.AnchorRecords) > MaxAnchorRecords || len(b.AnchorKeys) > MaxAnchorKeys {
		s.paramsInvalid(w, r, c, fmt.Sprintf("at most %d anchor_records and %d anchor_keys", MaxAnchorRecords, MaxAnchorKeys))
		return
	}
	av, ok := s.cfg.Ledger.(AnchorVerifier)
	if !ok {
		s.fail(w, r, &UnavailableError{Why: "ledger anchors are not turned on in this chapd", Retryable: false})
		return
	}
	v, err := av.VerifyAnchors(r.Context(), AnchorVerifyRequest{AgainstExport: b.AgainstExport, Records: b.AnchorRecords, Keys: b.AnchorKeys})
	var in *AnchorInputError
	if errors.As(err, &in) {
		s.paramsInvalid(w, r, c, in.Why)
		return
	}
	if err != nil {
		s.fail(w, r, &UnavailableError{Why: "the ledger anchors could not be verified", Retryable: true, Err: err})
		return
	}
	s.writeJSON(w, r, http.StatusOK, v)
}

func (s *Server) vaultStatus(w http.ResponseWriter, r *http.Request, c *Caller) {
	if !s.orchOnly(w, r, c) {
		return
	}
	v, err := s.cfg.Vault.Status(r.Context())
	if err != nil {
		s.fail(w, r, &UnavailableError{Why: "the vault status could not be read", Retryable: true, Err: err})
		return
	}
	s.writeJSON(w, r, http.StatusOK, v)
}
