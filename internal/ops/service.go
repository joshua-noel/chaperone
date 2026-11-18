package ops

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/redact"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// Redactor masks secrets in a string. *redact.Registry is one.
type Redactor interface {
	Redact(s string) (string, redact.Result)
}

// Config configures a [Service].
type Config struct {
	DB       *store.DB
	Ledger   Ledger
	Policy   *policy.Engine
	Adapters map[string]Adapter // by op kind
	// Approvals is the approvals engine (L1-12). Nil means it is not running:
	// ops that need a card are refused OP_APPROVAL_REQUIRED and
	// /v0/approvals answers APPROVAL_UNAVAILABLE.
	Approvals Approvals
	Alerter   Alerter  // optional
	Redactor  Redactor // optional; masks adapter results before they are stored
	Now       func() time.Time
	Log       *slog.Logger
	// ExecTimeout bounds one adapter Execute call. Default 5 minutes.
	ExecTimeout time.Duration
}

// Service runs the op lifecycle.
type Service struct {
	db       *store.DB
	led      Ledger
	policy   *policy.Engine
	adapters map[string]Adapter
	appr     Approvals
	alert    Alerter
	redactor Redactor
	nowFn    func() time.Time
	log      *slog.Logger
	execTO   time.Duration

	// idFn lets tests choose ids; nil means random.
	idFn func(prefix string) string

	// inflight remembers ops being released by this process so that the same
	// op is never released twice concurrently. The state CAS is the real guard.
	mu       sync.Mutex
	inflight map[string]chan struct{}
}

// NewService builds a service. It does not touch the database.
func NewService(cfg Config) (*Service, error) {
	switch {
	case cfg.DB == nil:
		return nil, errors.New("ops: no database")
	case cfg.Ledger == nil:
		return nil, errors.New("ops: no ledger (an op never runs without one)")
	case cfg.Policy == nil:
		return nil, errors.New("ops: no policy engine")
	}
	s := &Service{
		db: cfg.DB, led: cfg.Ledger, policy: cfg.Policy, adapters: cfg.Adapters,
		appr: cfg.Approvals, alert: cfg.Alerter, redactor: cfg.Redactor,
		nowFn: cfg.Now, log: cfg.Log, execTO: cfg.ExecTimeout,
		inflight: map[string]chan struct{}{},
	}
	if s.nowFn == nil {
		s.nowFn = time.Now
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.execTO <= 0 {
		s.execTO = 5 * time.Minute
	}
	if s.adapters == nil {
		s.adapters = map[string]Adapter{}
	}
	return s, nil
}

func (s *Service) now() time.Time { return s.nowFn() }

// ApprovalsAvailable reports whether an approvals engine is wired.
func (s *Service) ApprovalsAvailable() bool { return s.appr != nil }

// Policy returns the policy engine.
func (s *Service) Policy() *policy.Engine { return s.policy }

const idAlphabet = "0123456789abcdefghijklmnopqrstuvwxyz"

func (s *Service) newID(prefix string) string {
	if s.idFn != nil {
		return s.idFn(prefix)
	}
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("ops: crypto/rand failed: " + err.Error())
	}
	out := make([]byte, len(b))
	for i, v := range b {
		out[i] = idAlphabet[int(v)%len(idAlphabet)]
	}
	return prefix + string(out)
}

func (s *Service) unavailable(why string, err error) error {
	s.log.Error("ops: failing closed", "why", why, "err", err)
	return &UnavailableError{Why: why, Retryable: true, Err: err}
}

// Submission is a validated request body (see the HTTP layer).
type Submission struct {
	Op          string
	Project     string // as sent; may be empty for a run
	Target      spec.Target
	Params      map[string]any
	ParamsJSON  string // JCS form of Params, what OpHash covers
	OpHash      string // computed by chapd
	Reason      string
	ApprovalID  string
	Traceparent string
	DryRun      bool
}

// Mode says which route a submission came through.
type Mode int

const (
	// ModeOp is POST /v0/ops.
	ModeOp Mode = iota
	// ModeApproval is POST /v0/approvals (`chap request op ...`).
	ModeApproval
)

// DryRunVerdict is the answer to a dry run.
type DryRunVerdict struct {
	Type          string       `json:"type"`
	WouldAllow    bool         `json:"would_allow"`
	Outcome       string       `json:"outcome"` // allow, approval, refuse
	OpHash        string       `json:"op_hash"`
	Class         string       `json:"class"`
	PolicyVersion string       `json:"policy_version"`
	Checks        []Check      `json:"checks"`
	Denial        *spec.Denial `json:"denial,omitempty"`
}

// SubmitResult is the successful outcome of a submission: an op (possibly not
// terminal), or a dry-run verdict.
type SubmitResult struct {
	Op      *record
	Verdict *DryRunVerdict
}

// Submit runs one request through policy and, if allowed, releases it. It
// returns *DeniedError for a refusal and *UnavailableError when it failed
// closed. The call waits up to wait for the op to reach a terminal state.
func (s *Service) Submit(ctx context.Context, c *Caller, sub *Submission, mode Mode, wait time.Duration) (*SubmitResult, error) {
	project, d := s.resolveProject(c, sub)
	if s.submissionLeaks(sub) {
		// A secret in what the agent sent is refused whole, before anything is
		// stored or echoed: no op row, no params, no target in the denial.
		return nil, s.deny(ctx, c, denial{Project: project, Surface: "output", Verb: "request", Target: "-", Code: CodeRedactionBlocked, Why: redactionBlockedWhy})
	}
	if d != nil {
		return nil, s.deny(ctx, c, *d)
	}
	deny := func(code, why string) denial {
		return denial{Project: project, Verb: sub.Op, Target: sub.Target.Ref, Code: code, Why: why}
	}
	eff := s.policy.For(project)

	entry, ok := s.policy.Catalog().Lookup(sub.Op)
	if !ok {
		return nil, s.deny(ctx, c, deny(CodeParamsInvalid, "unknown op kind "+sub.Op))
	}
	// 1. The token: scope first, so a caller learns nothing about policy for an
	// op that is not theirs to ask for. From here on the request is well formed
	// and has a hash, so every refusal is recorded with its op row.
	if why := s.notInToken(c, eff, project, sub.Op); why != "" {
		return s.refusal(ctx, c, sub, project, entry, eff, deny(CodeOpNotInToken, why))
	}
	// 2. Policy: enabled? (Every op is disabled until a policy PR enables it.)
	if eff.Invalid != nil {
		return s.refusal(ctx, c, sub, project, entry, eff, deny(CodePolicyRefused, eff.Invalid.Error()))
	}
	if !eff.Enabled(sub.Op) {
		return s.refusal(ctx, c, sub, project, entry, eff, deny(CodeOpDisabled, sub.Op+" is disabled by policy for "+project))
	}
	adapter, ok := s.adapters[sub.Op]
	if !ok {
		return s.refusal(ctx, c, sub, project, entry, eff, deny(CodeOpDisabled, sub.Op+" has no adapter installed in this chapd"))
	}

	// 3. An approval named by the caller: resume or refuse.
	if sub.ApprovalID != "" && mode == ModeOp && !sub.DryRun {
		return s.resume(ctx, c, sub, project, deny, wait)
	}

	// 4. Idempotency: the same caller asking for the same action again gets the
	// op it already has. No second card, no second push (ADR-004 section 6).
	if !sub.DryRun {
		if rec, err := s.findLive(ctx, c, sub.OpHash); err != nil {
			return nil, s.unavailable("could not look up the op", err)
		} else if rec != nil {
			return s.finish(ctx, rec, wait)
		}
	}

	// 5. Rate limit per caller and op.
	if !sub.DryRun {
		if retry, err := s.rateLimited(ctx, c, sub.Op, eff); err != nil {
			return nil, s.unavailable("could not check the rate limit", err)
		} else if retry > 0 {
			d := deny(CodePolicyRefused, fmt.Sprintf("rate limit: %s allows %d calls per minute per caller; retry in %d s", sub.Op, eff.Rate(sub.Op), retry))
			d.Status, d.RetryAfter = 429, retry
			return nil, s.deny(ctx, c, d)
		}
		if retry, err := s.hourLimited(ctx, c, sub.Op, eff); err != nil {
			return nil, s.unavailable("could not check the rate limit", err)
		} else if retry > 0 {
			d := deny(CodePolicyRefused, fmt.Sprintf("rate limit: %s allows %d calls per hour per caller; retry in %d s", sub.Op, eff.RateHour(sub.Op), retry))
			d.Status, d.RetryAfter = 429, retry
			return nil, s.deny(ctx, c, d)
		}
	}

	req := &Request{
		Op: sub.Op, Project: project, Target: sub.Target, Params: sub.Params, OpHash: sub.OpHash,
		Reason: sub.Reason, Caller: c, PolicyVer: eff.Version,
	}
	// 6. The adapter's read-only preconditions. A failed precondition is
	// refused here and cannot be approved away.
	res, err := adapter.Check(ctx, req)
	var ref *Refusal
	switch {
	case errors.As(err, &ref):
		d := deny(ref.Code, ref.Why)
		d.Surface = ref.Surface
		d.CanRequest = ref.CanRequest && s.appr != nil
		d.Command = requestCommand(sub.Op, sub.Target, sub.ParamsJSON)
		if sub.DryRun {
			return s.dryRun(ctx, c, entry, eff, sub, res, &d)
		}
		return nil, s.denyWithOp(ctx, c, sub, project, entry, eff, d)
	case err != nil:
		return nil, s.unavailable("the "+sub.Op+" adapter could not check this request", err)
	}
	needs := entry.Class.NeedsApproval() || res.NeedsApproval

	if sub.DryRun {
		return s.dryRun(ctx, c, entry, eff, sub, res, nil)
	}

	switch {
	case !needs && mode == ModeApproval:
		return nil, s.denyWithOp(ctx, c, sub, project, entry, eff,
			deny(CodeParamsInvalid, sub.Op+" needs no approval; call it directly"))
	case !needs:
		return s.allowAndRelease(ctx, c, sub, project, entry, eff, res, wait)
	case mode == ModeOp:
		why := res.ApprovalWhy
		if why == "" {
			why = sub.Op + " needs an approval for this exact request"
		}
		d := deny(CodeApprovalRequired, why)
		d.CanRequest = s.appr != nil
		d.Command = requestCommand(sub.Op, sub.Target, sub.ParamsJSON)
		return nil, s.denyWithOp(ctx, c, sub, project, entry, eff, d)
	default:
		return s.requestApproval(ctx, c, sub, project, entry, eff, res, deny, wait)
	}
}

// refusal records a refused request: the op row (requested, then denied), its
// op.request and denial events, in one transaction. A dry run has no op, so
// its refusal is only a denial.
func (s *Service) refusal(ctx context.Context, c *Caller, sub *Submission, project string, entry policy.Entry, eff *policy.Effective, d denial) (*SubmitResult, error) {
	if sub.DryRun {
		return nil, s.deny(ctx, c, d)
	}
	return nil, s.denyWithOp(ctx, c, sub, project, entry, eff, d)
}

// resolveProject applies the "never from the request" rule: a run's project is
// its token's; the orchestrator must name one inside its scope.
func (s *Service) resolveProject(c *Caller, sub *Submission) (string, *denial) {
	fallback := c.Project
	if c.Kind == KindOrchestrator {
		fallback = ""
		if len(c.Projects) > 0 {
			fallback = c.Projects[0]
		}
	}
	if sub.Project != "" && validProject(sub.Project) {
		if c.Kind == KindOrchestrator {
			fallback = sub.Project
		}
	}
	bad := func(code, why string) (string, *denial) {
		return fallback, &denial{Project: fallback, Verb: sub.Op, Target: sub.Target.Ref, Code: code, Why: why}
	}
	if c.Kind == KindRun {
		if sub.Project != "" && sub.Project != c.Project {
			return bad(CodeParamsInvalid, "project in the body differs from the run token's project")
		}
		return c.Project, nil
	}
	if sub.Project == "" {
		return bad(CodeParamsInvalid, "the orchestrator must name a project: add --project <name> to the chap command")
	}
	return sub.Project, nil
}

// notInToken returns the reason an op is outside the caller's scope, or "".
func (s *Service) notInToken(c *Caller, eff *policy.Effective, project, op string) string {
	if c.Kind == KindOrchestrator {
		if !containsString(c.Projects, project) {
			return "project " + project + " is not in this orchestrator token's scope"
		}
	}
	if !spec.OpAllowed(op, c.opPatterns()) {
		return op + " is not in this token's scope"
	}
	if c.Kind == KindRun {
		ceiling, ok := eff.ProfileCeiling(c.Profile)
		if !ok {
			return "profile " + c.Profile + " has no op ceiling in policy"
		}
		if !containsString(ceiling, op) {
			return op + " is not allowed for profile " + c.Profile
		}
	}
	return ""
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func validProject(p string) bool {
	if len(p) < 2 || len(p) > 39 || p[0] < 'a' || p[0] > 'z' {
		return false
	}
	for _, r := range p {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// redactionBlockedWhy is the only text a REDACTION_BLOCKED denial carries: it
// names no field and quotes nothing of what was sent.
const redactionBlockedWhy = "the request held a secret, so it was refused and nothing was stored or echoed; remove the secret and ask again"

// leaks reports whether any of the strings holds a secret (an exact value of
// the registry or a secret-shaped string).
func (s *Service) leaks(parts ...string) bool {
	if s.redactor == nil {
		return false
	}
	for _, p := range parts {
		if p == "" {
			continue
		}
		if _, res := s.redactor.Redact(p); res.Blocked() {
			return true
		}
	}
	return false
}

// submissionLeaks reports whether anything the agent sent (op, project,
// target, params, reason, ids) holds a secret. The params are scanned in
// their JSON form and as individual strings, keys included, so an escaped or
// nested secret is found as well.
func (s *Service) submissionLeaks(sub *Submission) bool {
	if s.redactor == nil {
		return false
	}
	parts := []string{sub.Op, sub.Project, sub.Target.Adapter, sub.Target.Ref, sub.Reason, sub.ApprovalID, sub.Traceparent, sub.OpHash, sub.ParamsJSON}
	if b, err := json.Marshal(sub.Params); err == nil {
		parts = append(parts, string(b))
	}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			parts = append(parts, x)
		case map[string]any:
			for k, e := range x {
				parts = append(parts, k)
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(sub.Params)
	return s.leaks(parts...)
}

// deny records a refusal that has no op row.
func (s *Service) deny(ctx context.Context, c *Caller, d denial) error {
	var out *DeniedError
	err := s.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		out, err = s.refuse(ctx, tx, c, d)
		return err
	})
	if err != nil {
		return s.unavailable("could not record the denial", err)
	}
	return out
}

// newRecord builds the row for a submission in state requested.
func (s *Service) newRecord(c *Caller, sub *Submission, project string, entry policy.Entry, eff *policy.Effective) *record {
	now := s.now().UTC()
	r := &record{
		ID: s.newID("q-"), State: StateRequested, Op: sub.Op, Project: project,
		TargetAdapter: sub.Target.Adapter, TargetRef: sub.Target.Ref,
		ParamsJSON: sub.ParamsJSON, OpHash: sub.OpHash,
		RequesterKind: c.Kind, RequesterKey: c.Key(),
		Class: string(entry.Class), Reversibility: entry.Reversibility, PolicyVersion: eff.Version,
		Reason: sub.Reason, Traceparent: sub.Traceparent,
		RequestedAt: now, ExpiresAt: now.Add(time.Duration(eff.TTL(sub.Op)) * time.Minute), UpdatedAt: now,
	}
	if c.Kind == KindRun {
		r.RunID, r.Profile, r.TokenJTI = c.RunID, c.Profile, c.JTI
		r.ScopeJSON = scopeJSON(c)
	} else {
		r.OrchID = c.OrchID
	}
	return r
}

func (r *record) event(name string, attrs map[string]any, body string) Event {
	attrs["factory.requester.kind"] = r.RequesterKind
	if r.RequesterKind == KindOrchestrator {
		attrs["factory.orchestrator.id"] = r.OrchID
	}
	return Event{Name: name, RunID: r.RunID, Project: r.Project, Attributes: attrs, Body: body}
}

// requestEvent is the op.request event of r. Critical ops are logged loudly.
func (r *record) requestEvent() Event {
	e := r.event("op.request", map[string]any{
		"factory.request_id":    r.ID,
		"factory.op":            r.Op,
		"factory.op_hash":       r.OpHash,
		"factory.reversibility": r.Reversibility,
	}, clamp(r.Op+" "+r.TargetAdapter+":"+r.TargetRef, 1000))
	if r.Class == string(policy.ClassCritical) {
		e.Severity = "WARN"
	}
	return e
}

// resultEvent is the op.result event for an outcome. Every one carries the
// policy version the op was evaluated under.
func (r *record) resultEvent(outcome, cause string) Event {
	attrs := map[string]any{
		"factory.request_id":     r.ID,
		"factory.op_hash":        r.OpHash,
		"factory.outcome":        outcome,
		"factory.policy_version": r.PolicyVersion,
	}
	if outcome == "refused" {
		attrs["factory.cause_code"] = cause
	} else {
		attrs["factory.execution_id"] = r.ExecutionID
		if r.ExternalRef != "" && outcome != "unconfirmed" {
			attrs["factory.external_ref"] = r.ExternalRef
		}
		if cause != "" {
			attrs["factory.cause_code"] = cause
		}
	}
	e := r.event("op.result", attrs, clamp(r.Op+" "+outcome, 1000))
	if r.Class == string(policy.ClassCritical) {
		e.Severity = "WARN"
	}
	return e
}

// denyWithOp stores the op in state requested then denied, with op.request and
// denial events, all in one transaction.
func (s *Service) denyWithOp(ctx context.Context, c *Caller, sub *Submission, project string, entry policy.Entry, eff *policy.Effective, d denial) error {
	rec := s.newRecord(c, sub, project, entry, eff)
	d.RequestID = rec.ID
	var out *DeniedError
	err := s.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		if err := insertRecord(ctx, tx, rec); err != nil {
			return err
		}
		if err := s.led.AppendTx(ctx, tx, rec.requestEvent()); err != nil {
			return err
		}
		var err error
		if out, err = s.refuse(ctx, tx, c, d); err != nil {
			return err
		}
		body, err := json.Marshal(out.Denial)
		if err != nil {
			return err
		}
		return transition{From: StateRequested, To: StateDenied, Now: s.now(), CauseCode: d.Code, DenialJSON: string(body)}.apply(ctx, tx, rec.ID)
	})
	if errors.Is(err, errLive) {
		return s.deny(ctx, c, d) // the live op stays; this refusal has no row of its own
	}
	if err != nil {
		return s.unavailable("could not record the denial", err)
	}
	s.alertRequest(ctx, rec)
	return out
}

func (s *Service) alertRequest(ctx context.Context, r *record) {
	if s.alert != nil && r.Class == string(policy.ClassCritical) {
		s.alert.Alert(ctx, Alert{Kind: AlertRequest, Op: r.Op, Project: r.Project, RequestID: r.ID, Requester: r.RequesterKey})
	}
}

// findLive returns the caller's non-terminal op with this op_hash, if any.
func (s *Service) findLive(ctx context.Context, c *Caller, opHash string) (*record, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT `+recordColumns+` FROM ops
        WHERE requester_key = ? AND op_hash = ? AND state IN ('pending_approval','allowed','executing','unconfirmed')
        ORDER BY requested_at DESC LIMIT 1`, c.Key(), opHash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	return scanRecord(rows)
}

// rateLimited returns the seconds to wait when the caller used up op's rate in
// the last minute, else 0. Only ops that passed policy count: refusals are
// bounded by the thrash counter instead.
func (s *Service) rateLimited(ctx context.Context, c *Caller, op string, eff *policy.Effective) (int, error) {
	return s.rateWindow(ctx, c, op, eff.Rate(op), 60)
}

// hourLimited is rateLimited for the policy's optional per-hour cap
// (`rate_per_hour`): the seconds to wait when the caller made that many calls
// of op in the last 60 minutes, else 0. It is 0 when the policy sets no cap.
func (s *Service) hourLimited(ctx context.Context, c *Caller, op string, eff *policy.Effective) (int, error) {
	limit := eff.RateHour(op)
	if limit < 1 {
		return 0, nil
	}
	return s.rateWindow(ctx, c, op, limit, 3600)
}

func (s *Service) rateWindow(ctx context.Context, c *Caller, op string, limit, window int) (int, error) {
	now := s.now().Unix()
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT requested_at FROM ops
        WHERE requester_key = ? AND op = ? AND state <> 'denied' AND requested_at > ?
        ORDER BY requested_at ASC`, c.Key(), op, now-int64(window))
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var times []int64
	for rows.Next() {
		var t int64
		if err := rows.Scan(&t); err != nil {
			return 0, err
		}
		times = append(times, t)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(times) < limit {
		return 0, nil
	}
	// The call that frees a slot is the (len-limit+1)th oldest leaving the window.
	wait := int(times[len(times)-limit] + int64(window) - now)
	if wait < 1 {
		wait = 1
	}
	return wait, nil
}

func (s *Service) dryRun(ctx context.Context, c *Caller, entry policy.Entry, eff *policy.Effective, sub *Submission, res CheckResult, refused *denial) (*SubmitResult, error) {
	v := &DryRunVerdict{
		Type: "dry_run", OpHash: sub.OpHash, Class: string(entry.Class),
		PolicyVersion: eff.Version, Checks: res.Checks,
	}
	if v.Checks == nil {
		v.Checks = []Check{}
	}
	switch {
	case refused != nil:
		v.Outcome = "refuse"
		// A dry run creates no op, but a refusal is still a denial and is ledgered.
		err := s.deny(ctx, c, *refused)
		var de *DeniedError
		if errors.As(err, &de) {
			v.Denial = &de.Denial
		} else {
			return nil, err
		}
	case entry.Class.NeedsApproval() || res.NeedsApproval:
		v.Outcome = "approval"
	default:
		v.Outcome, v.WouldAllow = "allow", true
	}
	return &SubmitResult{Verdict: v}, nil
}

func (s *Service) allowAndRelease(ctx context.Context, c *Caller, sub *Submission, project string, entry policy.Entry, eff *policy.Effective, res CheckResult, wait time.Duration) (*SubmitResult, error) {
	rec := s.newRecord(c, sub, project, entry, eff)
	checks, _ := json.Marshal(res.Checks)
	err := s.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		if err := insertRecord(ctx, tx, rec); err != nil {
			return err
		}
		if err := s.led.AppendTx(ctx, tx, rec.requestEvent()); err != nil {
			return err
		}
		return transition{From: StateRequested, To: StateAllowed, Now: s.now(), ChecksJSON: string(checks)}.apply(ctx, tx, rec.ID)
	})
	if errors.Is(err, errLive) {
		return s.joinLive(ctx, c, sub, wait)
	}
	if err != nil {
		return nil, s.unavailable("could not record the request", err)
	}
	s.alertRequest(ctx, rec)
	return s.release(ctx, rec.ID, wait)
}

func (s *Service) requestApproval(ctx context.Context, c *Caller, sub *Submission, project string, entry policy.Entry, eff *policy.Effective, res CheckResult, deny func(code, why string) denial, wait time.Duration) (*SubmitResult, error) {
	if s.appr == nil {
		d := deny(CodeApprovalUnavail, "the approvals engine is not running; nothing was queued")
		return nil, s.denyWithOp(ctx, c, sub, project, entry, eff, d)
	}
	rec := s.newRecord(c, sub, project, entry, eff)
	checks, _ := json.Marshal(res.Checks)
	var refusal *DeniedError
	var info ApprovalInfo
	err := s.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		if err := insertRecord(ctx, tx, rec); err != nil {
			return err
		}
		if err := s.led.AppendTx(ctx, tx, rec.requestEvent()); err != nil {
			return err
		}
		// Caps bound what agents can queue, never what the operator approves.
		if why, err := s.pendingCap(ctx, tx, c, project, eff); err != nil {
			return err
		} else if why != "" {
			d := deny(CodePolicyRefused, why)
			d.Status, d.RetryAfter, d.RequestID = 429, 60, rec.ID
			if refusal, err = s.refuse(ctx, tx, c, d); err != nil {
				return err
			}
			if err := s.raiseFlood(ctx, tx, rec); err != nil {
				return err
			}
			return s.markDenied(ctx, tx, rec, refusal, d.Code)
		}
		var err error
		specReq := rec.specRequest()
		specReq.Params = sub.Params
		info, err = s.appr.Create(ctx, tx, ApprovalInput{
			Request: specReq, Evidence: res.Evidence,
			RequestID: rec.ID, Op: rec.Op, OpHash: rec.OpHash, Project: project, Class: rec.Class,
			Critical: rec.Class == string(policy.ClassCritical), Caller: c, Reason: sub.Reason,
			Checks: res.Checks, PolicyVer: eff.Version, ExpiresAt: rec.ExpiresAt,
		})
		var ref *Refusal
		if errors.As(err, &ref) {
			d := deny(ref.Code, ref.Why)
			d.RequestID, d.CanRequest, d.Command = rec.ID, ref.CanRequest, requestCommand(rec.Op, sub.Target, sub.ParamsJSON)
			if refusal, err = s.refuse(ctx, tx, c, d); err != nil {
				return err
			}
			return s.markDenied(ctx, tx, rec, refusal, d.Code)
		}
		if err != nil {
			return err
		}
		return transition{From: StateRequested, To: StatePendingApproval, Now: s.now(), ApprovalID: info.ID, ChecksJSON: string(checks)}.apply(ctx, tx, rec.ID)
	})
	if errors.Is(err, errLive) {
		return s.joinLive(ctx, c, sub, wait)
	}
	if err != nil {
		return nil, s.unavailable("could not record the approval request", err)
	}
	if refusal != nil {
		return nil, refusal
	}
	s.alertRequest(ctx, rec)
	if info.After != nil {
		info.After(context.WithoutCancel(ctx))
	}
	out, err := dbGet(ctx, s.db, rec.ID)
	if err != nil {
		return nil, s.unavailable("could not read the op back", err)
	}
	return &SubmitResult{Op: out}, nil
}

// joinLive answers a request that lost the race to an identical one: it gets
// the winner's op.
func (s *Service) joinLive(ctx context.Context, c *Caller, sub *Submission, wait time.Duration) (*SubmitResult, error) {
	rec, err := s.findLive(ctx, c, sub.OpHash)
	if err != nil {
		return nil, s.unavailable("could not look up the op", err)
	}
	if rec == nil {
		return nil, s.unavailable("a concurrent identical request finished; retry", errLive)
	}
	return s.finish(ctx, rec, wait)
}

func (s *Service) markDenied(ctx context.Context, tx *store.Tx, rec *record, d *DeniedError, code string) error {
	body, err := json.Marshal(d.Denial)
	if err != nil {
		return err
	}
	return transition{From: StateRequested, To: StateDenied, Now: s.now(), CauseCode: code, DenialJSON: string(body)}.apply(ctx, tx, rec.ID)
}

// pendingCap returns the reason the caller may not queue another approval, or "".
func (s *Service) pendingCap(ctx context.Context, tx *store.Tx, c *Caller, project string, eff *policy.Effective) (string, error) {
	count := func(where string, args ...any) (int, error) {
		var n int
		err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM ops WHERE state = 'pending_approval' AND `+where, args...).Scan(&n)
		return n, err
	}
	chap := eff.Limits.Pending
	if n, err := count(`requester_key = ?`, c.Key()); err != nil {
		return "", err
	} else if n >= chap.PerRun {
		return fmt.Sprintf("approval flood: %d approvals already pending for this caller (limit %d)", n, chap.PerRun), nil
	}
	if n, err := count(`project = ?`, project); err != nil {
		return "", err
	} else if n >= chap.PerProject {
		return fmt.Sprintf("approval flood: %d approvals already pending for project %s (limit %d)", n, project, chap.PerProject), nil
	}
	if n, err := count(`1 = 1`); err != nil {
		return "", err
	} else if n >= chap.Total {
		return fmt.Sprintf("approval flood: %d approvals already pending in total (limit %d)", n, chap.Total), nil
	}
	return "", nil
}

// raiseFlood writes the APPROVAL_FLOOD stop (stop table: halts run, action pause).
func (s *Service) raiseFlood(ctx context.Context, tx *store.Tx, rec *record) error {
	return s.led.AppendTx(ctx, tx, Event{
		Name: "stop.raise", RunID: rec.RunID, Project: rec.Project, Severity: "WARN",
		Attributes: map[string]any{
			"factory.stop.id":    s.newID("s-"),
			"factory.cause_code": "APPROVAL_FLOOD",
			"factory.halts":      "run",
			"factory.action":     "pause",
		},
		Body: clamp("approval flood by "+rec.RequesterKey, 1000),
	})
}

// resume handles POST /v0/ops with approval_id.
func (s *Service) resume(ctx context.Context, c *Caller, sub *Submission, project string, deny func(code, why string) denial, wait time.Duration) (*SubmitResult, error) {
	if s.appr == nil {
		return nil, s.deny(ctx, c, deny(CodeApprovalUnavail, "the approvals engine is not running"))
	}
	info, err := s.appr.Lookup(ctx, sub.ApprovalID)
	if errors.Is(err, ErrApprovalNotFound) || (err == nil && info.OwnerKey != c.Key()) {
		return nil, s.deny(ctx, c, deny(CodeParamsInvalid, "unknown approval_id"))
	}
	if err != nil {
		return nil, s.deny(ctx, c, deny(CodeApprovalUnavail, "the approval store could not be read"))
	}
	if info.OpHash != sub.OpHash {
		return nil, s.deny(ctx, c, deny(CodeHashMismatch, "this approval applies to a different request ("+shortHash(info.OpHash)+")"))
	}
	switch info.State {
	case "consumed":
		return nil, s.deny(ctx, c, deny(CodeApprovalConsumed, "this approval already released an op"))
	case "denied", "cancelled":
		return nil, s.deny(ctx, c, deny(CodeApprovalDenied, "the approval was "+info.State))
	case "expired":
		return nil, s.deny(ctx, c, deny(CodeApprovalExpired, "the approval expired"))
	}
	rec, err := dbGet(ctx, s.db, info.RequestID)
	if err != nil {
		return nil, s.unavailable("could not read the op of this approval", err)
	}
	if rec.RequesterKey != c.Key() || rec.OpHash != sub.OpHash {
		return nil, s.deny(ctx, c, deny(CodeHashMismatch, "this approval belongs to another request"))
	}
	return s.finish(ctx, rec, wait)
}

func shortHash(h string) string {
	h = strings.TrimPrefix(h, "sha256:")
	if len(h) > 8 {
		h = h[:8]
	}
	return h
}

// finish releases an allowed op and waits for the result, or just waits.
func (s *Service) finish(ctx context.Context, rec *record, wait time.Duration) (*SubmitResult, error) {
	if rec.State == StateAllowed {
		return s.release(ctx, rec.ID, wait)
	}
	if rec.State == StatePendingApproval {
		wait = 0 // a card waits for a human, not for this call
	}
	out, err := s.waitFor(ctx, rec.ID, wait, "")
	if err != nil {
		return nil, err
	}
	return &SubmitResult{Op: out}, nil
}

// shortID is for log lines only.
func shortID(s string) string { return clamp(s, 12) }
