package approvals

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"time"

	"github.com/joshua-noel/chaperone/internal/notify"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// Engine is the approvals engine. It is safe for concurrent use: every state
// change is a compare-and-set inside a BEGIN IMMEDIATE transaction.
type Engine struct {
	cfg  Config
	chap Limits
	log  *slog.Logger
	now  func() time.Time
}

// New checks cfg and builds an engine over a migrated database (migration 0006).
func New(cfg Config) (*Engine, error) {
	switch {
	case cfg.DB == nil:
		return nil, errors.New("approvals: Config.DB is required")
	case cfg.Ledger == nil:
		return nil, errors.New("approvals: Config.Ledger is required (an approval without a ledger event is never allowed)")
	case cfg.Catalog == nil:
		return nil, errors.New("approvals: Config.Catalog is required")
	}
	e := &Engine{cfg: cfg, chap: cfg.Limits.withDefaults(), log: cfg.Log, now: cfg.Now}
	if e.log == nil {
		e.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if e.now == nil {
		e.now = time.Now
	}
	if len(e.cfg.Channels) == 0 {
		e.cfg.Channels = []string{"pc"}
	}
	for _, c := range e.cfg.Channels {
		if c != "pc" && c != "phone" {
			return nil, fmt.Errorf("approvals: unknown channel %q", c)
		}
	}
	if len(e.cfg.PhoneOrigins) > 0 && !slices.Contains(e.cfg.Channels, "phone") {
		e.cfg.Channels = append(slices.Clone(e.cfg.Channels), "phone")
	}
	if slices.Contains(e.cfg.Channels, "phone") && len(e.cfg.PhoneOrigins) == 0 {
		return nil, errors.New("approvals: the phone channel needs Config.PhoneOrigins (nothing else can make a phone assertion)")
	}
	return e, nil
}

// Effects are the actions a transaction must not perform because they cannot be
// rolled back: the wake-up push and the critical-class alerts. Run them once the
// transaction has committed. The zero value does nothing.
type Effects struct {
	e      *Engine
	wake   *notify.Wake
	alerts []Alert
}

func (f Effects) merge(g Effects) Effects {
	if f.e == nil {
		f.e = g.e
	}
	if g.wake != nil {
		f.wake = g.wake
	}
	f.alerts = append(f.alerts, g.alerts...)
	return f
}

// WithoutAlerts returns the effects with the critical-class alerts dropped, for
// a caller that raises those itself (the op state machine alerts on request and
// on execution of the ops it owns).
func (f Effects) WithoutAlerts() Effects {
	f.alerts = nil
	return f
}

// Run performs the effects. It never fails: a push that cannot be sent is a
// missed wake-up and a log line, and an alert hook has no way to refuse
// anything (the ledger event is already committed).
func (f Effects) Run(ctx context.Context) {
	if f.e == nil {
		return
	}
	if f.wake != nil && f.e.cfg.Notifier != nil {
		if err := f.e.cfg.Notifier.Notify(ctx, *f.wake); err != nil {
			f.e.log.Warn("wake-up not sent", "op", f.wake.Kind, "err", err)
		}
	}
	if f.e.cfg.Alert != nil {
		for _, a := range f.alerts {
			f.e.cfg.Alert(a)
		}
	}
}

// Atomic runs fn in a write transaction and, after it commits, the effects fn
// returned. It is how a caller combines engine calls with its own state change.
func (e *Engine) Atomic(ctx context.Context, fn func(ctx context.Context, tx *store.Tx) (Effects, error)) error {
	var fx Effects
	err := e.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) (err error) {
		fx, err = fn(ctx, tx)
		return err
	})
	if err != nil {
		return err
	}
	fx.Run(ctx)
	return nil
}

// ---- requests ----

// RequestInput is what the op state machine hands over to make a card.
type RequestInput struct {
	// Request is the full request document as chapd built it (request_id,
	// requester from the token, times, op_hash). The engine recomputes op_hash.
	Request spec.Request
	// PolicyVersion is the policy pack version that evaluated Checks.
	PolicyVersion string
	// Checks are the preconditions evaluated before the card is shown. A failed
	// check cannot be approved away: the request is refused.
	Checks []spec.ApprovalCheck
	// Evidence is extra card text from the adapter (see [Evidence]).
	Evidence []Evidence
}

// Result is the outcome of [Engine.RequestTx].
type Result struct {
	// Approval is the card: new, or the pending one this request deduplicated to.
	Approval *Approval
	// Created is false when the request matched a pending card of the same
	// caller and op hash. The caller then returns that card's op (Approval.RequestID)
	// and discards the request id it minted.
	Created bool
	// Refusal is set when no card exists. The caller makes a denial from it and
	// COMMITS the transaction: a stop hook may have written to it.
	Refusal *Refusal
	// Effects must be run after the commit.
	Effects Effects
}

// RequestTTL is how long a card for op may wait for a decision.
func (e *Engine) RequestTTL(op string) time.Duration {
	if op == "deploy" {
		return e.chap.DeployTTL
	}
	return e.chap.RequestTTL
}

// RequestTx creates the approval card for one request (ADR-004 sections 3 and 6),
// inside the caller's transaction.
func (e *Engine) RequestTx(ctx context.Context, tx *store.Tx, in RequestInput) (Result, error) {
	now := e.now()
	req := in.Request

	tree, err := spec.Tree(req)
	if err != nil {
		return Result{Refusal: refuse(CodeParamsInvalid, "the request cannot be hashed: "+err.Error())}, nil
	}
	if err := spec.Validate(spec.SchemaRequest, tree); err != nil {
		return Result{Refusal: refuse(CodeParamsInvalid, "the request is not a valid operation request: "+err.Error())}, nil
	}
	opHash, err := spec.OpHash(req)
	if err != nil {
		return Result{Refusal: refuse(CodeParamsInvalid, err.Error())}, nil
	}
	if req.OpHash != opHash {
		return Result{Refusal: refuse(CodeParamsInvalid, "op_hash is not the hash of the request")}, nil
	}
	if in.PolicyVersion == "" || len(in.PolicyVersion) > 64 {
		return Result{}, errors.New("approvals: RequestInput.PolicyVersion must be 1-64 characters")
	}
	info, ok := e.cfg.Catalog.Lookup(req.Op)
	if !ok {
		return Result{Refusal: refuse(CodeParamsInvalid, "unknown op")}, nil
	}
	if info.Class == ClassRoutine {
		return Result{Refusal: refuse(CodeParamsInvalid, "this op never needs an approval")}, nil
	}
	kind, requesterKey, runID, err := requesterOf(req.Requester)
	if err != nil {
		return Result{Refusal: refuse(CodeParamsInvalid, err.Error())}, nil
	}
	for _, c := range in.Checks {
		if !c.Passed {
			return Result{Refusal: refuse(CodePolicyRefused,
				"the check "+c.Name+" failed; a failed precondition cannot be approved away")}, nil
		}
	}
	requested, err := time.Parse(time.RFC3339, req.ExpiresAt)
	if err != nil {
		return Result{Refusal: refuse(CodeParamsInvalid, "expires_at is not a timestamp")}, nil
	}
	// The card never outlives the policy's window, whatever the request says.
	expires := minTime(requested, now.Add(e.RequestTTL(req.Op))).Truncate(time.Second)
	if !expires.After(now) {
		return Result{Refusal: refuse(CodeParamsInvalid, "the request has already expired")}, nil
	}

	if _, err := e.sweepTx(ctx, tx); err != nil {
		return Result{}, err
	}

	// Dedupe: the same caller asking for the same op hash while a card waits.
	if existing, err := e.pendingFor(ctx, tx, opHash, kind, requesterKey); err != nil {
		return Result{}, err
	} else if existing != nil {
		return Result{Approval: existing}, nil
	}

	// Sticky deny: a denied or unanswered op hash stays refused (section 6, item 5).
	if wait, err := e.stickyWait(ctx, tx, opHash, now); err != nil {
		return Result{}, err
	} else if wait > 0 {
		r := refuse(CodeDenied, "this exact action was denied or left unanswered recently; it is refused until the cooldown ends")
		r.RetryAfter = wait
		return Result{Refusal: r}, nil
	}

	// Pending caps (section 6, item 4): they bound what agents queue.
	if r, err := e.overCap(ctx, tx, req, kind, requesterKey); err != nil {
		return Result{}, err
	} else if r != nil {
		if e.cfg.Stop != nil {
			if err := e.cfg.Stop(ctx, tx, Stop{Code: StopFlood, RunID: runID, RequesterKind: kind,
				RequesterKey: requesterKey, Project: req.Project, Why: r.Why}); err != nil {
				return Result{}, err
			}
		}
		return Result{Refusal: r}, nil
	}

	a := &Approval{
		ID: newApprovalID(), RequestID: req.RequestID, RequesterKind: kind, RequesterKey: requesterKey,
		RunID: runID, Project: req.Project, Op: req.Op, OpHash: opHash, Class: info.Class,
		PolicyVersion: in.PolicyVersion, Request: req, Checks: nonNilChecks(in.Checks), Evidence: nonNilEvidence(in.Evidence),
		State: StatePending, Created: now.Truncate(time.Second), RequestExpires: expires,
	}
	if a.CardText, err = renderCard(a); err != nil {
		return Result{Refusal: refuse(CodeParamsInvalid, err.Error())}, nil
	}
	a.DisplaySHA256 = DisplayHash(a.CardText)
	if err := insertApproval(ctx, tx, a); err != nil {
		return Result{}, err
	}

	fx := Effects{e: e}
	pending, err := countWhere(ctx, tx, `state = 'pending'`)
	if err != nil {
		return Result{}, err
	}
	// The wake-up is made from the catalog's op name and the project, never
	// from a parameter: notify.Build refuses anything else anyway.
	fx.wake = &notify.Wake{Kind: info.Name, Project: req.Project, OpHash: opHash, ExpiresAt: expires, Pending: pending}
	if info.Class == ClassCritical {
		fx.alerts = append(fx.alerts, e.alert(AlertRequested, a))
	}
	return Result{Approval: a, Created: true, Effects: fx}, nil
}

// requesterOf says who asked, in the engine's own terms: the kind ("run",
// "orchestrator" or "key"), the key of that requester and the run id. A key
// reaches the engine as the spec's orchestrator "key.<id>" (spec.KeyRequester)
// and is stored as a key.
func requesterOf(r spec.Requester) (kind, key, runID string, err error) {
	switch r.Kind {
	case "run":
		if r.RunID == "" {
			return "", "", "", errors.New("a run request has no run_id")
		}
		return "run", r.RunID, r.RunID, nil
	case "orchestrator":
		if r.ID == "" {
			return "", "", "", errors.New("an orchestrator request has no id")
		}
		if id, ok := spec.KeyIDOf(r); ok {
			return "key", id, "", nil
		}
		return "orchestrator", r.ID, "", nil
	}
	return "", "", "", fmt.Errorf("unknown requester kind %q", r.Kind)
}

func (e *Engine) alert(stage string, a *Approval) Alert {
	who := requesterWho(a)
	return Alert{Stage: stage, Op: a.Op, Project: a.Project, ApprovalID: a.ID, RequestID: a.RequestID, OpHash: a.OpHash, Requester: who}
}

func nonNilChecks(c []spec.ApprovalCheck) []spec.ApprovalCheck {
	if c == nil {
		return []spec.ApprovalCheck{}
	}
	return c
}

func nonNilEvidence(c []Evidence) []Evidence {
	if c == nil {
		return []Evidence{}
	}
	return c
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func insertApproval(ctx context.Context, tx *store.Tx, a *Approval) error {
	reqJSON, err := marshal(a.Request)
	if err != nil {
		return err
	}
	checks, err := marshal(a.Checks)
	if err != nil {
		return err
	}
	ev, err := marshal(a.Evidence)
	if err != nil {
		return err
	}
	var run, key any
	if a.RunID != "" {
		run = a.RunID
	}
	if a.RequesterKind == "key" {
		key = a.RequesterKey
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO approvals (approval_id, request_id, requester_kind, requester_key, run_id, project, op, op_hash, class,
			policy_version, request_json, checks_json, evidence_json, card_text, display_sha256, state, created_unix,
			request_expires_unix, key_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)`,
		a.ID, a.RequestID, a.RequesterKind, a.RequesterKey, run, a.Project, a.Op, a.OpHash, string(a.Class),
		a.PolicyVersion, reqJSON, checks, ev, a.CardText, a.DisplaySHA256, a.Created.Unix(), a.RequestExpires.Unix(), key)
	return err
}

// pendingFor returns the live pending card of this caller for opHash, or nil.
func (e *Engine) pendingFor(ctx context.Context, q queryer, opHash, kind, key string) (*Approval, error) {
	as, err := listApprovals(ctx, q, `WHERE op_hash = ? AND requester_kind = ? AND requester_key = ? AND state = 'pending'`,
		opHash, kind, key)
	if err != nil || len(as) == 0 {
		return nil, err
	}
	return as[0], nil
}

// stickyWait returns how much longer opHash stays refused, or 0. A denial counts
// from the decision; an expiry counts from the moment the request ran out. A
// cancelled request (the run ended, the requester withdrew) and an approval
// that went unused do not: neither is the operator's "no".
func (e *Engine) stickyWait(ctx context.Context, q queryer, opHash string, now time.Time) (time.Duration, error) {
	var until sql.NullInt64
	err := q.QueryRowContext(ctx,
		`SELECT max(CASE state WHEN 'denied' THEN decided_unix ELSE request_expires_unix END)
		 FROM approvals
		 WHERE op_hash = ? AND ((state = 'denied') OR (state = 'expired' AND decided_unix IS NULL))`, opHash).Scan(&until)
	if err != nil || !until.Valid {
		return 0, err
	}
	end := time.Unix(until.Int64, 0).Add(e.chap.StickyDeny)
	if !end.After(now) {
		return 0, nil
	}
	return end.Sub(now), nil
}

// overCap checks the three pending caps and returns the refusal for the first
// one exceeded.
func (e *Engine) overCap(ctx context.Context, q queryer, req spec.Request, kind, key string) (*Refusal, error) {
	type capCheck struct {
		name  string
		limit int
		where string
		args  []any
	}
	checks := []capCheck{
		{"this " + kind, e.chap.PerRun, `state = 'pending' AND requester_kind = ? AND requester_key = ?`, []any{kind, key}},
		{"this project", e.chap.PerProject, `state = 'pending' AND project = ?`, []any{req.Project}},
		{"Chaperone", e.chap.Total, `state = 'pending'`, nil},
	}
	for _, c := range checks {
		n, err := countWhere(ctx, q, c.where, c.args...)
		if err != nil {
			return nil, err
		}
		if n >= c.limit {
			r := refuse(CodePolicyRefused, fmt.Sprintf(
				"%s already has %d approvals waiting (the limit is %d); wait for a decision before asking again", c.name, n, c.limit))
			r.Stop = StopFlood
			r.RetryAfter = time.Minute
			return r, nil
		}
	}
	return nil, nil
}

// ---- reads ----

// Get returns one approval, or nil when there is none.
func (e *Engine) Get(ctx context.Context, id string) (*Approval, error) {
	return getApproval(ctx, e.cfg.DB.SQL(), id)
}

// GetByRequest returns the approval of a request, or nil.
func (e *Engine) GetByRequest(ctx context.Context, requestID string) (*Approval, error) {
	as, err := listApprovals(ctx, e.cfg.DB.SQL(), `WHERE request_id = ?`, requestID)
	if err != nil || len(as) == 0 {
		return nil, err
	}
	return as[0], nil
}

// Pending lists the cards waiting for a decision, oldest first. A card past its
// expiry is not listed even before the sweep has marked it.
func (e *Engine) Pending(ctx context.Context) ([]*Approval, error) {
	return listApprovals(ctx, e.cfg.DB.SQL(), `WHERE state = 'pending' AND request_expires_unix >= ? ORDER BY created_unix, approval_id`,
		e.now().Unix())
}

// Recent lists the n most recently created approvals, newest first, in any state.
func (e *Engine) Recent(ctx context.Context, n int) ([]*Approval, error) {
	return listApprovals(ctx, e.cfg.DB.SQL(), `ORDER BY created_unix DESC, approval_id DESC LIMIT ?`, n)
}

// ListFor lists a caller's own approvals, newest first (GET /v0/approvals). state
// "" means every state.
func (e *Engine) ListFor(ctx context.Context, kind, key string, state State, limit int) ([]*Approval, error) {
	if state == "" {
		return listApprovals(ctx, e.cfg.DB.SQL(), `WHERE requester_kind = ? AND requester_key = ? ORDER BY created_unix DESC, approval_id DESC LIMIT ?`,
			kind, key, limit)
	}
	return listApprovals(ctx, e.cfg.DB.SQL(), `WHERE requester_kind = ? AND requester_key = ? AND state = ? ORDER BY created_unix DESC, approval_id DESC LIMIT ?`,
		kind, key, string(state), limit)
}

// ListPage lists a caller's own approvals like [Engine.ListFor], newest first,
// starting after the approval named by after (empty: from the newest). next is
// the id to pass as after for the following page, or "" on the last page.
func (e *Engine) ListPage(ctx context.Context, kind, key string, state State, limit int, after string) (items []*Approval, next string, err error) {
	where, args := `WHERE requester_kind = ? AND requester_key = ?`, []any{kind, key}
	if state != "" {
		where, args = where+` AND state = ?`, append(args, string(state))
	}
	if after != "" {
		var created int64
		switch err := e.cfg.DB.SQL().QueryRowContext(ctx, `SELECT created_unix FROM approvals WHERE approval_id = ?`, after).Scan(&created); {
		case errors.Is(err, sql.ErrNoRows):
			return nil, "", nil
		case err != nil:
			return nil, "", err
		}
		where, args = where+` AND (created_unix < ? OR (created_unix = ? AND approval_id < ?))`, append(args, created, created, after)
	}
	items, err = listApprovals(ctx, e.cfg.DB.SQL(), where+` ORDER BY created_unix DESC, approval_id DESC LIMIT ?`, append(args, limit+1)...)
	if err != nil {
		return nil, "", err
	}
	if len(items) > limit {
		items = items[:limit]
		next = items[limit-1].ID
	}
	return items, next, nil
}

// PendingCount is the number of live pending cards (the `approvals.pending`
// event chap-host shows as a toast).
func (e *Engine) PendingCount(ctx context.Context) (int, error) {
	return countWhere(ctx, e.cfg.DB.SQL(), `state = 'pending' AND request_expires_unix >= ?`, e.now().Unix())
}

// ---- expiry ----

// Sweep marks every card whose request ran out unanswered, and every approval
// that went unused past its expiry, as expired, and reports each to
// [Config.OnDecided] so the op state machine can close the op. Call it on a
// timer (see [Engine.Run]); the other entry points sweep first too.
func (e *Engine) Sweep(ctx context.Context) (int, error) {
	n := 0
	err := e.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) (err error) {
		n, err = e.sweepTx(ctx, tx)
		return err
	})
	return n, err
}

// Run sweeps every interval until ctx ends.
func (e *Engine) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := e.Sweep(ctx); err != nil && ctx.Err() == nil {
				e.log.Error("approvals sweep failed", "err", err)
			}
		}
	}
}

// sweepTx expires what is due inside tx. A request is due when now is past its
// last instant, an approval likewise.
func (e *Engine) sweepTx(ctx context.Context, tx *store.Tx) (int, error) {
	now := e.now().Unix()
	due, err := listApprovals(ctx, tx,
		`WHERE (state = 'pending' AND request_expires_unix < ?) OR (state = 'approved' AND approval_expires_unix < ?)`, now, now)
	if err != nil {
		return 0, err
	}
	for _, a := range due {
		res, err := tx.ExecContext(ctx, `UPDATE approvals SET state = 'expired' WHERE approval_id = ? AND state = ?`, a.ID, string(a.State))
		if err != nil {
			return 0, err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			continue
		}
		a.State = StateExpired
		if e.cfg.OnDecided != nil {
			if err := e.cfg.OnDecided(ctx, tx, Decision{Approval: *a, Outcome: OutcomeExpired, Reason: "expired"}); err != nil {
				return 0, err
			}
		}
	}
	return len(due), nil
}

func (e *Engine) channelAllowed(c string) bool { return slices.Contains(e.cfg.Channels, c) }

// requesterWho names the requester of a for an alert: "run <id>", "orchestrator
// <id>" or "key <id>". An unknown kind is named as such, never as a run.
func requesterWho(a *Approval) string {
	switch a.RequesterKind {
	case "run":
		return "run " + a.RunID
	case "orchestrator":
		return "orchestrator " + a.RequesterKey
	case "key":
		return "key " + a.RequesterKey
	}
	return "unknown requester " + a.RequesterKey
}
