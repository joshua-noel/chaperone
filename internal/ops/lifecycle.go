package ops

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// Cause codes written on op.result for terminal states that are not an adapter
// outcome. The schema's cause_code is free UPPER_SNAKE text.
const (
	causeCancelled   = "CANCELLED_BY_REQUESTER"
	causeRunEnded    = "RUN_ENDED"
	causeOrchRevoked = "ORCHESTRATOR_REVOKED"
	causeExpired     = "OP_APPROVAL_EXPIRED"
	causeRestart     = "CHAPD_RESTARTED"
	causePolicyMoved = "OP_POLICY_REFUSED"
)

// maxWait is the longest a call may hold (api/openapi.yaml, parameter wait).
const maxWait = 55 * time.Second

// release moves an allowed op to executing and runs its adapter, waiting up to
// wait for the result. The execution continues after the caller gives up: the
// outcome is always recorded, whoever is listening.
func (s *Service) release(ctx context.Context, id string, wait time.Duration) (*SubmitResult, error) {
	done, err := s.startRelease(ctx, id)
	if err != nil {
		return nil, err
	}
	if done != nil {
		if wait > maxWait {
			wait = maxWait
		}
		t := time.NewTimer(wait)
		defer t.Stop()
		select {
		case <-done:
		case <-t.C:
		case <-ctx.Done():
		}
	}
	rec, err := dbGet(context.WithoutCancel(ctx), s.db, id)
	if err != nil {
		return nil, s.unavailable("could not read the op back", err)
	}
	return &SubmitResult{Op: rec}, nil
}

// Release is for the approvals engine: call it after the transaction that
// approved the op has committed. It returns when the op reaches a terminal or
// unconfirmed state, or ctx ends (the execution carries on).
func (s *Service) Release(ctx context.Context, id string) error {
	_, err := s.release(ctx, id, maxWait)
	return err
}

// startRelease does the work that must finish before the caller is answered
// (the re-check, the allowed -> executing compare-and-set) and starts the
// adapter in a goroutine. The returned channel closes when the op is no longer
// executing in this process; nil means there is nothing to wait for.
func (s *Service) startRelease(ctx context.Context, id string) (<-chan struct{}, error) {
	s.mu.Lock()
	if ch, busy := s.inflight[id]; busy {
		s.mu.Unlock()
		return ch, nil
	}
	ch := make(chan struct{})
	s.inflight[id] = ch
	s.mu.Unlock()
	finish := func() {
		s.mu.Lock()
		delete(s.inflight, id)
		s.mu.Unlock()
		close(ch)
	}

	bg := context.WithoutCancel(ctx)
	rec, err := dbGet(bg, s.db, id)
	if err != nil {
		finish()
		return nil, s.unavailable("could not read the op", err)
	}
	if rec.State != StateAllowed {
		finish()
		return nil, nil
	}
	adapter, ok := s.adapters[rec.Op]
	if !ok {
		err := s.settleRefused(bg, rec, StateAllowed, &Refusal{Code: CodeOpDisabled, Why: rec.Op + " has no adapter installed in this chapd"})
		finish()
		return nil, err
	}
	eff := s.policy.For(rec.Project)

	// An approval is valid only for the policy it was given under (spec: the
	// consumer compares policy_version). So is an enabled flag: re-check both.
	switch {
	case !rec.ExpiresAt.After(s.now()):
		err := s.settle(bg, rec, StateAllowed, StateExpired, "refused", causeExpired, Outcome{}, "")
		if err == nil {
			s.alertApprovedNotRun(bg, rec, causeExpired, "the approval ran out before the operation started")
		}
		finish()
		return nil, err
	case eff.Invalid != nil || !eff.Enabled(rec.Op):
		why := rec.Op + " is disabled by policy for " + rec.Project
		if eff.Invalid != nil {
			why = eff.Invalid.Error()
		}
		err := s.settleRefused(bg, rec, StateAllowed, &Refusal{Code: CodeOpDisabled, Why: why})
		finish()
		return nil, err
	case rec.ApprovalID != "" && rec.PolicyVersion != eff.Version:
		err := s.settleRefused(bg, rec, StateAllowed, &Refusal{Code: causePolicyMoved, CanRequest: s.appr != nil,
			Why: "the policy changed after this op was approved; the approval is not valid under policy " + eff.Version})
		finish()
		return nil, err
	}

	req, err := rec.request(nil)
	if err != nil {
		finish()
		return nil, s.unavailable("stored request is unreadable", err)
	}
	// What the approver saw on the card is what the adapter may bind itself to (pr.merge: the PR title). The evidence
	// cannot change after the card was made, and ConsumeTx below re-renders and verifies the card before it spends it.
	if rec.ApprovalID != "" && s.appr != nil {
		info, aerr := s.appr.Lookup(bg, rec.ApprovalID)
		if aerr != nil {
			finish()
			return nil, s.unavailable("could not read the approval", aerr)
		}
		req.ApprovedEvidence = info.Evidence
	}
	// Preconditions are checked again at release: CI may have turned red or the
	// head may have moved while a card waited.
	if _, cerr := adapter.Check(bg, req); cerr != nil {
		var ref *Refusal
		if errors.As(cerr, &ref) {
			err := s.settleRefused(bg, rec, StateAllowed, ref)
			finish()
			return nil, err
		}
		finish()
		return nil, s.unavailable("the "+rec.Op+" adapter could not re-check this request", cerr)
	}

	execID := s.newID("x-")
	err = s.db.Immediate(bg, func(ctx context.Context, tx *store.Tx) error {
		if err := (transition{From: StateAllowed, To: StateExecuting, Now: s.now(), ExecutionID: execID}).apply(ctx, tx, id); err != nil {
			return err
		}
		if rec.ApprovalID == "" || s.appr == nil {
			return nil
		}
		// The approval is spent in the same commit that releases the op: a
		// request whose hash differs, or an approval used before, rolls both back.
		sreq := rec.specRequest()
		sreq.Params = req.Params
		return s.appr.ConsumeTx(ctx, tx, rec.ApprovalID, sreq)
	})
	var ref *Refusal
	if errors.As(err, &ref) {
		err := s.settleRefused(bg, rec, StateAllowed, ref)
		finish()
		return nil, err
	}
	if errors.Is(err, errStale) {
		finish() // another process released it first
		return nil, nil
	}
	if err != nil {
		finish()
		return nil, s.unavailable("could not start the op", err)
	}
	rec.State, rec.ExecutionID = StateExecuting, execID
	req.ExecutionID = execID
	if s.alert != nil && rec.Class == string(policy.ClassCritical) {
		s.alert.Alert(bg, Alert{Kind: AlertExecution, Op: rec.Op, Project: rec.Project, RequestID: rec.ID, Requester: rec.RequesterKey})
	}

	go func() {
		defer finish()
		s.execute(bg, adapter, rec, req)
	}()
	return ch, nil
}

// execute runs the adapter and records the outcome. An adapter that returns an
// error, panics or times out leaves the result unknown: the op becomes
// unconfirmed, never failed and never succeeded (spec section 5).
func (s *Service) execute(ctx context.Context, adapter Adapter, rec *record, req *Request) {
	ctx, cancel := context.WithTimeout(ctx, s.execTO)
	defer cancel()
	var out Outcome
	var err error
	func() {
		defer func() {
			if p := recover(); p != nil {
				err = fmt.Errorf("adapter panic: %v", p)
			}
		}()
		out, err = adapter.Execute(ctx, req)
	}()
	to, outcome := StateSucceeded, "succeeded"
	switch {
	case err != nil || out.Unconfirmed:
		to, outcome = StateUnconfirmed, "unconfirmed"
		out.ExternalRef = ""
		if err != nil {
			// The error text is the adapter's and may quote a credential.
			s.log.Warn("ops: adapter result unknown", "op", rec.Op, "request", shortID(rec.ID), "err", s.mask(err.Error()))
		}
	case out.Failed:
		to, outcome = StateFailed, "failed"
		// What the adapter says went wrong (for pr.open, GitHub's own words),
		// so the operator does not need the agent's report to see it.
		msg, _ := out.Result["error"].(string)
		s.log.Warn("ops: op failed", "op", rec.Op, "request", shortID(rec.ID), "error", clamp(s.mask(msg), 500))
	}
	if serr := s.settle(context.WithoutCancel(ctx), rec, StateExecuting, to, outcome, "", out, rec.ExecutionID); serr != nil {
		// The result could not be written. The row stays `executing`; Recover
		// turns it into `unconfirmed` on the next start. Nothing is lost silently.
		s.log.Error("ops: could not record the result", "op", rec.Op, "request", shortID(rec.ID), "err", serr)
	}
}

// settle moves an op to a result state in one transaction with its op.result
// event. refused/expired/cancelled results carry a cause code.
func (s *Service) settle(ctx context.Context, rec *record, from, to State, outcome, cause string, out Outcome, execID string) error {
	t := transition{From: from, To: to, Now: s.now(), Outcome: outcome, CauseCode: cause}
	r := *rec
	if execID != "" {
		r.ExecutionID = execID
	}
	if out.ExternalRef != "" {
		t.ExternalRef = s.mask(out.ExternalRef)
		r.ExternalRef = t.ExternalRef
	}
	if len(out.Result) > 0 {
		body, err := json.Marshal(out.Result)
		if err != nil {
			return err
		}
		t.ResultJSON = s.maskJSON(string(body))
	}
	eventOutcome := outcome
	if to == StateExpired || to == StateCancelled {
		eventOutcome = "refused" // nothing was released
	}
	err := s.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		if err := t.apply(ctx, tx, rec.ID); err != nil {
			return err
		}
		return s.led.AppendTx(ctx, tx, r.resultEvent(eventOutcome, cause))
	})
	if err != nil && !errors.Is(err, errStale) {
		return s.unavailable("could not record the result", err)
	}
	return err
}

// settleRefused moves an allowed op to refused because a check made at release
// failed, and gives the agent the reason: the denial (cause code, why and the
// next command) is written in the same transaction as the op.result event and
// is stored on the op row, so `chap op show` shows it. Without it an op the
// agent saw allowed turns into a bare "refused" with no cause.
func (s *Service) settleRefused(ctx context.Context, rec *record, from State, ref *Refusal) error {
	d := denial{
		Project: rec.Project, Surface: ref.Surface, Verb: rec.Op, Target: rec.TargetRef,
		Code: ref.Code, Why: ref.Why, RequestID: rec.ID,
	}
	if ref.CanRequest {
		d.CanRequest = true
		d.Command = requestCommand(rec.Op, spec.Target{Adapter: rec.TargetAdapter, Ref: rec.TargetRef}, rec.ParamsJSON)
	}
	var storedCode, storedWhy string
	err := s.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		de, err := s.refuse(ctx, tx, rec.caller(), d)
		if err != nil {
			return err
		}
		storedCode, storedWhy = de.Denial.CauseCode, de.Denial.Why
		body, err := json.Marshal(de.Denial)
		if err != nil {
			return err
		}
		t := transition{From: from, To: StateRefused, Now: s.now(), Outcome: "refused", CauseCode: ref.Code, DenialJSON: string(body)}
		if err := t.apply(ctx, tx, rec.ID); err != nil {
			return err
		}
		return s.led.AppendTx(ctx, tx, rec.resultEvent("refused", ref.Code))
	})
	if err != nil && !errors.Is(err, errStale) {
		return s.unavailable("could not record the refusal", err)
	}
	if err == nil {
		// The alert says what was stored (after the leak check), never the adapter's raw words.
		s.alertApprovedNotRun(ctx, rec, storedCode, storedWhy)
	}
	return err
}

// alertApprovedNotRun tells the operator that an op he approved did not run. He spent a Hello on it; the card says
// "Approved" and nothing else would tell him it was refused at release (a stale CI head, a policy that moved) or
// ran out. The alert is not raised for an op that needed no approval: nobody waited on it. why is the stored
// (redacted) refusal text; control characters are replaced so it stays on one line in argv and in alerts-*.log.
func (s *Service) alertApprovedNotRun(ctx context.Context, rec *record, cause, why string) {
	if s.alert == nil || rec.ApprovalID == "" {
		return
	}
	s.alert.Alert(context.WithoutCancel(ctx), Alert{Kind: AlertApprovedNotRun, Op: rec.Op, Project: rec.Project, RequestID: rec.ID,
		Requester: rec.RequesterKey, Detail: oneLine(cause + ": " + clamp(why, 120))})
}

// oneLine replaces every control or line-breaking character with a space.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return ' '
		}
		return r
	}, s)
}
func (s *Service) mask(v string) string {
	if s.redactor == nil {
		return v
	}
	m, _ := s.redactor.Redact(v)
	return m
}

// maskJSON masks secrets in a result. A result that held one is not stored
// (REDACTION_BLOCKED): a half-masked body is still a leak candidate.
func (s *Service) maskJSON(v string) string {
	if s.redactor == nil {
		return v
	}
	if _, res := s.redactor.Redact(v); res.Blocked() {
		return `{"blocked":"` + CodeRedactionBlocked + `"}`
	}
	return v
}

// waitFor polls the op until it leaves since (or is terminal) or wait passes.
func (s *Service) waitFor(ctx context.Context, id string, wait time.Duration, since State) (*record, error) {
	if wait > maxWait {
		wait = maxWait
	}
	deadline := time.Now().Add(wait)
	for {
		rec, err := s.sweepOne(ctx, id)
		if err != nil {
			return nil, err
		}
		if rec.State.Terminal() || (since != "" && rec.State != since) || (since == "" && wait == 0) || !time.Now().Before(deadline) {
			return rec, nil
		}
		select {
		case <-ctx.Done():
			return rec, nil
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// sweepOne reads an op and expires it first if it is past its time.
func (s *Service) sweepOne(ctx context.Context, id string) (*record, error) {
	rec, err := dbGet(ctx, s.db, id)
	if errors.Is(err, errNotFound) {
		return nil, err
	}
	if err != nil {
		return nil, s.unavailable("could not read the op", err)
	}
	if (rec.State == StatePendingApproval || rec.State == StateAllowed) && !rec.ExpiresAt.After(s.now()) {
		if err := s.expire(ctx, rec); err != nil {
			return nil, err
		}
		return dbGet(ctx, s.db, id)
	}
	return rec, nil
}

// expire moves a waiting op past its time to expired and cancels its card.
func (s *Service) expire(ctx context.Context, rec *record) error {
	err := s.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		if rec.State == StatePendingApproval && rec.ApprovalID != "" && s.appr != nil {
			if err := s.appr.CancelTx(ctx, tx, rec.ApprovalID, "request expired"); err != nil {
				return err
			}
		}
		if err := (transition{From: rec.State, To: StateExpired, Now: s.now(), Outcome: "refused", CauseCode: causeExpired}).apply(ctx, tx, rec.ID); err != nil {
			return err
		}
		return s.led.AppendTx(ctx, tx, rec.resultEvent("refused", causeExpired))
	})
	if err != nil && !errors.Is(err, errStale) {
		return s.unavailable("could not expire the op", err)
	}
	if err == nil && rec.State == StateAllowed {
		// Approved, and the requester never came back to start it: the commonest way an approved op does not run.
		s.alertApprovedNotRun(ctx, rec, causeExpired, "the approval ran out before the requester started the operation")
	}
	return nil
}

// Sweep expires every waiting op past its time. chapd runs it on a timer.
func (s *Service) Sweep(ctx context.Context) (int, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT `+recordColumns+` FROM ops
        WHERE state IN ('pending_approval','allowed') AND expires_at <= ?`, s.now().Unix())
	if err != nil {
		return 0, err
	}
	var recs []*record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			rows.Close()
			return 0, err
		}
		recs = append(recs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	for _, r := range recs {
		if err := s.expire(ctx, r); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// Recover runs once at start: an op found `executing` was dispatched by a
// process that died. Nobody knows whether the action happened, so it becomes
// `unconfirmed`. The adapter is not run again: a second execution could repeat
// the write. The op stays unconfirmed until [Service.Reconcile] settles it, and
// no shipped code calls that yet.
func (s *Service) Recover(ctx context.Context) (int, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT `+recordColumns+` FROM ops WHERE state = 'executing'`)
	if err != nil {
		return 0, err
	}
	var recs []*record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			rows.Close()
			return 0, err
		}
		recs = append(recs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, r := range recs {
		if err := s.settle(ctx, r, StateExecuting, StateUnconfirmed, "unconfirmed", "", Outcome{}, r.ExecutionID); err != nil && !errors.Is(err, errStale) {
			return 0, err
		}
	}
	return len(recs), nil
}

// Reconcile writes the final result of an unconfirmed op once its adapter has
// asked the service. The execution_id is the one already assigned.
func (s *Service) Reconcile(ctx context.Context, id string, out Outcome) error {
	rec, err := dbGet(ctx, s.db, id)
	if err != nil {
		return err
	}
	if rec.State != StateUnconfirmed {
		return fmt.Errorf("ops: %s is %s, not unconfirmed", id, rec.State)
	}
	to, outcome := StateSucceeded, "succeeded"
	if out.Failed {
		to, outcome = StateFailed, "failed"
	}
	return s.settle(ctx, rec, StateUnconfirmed, to, outcome, "", out, rec.ExecutionID)
}

// Decision is the approvals engine's verdict on a pending op.
type Decision struct {
	Approved bool
	Expired  bool
	Reason   string
}

// Decided applies the engine's decision inside the engine's own transaction (the
// one that records the assertion and the op.approve event), so the op's state
// and the approval move together. After the transaction commits the engine
// calls [Service.Release] for an approved op. Only the console reaches this:
// no API route does.
func (s *Service) Decided(ctx context.Context, tx *store.Tx, id, approvalID string, d Decision) error {
	rec, err := txGet(ctx, tx, id)
	if err != nil {
		return err
	}
	if rec.State != StatePendingApproval {
		return errStale
	}
	if d.Approved {
		return transition{From: StatePendingApproval, To: StateAllowed, Now: s.now(), ApprovalID: approvalID}.apply(ctx, tx, id)
	}
	code, to := CodeApprovalDenied, StateDenied
	if d.Expired {
		code, to = CodeApprovalExpired, StateExpired
	}
	why := d.Reason
	if why == "" {
		why = "the approval was " + string(to)
	}
	c := rec.caller()
	de, err := s.refuse(ctx, tx, c, denial{Project: rec.Project, Verb: rec.Op, Target: rec.TargetRef, Code: code, Why: why, RequestID: rec.ID})
	if err != nil {
		return err
	}
	body, err := json.Marshal(de.Denial)
	if err != nil {
		return err
	}
	return transition{From: StatePendingApproval, To: to, Now: s.now(), CauseCode: code, DenialJSON: string(body)}.apply(ctx, tx, id)
}

// CancelRunOps is the Runs.TxEnd hook (ADR-005): inside the run-end
// transaction, cancel the run's pending approvals and waiting ops.
func (s *Service) CancelRunOps(ctx context.Context, tx *store.Tx, runID, reason string) error {
	return s.cancelOpsOf(ctx, tx, "run:"+runID, reason, causeRunEnded)
}

// CancelOrchOps is the Orchestrators.TxRevoke hook (ADR-007 item 7): revoking
// the orchestrator cancels its pending approvals and waiting ops.
func (s *Service) CancelOrchOps(ctx context.Context, tx *store.Tx, orchID string) error {
	return s.cancelOpsOf(ctx, tx, "orchestrator:"+orchID, "orchestrator revoked", causeOrchRevoked)
}

func (s *Service) cancelOpsOf(ctx context.Context, tx *store.Tx, requesterKey, reason, cause string) error {
	rows, err := tx.QueryContext(ctx, `SELECT `+recordColumns+` FROM ops WHERE requester_key = ? AND state IN ('pending_approval','allowed')`, requesterKey)
	if err != nil {
		return err
	}
	var recs []*record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			rows.Close()
			return err
		}
		recs = append(recs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range recs {
		if err := s.cancelTx(ctx, tx, r, reason, cause); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) cancelTx(ctx context.Context, tx *store.Tx, rec *record, reason, cause string) error {
	if rec.State == StatePendingApproval && rec.ApprovalID != "" && s.appr != nil {
		if err := s.appr.CancelTx(ctx, tx, rec.ApprovalID, reason); err != nil {
			return err
		}
	}
	if err := (transition{From: rec.State, To: StateCancelled, Now: s.now(), Outcome: "refused", CauseCode: cause}).apply(ctx, tx, rec.ID); err != nil {
		return err
	}
	return s.led.AppendTx(ctx, tx, rec.resultEvent("refused", cause))
}

// ConflictError: the op cannot be cancelled in its state.
type ConflictError struct {
	Why   string
	State State
}

func (e *ConflictError) Error() string { return e.Why }

// NotFoundError: no such op for this caller (another caller's op looks the same).
type NotFoundError struct{ Why string }

func (e *NotFoundError) Error() string { return e.Why }

// Cancel withdraws the caller's own op while it is pending approval or allowed.
func (s *Service) Cancel(ctx context.Context, c *Caller, id string) (*record, error) {
	rec, err := s.own(ctx, c, id)
	if err != nil {
		return nil, err
	}
	err = s.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		cur, err := txGet(ctx, tx, id)
		if err != nil {
			return err
		}
		if cur.State != StatePendingApproval && cur.State != StateAllowed {
			return &ConflictError{Why: "an op in state " + string(cur.State) + " cannot be cancelled", State: cur.State}
		}
		return s.cancelTx(ctx, tx, cur, "cancelled by requester", causeCancelled)
	})
	var ce *ConflictError
	switch {
	case errors.As(err, &ce):
		return nil, ce
	case err != nil:
		return nil, s.unavailable("could not cancel the op", err)
	}
	_ = rec
	return dbGet(ctx, s.db, id)
}

// own loads an op the caller owns; anything else is NotFound.
func (s *Service) own(ctx context.Context, c *Caller, id string) (*record, error) {
	rec, err := s.sweepOne(ctx, id)
	if errors.Is(err, errNotFound) || (err == nil && rec.RequesterKey != c.Key()) {
		return nil, &NotFoundError{Why: "no such op for this caller"}
	}
	return rec, err
}

// Get returns the caller's op, optionally holding up to wait for a change from since.
func (s *Service) Get(ctx context.Context, c *Caller, id string, wait time.Duration, since State) (*record, error) {
	if _, err := s.own(ctx, c, id); err != nil {
		return nil, err
	}
	rec, err := s.waitFor(ctx, id, wait, since)
	if errors.Is(err, errNotFound) {
		return nil, &NotFoundError{Why: "no such op for this caller"}
	}
	return rec, err
}

// List returns the caller's ops newest first. after is the id of the last op
// of the previous page.
func (s *Service) List(ctx context.Context, c *Caller, state State, limit int, after string) ([]*record, string, error) {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	q := `SELECT ` + recordColumns + ` FROM ops WHERE requester_key = ?`
	args := []any{c.Key()}
	if state != "" {
		q += ` AND state = ?`
		args = append(args, string(state))
	}
	if after != "" {
		var at int64
		var rowid int64
		err := s.db.SQL().QueryRowContext(ctx, `SELECT requested_at, rowid FROM ops WHERE id = ? AND requester_key = ?`, after, c.Key()).Scan(&at, &rowid)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", &NotFoundError{Why: "unknown cursor"}
		}
		if err != nil {
			return nil, "", s.unavailable("could not read the op list", err)
		}
		q += ` AND (requested_at < ? OR (requested_at = ? AND rowid < ?))`
		args = append(args, at, at, rowid)
	}
	q += ` ORDER BY requested_at DESC, rowid DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := s.db.SQL().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, "", s.unavailable("could not read the op list", err)
	}
	defer rows.Close()
	var out []*record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, "", err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = out[len(out)-1].ID
	}
	return out, next, nil
}

// specRequest is the spec operation-request document of the op, for tests and exports.
func (r *record) specRequest() spec.Request {
	req := spec.Request{
		SpecVersion: spec.SpecVersion, Type: "op.request", RequestID: r.ID, Project: r.Project, Op: r.Op,
		Target: spec.Target{Adapter: r.TargetAdapter, Ref: r.TargetRef}, OpHash: r.OpHash, Reason: r.Reason,
		RequestedAt: r.RequestedAt.Format(time.RFC3339), ExpiresAt: r.ExpiresAt.Format(time.RFC3339),
		Traceparent: r.Traceparent,
	}
	if r.RequesterKind == KindRun {
		req.Requester = spec.Requester{Kind: KindRun, RunID: r.RunID, TokenJTI: r.TokenJTI, Profile: r.Profile}
	} else {
		req.Requester = spec.Requester{Kind: KindOrchestrator, ID: r.OrchID}
	}
	return req
}
