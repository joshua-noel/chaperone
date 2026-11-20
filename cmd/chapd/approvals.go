package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/joshua-noel/chaperone/internal/approvals"
	"github.com/joshua-noel/chaperone/internal/ledger"
	"github.com/joshua-noel/chaperone/internal/notify"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/runtoken"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// The approvals engine (L1-12, ADR-004) is built once and serves two callers:
//
//   - the console decides cards with it (Console.UseApprovals; the engine's
//     Verifier is the console itself, so a decision rests on a fresh Windows
//     Hello assertion and never on the session);
//   - the op state machine (internal/ops) asks it for a card, cancels it, and
//     spends it, through [approvalsBridge], which is ops.Approvals.
//
// The console's own cards (secrets.write, requested by the orchestrator id
// "operator") have no row in the ops table; the bridge leaves them to the
// console.

// approvalsBridge implements ops.Approvals over the engine and connects the
// engine's decisions back to the op state machine.
type approvalsBridge struct {
	eng *approvals.Engine
	db  *store.DB
	// svc is set once ops.NewService has returned (the service needs the
	// bridge, the engine's hooks need the service).
	svc *ops.Service
	log *slog.Logger

	releasing sync.WaitGroup
}

var _ ops.Approvals = (*approvalsBridge)(nil)

// ---- ops.Approvals ----

func toSpecChecks(cs []ops.Check) []spec.ApprovalCheck {
	out := make([]spec.ApprovalCheck, len(cs))
	for i, c := range cs {
		out[i] = spec.ApprovalCheck{Name: c.Name, Passed: c.Passed, Detail: c.Detail}
	}
	return out
}

func toEvidence(es []ops.Evidence) []approvals.Evidence {
	out := make([]approvals.Evidence, len(es))
	for i, e := range es {
		out[i] = approvals.Evidence{Title: e.Name, Body: e.Text}
	}
	return out
}

func infoOf(a *approvals.Approval) ops.ApprovalInfo {
	expires := a.RequestExpires
	if !a.Expires.IsZero() {
		expires = a.Expires
	}
	ev := make([]ops.Evidence, len(a.Evidence))
	for i, e := range a.Evidence {
		ev[i] = ops.Evidence{Name: e.Title, Text: e.Body}
	}
	return ops.ApprovalInfo{
		ID: a.ID, RequestID: a.RequestID, Op: a.Op, OpHash: a.OpHash, State: string(a.State), Class: string(a.Class),
		Critical: a.Critical(), PolicyVersion: a.PolicyVersion, CreatedAt: a.Created, DecidedAt: a.Decided,
		ExpiresAt: expires, OwnerKey: a.RequesterKind + ":" + a.RequesterKey, Evidence: ev,
	}
}

// Create makes the card inside the op's transaction. The wake-up push is handed
// back as ApprovalInfo.After: ops runs it after the commit. The critical-class
// alerts of the engine's effects are dropped here because ops raises its own on
// request and on execution; the engine raises the one for the approval.
func (b *approvalsBridge) Create(ctx context.Context, tx *store.Tx, in ops.ApprovalInput) (ops.ApprovalInfo, error) {
	res, err := b.eng.RequestTx(ctx, tx, approvals.RequestInput{
		Request: in.Request, PolicyVersion: in.PolicyVer, Checks: toSpecChecks(in.Checks), Evidence: toEvidence(in.Evidence),
	})
	if err != nil {
		return ops.ApprovalInfo{}, err
	}
	if res.Refusal != nil {
		return ops.ApprovalInfo{}, &ops.Refusal{Code: res.Refusal.Code, Why: res.Refusal.Why}
	}
	if !res.Created {
		// ops stores one live op per requester and op hash, so a pending card of
		// the same caller and hash has a live op already: this cannot happen
		// unless the two tables disagree, and then nothing is queued.
		return ops.ApprovalInfo{}, fmt.Errorf("approvals: a pending card for this request already belongs to %s", res.Approval.RequestID)
	}
	info := infoOf(res.Approval)
	fx := res.Effects.WithoutAlerts()
	info.After = func(ctx context.Context) { fx.Run(ctx) }
	return info, nil
}

// Lookup reads one approval.
func (b *approvalsBridge) Lookup(ctx context.Context, id string) (ops.ApprovalInfo, error) {
	a, err := b.eng.Get(ctx, id)
	if err != nil {
		return ops.ApprovalInfo{}, err
	}
	if a == nil {
		return ops.ApprovalInfo{}, ops.ErrApprovalNotFound
	}
	return infoOf(a), nil
}

// List returns the approvals owned by key ("run:<id>" or "orchestrator:<id>").
func (b *approvalsBridge) List(ctx context.Context, ownerKey, state string, limit int, after string) ([]ops.ApprovalInfo, string, error) {
	kind, key, ok := strings.Cut(ownerKey, ":")
	if !ok {
		return nil, "", fmt.Errorf("approvals: owner key %q is not kind:id", ownerKey)
	}
	as, next, err := b.eng.ListPage(ctx, kind, key, approvals.State(state), limit, after)
	if err != nil {
		return nil, "", err
	}
	out := make([]ops.ApprovalInfo, len(as))
	for i, a := range as {
		out[i] = infoOf(a)
	}
	return out, next, nil
}

// CancelTx closes a card inside the transaction that cancels its op.
func (b *approvalsBridge) CancelTx(ctx context.Context, tx *store.Tx, approvalID, reason string) error {
	_, err := b.eng.CancelTx(ctx, tx, approvals.CancelInput{ApprovalID: approvalID, Reason: reason})
	return err
}

// ConsumeTx spends a card inside the transaction that releases its op. The
// engine's alert for the execution is dropped: ops raises it.
func (b *approvalsBridge) ConsumeTx(ctx context.Context, tx *store.Tx, approvalID string, req spec.Request) error {
	_, err := b.eng.ConsumeTx(ctx, tx, approvals.ConsumeInput{ApprovalID: approvalID, Request: req})
	var ref *approvals.Refusal
	if errors.As(err, &ref) {
		return &ops.Refusal{Code: ref.Code, Why: ref.Why}
	}
	return err
}

// ---- the engine's hooks ----

// isOp reports whether id is the id of a row of the ops table: a card made
// through ops, as opposed to one the console made for itself.
func (b *approvalsBridge) isOp(ctx context.Context, q interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}, id string) (state string, ok bool, err error) {
	err = q.QueryRowContext(ctx, `SELECT state FROM ops WHERE id = ?`, id).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return state, err == nil, err
}

// onDecided is approvals.Config.OnDecided: it runs inside the transaction of a
// decision (an expiry included) and moves the op the card belongs to.
func (b *approvalsBridge) onDecided(ctx context.Context, tx *store.Tx, d approvals.Decision) error {
	state, ok, err := b.isOp(ctx, tx, d.Approval.RequestID)
	if err != nil || !ok {
		return err // not an op's card: the console's own, which it settles itself
	}
	var dec ops.Decision
	switch d.Outcome {
	case approvals.OutcomeApproved:
		dec.Approved = true
	case approvals.OutcomeDenied:
		dec.Reason = d.Reason
	case approvals.OutcomeExpired:
		if state != string(ops.StatePendingApproval) {
			// An approval that went unused: the op was allowed and never
			// released. The release re-checks the approval and refuses it, and
			// the op expires on its own clock.
			return nil
		}
		dec.Expired, dec.Reason = true, d.Reason
	default:
		return fmt.Errorf("approvals: unknown outcome %q", d.Outcome)
	}
	return b.svc.Decided(ctx, tx, d.Approval.RequestID, d.Approval.ID, dec)
}

// afterApproved is approvals.Config.AfterApproved: the approval has committed,
// so the op is allowed; release it. The call waits for the adapter, so it runs
// on its own goroutine and the console's answer does not wait for GitHub.
func (b *approvalsBridge) afterApproved(ctx context.Context, a *approvals.Approval) {
	if _, ok, err := b.isOp(ctx, b.db.SQL(), a.RequestID); err != nil || !ok {
		if err != nil {
			b.log.Error("could not tell whether an approved card belongs to an op", "approval", a.ID, "err", err)
		}
		return
	}
	b.release(ctx, a.RequestID)
}

func (b *approvalsBridge) release(ctx context.Context, opID string) {
	bg := context.WithoutCancel(ctx)
	b.releasing.Add(1)
	go func() {
		defer b.releasing.Done()
		if err := b.svc.Release(bg, opID); err != nil {
			b.log.Error("could not release an approved op", "op", opID, "err", err)
		}
	}()
}

// releaseAllowed releases the ops that were approved but not released when
// chapd stopped. The release re-checks the approval, the policy and the
// preconditions, so a stale one is refused, never run.
func (b *approvalsBridge) releaseAllowed(ctx context.Context) error {
	rows, err := b.db.SQL().QueryContext(ctx, `SELECT id FROM ops WHERE state = 'allowed' AND approval_id IS NOT NULL`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		b.release(ctx, id)
	}
	return nil
}

// wait blocks until the releases that are running have returned, or d passes.
func (b *approvalsBridge) wait(d time.Duration) {
	done := make(chan struct{})
	go func() { b.releasing.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
	}
}

// stopRaiser is approvals.Config.Stop: the stop table's APPROVAL_FLOOD (pause
// the run) and POLICY_BREACH (quarantine the dependents), written in the
// transaction that raised them.
func stopRaiser(l *ledger.Ledger, newID func() string) func(context.Context, *store.Tx, approvals.Stop) error {
	return func(ctx context.Context, tx *store.Tx, s approvals.Stop) error {
		halts, action := "run", "pause"
		if s.Code == approvals.StopBreach {
			halts, action = "dependents", "quarantine"
		}
		body := s.Why
		switch s.RequesterKind {
		case "orchestrator":
			body = "orchestrator=" + s.RequesterKey + " " + body
		case "key":
			body = "key=" + s.RequesterKey + " " + body
		}
		if len(body) > 1000 {
			body = body[:1000]
		}
		_, err := l.AppendTx(ctx, tx, ledger.Draft{
			Name: "stop.raise", RunID: s.RunID, Project: s.Project, Severity: "WARN",
			Attributes: map[string]any{
				"factory.stop.id": newID(), "factory.cause_code": s.Code, "factory.halts": halts, "factory.action": action,
			},
			Body: body,
		})
		return err
	}
}

// approvalsLedger adapts the ledger to approvals.Ledger.
type approvalsLedger struct{ l *ledger.Ledger }

func (a approvalsLedger) AppendTx(ctx context.Context, tx *store.Tx, ev approvals.LedgerEvent) error {
	_, err := a.l.AppendTx(ctx, tx, ledger.Draft{Name: ev.Name, RunID: ev.RunID, Project: ev.Project, Severity: ev.Severity,
		Attributes: ev.Attributes, Body: ev.Body})
	return err
}

// policyCatalog gives the engine the op classes of the policy catalog, the one
// source of truth for them.
type policyCatalog struct{ c *policy.Catalog }

func (p policyCatalog) Lookup(op string) (approvals.OpInfo, bool) {
	e, ok := p.c.Lookup(op)
	return approvals.OpInfo{Name: op, Class: approvals.Class(e.Class)}, ok
}

// ---- alerts ----

// alerter delivers the loud notice of a critical-class op (decision #21): an
// ERROR line in the log, and, when the alerts script is configured, the Sunday
// Market host's own alert path (alerts.ps1 -Raise). It carries no parameters.
// It implements ops.Alerter, and takes the engine's alert as well.
type alerter struct {
	log    *slog.Logger
	script *ops.AlertsScript
}

var _ ops.Alerter = (*alerter)(nil)

func (a *alerter) raise(stage, op, project, requestID, requester string) {
	a.log.Error("CRITICAL OP "+stage, "op", op, "project", project, "request", requestID, "requester", requester)
	if a.script == nil {
		return
	}
	text := fmt.Sprintf("Chaperone critical op %s: %s in %s", stage, op, project)
	go a.script.RaiseDeployAlert(context.Background(), "chaperone-critical-"+stage, text)
}

// Alert implements ops.Alerter.
func (a *alerter) Alert(_ context.Context, al ops.Alert) {
	if al.Kind == ops.AlertApprovedNotRun {
		a.approvedNotRun(al)
		return
	}
	a.raise(string(al.Kind), al.Op, al.Project, al.RequestID, al.Requester)
}

// approvedNotRun tells the operator that an op he approved did not run. The key is per request, so a second one inside
// the script's 30-minute window is not swallowed by the first.
func (a *alerter) approvedNotRun(al ops.Alert) {
	a.log.Warn("APPROVED OP DID NOT RUN", "op", al.Op, "project", al.Project, "request", al.RequestID, "requester", al.Requester, "why", al.Detail)
	if a.script == nil {
		return
	}
	key := strings.ToLower("chaperone-no-run-" + al.RequestID)
	if len(key) > 40 {
		key = key[:40]
	}
	text := fmt.Sprintf("You approved %s in %s but it did not run (%s). The orchestrator must ask again.", al.Op, al.Project, al.Detail)
	go a.script.RaiseDeployAlert(context.Background(), key, text)
}

// engineAlert is approvals.Config.Alert.
func (a *alerter) engineAlert(al approvals.Alert) {
	a.raise(al.Stage, al.Op, al.Project, al.RequestID, al.Requester)
}

// ---- the notifier ----

// buildNotifier makes the phone wake-up path: the ntfy driver over the topic
// held in the vault, behind the one-push-per-op-hash, never-blocking service.
// Without a configured topic there is none and a card is seen in the console
// and the chap-host toast only.
func (a *App) buildNotifier(ctx context.Context) (*notify.Service, error) {
	driver := a.cfg.notifier
	if driver == nil {
		if a.cfg.NtfyTopicSecretID == "" {
			return nil, nil
		}
		if a.vault == nil {
			return nil, errors.New("chapd: -ntfy-topic-secret needs the vault (-vault-dir): the topic is a secret")
		}
		var topic notify.Topic
		err := a.vault.Use(ctx, a.cfg.NtfyTopicSecretID, func(secret []byte) error {
			var perr error
			topic, perr = notify.ParseTopic(strings.TrimSpace(string(secret)))
			return perr
		})
		if err != nil {
			return nil, fmt.Errorf("chapd: ntfy topic from the vault: %w", err)
		}
		if driver, err = notify.NewNtfy(notify.NtfyConfig{Topic: topic, BaseURL: a.cfg.NtfyURL}); err != nil {
			return nil, err
		}
	}
	a.phone = driver
	return notify.NewService(notify.ServiceConfig{Driver: driver, Logger: a.log, Now: a.cfg.now})
}

// pendingCount is how many approvals wait for the operator: the number chap-host
// shows in its toast.
func (a *App) pendingCount(ctx context.Context) int {
	if a.Approvals == nil {
		return 0
	}
	n, err := a.Approvals.PendingCount(ctx)
	if err != nil {
		a.log.Error("could not count the pending approvals", "err", err)
		return 0
	}
	return n
}

// tokenHolder names the holder of a bearer token that reached an approvals
// route, so the POLICY_BREACH stop is raised against the right run or
// orchestrator. It only reads: a token never decides anything.
func tokenHolder(v *runtoken.Verifier, o *runtoken.Orchestrators, k ops.KeyVerifier) func(context.Context, string) (approvals.Actor, bool) {
	return func(ctx context.Context, bearer string) (approvals.Actor, bool) {
		if strings.HasPrefix(bearer, "chap_orch_") {
			if p, err := o.Verify(ctx, bearer); err == nil {
				return approvals.Actor{Kind: approvals.ActorOrchestrator, ID: p.ID}, true
			}
			return approvals.Actor{}, false
		}
		if strings.HasPrefix(bearer, ops.KeyPrefix) {
			if k != nil {
				if c, err := k.VerifyKey(ctx, bearer); err == nil {
					return approvals.Actor{Kind: approvals.ActorKey, ID: c.KeyID}, true
				}
			}
			return approvals.Actor{}, false
		}
		if t, err := v.Verify(ctx, bearer); err == nil {
			return approvals.Actor{Kind: approvals.ActorRun, RunID: t.Claims.RunID}, true
		}
		return approvals.Actor{}, false
	}
}

// alertsScript is the Storefront host's alert path (alerts.ps1 -Raise), or
// nil when the alert flags are not set.
func (c deployConfig) alertsScript(log *slog.Logger) *ops.AlertsScript {
	if c.AlertsScript == "" {
		return nil
	}
	ps := c.PowerShell
	if ps == "" {
		ps = filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	}
	return &ops.AlertsScript{PowerShell: ps, Script: c.AlertsScript, Folder: c.AlertsFolder, Log: log}
}
