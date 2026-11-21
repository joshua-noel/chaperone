package keys

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/spec"
)

// Operator is what the Decider needs of the ops service: to ask for the card of an op as the operator, and to
// say how an op ended. *ops.Service is one.
type Operator interface {
	RequestAsOperator(ctx context.Context, project, op, reason string, target spec.Target, params map[string]any) (ops.OperatorCard, error)
	OpState(ctx context.Context, id string) (string, error)
}

var _ Operator = (*ops.Service)(nil)

// Decider is what a person at the console does about their own agents (ADR-008): answer an agent's
// request with Grant, Narrow or Deny; enrol an agent; make a key last longer. Every method takes the signed-in
// approver's id, and every request, enrolment and key is looked up for that person alone: another person's agent
// looks like no agent. Grant, enrol and extend start a card; nothing is made until the person signs that card with
// their own Windows Hello, so a form post alone never creates a key.
type Decider struct {
	s  *Store
	op Operator

	mu    sync.Mutex
	wrong map[string][]time.Time // wrong enrolment codes by approver
}

// NewDecider returns the Decider of s.
func NewDecider(s *Store, op Operator) *Decider {
	return &Decider{s: s, op: op, wrong: map[string][]time.Time{}}
}

// OwnerOf is the owner id of the agents of a person at the console.
func OwnerOf(approver string) string { return "person:" + approver }

// Narrowing is what an owner keeps of a request. A nil list or a zero number means "as asked"; a list can only
// name things that were asked for (anything else is refused, whatever the form said).
type Narrowing struct {
	Ops, Units []string
	TTLHours   int
	Rate       int
}

func toAny(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

// mine reads a request that belongs to approver's agents.
func (d *Decider) mine(ctx context.Context, approver, id string) (*requestRow, error) {
	rq, err := d.s.requestRow(ctx, d.s.cfg.DB.SQL(), id)
	if err != nil {
		return nil, err
	}
	if rq.Owner != OwnerOf(approver) {
		return nil, ErrNotFound // another person's agent looks like no agent
	}
	return rq, nil
}

// Pending lists the requests waiting for approver, oldest first (the order they came in: "needed today" does not
// change it).
func (d *Decider) Pending(ctx context.Context, approver string) ([]ops.KeyRequestInfo, error) {
	list, err := d.s.ListRequests(ctx, OwnerOf(approver), "", true)
	for i, j := 0, len(list)-1; i < j; i, j = i+1, j-1 {
		list[i], list[j] = list[j], list[i]
	}
	return list, err
}

// Recent lists the requests approver has already answered or that ended, newest first.
func (d *Decider) Recent(ctx context.Context, approver string) ([]ops.KeyRequestInfo, error) {
	all, err := d.s.ListRequests(ctx, OwnerOf(approver), "", false)
	var out []ops.KeyRequestInfo
	for _, r := range all {
		if r.State != reqPending {
			out = append(out, r)
		}
	}
	if len(out) > 20 {
		out = out[:20]
	}
	return out, err
}

// Request returns one of approver's requests.
func (d *Decider) Request(ctx context.Context, approver, id string) (ops.KeyRequestInfo, error) {
	rq, err := d.mine(ctx, approver, id)
	if err != nil {
		return ops.KeyRequestInfo{}, err
	}
	return d.s.view(rq), nil
}

// Keys lists the keys approver may see and revoke at the console, newest first: the keys of their own agents, and the
// keys that orchestrators own (whoever built a key, the operator can always see it and end it, even when its
// orchestrator is gone). Another person's keys are not listed: people are not modelled yet, and that person's agent
// looks like no agent.
func (d *Decider) Keys(ctx context.Context, approver string) ([]ops.KeyInfo, error) {
	all, err := d.s.List(ctx, "")
	var out []ops.KeyInfo
	for _, k := range all {
		if k.Owner == OwnerOf(approver) || !personRE.MatchString(k.Owner) {
			out = append(out, k)
		}
	}
	return out, err
}

// cardWaiting says whether the card an earlier tap started for this request is still waiting to be signed.
func (d *Decider) cardWaiting(ctx context.Context, opID string) bool {
	if opID == "" {
		return false
	}
	st, err := d.op.OpState(ctx, opID)
	if err != nil {
		return false
	}
	switch st {
	case string(ops.StatePendingApproval), string(ops.StateAllowed), string(ops.StateExecuting):
		return true
	}
	return false
}

// asRule turns what the ops pipeline says about a refused op into a rule the page can show.
func asRule(err error) error {
	var de *ops.DeniedError
	if errors.As(err, &de) {
		return rule("%s", de.Denial.Why)
	}
	var re *ops.Refusal
	if errors.As(err, &re) {
		return rule("%s", re.Why)
	}
	return err
}

// Grant starts the card that grants a request: as asked (n nil), or narrowed. The grant can only be smaller than
// the ask. The returned card is signed on the approvals page; the key row is written only then.
func (d *Decider) Grant(ctx context.Context, approver, id string, n *Narrowing) (ops.OperatorCard, error) {
	rq, err := d.mine(ctx, approver, id)
	if err != nil {
		return ops.OperatorCard{}, err
	}
	if rq.State != reqPending || !d.s.now().Before(unixTime(rq.Expires)) {
		return ops.OperatorCard{}, rule("this request is no longer waiting: it was answered, withdrawn, cancelled, or it expired")
	}
	if d.cardWaiting(ctx, rq.IssueOp) {
		return ops.OperatorCard{}, rule("a card for this request is already waiting: sign or deny it on the approvals page first")
	}
	if stopped, err := d.s.AgentStopped(ctx, rq.Owner, rq.Holder); err != nil {
		return ops.OperatorCard{}, err
	} else if stopped {
		return ops.OperatorCard{}, rule("%s is %s", rq.Holder, StoppedWhy)
	}
	if rq.Kind == reqExtend {
		return d.grantExtend(ctx, rq, n)
	}
	grantOps, grantUnits, ttl, rate := rq.Ops, rq.Units, rq.TTLHours, rq.Rate
	if n != nil {
		if n.Ops != nil {
			grantOps = sortedUnique(n.Ops)
		}
		if n.Units != nil {
			grantUnits = sortedUnique(lowerAll(n.Units))
		}
		if n.TTLHours != 0 {
			ttl = n.TTLHours
		}
		if n.Rate != 0 {
			rate = n.Rate
		}
	}
	// Checked here as well as when the card is made and again when the key is: never wider than the ask.
	switch {
	case len(grantOps) == 0:
		return ops.OperatorCard{}, rule("keep at least one op, or deny the request")
	case !subset(grantOps, rq.Ops), !subset(grantUnits, rq.Units):
		return ops.OperatorCard{}, rule("a grant can only narrow what was asked: it cannot add an op or a repository")
	case ttl > rq.TTLHours, rate > rq.Rate:
		return ops.OperatorCard{}, rule("a grant can only narrow what was asked: it cannot last longer or run faster")
	case ttl < 1 || rate < 1:
		return ops.OperatorCard{}, rule("a key lasts at least an hour and makes at least one call an hour")
	}
	params := map[string]any{
		"request": rq.ID, "owner": rq.Owner, "holder": rq.Holder, "holder_kind": HolderAgent,
		"ops": toAny(grantOps), "units": toAny(grantUnits), "ttl_hours": float64(ttl), "rate_per_hour": float64(rate),
	}
	reason := fmt.Sprintf("%s granted its own agent %s a key (request %s)", ownerName(rq.Owner), rq.Holder, rq.ID)
	card, err := d.op.RequestAsOperator(ctx, rq.Project, OpIssue, reason, spec.Target{Adapter: "chaperone", Ref: "key:" + rq.Holder}, params)
	if err != nil {
		return ops.OperatorCard{}, asRule(err)
	}
	if err := d.s.BindIssue(ctx, rq.ID, card.OpID, grantOps, grantUnits, ttl, rate); err != nil {
		return ops.OperatorCard{}, err
	}
	return card, nil
}

func (d *Decider) grantExtend(ctx context.Context, rq *requestRow, n *Narrowing) (ops.OperatorCard, error) {
	hours := rq.TTLHours
	if n != nil && n.TTLHours != 0 {
		hours = n.TTLHours
	}
	if hours > rq.TTLHours || hours < 1 {
		return ops.OperatorCard{}, rule("an extension can only narrow what was asked: at most %d hours", rq.TTLHours)
	}
	params := map[string]any{
		"key": rq.ExtendsKey, "extend_hours": float64(hours), "owner": rq.Owner, "holder": rq.Holder, "request": rq.ID,
	}
	reason := fmt.Sprintf("%s extended its own agent %s's key (request %s)", ownerName(rq.Owner), rq.Holder, rq.ID)
	card, err := d.op.RequestAsOperator(ctx, rq.Project, OpExtend, reason, spec.Target{Adapter: "chaperone", Ref: "key:" + rq.ExtendsKey}, params)
	if err != nil {
		return ops.OperatorCard{}, asRule(err)
	}
	if err := d.s.BindIssue(ctx, rq.ID, card.OpID, rq.Ops, rq.Units, hours, rq.Rate); err != nil {
		return ops.OperatorCard{}, err
	}
	return card, nil
}

// Deny answers a request with a no. The same exact ask is refused for the next hour.
func (d *Decider) Deny(ctx context.Context, approver, id, reason string) (ops.KeyRequestInfo, error) {
	if _, err := d.mine(ctx, approver, id); err != nil {
		return ops.KeyRequestInfo{}, err
	}
	v, err := d.s.Deny(ctx, id, approver, reason)
	if errors.Is(err, ErrRequestState) {
		return ops.KeyRequestInfo{}, rule("this request is no longer waiting")
	}
	return v, err
}

// Extend starts the card that makes a live key of approver's agent last longer: the one-tap path, with no request
// needed. hours is what is added.
func (d *Decider) Extend(ctx context.Context, approver, keyID string, hours int) (ops.OperatorCard, error) {
	k, err := d.s.keyFacts(ctx, d.s.cfg.DB.SQL(), keyID)
	if err != nil {
		return ops.OperatorCard{}, err
	}
	if k.Owner != OwnerOf(approver) {
		return ops.OperatorCard{}, ErrNotFound
	}
	if _, _, err := d.s.extendCheck(ctx, d.s.cfg.DB.SQL(), keyID, hours); err != nil {
		return ops.OperatorCard{}, err
	}
	params := map[string]any{"key": k.ID, "extend_hours": float64(hours), "owner": k.Owner, "holder": k.Holder}
	reason := fmt.Sprintf("%s extended its own agent %s's key", ownerName(k.Owner), k.Holder)
	card, err := d.op.RequestAsOperator(ctx, k.Project, OpExtend, reason, spec.Target{Adapter: "chaperone", Ref: "key:" + k.ID}, params)
	if err != nil {
		return ops.OperatorCard{}, asRule(err)
	}
	return card, nil
}

// wrongCodeLimit and wrongCodeWindow lock the enrolment-code box of a person who keeps guessing.
const (
	wrongCodeLimit  = 5
	wrongCodeWindow = 10 * time.Minute
)

// ErrCodeLocked is a person who entered too many wrong enrolment codes.
var ErrCodeLocked = errors.New("keys: too many wrong enrolment codes")

// LookupEnrol finds the enrolment a code names, for the page that asks the owner to confirm it. A wrong code is
// counted; too many in ten minutes lock the box for that person until they pass.
func (d *Decider) LookupEnrol(ctx context.Context, approver, code string) (EnrolView, error) {
	now := d.s.now()
	d.mu.Lock()
	recent := d.wrong[approver][:0:0]
	for _, t := range d.wrong[approver] {
		if now.Sub(t) < wrongCodeWindow {
			recent = append(recent, t)
		}
	}
	d.wrong[approver] = recent
	locked := len(recent) >= wrongCodeLimit
	d.mu.Unlock()
	if locked {
		return EnrolView{}, ErrCodeLocked
	}
	v, err := d.s.EnrolmentByCode(ctx, code)
	if errors.Is(err, ErrNotFound) {
		d.mu.Lock()
		d.wrong[approver] = append(d.wrong[approver], now)
		d.mu.Unlock()
	}
	return v, err
}

// ApproveEnrol starts the card that enrols the agent a code names, for approver.
func (d *Decider) ApproveEnrol(ctx context.Context, approver, code string) (ops.OperatorCard, error) {
	v, err := d.LookupEnrol(ctx, approver, code)
	if err != nil {
		return ops.OperatorCard{}, err
	}
	params := map[string]any{
		"enrolment": v.ID, "owner": OwnerOf(approver), "holder": v.Label, "holder_kind": HolderAgent,
		"ops": []any{}, "units": []any{}, "ttl_hours": float64(BootstrapHours), "rate_per_hour": float64(BootstrapRate),
	}
	reason := fmt.Sprintf("%s enrols the agent %s (it gets no access, only the right to ask)", approver, v.Label)
	card, err := d.op.RequestAsOperator(ctx, v.Project, OpIssue, reason, spec.Target{Adapter: "chaperone", Ref: "key:" + v.Label}, params)
	if err != nil {
		return ops.OperatorCard{}, asRule(err)
	}
	if err := d.s.BindEnrolIssue(ctx, v.ID, card.OpID); err != nil {
		return ops.OperatorCard{}, err
	}
	return card, nil
}

// Revoke ends a key at the console. A key of the approver's own agent is the human stop (ADR-008): if an agent held it,
// the agent is stopped for good (an orchestrator's token can never do this). A key an orchestrator owns is ended
// without a stop: it is the operator's power over what an orchestrator built, and the orchestrator may ask again
// (each ask is a card). Revoking only takes access away, so the signed-in session is enough and there is no card:
// the same rule as denying a request, cancelling a card or revoking a run. Another person's key looks like no key.
func (d *Decider) Revoke(ctx context.Context, approver, keyID string) (ops.KeyInfo, error) {
	k, err := d.s.Get(ctx, keyID)
	if err != nil {
		return ops.KeyInfo{}, err
	}
	mine := k.Owner == OwnerOf(approver)
	if !mine && personRE.MatchString(k.Owner) {
		return ops.KeyInfo{}, ErrNotFound
	}
	info, err := d.s.Revoke(ctx, keyID, OwnerOf(approver), mine)
	if errors.Is(err, ErrRevoked) {
		return ops.KeyInfo{}, rule("this key is already revoked")
	}
	return info, err
}

// WaitingEnrolments lists the enrolments that wait for an owner now, oldest first. Until an owner answers, an
// enrolment has no owner, so every signed-in approver sees them all: that is the point, because a start needs no
// credential and a process may keep the slots filled.
func (d *Decider) WaitingEnrolments(ctx context.Context) ([]EnrolView, error) {
	return d.s.WaitingEnrolments(ctx)
}

// CancelEnrol cancels a waiting enrolment, and the ledger names the approver who did. Like a revoke it only takes
// away, so a session is enough, and like the list of waiting enrolments it is open to any signed-in approver: until an
// owner answers, an enrolment has no owner (the same reach as denying a card, which any approver may do). An
// enrolment whose card is already waiting is refused: deny the card first.
func (d *Decider) CancelEnrol(ctx context.Context, approver, id string) error {
	e, err := d.s.enrolRow(ctx, d.s.cfg.DB.SQL(), id)
	if err != nil {
		return err
	}
	if d.cardWaiting(ctx, e.IssueOp) {
		return rule("a card for this enrolment is already waiting: deny it on the approvals page first")
	}
	return d.s.CancelEnrolment(ctx, id, OwnerOf(approver))
}
