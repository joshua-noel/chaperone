package approvals

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// systemApprover is the approver id on the op.approve event of a cancellation:
// nobody decided it, the requester or the run's end did.
const systemApprover = "chaperone"

// ConsumeInput releases an op under its approval.
type ConsumeInput struct {
	ApprovalID string
	// Request is the request being released now. Its op hash is computed again
	// from its content; the op_hash member it carries is not trusted.
	Request spec.Request
}

// ConsumeTx is the approved→consumed compare-and-set (ADR-004 section 1). The op
// state machine calls it inside the transaction that moves the op to executing
// and writes the ledger event, so the approval is used exactly when the op is
// released and never otherwise.
//
// It refuses, without writing anything (so the caller may roll back), when:
//   - the request being released does not hash to the approved op_hash, or is
//     another request or another requester: APPROVAL_HASH_MISMATCH, and the
//     approval stays unused for the request it was made for;
//   - the approval was used already: APPROVAL_CONSUMED;
//   - nobody has decided yet: OP_APPROVAL_REQUIRED; the operator denied or the
//     request was cancelled: OP_APPROVAL_DENIED;
//   - the approval, or the request it was made for, ran out: OP_APPROVAL_EXPIRED;
//   - the policy changed since the card was made: OP_POLICY_REFUSED.
//
// The refusal is the returned error (a *[Refusal]); effects must be run after the commit.
func (e *Engine) ConsumeTx(ctx context.Context, tx *store.Tx, in ConsumeInput) (Effects, error) {
	now := e.now()
	a, err := getApproval(ctx, tx, in.ApprovalID)
	if err != nil {
		return Effects{}, err
	}
	if a == nil {
		return Effects{}, refuse(CodeNoSuchApproval, "there is no such approval")
	}
	hash, err := spec.OpHash(in.Request)
	if err != nil {
		return Effects{}, &Refusal{Code: CodeParamsInvalid, ApprovalID: a.ID, Why: "the request cannot be hashed: " + err.Error()}
	}
	req := in.Request
	key, run, kerr := requesterOf(req.Requester)
	if hash != a.OpHash || req.RequestID != a.RequestID || kerr != nil || req.Requester.Kind != a.RequesterKind ||
		key != a.RequesterKey || run != a.RunID {
		return Effects{}, &Refusal{Code: CodeHashMismatch, ApprovalID: a.ID,
			Why: "this approval does not apply to this request: its op hash, request or requester differs"}
	}
	if r := verifyCard(a); r != nil {
		return Effects{}, r
	}
	var r *Refusal
	switch a.State {
	case StateApproved:
		if now.Unix() > a.Expires.Unix() {
			r = refuse(CodeExpired, "the approval expired before the op was released")
		}
	case StatePending:
		r = refuse(CodeApprovalRequired, "nobody has decided this request yet")
		if now.Unix() > a.RequestExpires.Unix() {
			r = refuse(CodeExpired, "this request expired before it was decided")
		}
	case StateConsumed:
		r = refuse(CodeConsumed, "this approval has already released an op")
	case StateDenied:
		r = refuse(CodeDenied, "this request was denied")
	case StateCancelled:
		r = refuse(CodeDenied, "this request was cancelled")
	default:
		r = refuse(CodeExpired, "this approval expired")
	}
	if r == nil {
		if v := e.currentPolicy(); v != "" && v != a.PolicyVersion {
			r = refuse(CodePolicyRefused, "the policy changed after the approval was given; a new approval is needed")
		}
	}
	if r != nil {
		r.ApprovalID = a.ID
		return Effects{}, r
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE approvals SET state = 'consumed', consumed_unix = ?
		 WHERE approval_id = ? AND state = 'approved' AND approval_expires_unix >= ?`, now.Unix(), a.ID, now.Unix())
	if err != nil {
		return Effects{}, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return Effects{}, &Refusal{Code: CodeConsumed, ApprovalID: a.ID, Why: "this approval has already released an op"}
	}
	fx := Effects{e: e}
	if a.Class == ClassCritical {
		fx.alerts = append(fx.alerts, e.alert(AlertExecuting, a))
	}
	return fx, nil
}

// CancelInput withdraws approvals: of one approval, of one request (the
// requester cancelled it), or of every request of one run (the run ended or was
// revoked). Exactly one of ApprovalID, RequestID and RunID is set.
type CancelInput struct {
	ApprovalID string
	RequestID  string
	RunID      string
	Reason     string
}

// CancelTx closes the pending and approved-but-unused approvals named by in, and
// appends an op.approve event with decision denied and the reason for each
// (api/openapi.yaml, "cancelled by requester", "run ended"). A cancellation is
// not the operator's "no", so it starts no sticky-deny window. It returns how many
// approvals it closed.
func (e *Engine) CancelTx(ctx context.Context, tx *store.Tx, in CancelInput) (int, error) {
	if n := countSet(in.ApprovalID, in.RequestID, in.RunID); n != 1 {
		return 0, errors.New("approvals: CancelInput needs exactly one of ApprovalID, RequestID and RunID")
	}
	reason := strings.TrimSpace(in.Reason)
	if reason == "" || !utf8.ValidString(reason) || utf8.RuneCountInString(reason) > 500 {
		return 0, errors.New("approvals: CancelInput.Reason must be 1 to 500 characters")
	}
	var open []*Approval
	var err error
	switch {
	case in.ApprovalID != "":
		open, err = listApprovals(ctx, tx, `WHERE approval_id = ? AND state IN ('pending', 'approved')`, in.ApprovalID)
	case in.RequestID != "":
		open, err = listApprovals(ctx, tx, `WHERE request_id = ? AND state IN ('pending', 'approved')`, in.RequestID)
	default:
		open, err = listApprovals(ctx, tx, `WHERE run_id = ? AND state IN ('pending', 'approved')`, in.RunID)
	}
	if err != nil {
		return 0, err
	}
	for _, a := range open {
		res, err := tx.ExecContext(ctx, `UPDATE approvals SET state = 'cancelled' WHERE approval_id = ? AND state = ?`, a.ID, string(a.State))
		if err != nil {
			return 0, err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return 0, fmt.Errorf("approvals: %s changed during cancellation", a.ID)
		}
		a.State, a.Approver = StateCancelled, systemApprover
		if err := e.ledgerDecision(ctx, tx, a, "denied", "", "cancelled: "+reason); err != nil {
			return 0, err
		}
	}
	return len(open), nil
}

func countSet(vs ...string) int {
	n := 0
	for _, v := range vs {
		if v != "" {
			n++
		}
	}
	return n
}
