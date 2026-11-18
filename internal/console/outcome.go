package console

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// What happened after the operator approved. An approval only lets an op start: at release the op's adapter checks
// again (the CI head may have moved while the card waited, the policy may have changed) and can still refuse it. The
// Approvals screen used to say "Approved." and nothing more. These functions read the op that carries the approval,
// so the card and the Recent table can say whether it ran.

type opOutcome struct {
	State, Cause, Why string
}

// Outcome kinds, the words of the page's status line and of the Recent column.
const (
	outcomeRunning = "running" // released or about to be
	outcomeRan     = "ran"     // the operation succeeded
	outcomeNotRun  = "not_run" // refused at release, or the approval ran out or was withdrawn
	outcomeFailed  = "failed"  // it started and failed
	outcomeUnknown = "unknown" // it started and its result is not known
	outcomeNone    = "no_op"   // no op carries this approval (a console request, or a denied card)
	outcomeWaiting = "waiting" // not released yet
)

// opOutcomes reads the ops that carry the given approvals.
func (c *Console) opOutcomes(ctx context.Context, ids []string) (map[string]opOutcome, error) {
	out := map[string]opOutcome{}
	if len(ids) == 0 {
		return out, nil
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := c.db.SQL().QueryContext(ctx,
		`SELECT approval_id, state, coalesce(cause_code, ''), coalesce(denial_json, '') FROM ops WHERE approval_id IN (?`+strings.Repeat(",?", len(ids)-1)+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, state, cause, denial string
		if err := rows.Scan(&id, &state, &cause, &denial); err != nil {
			return nil, err
		}
		o := opOutcome{State: state, Cause: cause}
		var d struct {
			Why string `json:"why"`
		}
		if json.Unmarshal([]byte(denial), &d) == nil {
			o.Why = d.Why
		}
		out[id] = o
	}
	return out, rows.Err()
}

// describe says in a sentence what became of an approved request, and which kind of ending it is.
func (o opOutcome) describe() (kind, text string) {
	reason := o.Why
	if reason == "" {
		reason = o.Cause
	}
	switch o.State {
	case "succeeded":
		return outcomeRan, "Done: it ran."
	case "allowed":
		return outcomeWaiting, "Approved. Waiting for the orchestrator to start it."
	case "executing":
		return outcomeRunning, "Running now..."
	case "refused":
		return outcomeNotRun, "Approved, but it did not run: " + reason + ". Nothing was changed. The orchestrator has to ask again."
	case "expired":
		return outcomeNotRun, "Approved, but it did not run: the approval ran out before the operation started. The orchestrator has to ask again."
	case "cancelled":
		return outcomeNotRun, "Approved, but it did not run: the request was withdrawn. Nothing was changed."
	case "failed":
		return outcomeFailed, "Approved and started, but it failed. Look at the result with chap op show."
	case "unconfirmed":
		return outcomeUnknown, "Approved and started, but chapd does not know the result. Check it by hand before it is asked again."
	case "":
		return outcomeNone, ""
	}
	return outcomeWaiting, "Approved. Waiting for the orchestrator to start it."
}

// approvalOutcome is GET /approvals/{id}/outcome: what became of the op behind an approval. The page asks it after
// "Approved." until the op has ended.
func (c *Console) approvalOutcome(w http.ResponseWriter, r *http.Request) {
	if stateOf(r).user == nil {
		writeError(w, http.StatusUnauthorized, "signed_out")
		return
	}
	id := r.PathValue("id")
	m, err := c.opOutcomes(r.Context(), []string{id})
	if err != nil {
		c.log.Error("approval outcome", "approval", id, "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	kind, text := m[id].describe()
	writeJSON(w, http.StatusOK, map[string]string{"kind": kind, "text": text})
}
