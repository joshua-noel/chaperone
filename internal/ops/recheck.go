package ops

import (
	"context"
	"errors"
	"strings"
)

// Recheck is the answer of a read-only look at a waiting approval: would the op still be allowed to start now?
type Recheck struct {
	// Stale is true when the request, asked for again now, would be refused (the branch fell behind, CI moved or went
	// red, the policy changed). The approval is not cancelled: the console only warns, and the same checks run again
	// when the op is released.
	Stale bool
	// Why says so in a short sentence for the operator. It names no secret; branch names and shas come from GitHub.
	Why string
	// NewCard is true when approving this card cannot help: the merge is bound to what the card showed (the PR title),
	// and that changed. Only a new card, asked for again, can be released.
	NewCard bool
}

// Recheck looks again at the request behind a pending approval, before the operator spends a Hello on it (review item 1:
// "approving can silently do nothing"). It writes nothing: no state change, no ledger event, no token for write access.
// The adapter's Check is a dry run by contract (Adapter), and only pr.merge is looked at: it is the op whose answer
// moves while a card waits (another merge, a CI run). A request it cannot judge (GitHub unreachable) returns the
// error, and the console then says it could not check rather than show a wrong flag. Text that reaches the console
// (the refusal's reason, the error) goes through the same leak checks as on the release path.
func (s *Service) Recheck(ctx context.Context, requestID string) (Recheck, error) {
	rec, err := dbGet(ctx, s.db, requestID)
	if err != nil {
		return Recheck{}, err
	}
	if rec.Op != "pr.merge" || rec.State != StatePendingApproval {
		return Recheck{}, nil
	}
	eff := s.policy.For(rec.Project)
	switch {
	case eff.Invalid != nil:
		return Recheck{Stale: true, Why: s.shown(eff.Invalid.Error(), eff.Invalid.Error())}, nil
	case !eff.Enabled(rec.Op):
		return Recheck{Stale: true, Why: "pr.merge is switched off for " + rec.Project + " now."}, nil
	case rec.PolicyVersion != eff.Version:
		return Recheck{Stale: true, Why: "the policy changed after this was asked for, so this approval would not be valid."}, nil
	}
	adapter, ok := s.adapters[rec.Op]
	if !ok {
		return Recheck{}, nil
	}
	req, err := rec.request(nil)
	if err != nil {
		return Recheck{}, err
	}
	// What the approver saw on the card (the PR title) is what release binds the merge to (startRelease). A look without
	// it would pass a retitled PR that release refuses. If the card cannot be read there is no verdict: an error, so the
	// console says it could not check, never that the card is fine.
	if rec.ApprovalID != "" && s.appr != nil {
		info, aerr := s.appr.Lookup(ctx, rec.ApprovalID)
		if aerr != nil {
			return Recheck{}, errors.New(s.mask("could not read the approval: " + aerr.Error()))
		}
		req.ApprovedEvidence = info.Evidence
	}
	_, cerr := adapter.Check(ctx, req)
	var ref *Refusal
	switch {
	case cerr == nil:
		return Recheck{}, nil
	case errors.As(cerr, &ref):
		return Recheck{Stale: true, Why: s.shown(ref.Why, plainRefusal(ref)), NewCard: retitled(ref)}, nil
	}
	// The console logs this error: mask it, as the adapter errors of the release path are masked.
	return Recheck{}, errors.New(s.mask(cerr.Error()))
}

// shown is text the console may draw: the same leak check as a refusal at release, on the adapter's raw text and on
// the sentence made from it (which is clipped). Text that holds a secret is replaced by a sentence that names none
// (REDACTION_BLOCKED).
func (s *Service) shown(raw, out string) string {
	if s.leaks(raw, out) {
		return "the reason held a secret, so it is not shown (" + CodeRedactionBlocked + ")."
	}
	return out
}

// retitled reports whether the refusal is the title binding: the PR title is not the one on the card (the merge checks'
// title_approved at release, recheck_title just before the merge). The text is the merge checks' own (titleEdited).
func retitled(r *Refusal) bool {
	return strings.Contains(r.Why, "title_approved: "+titleEdited) || strings.Contains(r.Why, "recheck_title: "+titleEdited)
}

// plainRefusal turns a refusal at the pre-merge checks into one sentence. The stop code leads the refusal's text
// (CI_STALE, CI_RED); the rest is the failing check's own detail, already clipped by the merge checks. A retitled PR
// carries CI_STALE too, but it is not a stale branch, so it has a sentence of its own.
func plainRefusal(r *Refusal) string {
	why := r.Why
	switch {
	case retitled(r):
		return "the pull request was retitled after this card was made, so release will refuse it; ask again for a new card."
	case strings.HasPrefix(why, StopCIStale+":"):
		return "its branch is behind the base, or CI has not run on its current head (" + strings.TrimSpace(strings.TrimPrefix(why, StopCIStale+":")) + ")."
	case strings.HasPrefix(why, StopCIRed+":"):
		return "a required check is failing (" + strings.TrimSpace(strings.TrimPrefix(why, StopCIRed+":")) + ")."
	}
	return clip(why, 300) + "."
}
