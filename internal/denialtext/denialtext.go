// Package denialtext is the one table of plain words for a denial: what each cause code means and what the caller
// does next. The console (Home, "Recent denials") and the chap command line both read it, so the two never tell a
// different story. It holds no logic about policy and imports nothing: a denial's cause_code and why are its input.
package denialtext

import (
	"regexp"
	"strings"
)

// Cause codes the table knows: every code Chaperone itself emits (denial.schema.json's enum, less the net, package and
// image codes, which the runner's egress proxy and admission raise). They are copied, not imported, to keep chap thin;
// TestPlainCoversEveryCodeChaperoneEmits loops over the embedded schema enum so a new code cannot go without words.
const (
	OpNotInToken      = "OP_NOT_IN_TOKEN"
	OpDisabled        = "OP_DISABLED"
	PolicyRefused     = "OP_POLICY_REFUSED"
	ApprovalDenied    = "OP_APPROVAL_DENIED"
	ApprovalExpired   = "OP_APPROVAL_EXPIRED"
	ApprovalRequired  = "OP_APPROVAL_REQUIRED"
	ParamsInvalid     = "OP_PARAMS_INVALID"
	HashMismatch      = "APPROVAL_HASH_MISMATCH"
	ApprovalConsumed  = "APPROVAL_CONSUMED"
	ApprovalIntegrity = "APPROVAL_INTEGRITY_FAILED"
	ApprovalUnavail   = "APPROVAL_UNAVAILABLE"
	DisplayMismatch   = "DISPLAY_MISMATCH"
	ScopeBranch       = "SCOPE_BRANCH"
	ScopePath         = "SCOPE_PATH"
	RedactionBlocked  = "REDACTION_BLOCKED"
	TokenExpired      = "TOKEN_EXPIRED"
	TokenRevoked      = "TOKEN_REVOKED"
	TokenInvalid      = "TOKEN_INVALID"
)

// Plain says in words what the cause code means. It is "" for a code the table does not know, so a caller shows
// the code itself.
func Plain(cause string) string {
	switch cause {
	case OpNotInToken:
		return "this token does not allow that operation"
	case OpDisabled:
		return "that operation is switched off"
	case PolicyRefused:
		return "refused by policy"
	case ApprovalRequired:
		return "needs the operator's approval first"
	case ApprovalDenied:
		return "the approval named in the request cannot be used (denied, expired or already used)"
	case ApprovalExpired:
		return "the approval card ran out before it was decided"
	case ParamsInvalid:
		return "the request is malformed or holds a value that is not allowed"
	case HashMismatch:
		return "the approval is genuine but does not apply to this request (its request, hash or run differs)"
	case ApprovalConsumed:
		return "that approval was already used"
	case ApprovalIntegrity:
		return "the approval record failed its integrity check, so it is void (a fault on the approval side)"
	case ApprovalUnavail:
		return "the approvals store cannot be reached, so nothing ran (a fault on the approval side)"
	case DisplayMismatch:
		return "the card the operator would have seen did not match the request, so the approval was refused (a fault on the approval side)"
	case ScopeBranch:
		return "that branch or repository is outside what this run may change"
	case ScopePath:
		return "that repository or path is outside what this token covers"
	case RedactionBlocked:
		return "the text holds something shaped like a secret, so it was not stored or sent"
	case TokenExpired:
		return "the token has expired"
	case TokenRevoked:
		return "the token was revoked or its run has ended"
	case TokenInvalid:
		return "chapd does not accept this token"
	}
	return ""
}

var (
	floodRE = regexp.MustCompile(`^approval flood: (\d+) approvals? already pending`)
	stopRE  = regexp.MustCompile(`^(CI_STALE|CI_RED):`)
	// titleRE is a merge refused because the PR's title is not the one on the card the operator approved (or is not a
	// valid header now). The stop is CI_STALE and the check name follows it: ops writes "CI_STALE: title_approved: ..."
	// at the release check and "CI_STALE: recheck_title: ..." just before the write.
	titleRE = regexp.MustCompile(`^CI_STALE: (?:title_approved|recheck_title):`)
)

// NextStep says what the caller does next, in one line with no leading label. It is "" when asking again or doing
// something else cannot change the answer: the caller then keeps the "not possible" line (OP_NOT_IN_TOKEN,
// OP_DISABLED, and a refusal by policy that has no cause of its own). No step coaches a way round a control. why is
// the denial's own text (it may be empty: the console's list has only the code); orch is the orchestrator's id when
// the caller is one, "" for a run.
func NextStep(cause, why, orch string) string {
	switch cause {
	case PolicyRefused:
		if titleRE.MatchString(why) {
			// Not a stale branch: updating it changes nothing. A new request makes a new card with the title as it is now.
			return "the PR title is not the one the operator approved: make sure it is a valid title (type(scope): description, 72 characters at most), then ask again so a new card shows the title as it is now"
		}
		if m := stopRE.FindStringSubmatch(why); m != nil {
			if m[1] == "CI_RED" {
				return "fix the code so the existing check passes (never edit, skip or disable the check), push, wait for CI to go green on the new head, then ask again"
			}
			return "ask the orchestrator to bring the branch up to date (chap pr update), wait for CI on the new head, then ask again"
		}
		if m := floodRE.FindStringSubmatch(why); m != nil {
			n := m[1]
			if n == "1" {
				return "1 request is waiting for the operator; nothing more can be asked until he decides"
			}
			return n + " requests are waiting for the operator; nothing more can be asked until he decides"
		}
		if strings.HasPrefix(why, "rate limit:") {
			return "wait the time given, then ask again"
		}
	case ParamsInvalid:
		return "read the why line: if it names something you can correct, correct the request and ask again; if not, stop and say so"
	case HashMismatch:
		return "that approval is for another request: make a new request and wait for its own approval"
	case ApprovalConsumed:
		return "an approval works once: make a new request and wait for its own approval"
	case ApprovalIntegrity, DisplayMismatch:
		return "stop and tell the operator: this is a fault on the approval side, and asking again does not help"
	case ApprovalUnavail:
		return "nothing ran: wait a little and ask again; if it keeps happening, tell the operator"
	case ScopeBranch, ScopePath:
		return "work only inside the scope this token gives; if the task needs more, stop and say so (a run tells the orchestrator, the orchestrator tells the operator)"
	case RedactionBlocked:
		return "take the secret out of the text and ask again; never paste or disguise a credential"
	case TokenRevoked:
		// Revoked is what a stop (Stop all, a run or token revoke), a run that has ended, or a replaced orchestrator token
		// produces. The cause is not always the operator, so it is not named; no workaround is offered, so an agent never
		// goes looking for a way round it. Like an expired token, it reads differently for a run (it reports to the
		// orchestrator) and for the orchestrator (it asks the operator).
		if orch == "" {
			return "the token was revoked or its run has ended: stop and report to the orchestrator; do not re-issue or work around it"
		}
		return "the token was revoked or its run has ended: stop; do not re-issue or work around it; ask the operator"
	case TokenExpired:
		if orch == "" {
			// A run's token is never re-issued by hand: the run ends here.
			return "the run's token has expired: stop and report to the orchestrator"
		}
		return "the operator issues a new token: chapd orch issue -id " + orch + " -project <p> -ops <op,...> (in an elevated window)"
	}
	return ""
}
