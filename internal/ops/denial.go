package ops

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// Denial cause codes this package produces (spec denial.schema.json).
const (
	CodeOpNotInToken     = "OP_NOT_IN_TOKEN"
	CodeOpDisabled       = "OP_DISABLED"
	CodeApprovalRequired = "OP_APPROVAL_REQUIRED"
	CodeApprovalDenied   = "OP_APPROVAL_DENIED"
	CodeApprovalExpired  = "OP_APPROVAL_EXPIRED"
	CodePolicyRefused    = "OP_POLICY_REFUSED"
	CodeParamsInvalid    = "OP_PARAMS_INVALID"
	CodeHashMismatch     = "APPROVAL_HASH_MISMATCH"
	CodeApprovalConsumed = "APPROVAL_CONSUMED"
	CodeApprovalIntegrty = "APPROVAL_INTEGRITY_FAILED"
	CodeApprovalUnavail  = "APPROVAL_UNAVAILABLE"
	CodeDisplayMismatch  = "DISPLAY_MISMATCH"
	CodeTokenExpired     = "TOKEN_EXPIRED"
	CodeTokenInvalid     = "TOKEN_INVALID"
	CodeTokenRevoked     = "TOKEN_REVOKED"
	CodeScopeBranch      = "SCOPE_BRANCH"
	CodeScopePath        = "SCOPE_PATH"
	CodeRedactionBlocked = "REDACTION_BLOCKED"
)

// faultCodes are failures on the approval side: not agent behaviour, so they
// never count as thrash (the schema pins their count to 1).
var faultCodes = map[string]bool{
	CodeApprovalIntegrty: true, CodeApprovalUnavail: true, CodeDisplayMismatch: true,
}

// DeniedError is a refusal ready to be written to the caller: the structured
// denial (already in the ledger when the error is returned) and its HTTP
// status.
type DeniedError struct {
	Denial     spec.Denial
	Status     int
	RetryAfter int // seconds; 429 only
}

func (e *DeniedError) Error() string { return e.Denial.CauseCode + ": " + e.Denial.Why }

// UnavailableError means chapd failed closed: nothing ran because something it
// must write did not commit.
type UnavailableError struct {
	Why       string
	Retryable bool
	Err       error
}

func (e *UnavailableError) Error() string {
	if e.Err != nil {
		return e.Why + ": " + e.Err.Error()
	}
	return e.Why
}
func (e *UnavailableError) Unwrap() error { return e.Err }

// denial is the input of a refusal.
type denial struct {
	Project    string
	Surface    string // default "op"
	Verb       string
	Target     string
	Code       string
	Why        string
	CanRequest bool
	Command    string // the `chap request ...` line when CanRequest
	Status     int    // default by code
	RetryAfter int
	RequestID  string // the op row this denial belongs to, if any
}

// statusFor is the HTTP status of a cause code (api/openapi.yaml).
func statusFor(code string) int {
	switch code {
	case CodeParamsInvalid:
		return http.StatusBadRequest
	case CodeTokenInvalid, CodeTokenExpired, CodeTokenRevoked:
		return http.StatusUnauthorized
	case CodeHashMismatch, CodeApprovalConsumed:
		return http.StatusConflict
	case CodeApprovalIntegrty, CodeApprovalUnavail, CodeDisplayMismatch:
		return http.StatusServiceUnavailable
	}
	return http.StatusForbidden
}

func clamp(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Cut on a rune boundary.
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

func cleanVerb(v string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(v) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9' && b.Len() > 0, (r == '.' || r == '_' || r == '-') && b.Len() > 0:
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "request"
	}
	return clamp(b.String(), 40)
}

// requestCommand builds the exact `chap request op ...` line of a denial. It
// carries the target and the params, so the op can be rebuilt from the denial
// alone (the command is at most 300 characters; if the params do not fit they
// are left out and `chap` asks for them).
func requestCommand(op string, target spec.Target, paramsJSON string) string {
	base := fmt.Sprintf("chap request op %s --target %s:%s", op, target.Adapter, shellQuote(target.Ref))
	reason := fmt.Sprintf(` --reason "<why %s is needed>"`, op)
	if paramsJSON != "" && paramsJSON != "{}" {
		full := base + " --params " + shellQuote(paramsJSON) + reason
		if len(full)-len("chap request ") <= 300 {
			return full
		}
	}
	return base + reason
}

// shellQuote single-quotes s for a POSIX shell when it needs it.
func shellQuote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._/-#@:+=,", r))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// refuse builds the denial for caller c, counts it toward thrash, writes the
// `denial` ledger event in tx and, when d.RequestID is set, stores the body on
// the op row. It does not commit. Faults on the approval side are not counted.
//
// A denial echoes what the agent aimed at (target, the `chap request` line, the
// reason text). If any of that holds a secret, the whole denial becomes a
// REDACTION_BLOCKED that names nothing of the request, before it is counted,
// ledgered, stored or rendered.
func (s *Service) refuse(ctx context.Context, tx *store.Tx, c *Caller, d denial) (*DeniedError, error) {
	if s.leaks(d.Verb, d.Target, d.Why, d.Command) {
		d = denial{
			Project: d.Project, Surface: "output", Verb: "request", Target: "-",
			Code: CodeRedactionBlocked, Why: redactionBlockedWhy, RequestID: d.RequestID,
		}
	}
	now := s.now().UTC()
	eff := s.policy.For(d.Project)
	win := eff.Limits.Thrash.WindowSeconds
	thr := eff.Limits.Thrash.Threshold

	surface := d.Surface
	if surface == "" {
		surface = "op"
	}
	verb := cleanVerb(d.Verb)
	target := clamp(d.Target, 300)
	if target == "" {
		target = "-"
	}

	count := 1
	id := s.newID("d-")
	if !faultCodes[d.Code] {
		var prior int
		err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM denials WHERE requester_key = ? AND surface = ? AND verb = ? AND target = ? AND at > ?`,
			c.Key(), surface, verb, target, now.Unix()-int64(win)).Scan(&prior)
		if err != nil {
			return nil, err
		}
		count = prior + 1
		if _, err := tx.ExecContext(ctx, `INSERT INTO denials (denial_id, at, requester_key, project, surface, verb, target, cause_code, request_id)
            VALUES (?,?,?,?,?,?,?,?,?)`, id, now.Unix(), c.Key(), d.Project, surface, verb, target, d.Code, nullable(d.RequestID)); err != nil {
			return nil, err
		}
	}

	body := spec.Denial{
		SpecVersion:   spec.SpecVersion,
		Type:          "denial",
		DenialID:      id,
		Project:       d.Project,
		At:            now.Format(time.RFC3339),
		Surface:       surface,
		Action:        spec.DenialAction{Verb: verb, Target: target},
		CauseCode:     d.Code,
		Why:           clamp(d.Why, 500),
		Request:       spec.DenialRequest{Possible: d.CanRequest},
		Thrash:        spec.Thrash{Count: count, WindowSeconds: win, Flagged: !faultCodes[d.Code] && count >= thr},
		PolicyVersion: eff.Version,
	}
	if d.CanRequest {
		body.Request.Command = clamp(d.Command, 300)
	}
	sr := c.specRequester()
	switch sr.Kind {
	case KindRun:
		body.RunID, body.Profile = sr.RunID, sr.Profile
	case KindOrchestrator:
		body.OrchestratorID = sr.ID // a key is projected as the orchestrator "key.<id>"
	}

	if err := s.led.AppendTx(ctx, tx, Event{
		Name:       "denial",
		RunID:      body.RunID,
		Project:    d.Project,
		Attributes: denialAttrs(id, surface, d.Code, count, sr.Kind, body.OrchestratorID),
		Body:       clamp(fmt.Sprintf("%s %s: %s", verb, target, d.Code), 1000),
	}); err != nil {
		return nil, err
	}

	status := d.Status
	if status == 0 {
		status = statusFor(d.Code)
	}
	return &DeniedError{Denial: body, Status: status, RetryAfter: d.RetryAfter}, nil
}

// denialAttrs is the closed attribute set of a denial event. An orchestrator's
// denial names it in factory.orchestrator.id (spec v0.1.1).
func denialAttrs(id, surface, code string, count int, kind, orchID string) map[string]any {
	attrs := map[string]any{
		"factory.denial.id":      id,
		"factory.surface":        surface,
		"factory.cause_code":     code,
		"factory.thrash.count":   float64(count),
		"factory.requester.kind": kind,
	}
	if orchID != "" {
		attrs["factory.orchestrator.id"] = orchID
	}
	return attrs
}
