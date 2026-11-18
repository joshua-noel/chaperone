package runtoken

import (
	"errors"
	"fmt"

	"github.com/joshua-noel/chaperone/internal/spec"
)

// Denial cause codes this package raises (denial.schema.json, surface token,
// op and scope) and the stop codes it names. Callers match on Error.Code.
const (
	CauseTokenInvalid = "TOKEN_INVALID"
	CauseTokenExpired = "TOKEN_EXPIRED"
	CauseTokenRevoked = "TOKEN_REVOKED"
	CauseOpNotInToken = "OP_NOT_IN_TOKEN"
	CauseScopeBranch  = "SCOPE_BRANCH"
	CauseOpDisabled   = "OP_DISABLED"

	StopTokenMisuse     = "TOKEN_MISUSE"
	StopTimeExceeded    = "TIME_EXCEEDED"
	StopOperatorStopRun = "OPERATOR_STOP_RUN"
	StopOperatorStopAll = "OPERATOR_STOP_ALL"

	surfaceToken = "token"
	surfaceOp    = "op"
	surfaceScope = "scope"
)

// Error is a refusal with the denial cause code the API answers with. Use
// errors.As to read it. Detail is for the ledger and the operator; it never
// holds a token.
type Error struct {
	// Code is the denial cause_code: TOKEN_INVALID, TOKEN_EXPIRED,
	// TOKEN_REVOKED, OP_NOT_IN_TOKEN, SCOPE_BRANCH or OP_DISABLED.
	Code string
	// Surface is the denial surface that code belongs to: token, op or scope.
	Surface string
	// Stop is the stop-table code the refusal also raises, "TOKEN_MISUSE" for
	// use after revocation or expiry and for a bad signature (ADR-005);
	// empty when the refusal raises no stop. Raising it is the caller's job.
	Stop   string
	Detail string
	// Run names the run when the token was identified (its signature held),
	// even for TOKEN_EXPIRED and TOKEN_REVOKED: what a denial body needs. Nil
	// when the token could not be identified.
	Run *RunRef
	// OrchID is the orchestrators.id when an orchestrator token was found.
	OrchID string
	// Project is the first project of that token's scope, for the denial
	// body's required project; empty when the scope is unreadable.
	Project string
}

func (e *Error) Error() string { return e.Code + ": " + e.Detail }

func surfaceOf(code string) string {
	switch code {
	case CauseOpNotInToken, CauseOpDisabled:
		return surfaceOp
	case CauseScopeBranch:
		return surfaceScope
	}
	return surfaceToken
}

func refuse(code, format string, args ...any) *Error {
	return &Error{Code: code, Surface: surfaceOf(code), Detail: fmt.Sprintf(format, args...)}
}

func misuse(e *Error) *Error {
	e.Stop = StopTokenMisuse
	return e
}

// RunRef identifies a run in a refusal (spec Denial.request: run_id, project,
// profile).
type RunRef struct {
	RunID   string
	Project string
	Profile string // profile.name of the token
}

func runRef(c spec.RunTokenClaims) *RunRef {
	return &RunRef{RunID: c.RunID, Project: c.Project, Profile: c.Profile.Name}
}

func forRun(e *Error, c spec.RunTokenClaims) *Error {
	e.Run = runRef(c)
	return e
}

func forOrch(e *Error, id, project string) *Error {
	e.OrchID, e.Project = id, project
	return e
}

// CodeOf returns the cause code of err, or "" when err is not an *Error.
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

var (
	// ErrNotFound: the run or orchestrator the call names is not registered.
	ErrNotFound = errors.New("runtoken: not found")
	// ErrConflict: a run id or jti is already registered.
	ErrConflict = errors.New("runtoken: already exists")
	// ErrInvalid: the request is malformed (not a denial: the caller's bug).
	ErrInvalid = errors.New("runtoken: invalid request")
)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}
