package runtoken

import (
	"context"
	"fmt"

	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// Event is a ledger event before the ledger stamps it. The fields and their
// meaning are those of ledger.Draft (L1-02): the ledger adds chain, seq,
// prev_hash, hash, trace_id, time and resource, and rejects attributes the
// spec's closed set for Name does not allow.
type Event struct {
	Name       string // spec event_name: grant, run.start, run.end, token.revoke, op.request, op.result
	RunID      string // empty for the orchestrator's events (spec: no run_id)
	Project    string
	Severity   string // TRACE..FATAL; empty means INFO
	Attributes map[string]any
	Body       string
}

// Appender writes an event inside the caller's transaction, so the state
// change and its event commit together or not at all (ADR-006). Any error
// fails the operation closed: the transaction rolls back.
type Appender interface {
	Append(ctx context.Context, tx *store.Tx, e Event) error
}

func grantEvent(c spec.RunTokenClaims) Event {
	attrs := map[string]any{
		"factory.token.jti":    c.JTI,
		"factory.token.exp":    c.Exp,
		"factory.brief.sha256": c.BriefSHA,
		"factory.isolation":    c.Isolation,
		"factory.scope.ops":    nonNil(c.TaskScope.Ops),
	}
	if c.Profile.Digest != "" {
		attrs["factory.profile.digest"] = c.Profile.Digest
	}
	return Event{Name: "grant", RunID: c.RunID, Project: c.Project, Attributes: attrs}
}

func runStartEvent(c spec.RunTokenClaims) Event {
	return Event{Name: "run.start", RunID: c.RunID, Project: c.Project, Attributes: map[string]any{
		"factory.profile.name":    c.Profile.Name,
		"factory.profile.version": c.Profile.Version,
		"factory.isolation":       c.Isolation,
	}}
}

// Revocation reasons of the token.revoke event (spec: run_end, stop, operator).
const (
	revokeRunEnd   = "run_end"
	revokeStop     = "stop"
	revokeOperator = "operator"
)

func tokenRevokeEvent(r RunRecord, reason, cause string) Event {
	attrs := map[string]any{
		"factory.token.jti":     r.JTI,
		"factory.revoke.reason": reason,
	}
	sev := "INFO"
	if reason == revokeStop {
		attrs["factory.cause_code"] = cause
	}
	if reason != revokeRunEnd {
		sev = "WARN"
	}
	return Event{Name: "token.revoke", RunID: r.RunID, Project: r.Project, Severity: sev, Attributes: attrs}
}

func runEndEvent(r RunRecord, outcome, cause string, actualMinutes float64, actualTokens int64) Event {
	attrs := map[string]any{
		"factory.outcome":        outcome,
		"factory.plan.minutes":   int64(r.Claims.Budget.Minutes),
		"factory.plan.tokens":    r.Claims.Budget.Tokens,
		"factory.actual.minutes": actualMinutes,
		"factory.actual.tokens":  actualTokens,
	}
	if cause != "" {
		attrs["factory.cause_code"] = cause
	}
	sev := "INFO"
	if outcome == "killed" {
		sev = "WARN"
	}
	return Event{Name: "run.end", RunID: r.RunID, Project: r.Project, Severity: sev, Attributes: attrs}
}

// orchOpEvents are the op.request and op.result pair ADR-007 item 8 asks for
// when the operator issues or revokes an orchestrator token. The spec's
// requester.kind has no operator value, so the events carry "orchestrator"
// (run_id absent) and the body says what happened.
func orchOpEvents(op, project, id string, params map[string]any, policyVersion, body string) ([]Event, error) {
	request := map[string]any{
		"spec_version": "0",
		"project":      project,
		"op":           op,
		"target":       map[string]any{"adapter": "chaperone", "ref": "orchestrator:" + id},
		"params":       params,
	}
	opHash, err := spec.OpHash(request)
	if err != nil {
		return nil, fmt.Errorf("runtoken: %s op_hash: %w", op, err)
	}
	rid, err := randomLower(8)
	if err != nil {
		return nil, err
	}
	xid, err := randomLower(8)
	if err != nil {
		return nil, err
	}
	return []Event{
		{Name: "op.request", Project: project, Attributes: map[string]any{
			"factory.request_id":      "q-" + rid,
			"factory.op":              op,
			"factory.op_hash":         opHash,
			"factory.reversibility":   "reversible",
			"factory.requester.kind":  "orchestrator",
			"factory.orchestrator.id": OperatorID,
		}, Body: body},
		{Name: "op.result", Project: project, Attributes: map[string]any{
			"factory.request_id":      "q-" + rid,
			"factory.op_hash":         opHash,
			"factory.execution_id":    "x-" + xid,
			"factory.outcome":         "succeeded",
			"factory.policy_version":  policyVersion,
			"factory.requester.kind":  "orchestrator",
			"factory.orchestrator.id": OperatorID,
		}},
	}, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// OperatorID is the orchestrator id of what the operator does at the machine
// (spec v0.1.1, "Operator-recorded ops"): issuing or revoking an orchestrator
// token, enrolling an approver, writing a secret from the console.
const OperatorID = "operator"
