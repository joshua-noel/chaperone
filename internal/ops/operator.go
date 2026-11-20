package ops

import (
	"context"
	"errors"
	"fmt"

	"github.com/joshua-noel/chaperone/internal/spec"
)

// OperatorID is the orchestrator id chapd itself uses for what a person asks for at the console (spec v0.1.1,
// "Operator-recorded ops"). No orchestrator token can carry it (runtoken refuses to issue one), so only code
// inside chapd can speak as the operator.
const OperatorID = "operator"

// The ops of the "agent asks, you tap" flow (ADR-008). keys.request is the one op an agent's key holds without
// listing it; keys.extend is the owner's own. Neither can ever be in a key's list (NeverInKey).
const (
	OpKeysRequest = "keys.request"
	OpKeysExtend  = "keys.extend"
)

// operatorOps are the ops the operator caller may start: the cards a person signs at the console.
var operatorOps = []string{"keys.issue", OpKeysExtend}

// OperatorCaller is the caller of an op a person started at the console. The person's own Hello on the op's
// card is what authorises it; this caller only carries the op into the pipeline.
func OperatorCaller(project string) *Caller {
	return &Caller{Kind: KindOrchestrator, OrchID: OperatorID, Projects: []string{project}, ScopeOps: operatorOps}
}

// NewSubmission builds the submission of op for caller c the way the HTTP layer does: the hash covers the
// project chapd resolves and exactly these params.
func NewSubmission(c *Caller, op, project, reason string, target spec.Target, params map[string]any) (*Submission, error) {
	jcs, err := spec.JCS(params)
	if err != nil {
		return nil, fmt.Errorf("ops: params cannot be hashed: %w", err)
	}
	if c.Kind == KindRun || c.Kind == KindKey {
		project = c.Project
	}
	h, err := spec.OpHash(map[string]any{
		"spec_version": spec.SpecVersion, "project": project, "op": op,
		"target": map[string]any{"adapter": target.Adapter, "ref": target.Ref}, "params": params,
	})
	if err != nil {
		return nil, fmt.Errorf("ops: the request cannot be hashed: %w", err)
	}
	return &Submission{Op: op, Project: project, Target: target, Params: params, ParamsJSON: string(jcs), OpHash: h, Reason: reason}, nil
}

// OperatorCard is a card an operator-started op waits behind.
type OperatorCard struct {
	OpID       string
	ApprovalID string
	State      string
}

// RequestAsOperator asks for the card of op, as the operator. The op runs only when a person signs the card
// with Windows Hello; a refusal comes back as the error the pipeline gave.
func (s *Service) RequestAsOperator(ctx context.Context, project, op, reason string, target spec.Target, params map[string]any) (OperatorCard, error) {
	c := OperatorCaller(project)
	sub, err := NewSubmission(c, op, project, reason, target, params)
	if err != nil {
		return OperatorCard{}, err
	}
	res, err := s.Submit(ctx, c, sub, ModeApproval, 0)
	if err != nil {
		return OperatorCard{}, err
	}
	if res == nil || res.Op == nil {
		return OperatorCard{}, errors.New("ops: the operator request made no op")
	}
	return OperatorCard{OpID: res.Op.ID, ApprovalID: res.Op.ApprovalID, State: string(res.Op.State)}, nil
}

// OpState reports an op's state; an unknown id is an error.
func (s *Service) OpState(ctx context.Context, id string) (state string, err error) {
	rec, err := dbGet(ctx, s.db, id)
	if err != nil {
		return "", err
	}
	return string(rec.State), nil
}
