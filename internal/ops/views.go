package ops

import (
	"encoding/json"
	"time"

	"github.com/joshua-noel/chaperone/internal/spec"
)

// opView is components.schemas.Op of api/openapi.yaml.
type opView struct {
	ID            string          `json:"id"`
	State         State           `json:"state"`
	Op            string          `json:"op"`
	Project       string          `json:"project"`
	Target        spec.Target     `json:"target"`
	OpHash        string          `json:"op_hash"`
	Requester     requesterView   `json:"requester"`
	Class         string          `json:"class"`
	Reversibility string          `json:"reversibility"`
	PolicyVersion string          `json:"policy_version,omitempty"`
	Reason        string          `json:"reason,omitempty"`
	RequestedAt   string          `json:"requested_at"`
	ExpiresAt     string          `json:"expires_at"`
	UpdatedAt     string          `json:"updated_at"`
	Approval      *approvalView   `json:"approval,omitempty"`
	ExecutionID   string          `json:"execution_id,omitempty"`
	Outcome       string          `json:"outcome,omitempty"`
	ExternalRef   string          `json:"external_ref,omitempty"`
	Result        json.RawMessage `json:"result,omitempty"`
	Checks        []Check         `json:"checks,omitempty"`
	Denial        json.RawMessage `json:"denial,omitempty"`
}

type requesterView struct {
	Kind           string `json:"kind"`
	RunID          string `json:"run_id,omitempty"`
	Profile        string `json:"profile,omitempty"`
	OrchestratorID string `json:"orchestrator_id,omitempty"`
	KeyID          string `json:"key_id,omitempty"`
	Owner          string `json:"owner,omitempty"`
	Holder         string `json:"holder,omitempty"`
}

// requesterViewOf is the API's requester object. Unlike the ledger it names a
// key as a key: the projection onto the spec is for spec documents only.
func requesterViewOf(kind, runID, profile, orchID, keyID, owner, holder string) requesterView {
	switch kind {
	case KindRun:
		return requesterView{Kind: KindRun, RunID: runID, Profile: profile}
	case KindOrchestrator:
		return requesterView{Kind: KindOrchestrator, OrchestratorID: orchID}
	case KindKey:
		return requesterView{Kind: KindKey, KeyID: keyID, Owner: owner, Holder: holder}
	}
	return requesterView{}
}

func (c *Caller) requesterView() requesterView {
	return requesterViewOf(c.Kind, c.RunID, c.Profile, c.OrchID, c.KeyID, c.KeyOwner, c.KeyHolder)
}

// approvalView is components.schemas.ApprovalSummary.
type approvalView struct {
	ID            string `json:"id"`
	RequestID     string `json:"request_id"`
	Op            string `json:"op"`
	OpHash        string `json:"op_hash"`
	State         string `json:"state"`
	Class         string `json:"class"`
	Critical      bool   `json:"critical"`
	PolicyVersion string `json:"policy_version"`
	CreatedAt     string `json:"created_at"`
	DecidedAt     string `json:"decided_at,omitempty"`
	ExpiresAt     string `json:"expires_at"`
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func (a ApprovalInfo) view() *approvalView {
	v := &approvalView{
		ID: a.ID, RequestID: a.RequestID, Op: a.Op, OpHash: a.OpHash, State: a.State, Class: a.Class,
		Critical: a.Critical, PolicyVersion: a.PolicyVersion, CreatedAt: ts(a.CreatedAt), ExpiresAt: ts(a.ExpiresAt),
	}
	if !a.DecidedAt.IsZero() {
		v.DecidedAt = ts(a.DecidedAt)
	}
	return v
}

func (r *record) view(appr *ApprovalInfo) opView {
	v := opView{
		ID: r.ID, State: r.State, Op: r.Op, Project: r.Project,
		Target: spec.Target{Adapter: r.TargetAdapter, Ref: r.TargetRef},
		OpHash: r.OpHash, Class: r.Class, Reversibility: r.Reversibility, PolicyVersion: r.PolicyVersion,
		Reason: r.Reason, RequestedAt: ts(r.RequestedAt), ExpiresAt: ts(r.ExpiresAt), UpdatedAt: ts(r.UpdatedAt),
		ExecutionID: r.ExecutionID, Outcome: r.Outcome, ExternalRef: r.ExternalRef, Checks: r.checks(),
	}
	holder := ""
	if r.RequesterKind == KindKey {
		holder = r.caller().KeyHolder
	}
	v.Requester = requesterViewOf(r.RequesterKind, r.RunID, r.Profile, r.OrchID, r.KeyID, r.OwnerID, holder)
	if r.ResultJSON != "" {
		v.Result = json.RawMessage(r.ResultJSON)
	}
	if r.DenialJSON != "" {
		v.Denial = json.RawMessage(r.DenialJSON)
	}
	if appr != nil {
		v.Approval = appr.view()
	}
	return v
}
