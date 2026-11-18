package ops

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// record is one row of the ops table.
type record struct {
	ID            string
	State         State
	Op            string
	Project       string
	TargetAdapter string
	TargetRef     string
	ParamsJSON    string
	OpHash        string
	RequesterKind string
	RequesterKey  string
	RunID         string
	OrchID        string
	Profile       string
	TokenJTI      string
	Class         string
	Reversibility string
	PolicyVersion string
	Reason        string
	Traceparent   string
	RequestedAt   time.Time
	ExpiresAt     time.Time
	UpdatedAt     time.Time
	ApprovalID    string
	ExecutionID   string
	Outcome       string
	CauseCode     string
	ExternalRef   string
	ResultJSON    string
	ChecksJSON    string
	DenialJSON    string
	ScopeJSON     string // the run's task scope at request time; "" for an orchestrator
}

const recordColumns = `id, state, op, project, target_adapter, target_ref, params_json, op_hash,
    requester_kind, requester_key, COALESCE(run_id,''), COALESCE(orchestrator_id,''), COALESCE(profile,''), COALESCE(token_jti,''),
    class, reversibility, policy_version, COALESCE(reason,''), COALESCE(traceparent,''),
    requested_at, expires_at, updated_at,
    COALESCE(approval_id,''), COALESCE(execution_id,''), COALESCE(outcome,''), COALESCE(cause_code,''),
    COALESCE(external_ref,''), COALESCE(result_json,''), COALESCE(checks_json,''), COALESCE(denial_json,''), COALESCE(scope_json,'')`

type rowScanner interface{ Scan(dest ...any) error }

func scanRecord(r rowScanner) (*record, error) {
	var rec record
	var state string
	var req, exp, upd int64
	err := r.Scan(&rec.ID, &state, &rec.Op, &rec.Project, &rec.TargetAdapter, &rec.TargetRef, &rec.ParamsJSON, &rec.OpHash,
		&rec.RequesterKind, &rec.RequesterKey, &rec.RunID, &rec.OrchID, &rec.Profile, &rec.TokenJTI,
		&rec.Class, &rec.Reversibility, &rec.PolicyVersion, &rec.Reason, &rec.Traceparent,
		&req, &exp, &upd,
		&rec.ApprovalID, &rec.ExecutionID, &rec.Outcome, &rec.CauseCode,
		&rec.ExternalRef, &rec.ResultJSON, &rec.ChecksJSON, &rec.DenialJSON, &rec.ScopeJSON)
	if err != nil {
		return nil, err
	}
	rec.State = State(state)
	rec.RequestedAt = time.Unix(req, 0).UTC()
	rec.ExpiresAt = time.Unix(exp, 0).UTC()
	rec.UpdatedAt = time.Unix(upd, 0).UTC()
	return &rec, nil
}

// errNotFound: no such op.
var errNotFound = errors.New("ops: no such op")

// errStale: the compare-and-set found the op in another state.
var errStale = errors.New("ops: op is no longer in the expected state")

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// errLive: the caller already has a live op for this action.
var errLive = errors.New("ops: the caller already has a live op for this request")

func insertRecord(ctx context.Context, tx *store.Tx, r *record) error {
	err := insertRow(ctx, tx, r)
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return errLive
	}
	return err
}

func insertRow(ctx context.Context, tx *store.Tx, r *record) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO ops (id, state, op, project, target_adapter, target_ref, params_json, op_hash,
        requester_kind, requester_key, run_id, orchestrator_id, profile, token_jti,
        class, reversibility, policy_version, reason, traceparent, requested_at, expires_at, updated_at, scope_json)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.ID, string(r.State), r.Op, r.Project, r.TargetAdapter, r.TargetRef, r.ParamsJSON, r.OpHash,
		r.RequesterKind, r.RequesterKey, nullable(r.RunID), nullable(r.OrchID), nullable(r.Profile), nullable(r.TokenJTI),
		r.Class, r.Reversibility, r.PolicyVersion, nullable(r.Reason), nullable(r.Traceparent),
		r.RequestedAt.Unix(), r.ExpiresAt.Unix(), r.UpdatedAt.Unix(), nullable(r.ScopeJSON))
	return err
}

func txGet(ctx context.Context, tx *store.Tx, id string) (*record, error) {
	rec, err := scanRecord(tx.QueryRowContext(ctx, `SELECT `+recordColumns+` FROM ops WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return rec, err
}

func dbGet(ctx context.Context, db *store.DB, id string) (*record, error) {
	rec, err := scanRecord(db.SQL().QueryRowContext(ctx, `SELECT `+recordColumns+` FROM ops WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return rec, err
}

// transition is one compare-and-set of an op's state with the columns that go
// with it. Zero strings leave a column unchanged.
type transition struct {
	From, To     State
	Now          time.Time
	ApprovalID   string
	ExecutionID  string
	Outcome      string
	CauseCode    string
	ExternalRef  string
	ResultJSON   string
	ChecksJSON   string
	DenialJSON   string
	ExtendExpiry time.Time
}

func (t transition) apply(ctx context.Context, tx *store.Tx, id string) error {
	res, err := tx.ExecContext(ctx, `UPDATE ops SET state = ?, updated_at = ?,
        approval_id  = COALESCE(?, approval_id),
        execution_id = COALESCE(?, execution_id),
        outcome      = COALESCE(?, outcome),
        cause_code   = COALESCE(?, cause_code),
        external_ref = COALESCE(?, external_ref),
        result_json  = COALESCE(?, result_json),
        checks_json  = COALESCE(?, checks_json),
        denial_json  = COALESCE(?, denial_json)
        WHERE id = ? AND state = ?`,
		string(t.To), t.Now.Unix(),
		nullable(t.ApprovalID), nullable(t.ExecutionID), nullable(t.Outcome), nullable(t.CauseCode),
		nullable(t.ExternalRef), nullable(t.ResultJSON), nullable(t.ChecksJSON), nullable(t.DenialJSON),
		id, string(t.From))
	if err != nil {
		return fmt.Errorf("ops: transition %s -> %s: %w", t.From, t.To, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errStale
	}
	return nil
}

// runScope is the part of a run token's task scope an adapter judges a request
// against. It is stored with the op because the token is not at hand when the
// op is re-checked and released.
type runScope struct {
	Repo   string   `json:"repo"`
	Base   string   `json:"base"`
	Branch string   `json:"branch"`
	Paths  []string `json:"paths,omitempty"`
}

// scopeJSON is the stored form of a run caller's scope, "" for any other caller.
func scopeJSON(c *Caller) string {
	if c.Kind != KindRun {
		return ""
	}
	b, err := json.Marshal(runScope{Repo: c.Repo, Base: c.Base, Branch: c.Branch, Paths: c.Paths})
	if err != nil {
		return "" // cannot happen: strings only
	}
	return string(b)
}

// caller rebuilds the identity and, for a run, the task scope of the op's
// requester. The token itself is not kept (it may be gone by now).
func (r *record) caller() *Caller {
	c := &Caller{Kind: r.RequesterKind, RunID: r.RunID, OrchID: r.OrchID, Profile: r.Profile, JTI: r.TokenJTI}
	if r.RequesterKind == KindRun {
		c.Project = r.Project
		var s runScope
		if r.ScopeJSON != "" && json.Unmarshal([]byte(r.ScopeJSON), &s) == nil {
			c.Repo, c.Base, c.Branch, c.Paths = s.Repo, s.Base, s.Branch, s.Paths
		}
	}
	return c
}

// request rebuilds the adapter-facing request from the row. The caller is
// rebuilt from what was stored when the op was requested.
func (r *record) request(c *Caller) (*Request, error) {
	tree, err := spec.ParseStrict([]byte(r.ParamsJSON))
	if err != nil {
		return nil, fmt.Errorf("ops: stored params of %s: %w", r.ID, err)
	}
	params, _ := tree.(map[string]any)
	if c == nil {
		c = r.caller()
	}
	return &Request{
		ID: r.ID, Op: r.Op, Project: r.Project,
		Target: spec.Target{Adapter: r.TargetAdapter, Ref: r.TargetRef},
		Params: params, OpHash: r.OpHash, Reason: r.Reason, Caller: c,
		ExecutionID: r.ExecutionID, PolicyVer: r.PolicyVersion,
	}, nil
}

// checks decodes the stored checks.
func (r *record) checks() []Check {
	if r.ChecksJSON == "" {
		return nil
	}
	var cs []Check
	_ = json.Unmarshal([]byte(r.ChecksJSON), &cs)
	return cs
}
