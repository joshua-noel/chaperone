// Package ops is chapd's op lifecycle (ticket L1-07): the HTTP server, the auth
// middleware with its two verifiers, the policy checks every request passes,
// the op state machine whose every transition commits in the same SQLite
// transaction as its ledger event, per-caller rate limits and the thrash
// counter.
//
// The package codes against small interfaces for what other tickets provide
// (the ledger L1-02, the token verifiers L1-04, the approvals engine L1-12, the
// adapters L1-09..L1-16); cmd/chapd wires the real ones.
package ops

import (
	"context"
	"time"

	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// State is an op's place in its life (api/openapi.yaml, "One op, one request id,
// one life").
type State string

const (
	StateRequested       State = "requested"
	StateDenied          State = "denied"
	StatePendingApproval State = "pending_approval"
	StateAllowed         State = "allowed"
	StateExecuting       State = "executing"
	StateSucceeded       State = "succeeded"
	StateRefused         State = "refused"
	StateFailed          State = "failed"
	StateExpired         State = "expired"
	StateCancelled       State = "cancelled"
	StateUnconfirmed     State = "unconfirmed"
)

// Terminal reports whether the op can no longer change.
func (s State) Terminal() bool {
	switch s {
	case StateDenied, StateSucceeded, StateRefused, StateFailed, StateExpired, StateCancelled:
		return true
	}
	return false
}

// Requester kinds, as in the spec's operation request.
const (
	KindRun          = "run"
	KindOrchestrator = "orchestrator"
)

// Caller is who is asking, as the token verifiers established it. Nothing in a
// request body can change it.
type Caller struct {
	Kind string // KindRun or KindOrchestrator

	// Run callers.
	RunID    string
	JTI      string
	Profile  string // a profile kind or "host-interim"
	Interim  bool
	Project  string // the run's project
	Repo     string
	Base     string
	Branch   string
	Paths    []string
	TokenOps []string // task_scope.ops: patterns, possibly "x.*"

	// Orchestrator callers.
	OrchID      string
	Fingerprint string
	Projects    []string // scope.projects
	MintInterim bool

	ScopeOps []string // orchestrator scope.ops
	Expires  time.Time
}

// Key is the stable name of the caller used for rate limits, thrash and
// ownership ("run:<id>" or "orchestrator:<id>").
func (c *Caller) Key() string {
	if c.Kind == KindRun {
		return "run:" + c.RunID
	}
	return "orchestrator:" + c.OrchID
}

// opPatterns returns the op patterns the caller's token grants.
func (c *Caller) opPatterns() []string {
	if c.Kind == KindRun {
		return c.TokenOps
	}
	return c.ScopeOps
}

// Request is what an adapter is handed: the op as chapd stored it.
type Request struct {
	ID          string // spec request_id
	Op          string
	Project     string
	Target      spec.Target
	Params      map[string]any
	OpHash      string
	Reason      string
	Caller      *Caller
	ExecutionID string // empty in Check, set in Execute
	PolicyVer   string
	// ApprovedEvidence is the evidence block list of the approval this op is released under, as the approver saw it on
	// the card. It is set only when the op is released (Check and Execute of a request that was approved); empty
	// otherwise. An adapter may bind what it does to it (pr.merge: the PR title).
	ApprovedEvidence []Evidence
}

// Check is one policy precondition and its result (the card's checks).
type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}

// Evidence is adapter text for the approval card (a diff stat, the commits of a
// deploy): the exact text the approver sees, so it is hashed with the card.
type Evidence struct {
	Name string
	Text string
}

// CheckResult is an adapter's read-only verdict on a request.
type CheckResult struct {
	Checks   []Check
	Evidence []Evidence
	// NeedsApproval is set when an op that is not high-impact by class needs a
	// human anyway for this request (a medium or high tier PR, a gate file).
	NeedsApproval bool
	// ApprovalWhy says why, for the denial's why line.
	ApprovalWhy string
}

// Outcome is what an adapter reports after it ran.
type Outcome struct {
	Result      map[string]any // op-specific, redacted by the caller
	ExternalRef string         // the service's id; empty when unconfirmed
	Failed      bool           // the service reported failure
	Unconfirmed bool           // dispatched, no receipt
}

// Adapter is one op kind's implementation. Check has no side effects and may
// be called many times (submit, dry run, approval request, release).
//
// Execute is called at most once for each execution id, and chapd never retries
// a write by itself. The op moves from allowed to executing in one transaction
// before Execute is called, and only one caller wins that move. An op that was
// executing when the process died is marked unconfirmed at the next start
// (Service.Recover) and its adapter is not run again; no shipped code calls
// Service.Reconcile. A caller who asks again for the same action while the op
// is live (pending, allowed, executing or unconfirmed) is given the same op.
//
// Most adapters are repeat-safe anyway: a second Execute with the same
// Request.ExecutionID changes the service once (Linear derives its comment id
// from it, a move to the state the item is in sends nothing, pr.merge is bound
// to one head sha, issue.reopen checks the state first). Three are not:
// issue.open, issue.comment and ci.report send their write again, because
// GitHub has no idempotency key for an issue or a comment, and a check run
// would need an external_id lookup that is not built. Their connector tests
// declare it (NotRepeatable). They are safe only because chapd does not repeat
// an Execute: a new path that does (a Reconcile that runs the adapter again)
// must make them repeat-safe first.
type Adapter interface {
	Check(ctx context.Context, req *Request) (CheckResult, error)
	Execute(ctx context.Context, req *Request) (Outcome, error)
}

// Refusal is an adapter's or the validator's structured "no". Check returns it
// as its error. Code is a denial cause code.
type Refusal struct {
	Code string
	Why  string
	// CanRequest is true when `chap request ...` would help (an approval card
	// can be created). Preconditions such as red CI are never requestable.
	CanRequest bool
	Surface    string // default "op"
}

func (r *Refusal) Error() string { return r.Code + ": " + r.Why }

// Event is one ledger event to append in the caller's transaction. Attributes
// are the spec's closed set for Name.
type Event struct {
	Name       string
	RunID      string // empty for the orchestrator
	Project    string
	Severity   string // "" means INFO
	Attributes map[string]any
	Body       string
}

// Ledger appends events inside a store transaction. An error means the event
// did not commit and the caller must roll back and fail closed.
type Ledger interface {
	AppendTx(ctx context.Context, tx *store.Tx, e Event) error
}

// ApprovalInput is what chapd gives the approvals engine to create a card.
type ApprovalInput struct {
	// Request is the full spec operation request, params included: the card
	// renders and hashes exactly these params. op_hash is as chapd computed it.
	Request   spec.Request
	Evidence  []Evidence
	RequestID string
	Op        string
	OpHash    string
	Project   string
	Class     string
	Critical  bool
	Caller    *Caller
	Reason    string
	Checks    []Check
	PolicyVer string
	ExpiresAt time.Time
}

// ApprovalInfo is the requester-visible summary of an approval.
type ApprovalInfo struct {
	ID            string
	RequestID     string
	Op            string
	OpHash        string
	State         string // pending, approved, denied, expired, cancelled, consumed
	Class         string
	Critical      bool
	PolicyVersion string
	CreatedAt     time.Time
	DecidedAt     time.Time
	ExpiresAt     time.Time
	OwnerKey      string // Caller.Key() of the requester
	// Evidence is the card's evidence blocks, as stored and signed with the card. It is not part of any API view.
	Evidence []Evidence
	// After is work the engine wants done once the transaction that created the
	// card has committed (the wake-up push). ops runs it after the commit, never
	// inside the transaction. Nil when there is nothing to do.
	After func(ctx context.Context)
}

// Approvals is the approvals engine (L1-12). It never decides on an API call:
// decisions come from the console and reach chapd through [Service.Decided].
type Approvals interface {
	// Create makes (or, for the same caller and op_hash, returns) the card
	// inside tx. It also queues the wake-up push exactly once per op_hash.
	Create(ctx context.Context, tx *store.Tx, in ApprovalInput) (ApprovalInfo, error)
	// Lookup reads one approval.
	Lookup(ctx context.Context, id string) (ApprovalInfo, error)
	// List returns the approvals owned by key, newest first.
	List(ctx context.Context, ownerKey, state string, limit int, after string) ([]ApprovalInfo, string, error)
	// CancelTx cancels a pending approval inside tx (run ended, requester
	// cancelled, op expired) and writes its op.approve event.
	CancelTx(ctx context.Context, tx *store.Tx, approvalID, reason string) error
	// ConsumeTx spends the approval inside tx, the transaction that moves the
	// op from allowed to executing, so the approval is used exactly when the op
	// is released. req is the request being released: the engine hashes it
	// again. An expected "no" (the hash differs, the approval was used, expired,
	// denied) is returned as a [*Refusal].
	ConsumeTx(ctx context.Context, tx *store.Tx, approvalID string, req spec.Request) error
}

// ErrApprovalNotFound is returned by [Approvals.Lookup] for an unknown id.
var ErrApprovalNotFound = errorString("ops: approval not found")

type errorString string

func (e errorString) Error() string { return string(e) }

// AlertKind says which moment of an op raised the alert: the three moments of a critical op, or an approved op
// that did not run.
type AlertKind string

const (
	AlertRequest   AlertKind = "request"
	AlertApproval  AlertKind = "approval"
	AlertExecution AlertKind = "execution"
	// AlertApprovedNotRun is raised for any op the operator approved and that was then refused at release (a stale CI
	// head, a moved policy) or whose approval ran out. Detail carries the cause code and the reason.
	AlertApprovedNotRun AlertKind = "approved_not_run"
)

// Alert is the loud notice for a critical-class op (decision #21).
type Alert struct {
	Kind      AlertKind
	Op        string
	Project   string
	RequestID string
	Requester string // Caller.Key()
	Detail    string
}

// Alerter delivers alerts. It is called after the transaction commits; a
// failure to alert never undoes an op, it is logged by the implementation.
type Alerter interface {
	Alert(ctx context.Context, a Alert)
}
