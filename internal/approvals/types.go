package approvals

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/joshua-noel/chaperone/internal/notify"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// Class is an op's class in the catalog (ADR-004 section 2, decisions #15 and #21).
// Gated, high and critical ops can need a card; routine ops never do.
// Critical is a label, not a different ceremony: one device approves it, and
// the card says CRITICAL and an alert goes out on request, approval and execution.
type Class string

// Op classes.
const (
	ClassRoutine  Class = "routine"
	ClassGated    Class = "gated"
	ClassHigh     Class = "high"
	ClassCritical Class = "critical"
)

// OpInfo is what the approvals engine knows about an op from the catalog. The
// name is the catalog's, never text from a request: it is what the push shows.
type OpInfo struct {
	Name  string
	Class Class
}

// Catalog is the op catalog (L1-07). Lookup reports false for an unknown op.
type Catalog interface {
	Lookup(op string) (OpInfo, bool)
}

// StaticCatalog is a Catalog from a map of op name to class.
type StaticCatalog map[string]Class

// Lookup implements [Catalog].
func (c StaticCatalog) Lookup(op string) (OpInfo, bool) {
	class, ok := c[op]
	return OpInfo{Name: op, Class: class}, ok
}

// PhaseOneCatalog lists the Phase 1 ops with the classes ADR-004 section 2
// gives them. Whether an op is enabled is policy data and is not decided here.
func PhaseOneCatalog() StaticCatalog {
	return StaticCatalog{
		"pr.open": ClassRoutine, "pr.update": ClassRoutine, "branch.push": ClassRoutine,
		"issue.open": ClassRoutine, "issue.comment": ClassRoutine, "issue.reopen": ClassRoutine,
		"health": ClassRoutine, "logs": ClassRoutine, "ci.report": ClassRoutine,
		"intake.list": ClassRoutine, "intake.comment": ClassRoutine, "intake.move": ClassRoutine, "intake.states": ClassRoutine,
		"pr.view": ClassRoutine, "pr.diff": ClassRoutine, "pr.checks": ClassRoutine, "pr.files": ClassRoutine,
		"pr.merge":             ClassGated, // low-tier PRs need no card; medium and high do
		"deploy":               ClassHigh,
		"mail.send":            ClassHigh,
		"drive.share":          ClassHigh,
		"data.apply":           ClassHigh,
		"pr.push.workflow":     ClassHigh,
		"keys.issue":           ClassHigh, // ADR-008: every key is a card signed with Hello
		"keys.extend":          ClassHigh, // ADR-008: making an agent's key last longer is a card signed with Hello
		"secrets.write":        ClassCritical,
		"repo.settings":        ClassCritical,
		"host.scripts.refresh": ClassCritical,
		"approvers.enroll":     ClassCritical,
	}
}

// State is an approval's state (the ApprovalState enum of api/openapi.yaml).
type State string

// Approval states.
const (
	StatePending   State = "pending"
	StateApproved  State = "approved"
	StateDenied    State = "denied"
	StateExpired   State = "expired"
	StateCancelled State = "cancelled"
	StateConsumed  State = "consumed"
)

// Outcome is what happened to an approval, as the op state machine sees it.
type Outcome string

// Outcomes passed to [Config.OnDecided].
const (
	OutcomeApproved Outcome = "approved" // the op may now be released
	OutcomeDenied   Outcome = "denied"   // the operator said no
	OutcomeExpired  Outcome = "expired"  // nobody decided in time, or the approval went unused
)

// Approval is one stored approval card.
type Approval struct {
	ID            string
	RequestID     string
	RequesterKind string // "run", "orchestrator" or "key"
	RequesterKey  string // the run id, the orchestrator id or the key id
	RunID         string // empty for the orchestrator
	Project       string
	Op            string
	OpHash        string
	Class         Class
	PolicyVersion string
	Request       spec.Request
	Checks        []spec.ApprovalCheck
	Evidence      []Evidence
	CardText      string
	DisplaySHA256 string
	State         State

	Created        time.Time
	RequestExpires time.Time // last instant the card may be decided
	Decided        time.Time // zero until decided
	Approver       string    // the spec approver id
	Reason         string
	Expires        time.Time // last instant an approval may be consumed; zero until approved
	Consumed       time.Time
	// Record is the spec operation-approval document of a decision; nil until decided.
	Record *spec.Approval
}

// Critical reports whether the card carries the CRITICAL label.
func (a *Approval) Critical() bool { return a.Class == ClassCritical }

// Decision is passed to [Config.OnDecided] inside the transaction that made it.
type Decision struct {
	Approval Approval
	Outcome  Outcome
	Reason   string
}

// Evidence is a titled block of text the adapter computed when the request was
// made (the commit list of a deploy, the diff of a high-tier PR). It is part of
// the card, so it is hashed with it and shown in full. It is untrusted text:
// repository content passes through it.
type Evidence struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

// ActorKind says who is trying to decide an approval.
type ActorKind string

// Actor kinds. Only [ActorApprover] may decide; a token never can.
const (
	ActorApprover     ActorKind = "approver"
	ActorRun          ActorKind = "run"
	ActorOrchestrator ActorKind = "orchestrator"
	ActorKey          ActorKind = "key"
)

// Actor is the authenticated caller of a decision entry point.
type Actor struct {
	Kind ActorKind
	// ApproverRow and ApproverID identify a console approver: the approvers
	// table row, and the spec approver id (see ApproverSpecID in the console).
	ApproverRow int64
	ApproverID  string
	// RunID names the run a ActorRun token belongs to, when known.
	RunID string
	// ID names the orchestrator of an ActorOrchestrator token or the key of an
	// ActorKey token, when known.
	ID string
}

// Alert is a loud notice for a critical-class op: on request, approval and
// execution (decision #21, spec "logged loudly"). It carries no parameters.
type Alert struct {
	Stage      string // AlertRequested, AlertApproved or AlertExecuting
	Op         string
	Project    string
	ApprovalID string
	RequestID  string
	OpHash     string
	Requester  string // "run <id>" or "orchestrator <id>"
}

// Alert stages.
const (
	AlertRequested = "requested"
	AlertApproved  = "approved"
	AlertExecuting = "executing"
)

// Stop is a stop signal the engine asks the caller to raise (stop-table codes).
type Stop struct {
	Code          string // StopFlood or StopBreach
	RunID         string // empty for the orchestrator
	RequesterKind string
	RequesterKey  string
	Project       string
	Why           string
}

// Stop codes, from the spec's stop table.
const (
	StopFlood  = "APPROVAL_FLOOD"
	StopBreach = "POLICY_BREACH"
)

// LedgerEvent is an event the engine asks the ledger to append in the
// transaction that changed the state it describes. The ledger adapter
// (L1-07 over L1-02's AppendTx) turns it into a ledger.Draft.
type LedgerEvent struct {
	Name       string // "op.approve"
	RunID      string // empty for the orchestrator
	Project    string
	Severity   string // "" means INFO
	Attributes map[string]any
	Body       string
}

// Ledger appends an event inside tx. An error means the transition MUST NOT
// happen: the engine returns it and the transaction rolls back.
type Ledger interface {
	AppendTx(ctx context.Context, tx *store.Tx, ev LedgerEvent) error
}

// Verifier checks one WebAuthn assertion over a challenge. The console is the
// implementation (internal/console): it owns the credentials, the relying
// parties and the user-verification rules.
type Verifier interface {
	VerifyAssertion(ctx context.Context, in AssertionInput) (AssertionEvidence, error)
}

// AssertionInput is what a [Verifier] needs.
type AssertionInput struct {
	Origin      string // the console origin URL the response arrived at
	ApproverRow int64
	Challenge   []byte // the 32 raw challenge bytes
	Response    []byte // the PublicKeyCredential JSON as the browser sent it
}

// AssertionEvidence is what a verified assertion proves.
type AssertionEvidence struct {
	Channel      string // "pc" or "phone"
	CredentialID []byte // the authenticator's credential id
	RPID         string
	Origin       string
	// The kind of authenticator, for the ledger (ADR-004 amendment 15). Attachment is "platform", "cross-platform" or
	// "unreported", or empty when the verifier does not say (the ledger body then names no authenticator). Transports
	// is the browser's list. BackupEligible is the BE flag: true is a passkey that may be synced to an account.
	Attachment     string
	Transports     []string
	BackupEligible bool
}

// AssertionError is what a [Verifier] returns for a refused assertion. Reason
// is a short stable code (console.ReasonSignature and friends), safe to show.
type AssertionError struct {
	Reason string
	Err    error
}

func (e *AssertionError) Error() string {
	if e.Err != nil {
		return "approvals: assertion refused (" + e.Reason + "): " + e.Err.Error()
	}
	return "approvals: assertion refused (" + e.Reason + ")"
}

func (e *AssertionError) Unwrap() error { return e.Err }

// Limits are the policy values of ADR-004 section 6. The caps bound what agents
// can queue; nothing here limits how many approvals the operator makes (decision #16).
type Limits struct {
	PerRun     int           // pending cards per run (and per orchestrator); default 2
	PerProject int           // default 5
	Total      int           // default 10
	RequestTTL time.Duration // how long a card may be decided; default 30 minutes
	DeployTTL  time.Duration // the same for deploy; default 15 minutes
	// ApprovalTTL is how long an approval may be consumed after the decision;
	// default 5 minutes. Together with ChallengeTTL it fixes the expires_at the
	// challenge binds: begin + ChallengeTTL + ApprovalTTL.
	ApprovalTTL  time.Duration
	ChallengeTTL time.Duration // how long a challenge may be answered; default 2 minutes
	StickyDeny   time.Duration // how long a denied or expired op hash is refused; default 60 minutes
}

func (l Limits) withDefaults() Limits {
	def := func(v *int, d int) {
		if *v == 0 {
			*v = d
		}
	}
	defd := func(v *time.Duration, d time.Duration) {
		if *v == 0 {
			*v = d
		}
	}
	def(&l.PerRun, 2)
	def(&l.PerProject, 5)
	def(&l.Total, 10)
	defd(&l.RequestTTL, 30*time.Minute)
	defd(&l.DeployTTL, 15*time.Minute)
	defd(&l.ApprovalTTL, 5*time.Minute)
	defd(&l.ChallengeTTL, 2*time.Minute)
	defd(&l.StickyDeny, 60*time.Minute)
	return l
}

// Config configures [New].
type Config struct {
	DB      *store.DB
	Ledger  Ledger  // required
	Catalog Catalog // required
	// Verifier checks assertions. Required for [Engine.Approve].
	Verifier Verifier
	// Notifier sends the wake-up for a new card. Optional. Its failure never
	// fails an approval.
	Notifier notify.Notifier
	Limits   Limits
	// Channels lists the confirmation channels accepted. Default {"pc"}. The
	// phone channel needs [Config.PhoneOrigins]; setting those adds "phone".
	Channels []string
	// PhoneOrigins lists the console origin URLs that are the phone's (ADR-004
	// section 5: https://<server>.<tailnet>.ts.net). A decision begun at one of them
	// is the phone channel and needs number matching first ([Engine.PhoneMatch]);
	// every other origin is the server channel. Empty: no phone.
	PhoneOrigins []string
	// PolicyVersion returns the version of the policy pack in force. When set,
	// an approval given under another version is refused with OP_POLICY_REFUSED
	// (api/openapi.yaml, "The catalog and the policy version"). Optional.
	PolicyVersion func() string
	// OnDecided runs inside the transaction of every decision, expiry included,
	// so the op state machine moves the op in the same commit. Optional.
	OnDecided func(ctx context.Context, tx *store.Tx, d Decision) error
	// AfterApproved runs once after the commit of an approval, on the goroutine
	// of [Engine.Approve]; the op state machine releases the approved op from
	// it. It must not block for long. Optional.
	AfterApproved func(ctx context.Context, a *Approval)
	// Stop is asked to raise a stop signal: APPROVAL_FLOOD when a caller is over
	// a cap, POLICY_BREACH when a token tries to decide. It runs inside the
	// transaction when one exists. Optional.
	Stop func(ctx context.Context, tx *store.Tx, s Stop) error
	// Alert delivers a critical-class alert. It runs after the commit (see
	// [Effects]). Optional.
	Alert func(Alert)
	Log   *slog.Logger
	Now   func() time.Time
}

// Refusal codes: the spec's denial cause codes, POLICY_BREACH (a stop code),
// and four codes that are not denials because they answer the console, not an
// agent.
const (
	CodeApprovalRequired = "OP_APPROVAL_REQUIRED"
	CodeDenied           = "OP_APPROVAL_DENIED"
	CodeExpired          = "OP_APPROVAL_EXPIRED"
	CodePolicyRefused    = "OP_POLICY_REFUSED"
	CodeParamsInvalid    = "OP_PARAMS_INVALID"
	CodeHashMismatch     = "APPROVAL_HASH_MISMATCH"
	CodeConsumed         = "APPROVAL_CONSUMED"
	CodeIntegrity        = "APPROVAL_INTEGRITY_FAILED"
	CodeDisplayMismatch  = "DISPLAY_MISMATCH"
	CodeBreach           = "POLICY_BREACH"

	CodeNoSuchApproval = "NO_SUCH_APPROVAL"
	CodeChallenge      = "CHALLENGE_UNKNOWN"     // unknown, expired, already used, or another browser's
	CodeWrongRequest   = "WRONG_REQUEST"         // the challenge was made for another approval or approver
	CodeAssertion      = "ASSERTION_REFUSED"     // the authenticator evidence did not verify; Why is the reason code
	CodeNumberRequired = "PHONE_NUMBER_REQUIRED" // a phone decision without a matched number
)

// Refusal is an expected "no": a denial for the caller to turn into a denial
// body, or a refusal the console shows. It is an error so a call site can
// return it, but callers branch on it with [errors.As]; anything else an engine
// method returns is a fault (database, ledger) and the operation must fail closed.
type Refusal struct {
	Code string
	Why  string
	// Stop is a stop code to raise for the caller ("APPROVAL_FLOOD", "POLICY_BREACH"), or "".
	Stop string
	// RetryAfter is how long until the same request could be accepted, or 0.
	RetryAfter time.Duration
	// ApprovalID names the approval concerned, when there is one.
	ApprovalID string
}

func (r *Refusal) Error() string { return fmt.Sprintf("approvals: %s: %s", r.Code, r.Why) }

func refuse(code, why string) *Refusal { return &Refusal{Code: code, Why: why} }
