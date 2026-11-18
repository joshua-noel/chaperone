package spec

// Go forms of the v0 documents Chaperone reads and writes. Each field
// carries the schema's member name. Decode a received document with Load, which
// validates against the schema first; hash from the received bytes' tree, not
// from a value rebuilt out of a struct (OpHash, EventHash and the others accept
// either, and a struct round trip is tested to be lossless for every spec example).
//
// Timestamps stay strings: the schema fixes their exact spelling, and a
// parse and re-format must never change what was hashed.

// SpecVersion is the only spec_version v0 consumers accept.
const SpecVersion = "0"

// Requester is the party that asks for an operation: a run, authenticated by
// its token, or the orchestrator. Kind "run" sets RunID, TokenJTI and Profile;
// kind "orchestrator" sets ID.
type Requester struct {
	Kind     string `json:"kind"`
	RunID    string `json:"run_id,omitempty"`
	TokenJTI string `json:"token_jti,omitempty"`
	Profile  string `json:"profile,omitempty"`
	ID       string `json:"id,omitempty"`
}

// Target is what an operation acts on.
type Target struct {
	Adapter string `json:"adapter"`
	Ref     string `json:"ref"`
}

// Request is operation-request.schema.json. OpHash covers SpecVersion, Project,
// Op, Target and Params; Traceparent is advisory and outside the hash.
type Request struct {
	SpecVersion string         `json:"spec_version"`
	Type        string         `json:"type"`
	RequestID   string         `json:"request_id"`
	Requester   Requester      `json:"requester"`
	Project     string         `json:"project"`
	Op          string         `json:"op"`
	Target      Target         `json:"target"`
	Params      map[string]any `json:"params"`
	OpHash      string         `json:"op_hash"`
	Reason      string         `json:"reason,omitempty"`
	RequestedAt string         `json:"requested_at"`
	ExpiresAt   string         `json:"expires_at"`
	Traceparent string         `json:"traceparent,omitempty"`
}

// ApprovalCheck is one policy precondition shown on the approval card.
type ApprovalCheck struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}

// Shown records what the approver saw.
type Shown struct {
	DisplaySHA256 string   `json:"display_sha256"`
	Channels      []string `json:"channels"`
}

// Confirmation is authenticator evidence from one channel ("pc" or "phone").
type Confirmation struct {
	Channel         string `json:"channel"`
	CredentialID    string `json:"credential_id"`
	AssertionSHA256 string `json:"assertion_sha256"`
	At              string `json:"at"`
}

// Approver names the human who decided.
type Approver struct {
	ID string `json:"id"`
}

// Approval is operation-approval.schema.json. RunID is empty when the
// requester is the orchestrator; the challenge then omits run_id.
type Approval struct {
	SpecVersion     string          `json:"spec_version"`
	Type            string          `json:"type"`
	ApprovalID      string          `json:"approval_id"`
	RequestID       string          `json:"request_id"`
	RunID           string          `json:"run_id,omitempty"`
	OpHash          string          `json:"op_hash"`
	Decision        string          `json:"decision"`
	Reason          string          `json:"reason,omitempty"`
	PolicyVersion   string          `json:"policy_version"`
	Checks          []ApprovalCheck `json:"checks"`
	Shown           Shown           `json:"shown"`
	Confirmations   []Confirmation  `json:"confirmations"`
	Approver        Approver        `json:"approver"`
	Nonce           string          `json:"nonce"`
	SingleUse       bool            `json:"single_use"`
	DecidedAt       string          `json:"decided_at"`
	ExpiresAt       string          `json:"expires_at"`
	ChallengeSHA256 string          `json:"challenge_sha256"`
}

// TokenProfile is the profile claim of a run token.
type TokenProfile struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Digest        string `json:"digest,omitempty"`
	OverlayDigest string `json:"overlay_digest,omitempty"`
}

// TaskScope is the concrete scope Chaperone decided for a run.
type TaskScope struct {
	Repo   string   `json:"repo"`
	Base   string   `json:"base"`
	Branch string   `json:"branch"`
	Paths  []string `json:"paths"`
	Ops    []string `json:"ops"`
}

// Budget is the run's planned limits. USD is nil when the claim is absent.
type Budget struct {
	Minutes int      `json:"minutes"`
	Tokens  int64    `json:"tokens"`
	USD     *float64 `json:"usd,omitempty"`
}

// RunTokenClaims is run-token.schema.json: the claims of the JWT. Signature and
// header checks belong to the verifier (internal/runtoken, ADR-005).
type RunTokenClaims struct {
	Iss       string       `json:"iss"`
	Sub       string       `json:"sub"`
	Aud       string       `json:"aud"`
	Iat       int64        `json:"iat"`
	Exp       int64        `json:"exp"`
	JTI       string       `json:"jti"`
	RunID     string       `json:"run_id"`
	Project   string       `json:"project"`
	Profile   TokenProfile `json:"profile"`
	BriefSHA  string       `json:"brief_sha256"`
	Isolation string       `json:"isolation"`
	TaskScope TaskScope    `json:"task_scope"`
	Budget    Budget       `json:"budget"`
}

// Resource is the OTel resource of an event: the producing service.
type Resource struct {
	ServiceName       string `json:"service.name"`
	ServiceVersion    string `json:"service.version,omitempty"`
	ServiceInstanceID string `json:"service.instance.id"`
}

// Event is ledger-event.schema.json. Attributes are closed per EventName by the
// schema; they stay a map here because each name has its own set. Body is a
// pointer because the empty string is a valid body and must survive a round trip.
type Event struct {
	SpecVersion    string         `json:"spec_version"`
	Chain          string         `json:"chain"`
	Seq            int64          `json:"seq"`
	PrevHash       string         `json:"prev_hash"`
	Hash           string         `json:"hash"`
	TimeUnixNano   string         `json:"time_unix_nano"`
	TraceID        string         `json:"trace_id"`
	SpanID         string         `json:"span_id"`
	ParentSpanID   string         `json:"parent_span_id,omitempty"`
	SeverityNumber int            `json:"severity_number"`
	SeverityText   string         `json:"severity_text,omitempty"`
	EventName      string         `json:"event_name"`
	Resource       Resource       `json:"resource"`
	RunID          string         `json:"run_id,omitempty"`
	Project        string         `json:"project,omitempty"`
	Attributes     map[string]any `json:"attributes"`
	Body           *string        `json:"body,omitempty"`
}

// DenialAction is what was attempted.
type DenialAction struct {
	Verb   string `json:"verb"`
	Target string `json:"target"`
}

// DenialRequest says how to ask for more, or that asking is not possible.
type DenialRequest struct {
	Possible bool   `json:"possible"`
	Command  string `json:"command,omitempty"`
}

// Thrash counts repeat attempts of the same (surface, action).
type Thrash struct {
	Count         int  `json:"count"`
	WindowSeconds int  `json:"window_seconds"`
	Flagged       bool `json:"flagged"`
}

// Denial is denial.schema.json. A run's denial sets RunID and Profile; an
// orchestrator's sets OrchestratorID and neither of those.
type Denial struct {
	SpecVersion    string        `json:"spec_version"`
	Type           string        `json:"type"`
	DenialID       string        `json:"denial_id"`
	RunID          string        `json:"run_id,omitempty"`
	Project        string        `json:"project"`
	Profile        string        `json:"profile,omitempty"`
	At             string        `json:"at"`
	Surface        string        `json:"surface"`
	Action         DenialAction  `json:"action"`
	CauseCode      string        `json:"cause_code"`
	Why            string        `json:"why"`
	Request        DenialRequest `json:"request"`
	Thrash         Thrash        `json:"thrash"`
	PolicyVersion  string        `json:"policy_version,omitempty"`
	OrchestratorID string        `json:"orchestrator_id,omitempty"`
}

// GenericProfile is the part of a signed generic profile (profile.schema.json)
// that run-token checks read: its kind, branch prefix and allowed op patterns.
type GenericProfile struct {
	Profile      string `json:"profile"`
	BranchPrefix string `json:"branch_prefix"`
	Ops          struct {
		Allow []string `json:"allow"`
	} `json:"ops"`
}
