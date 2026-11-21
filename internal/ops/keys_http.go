package ops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// KeyInfo is a key as the API shows it (components.schemas.Key). It holds no
// token and no hash: the token exists in exactly two places, the one claim
// response and the holder's key file.
type KeyInfo struct {
	ID             string   `json:"id"`
	State          string   `json:"state"` // granted, live, expired or revoked
	Project        string   `json:"project"`
	Owner          string   `json:"owner"`
	HolderKind     string   `json:"holder_kind"`
	Holder         string   `json:"holder"`
	Ops            []string `json:"ops"`
	Units          []string `json:"units"`
	Sensitive      bool     `json:"sensitive"`
	GrantKind      string   `json:"grant_kind"` // approved (a script's owner), self (an owner granted their own agent) or bootstrap (a request-only key)
	RatePerHour    int      `json:"rate_per_hour"`
	IssuedAt       string   `json:"issued_at"`
	ExpiresAt      string   `json:"expires_at"`
	ClaimDeadline  string   `json:"claim_deadline,omitempty"`
	ClaimedAt      string   `json:"claimed_at,omitempty"`
	Fingerprint    string   `json:"fingerprint,omitempty"`
	GrantedBy      string   `json:"granted_by"`
	ApprovalID     string   `json:"approval_id"`
	RequestID      string   `json:"request_id"`
	RevokedAt      string   `json:"revoked_at,omitempty"`
	RevokedBy      string   `json:"revoked_by,omitempty"`
	RevokeReason   string   `json:"revoke_reason,omitempty"`
	StoppedByHuman bool     `json:"stopped_by_human,omitempty"`
	LastUsedAt     string   `json:"last_used_at,omitempty"`
	Uses           int      `json:"uses"`
}

// KeyAdmin is what the key routes need from the keys store (internal/keys).
// Every method takes the authenticated caller and decides what that caller may
// do to which key; a refusal is one of the errors below, never a partial effect.
type KeyAdmin interface {
	// Claim hands the claimant of a granted key its token, once.
	Claim(c *Caller, id string, r *http.Request) (token string, info KeyInfo, err error)
	// List lists the keys the caller may see: for an orchestrator the keys it owns, in its own projects.
	List(c *Caller, r *http.Request) ([]KeyInfo, error)
	// Get returns one key; a key may read only itself, an orchestrator only a key it owns.
	Get(c *Caller, id string, r *http.Request) (KeyInfo, error)
	// Revoke revokes a key: an orchestrator a key it owns, in its own projects (never a human stop: only the owner at
	// the console stops an agent), a key only itself.
	Revoke(c *Caller, id string, r *http.Request) (KeyInfo, error)
	// Requests lists key requests: an agent's key its own agent's, an orchestrator those of the agents it owns, in its projects.
	Requests(c *Caller, r *http.Request) ([]KeyRequestInfo, error)
	// Request returns one request; an agent's key reads only its own agent's.
	Request(c *Caller, id string, r *http.Request) (KeyRequestInfo, error)
	// Withdraw takes back a waiting request: only the agent's own key does.
	Withdraw(c *Caller, id string, r *http.Request) (KeyRequestInfo, error)
}

// KeyRequestGrant is what was granted of a request, or what was removed from it.
type KeyRequestGrant struct {
	Ops         []string `json:"ops"`
	Units       []string `json:"units"`
	TTLHours    int      `json:"ttl_hours"`
	RatePerHour int      `json:"rate_per_hour"`
}

// KeyRequestInfo is a key request as the API shows it (components.schemas.KeyRequest). The requester sees exactly
// what was granted and what was removed. It holds no token.
type KeyRequestInfo struct {
	ID          string           `json:"id"`
	Kind        string           `json:"kind"`  // new or extend
	State       string           `json:"state"` // pending, granted, denied, withdrawn, expired or cancelled
	Project     string           `json:"project"`
	Owner       string           `json:"owner"`
	Holder      string           `json:"holder"`
	Ops         []string         `json:"ops"`
	Units       []string         `json:"units"`
	TTLHours    int              `json:"ttl_hours"` // for an extension: the hours added
	RatePerHour int              `json:"rate_per_hour"`
	Reason      string           `json:"reason"`
	NeededToday bool             `json:"needed_today"`
	CreatedAt   string           `json:"created_at"`
	ExpiresAt   string           `json:"expires_at"`
	ExtendsKey  string           `json:"extends_key,omitempty"`
	DecidedAt   string           `json:"decided_at,omitempty"`
	DecidedBy   string           `json:"decided_by,omitempty"`
	DenyReason  string           `json:"deny_reason,omitempty"`
	Granted     *KeyRequestGrant `json:"granted,omitempty"`
	Removed     *KeyRequestGrant `json:"removed,omitempty"`
	KeyID       string           `json:"key_id,omitempty"` // a granted new key, to claim
	IssueOp     string           `json:"issue_op,omitempty"`
}

// AgentEnrolStart is the answer to the start of an enrolment: the agent keeps DeviceCode, and reads UserCode out.
type AgentEnrolStart struct {
	ID         string `json:"id"`
	UserCode   string `json:"user_code"`
	DeviceCode string `json:"device_code"`
	ExpiresAt  string `json:"expires_at"`
	Interval   int    `json:"interval"` // seconds between polls
}

// AgentEnrolPoll is the answer to a poll. A claimed enrolment carries the request-only key once, in the body.
type AgentEnrolPoll struct {
	State string   `json:"state"` // pending, claimed or expired
	Token string   `json:"token,omitempty"`
	Key   *KeyInfo `json:"key,omitempty"`
}

// EnrolError is an enrolment the rules turn down: a caller's mistake, shown as it is.
type EnrolError struct {
	Why    string
	Status int
}

func (e *EnrolError) Error() string { return e.Why }

// AgentEnrol is the device-code enrolment of agents (internal/keys). Its routes need no credential: the agent
// has none yet. They are bounded instead, and the owner's Hello is what turns an enrolment into a key.
type AgentEnrol interface {
	Start(ctx context.Context, project, label string) (AgentEnrolStart, error)
	Poll(ctx context.Context, id, deviceCode string) (AgentEnrolPoll, error)
}

// Errors the key routes map to HTTP answers.
var (
	ErrKeyNotFound  = errors.New("no such key for this caller")
	ErrKeyConflict  = errors.New("the key is not in a state that allows this")
	ErrKeyForbidden = errors.New("this caller may not do that to this key")
)

// claimWhy is the one claim failure that carries text of its own.
type KeyClaimError struct{ Why string }

func (e *KeyClaimError) Error() string { return e.Why }

func (s *Server) keyFail(w http.ResponseWriter, r *http.Request, c *Caller, err error) {
	var cl *KeyClaimError
	switch {
	case errors.Is(err, ErrKeyNotFound):
		s.fail(w, r, &NotFoundError{Why: "no such key for this caller"})
	case errors.As(err, &cl):
		s.fail(w, r, &ConflictError{Why: cl.Why})
	case errors.Is(err, ErrKeyConflict):
		s.fail(w, r, &ConflictError{Why: err.Error()})
	case errors.Is(err, ErrKeyForbidden):
		s.fail(w, r, s.cfg.Svc.deny(r.Context(), c, denial{Project: s.projectOf(c), Surface: "token", Verb: "request", Target: r.URL.Path, Code: CodeOpNotInToken, Why: err.Error()}))
	default:
		s.fail(w, r, &UnavailableError{Why: "the keys store failed", Retryable: true, Err: err})
	}
}

func (s *Server) listKeys(w http.ResponseWriter, r *http.Request, c *Caller) {
	items, err := s.cfg.Keys.List(c, r)
	if err != nil {
		s.keyFail(w, r, c, err)
		return
	}
	if items == nil {
		items = []KeyInfo{}
	}
	s.writeJSON(w, r, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) getKey(w http.ResponseWriter, r *http.Request, c *Caller) {
	info, err := s.cfg.Keys.Get(c, r.PathValue("id"), r)
	if err != nil {
		s.keyFail(w, r, c, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, info)
}

func (s *Server) revokeKey(w http.ResponseWriter, r *http.Request, c *Caller) {
	info, err := s.cfg.Keys.Revoke(c, r.PathValue("id"), r)
	if err != nil {
		s.keyFail(w, r, c, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, info)
}

// claimKey answers POST /v0/keys/{id}/claim: the one place a key's token is
// sent. The body carries it once; nothing else (a header, a log line, a ledger
// event, an op result, an error) ever does. It is sent with no-store, and only
// to the caller that asked for the key.
func (s *Server) claimKey(w http.ResponseWriter, r *http.Request, c *Caller) {
	token, info, err := s.cfg.Keys.Claim(c, r.PathValue("id"), r)
	if err != nil {
		s.keyFail(w, r, c, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	s.writeMinted(w, r, http.StatusOK, map[string]any{"token": token, "key": info})
}

// Time formats a key row's instants the way the rest of the API does.
func KeyTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return ts(t)
}

func (s *Server) listKeyRequests(w http.ResponseWriter, r *http.Request, c *Caller) {
	items, err := s.cfg.Keys.Requests(c, r)
	if err != nil {
		s.keyFail(w, r, c, err)
		return
	}
	if items == nil {
		items = []KeyRequestInfo{}
	}
	s.writeJSON(w, r, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) getKeyRequest(w http.ResponseWriter, r *http.Request, c *Caller) {
	info, err := s.cfg.Keys.Request(c, r.PathValue("id"), r)
	if err != nil {
		s.keyFail(w, r, c, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, info)
}

func (s *Server) withdrawKeyRequest(w http.ResponseWriter, r *http.Request, c *Caller) {
	info, err := s.cfg.Keys.Withdraw(c, r.PathValue("id"), r)
	if err != nil {
		s.keyFail(w, r, c, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, info)
}

// enrolFail answers a refused enrolment call. There is no caller to deny: the body is the plain reason.
func (s *Server) enrolFail(w http.ResponseWriter, status int, why string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "enrol_refused", "why": clamp(why, 500)})
}

func (s *Server) enrolBody(w http.ResponseWriter, r *http.Request, out any) bool {
	if r.Header.Get("Authorization") != "" {
		s.enrolFail(w, http.StatusBadRequest, "an enrolment call carries no credential: the agent has none yet")
		return false
	}
	// These routes need no credential, so nothing but the caller itself stops a web page in the operator's
	// browser from posting to the loopback address. A browser always sends Origin on a cross-origin POST, and a
	// body with no JSON content type is the one kind of post a page can make without a preflight; the agent's
	// command line sends neither. Both are refused.
	if r.Header.Get("Origin") != "" {
		s.enrolFail(w, http.StatusForbidden, "an enrolment call comes from the agent's command line, not from a web page")
		return false
	}
	if ct := strings.ToLower(r.Header.Get("Content-Type")); !strings.HasPrefix(ct, "application/json") {
		s.enrolFail(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return false
	}
	data, bad := readBody(w, r)
	if bad != "" {
		s.enrolFail(w, http.StatusBadRequest, bad)
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		s.enrolFail(w, http.StatusBadRequest, "the body is not what this route takes")
		return false
	}
	return true
}

func (s *Server) enrolErr(w http.ResponseWriter, err error) {
	var ee *EnrolError
	switch {
	case errors.As(err, &ee):
		s.enrolFail(w, ee.Status, ee.Why)
	case errors.Is(err, ErrKeyNotFound):
		s.enrolFail(w, http.StatusNotFound, "no such enrolment")
	default:
		s.enrolFail(w, http.StatusServiceUnavailable, "chapd could not do that now; nothing was changed")
	}
}

// startEnrol answers POST /v0/agents/enrolments. It needs no credential and writes only a waiting enrolment.
func (s *Server) startEnrol(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Project string `json:"project"`
		Label   string `json:"label"`
	}
	if !s.enrolBody(w, r, &b) {
		return
	}
	start, err := s.cfg.Agents.Start(r.Context(), b.Project, b.Label)
	if err != nil {
		s.enrolErr(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	s.writeMinted(w, r, http.StatusCreated, start)
}

// pollEnrol answers POST /v0/agents/enrolments/{id}/poll: the one place a request-only key is sent, once.
func (s *Server) pollEnrol(w http.ResponseWriter, r *http.Request) {
	var b struct {
		DeviceCode string `json:"device_code"`
	}
	if !s.enrolBody(w, r, &b) {
		return
	}
	poll, err := s.cfg.Agents.Poll(r.Context(), r.PathValue("id"), b.DeviceCode)
	if err != nil {
		s.enrolErr(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	s.writeMinted(w, r, http.StatusOK, poll)
}
