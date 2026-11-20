package ops

import (
	"errors"
	"net/http"
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
	// List lists the keys of the caller's owner: every key for an orchestrator.
	List(c *Caller, r *http.Request) ([]KeyInfo, error)
	// Get returns one key; a key may read only itself.
	Get(c *Caller, id string, r *http.Request) (KeyInfo, error)
	// Revoke revokes a key: an orchestrator any key (a human act: an agent's key
	// stops the agent), a key only itself.
	Revoke(c *Caller, id string, r *http.Request) (KeyInfo, error)
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
