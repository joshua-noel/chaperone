package keys

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/joshua-noel/chaperone/internal/ops"
)

// Admin is the keys store behind the /v0/keys routes: it decides what each kind
// of caller may do to which key.
//
//   - The orchestrator that asked for a key (and only it) claims it, once.
//   - An orchestrator lists every key and revokes any (a human act: the agent
//     that held the key is stopped). It never reads a token.
//   - A key may read and revoke itself and nothing else; its own revoke is not
//     a human stop.
//   - A run has no part in keys at all.
type Admin struct{ s *Store }

var _ ops.KeyAdmin = (*Admin)(nil)

// NewAdmin returns the ops.KeyAdmin of s.
func NewAdmin(s *Store) *Admin { return &Admin{s: s} }

func mapErr(err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return ops.ErrKeyNotFound
	case errors.Is(err, ErrAlreadyClaimed):
		return &ops.KeyClaimError{Why: "this key was already claimed; a key is handed over once"}
	case errors.Is(err, ErrClaimExpired):
		return &ops.KeyClaimError{Why: "the claim window has passed, so the key was revoked; ask for a new one"}
	case errors.Is(err, ErrRevoked):
		return &ops.KeyClaimError{Why: "the key is revoked"}
	}
	return err
}

// self resolves "self" (a key naming itself) to the caller's key id.
func self(c *ops.Caller, id string) string {
	if c.Kind == ops.KindKey && id == "self" {
		return c.KeyID
	}
	return id
}

// Claim implements [ops.KeyAdmin].
func (a *Admin) Claim(c *ops.Caller, id string, r *http.Request) (string, ops.KeyInfo, error) {
	var claimant string
	switch {
	case c.Kind == ops.KindOrchestrator:
		claimant = c.Key()
	case c.Kind == ops.KindKey && c.KeyHolderKind == HolderAgent:
		// Any live key of the agent may take a key that was granted to the agent (its request-only key, or the
		// key it had): the grant is for the agent, and an agent has one live key.
		claimant = agentClaimant(c.KeyOwner, c.KeyHolder)
	default:
		return "", ops.KeyInfo{}, fmt.Errorf("%w: only the caller that asked for a key claims it", ops.ErrKeyForbidden)
	}
	tok, info, err := a.s.Claim(r.Context(), id, claimant)
	return tok, info, mapErr(err)
}

// agentOnly refuses every caller but an agent's own key (requests are an agent's business).
func agentOnly(c *ops.Caller) error {
	if c.Kind == ops.KindKey && c.KeyHolderKind == HolderAgent {
		return nil
	}
	return fmt.Errorf("%w: only an agent's key reads or withdraws its own requests", ops.ErrKeyForbidden)
}

// Requests implements [ops.KeyAdmin]: an agent's key sees its own agent's requests; an orchestrator sees all.
func (a *Admin) Requests(c *ops.Caller, r *http.Request) ([]ops.KeyRequestInfo, error) {
	switch c.Kind {
	case ops.KindOrchestrator:
		return a.s.ListRequests(r.Context(), "", "", false)
	case ops.KindKey:
		if err := agentOnly(c); err != nil {
			return nil, err
		}
		return a.s.ListRequests(r.Context(), c.KeyOwner, c.KeyHolder, false)
	}
	return nil, fmt.Errorf("%w: a run has no keys", ops.ErrKeyForbidden)
}

// ownRequest reads one request of the caller's own agent: another agent's request looks like no request.
func (a *Admin) ownRequest(c *ops.Caller, id string, r *http.Request) (ops.KeyRequestInfo, error) {
	v, err := a.s.GetRequest(r.Context(), id)
	if err != nil {
		return ops.KeyRequestInfo{}, mapErr(err)
	}
	if c.Kind == ops.KindKey && (v.Owner != c.KeyOwner || v.Holder != c.KeyHolder) {
		return ops.KeyRequestInfo{}, ops.ErrKeyNotFound
	}
	return v, nil
}

// Request implements [ops.KeyAdmin].
func (a *Admin) Request(c *ops.Caller, id string, r *http.Request) (ops.KeyRequestInfo, error) {
	switch c.Kind {
	case ops.KindOrchestrator:
	case ops.KindKey:
		if err := agentOnly(c); err != nil {
			return ops.KeyRequestInfo{}, err
		}
	default:
		return ops.KeyRequestInfo{}, fmt.Errorf("%w: a run has no keys", ops.ErrKeyForbidden)
	}
	return a.ownRequest(c, id, r)
}

// Withdraw implements [ops.KeyAdmin]: an agent takes back its own waiting request.
func (a *Admin) Withdraw(c *ops.Caller, id string, r *http.Request) (ops.KeyRequestInfo, error) {
	if err := agentOnly(c); err != nil {
		return ops.KeyRequestInfo{}, err
	}
	if _, err := a.ownRequest(c, id, r); err != nil {
		return ops.KeyRequestInfo{}, err
	}
	v, err := a.s.Withdraw(r.Context(), id, c.KeyID)
	if errors.Is(err, ErrRequestState) {
		return ops.KeyRequestInfo{}, fmt.Errorf("%w: the request is not waiting any more", ops.ErrKeyConflict)
	}
	return v, mapErr(err)
}

// Enrolment is the ops.AgentEnrol of a Store: the device-code enrolment of agents.
type Enrolment struct{ s *Store }

var _ ops.AgentEnrol = (*Enrolment)(nil)

// NewEnrolment returns the ops.AgentEnrol of s.
func NewEnrolment(s *Store) *Enrolment { return &Enrolment{s: s} }

func enrolErr(err error) error {
	var ref *EnrolRefusal
	switch {
	case errors.As(err, &ref):
		return &ops.EnrolError{Why: ref.Why, Status: ref.Status}
	case errors.Is(err, ErrNotFound):
		return ops.ErrKeyNotFound
	case errors.Is(err, ErrAlreadyClaimed):
		return &ops.EnrolError{Why: "this enrolment was already claimed; a key is handed over once", Status: http.StatusConflict}
	}
	return err
}

// Start implements [ops.AgentEnrol].
func (e *Enrolment) Start(ctx context.Context, project, label string) (ops.AgentEnrolStart, error) {
	st, err := e.s.StartEnrolment(ctx, project, label)
	if err != nil {
		return ops.AgentEnrolStart{}, enrolErr(err)
	}
	return ops.AgentEnrolStart{ID: st.ID, UserCode: st.UserCode, DeviceCode: st.DeviceCode, ExpiresAt: ops.KeyTime(st.ExpiresAt), Interval: 2}, nil
}

// Poll implements [ops.AgentEnrol].
func (e *Enrolment) Poll(ctx context.Context, id, deviceCode string) (ops.AgentEnrolPoll, error) {
	p, err := e.s.PollEnrolment(ctx, id, deviceCode)
	if err != nil {
		return ops.AgentEnrolPoll{}, enrolErr(err)
	}
	out := ops.AgentEnrolPoll{State: p.State, Token: p.Token}
	if p.Token != "" {
		k := p.Key
		out.Key = &k
	}
	return out, nil
}

// List implements [ops.KeyAdmin].
func (a *Admin) List(c *ops.Caller, r *http.Request) ([]ops.KeyInfo, error) {
	switch c.Kind {
	case ops.KindOrchestrator:
		if _, err := a.s.Sweep(r.Context()); err != nil {
			return nil, err
		}
		return a.s.List(r.Context(), "")
	case ops.KindKey:
		k, err := a.s.Get(r.Context(), c.KeyID)
		if err != nil {
			return nil, mapErr(err)
		}
		return []ops.KeyInfo{k}, nil
	}
	return nil, fmt.Errorf("%w: a run has no keys", ops.ErrKeyForbidden)
}

// Get implements [ops.KeyAdmin].
func (a *Admin) Get(c *ops.Caller, id string, r *http.Request) (ops.KeyInfo, error) {
	id = self(c, id)
	switch c.Kind {
	case ops.KindOrchestrator:
	case ops.KindKey:
		if id != c.KeyID {
			return ops.KeyInfo{}, ops.ErrKeyNotFound // another key looks like no key
		}
	default:
		return ops.KeyInfo{}, fmt.Errorf("%w: a run has no keys", ops.ErrKeyForbidden)
	}
	k, err := a.s.Get(r.Context(), id)
	return k, mapErr(err)
}

// Revoke implements [ops.KeyAdmin].
func (a *Admin) Revoke(c *ops.Caller, id string, r *http.Request) (ops.KeyInfo, error) {
	id = self(c, id)
	human := false
	switch c.Kind {
	case ops.KindOrchestrator:
		human = true
	case ops.KindKey:
		if id != c.KeyID {
			return ops.KeyInfo{}, ops.ErrKeyNotFound
		}
	default:
		return ops.KeyInfo{}, fmt.Errorf("%w: a run has no keys", ops.ErrKeyForbidden)
	}
	k, err := a.s.Revoke(r.Context(), id, c.Key(), human)
	if errors.Is(err, ErrRevoked) {
		return ops.KeyInfo{}, fmt.Errorf("%w: the key is already revoked", ops.ErrKeyConflict)
	}
	return k, mapErr(err)
}
