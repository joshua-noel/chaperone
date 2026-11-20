package keys

import (
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
	if c.Kind != ops.KindOrchestrator {
		return "", ops.KeyInfo{}, fmt.Errorf("%w: only the caller that asked for a key claims it", ops.ErrKeyForbidden)
	}
	tok, info, err := a.s.Claim(r.Context(), id, c.Key())
	return tok, info, mapErr(err)
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
