package keys

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// note is an op that chapd records for itself (keys.claim, keys.revoke, keys.enrol): the op.request and the
// op.result of it. The spec has no "person at the console" requester, so the events carry the requester that
// acted (the orchestrator's id, "operator" for chapd itself, or a key projected as "key.<id>") and the body says
// what happened. They never hold a token.
type note struct {
	Op, Project, Requester string
	Ref                    string // the target: "key:<id>"
	Params                 map[string]any
	Body                   string
	Severity               string // "" means INFO
	Cause                  string // set: the op was refused, with this UPPER_SNAKE cause; empty: it succeeded
}

// appendOp writes the events of an op on a key (keys.claim, keys.revoke) in the caller's transaction.
func (s *Store) appendOp(ctx context.Context, tx *store.Tx, op, project, requesterID, keyID string, params map[string]any, body string) error {
	return s.appendNote(ctx, tx, note{Op: op, Project: project, Requester: requesterID, Ref: "key:" + keyID, Params: params, Body: body})
}

// appendNote writes the op.request and op.result pair of n in the caller's transaction.
func (s *Store) appendNote(ctx context.Context, tx *store.Tx, n note) error {
	request := map[string]any{
		"spec_version": "0",
		"project":      n.Project,
		"op":           n.Op,
		"target":       map[string]any{"adapter": "chaperone", "ref": n.Ref},
		"params":       n.Params,
	}
	opHash, err := spec.OpHash(request)
	if err != nil {
		return fmt.Errorf("keys: %s op_hash: %w", n.Op, err)
	}
	rid, err := randomLower(8)
	if err != nil {
		return err
	}
	xid, err := randomLower(8)
	if err != nil {
		return err
	}
	result := map[string]any{
		"factory.request_id":      "q-" + rid,
		"factory.op_hash":         opHash,
		"factory.policy_version":  s.cfg.PolicyVersion(),
		"factory.requester.kind":  "orchestrator",
		"factory.orchestrator.id": n.Requester,
	}
	if n.Cause != "" {
		result["factory.outcome"] = "refused"
		result["factory.cause_code"] = n.Cause
	} else {
		result["factory.outcome"] = "succeeded"
		result["factory.execution_id"] = "x-" + xid
	}
	evs := []ops.Event{
		{Name: "op.request", Project: n.Project, Severity: n.Severity, Attributes: map[string]any{
			"factory.request_id":      "q-" + rid,
			"factory.op":              n.Op,
			"factory.op_hash":         opHash,
			"factory.reversibility":   "reversible",
			"factory.requester.kind":  "orchestrator",
			"factory.orchestrator.id": n.Requester,
		}, Body: n.Body},
		{Name: "op.result", Project: n.Project, Attributes: result},
	}
	for _, ev := range evs {
		if err := s.cfg.Ledger.AppendTx(ctx, tx, ev); err != nil {
			return fmt.Errorf("keys: ledger %s: %w", ev.Name, err)
		}
	}
	return nil
}

func randomLower(n int) (string, error) {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	out := make([]byte, 0, n)
	buf := make([]byte, n*2)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("keys: random: %w", err)
		}
		for _, b := range buf {
			if b < 252 {
				out = append(out, alphabet[int(b)%36])
				if len(out) == n {
					break
				}
			}
		}
	}
	return string(out), nil
}
