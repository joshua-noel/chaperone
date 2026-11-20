package keys

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// appendOp writes the op.request and op.result pair of an operator-recorded op
// (keys.claim, keys.revoke) in the caller's transaction: the spec has no
// "person at the console" requester, so the events carry the requester that
// acted (the orchestrator's id, "operator" for chapd itself, or a key projected
// as "key.<id>") and the body says what happened. They never hold a token.
func (s *Store) appendOp(ctx context.Context, tx *store.Tx, op, project, requesterID, keyID string, params map[string]any, body string) error {
	request := map[string]any{
		"spec_version": "0",
		"project":      project,
		"op":           op,
		"target":       map[string]any{"adapter": "chaperone", "ref": "key:" + keyID},
		"params":       params,
	}
	opHash, err := spec.OpHash(request)
	if err != nil {
		return fmt.Errorf("keys: %s op_hash: %w", op, err)
	}
	rid, err := randomLower(8)
	if err != nil {
		return err
	}
	xid, err := randomLower(8)
	if err != nil {
		return err
	}
	evs := []ops.Event{
		{Name: "op.request", Project: project, Attributes: map[string]any{
			"factory.request_id":      "q-" + rid,
			"factory.op":              op,
			"factory.op_hash":         opHash,
			"factory.reversibility":   "reversible",
			"factory.requester.kind":  "orchestrator",
			"factory.orchestrator.id": requesterID,
		}, Body: body},
		{Name: "op.result", Project: project, Attributes: map[string]any{
			"factory.request_id":      "q-" + rid,
			"factory.op_hash":         opHash,
			"factory.execution_id":    "x-" + xid,
			"factory.outcome":         "succeeded",
			"factory.policy_version":  s.cfg.PolicyVersion(),
			"factory.requester.kind":  "orchestrator",
			"factory.orchestrator.id": requesterID,
		}},
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
