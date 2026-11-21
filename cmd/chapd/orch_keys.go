package main

import (
	"context"

	keystore "github.com/joshua-noel/chaperone/internal/keys"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/runtoken"
	"github.com/joshua-noel/chaperone/internal/store"
)

// orchestratorHooks are the two hooks that tie the keys an orchestrator owns to its token (ADR-008). A key built by
// an orchestrator is visible to, and revocable by, that orchestrator only, in the projects its token covers. So when
// the token is revoked, every key it owns is revoked in the same transaction, and when the token is re-issued without
// a project or an operation, the keys it owns that hold it are. Both are chapd's own, non-human revokes, ledgered. (The other
// way out was to leave such keys running with nobody able to revoke them; the operator can also revoke any key of an
// orchestrator on the Agents page.) An approved op the orchestrator had waiting is cancelled by the service.
//
// The re-issue could instead have been refused until the keys were revoked by hand; revoking them is the simpler
// safe choice, since the owner has just narrowed what the orchestrator may touch. A key is judged against the new
// scope alone (its project must be in it, each of its ops allowed by it), so a re-issue that keeps both leaves it.
func orchestratorHooks(svc *ops.Service, keys *keystore.Store) (txRevoke func(context.Context, *store.Tx, string) error, txReissue func(context.Context, *store.Tx, string, runtoken.OrchScope) error) {
	txRevoke = func(ctx context.Context, tx *store.Tx, id string) error {
		if err := svc.CancelOrchOps(ctx, tx, id); err != nil {
			return err
		}
		return keys.RevokeOwnedTx(ctx, tx, id, nil, "revoked with its owner, the orchestrator "+id)
	}
	txReissue = func(ctx context.Context, tx *store.Tx, id string, scope runtoken.OrchScope) error {
		return keys.RevokeOwnedBeyondTx(ctx, tx, id, scope.Projects, scope.Ops)
	}
	return txRevoke, txReissue
}
