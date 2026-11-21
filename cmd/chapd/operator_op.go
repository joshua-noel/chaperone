package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/joshua-noel/chaperone/internal/ledger"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/redact"
	"github.com/joshua-noel/chaperone/internal/runtoken"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
	"github.com/joshua-noel/chaperone/internal/version"
)

// An operator command that changes what chapd holds (`chapd vault delete`,
// `chapd connect github`) is recorded the way the spec's "Operator-recorded
// ops" rule records what the operator does at the machine, and the way
// `chapd orch issue` already is: an op.request and an op.result, both by the
// orchestrator id "operator", and no op.approve. The person who runs the command
// as the service account is the authority; there is no card for an offline
// command, so there is no approval to record.
//
// The spec has no event name for these commands and none is added: the op kind
// is free text (lower-case dotted words), so a new command adds no schema
// change. The event attributes stay closed; what happened goes in the body, and
// the op_hash covers the exact params. A secret value is never in either.

const operatorProject = "chaperone"

// operatorOp is one thing the operator did.
type operatorOp struct {
	Op            string         // op kind, for example "vault.delete"
	Ref           string         // what it acted on, for example "vault:github-app-key"
	Reversibility string         // reversible, compensable or irreversible
	Params        map[string]any // covered by the op_hash; never a secret
	Body          string         // one plain line for a reader of the ledger
}

// operatorLedger is the ledger of the database a command works on, opened for
// the one command.
type operatorLedger struct {
	led           *ledger.Ledger
	policyVersion string
}

// openOperatorLedger opens the chain chaperone.<instance> on a migrated database,
// the way `chapd orch` does. reg masks secrets in the event text; it may be the
// vault's registry. It fails when the ledger is unusable, for example a broken
// chain: a command that must be recorded is not started then.
func openOperatorLedger(ctx context.Context, db *store.DB, instance string, reg *redact.Registry) (*operatorLedger, error) {
	led, err := ledger.Open(ctx, db, ledger.Config{Instance: instance, Version: version.Version, Redactor: reg})
	if err != nil {
		return nil, fmt.Errorf("open the ledger: %w", err)
	}
	_, base, err := policy.Default()
	if err != nil {
		_ = led.Close()
		return nil, err
	}
	return &operatorLedger{led: led, policyVersion: base.BaselineVersion()}, nil
}

func (l *operatorLedger) Close() error { return l.led.Close() }

// appendTx writes the pair inside tx, so it commits or rolls back with the
// change it records.
func (l *operatorLedger) appendTx(ctx context.Context, tx *store.Tx, o operatorOp) error {
	drafts, err := o.drafts(l.policyVersion)
	if err != nil {
		return err
	}
	for _, d := range drafts {
		if _, err := l.led.AppendTx(ctx, tx, d); err != nil {
			return fmt.Errorf("ledger %s: %w", d.Name, err)
		}
	}
	return nil
}

// append writes the pair in a transaction of its own, for a record of
// something that was already done.
func (l *operatorLedger) append(ctx context.Context, db *store.DB, o operatorOp) error {
	return db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error { return l.appendTx(ctx, tx, o) })
}

func (o operatorOp) drafts(policyVersion string) ([]ledger.Draft, error) {
	hash, err := spec.OpHash(map[string]any{
		"spec_version": spec.SpecVersion, "project": operatorProject, "op": o.Op,
		"target": map[string]any{"adapter": "chaperone", "ref": o.Ref}, "params": o.Params,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: the op_hash cannot be made: %w", o.Op, err)
	}
	body := o.Body
	if len(body) > 1000 {
		body = body[:1000]
	}
	rid, xid := idMaker("q-")(), idMaker("x-")()
	who := map[string]any{"factory.requester.kind": "orchestrator", "factory.orchestrator.id": runtoken.OperatorID}
	with := func(m map[string]any) map[string]any {
		for k, v := range who {
			m[k] = v
		}
		return m
	}
	return []ledger.Draft{
		{Name: "op.request", Project: operatorProject, Severity: "WARN", Body: body, Attributes: with(map[string]any{
			"factory.request_id": rid, "factory.op": o.Op, "factory.op_hash": hash, "factory.reversibility": o.Reversibility})},
		{Name: "op.result", Project: operatorProject, Severity: "WARN", Body: body, Attributes: with(map[string]any{
			"factory.request_id": rid, "factory.op_hash": hash, "factory.execution_id": xid, "factory.outcome": "succeeded",
			"factory.policy_version": policyVersion})},
	}, nil
}

// bodyList joins names for a ledger body.
func bodyList(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}
