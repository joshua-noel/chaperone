package approvals

import (
	"context"
	"testing"

	"github.com/joshua-noel/chaperone/internal/ledger"
	"github.com/joshua-noel/chaperone/internal/redact"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// realLedger adapts the real ledger (L1-02) to [Ledger], as chapd will.
type realLedger struct{ l *ledger.Ledger }

func (r *realLedger) AppendTx(ctx context.Context, tx *store.Tx, ev LedgerEvent) error {
	_, err := r.l.AppendTx(ctx, tx, ledger.Draft{Name: ev.Name, RunID: ev.RunID, Project: ev.Project, Severity: ev.Severity,
		Attributes: ev.Attributes, Body: ev.Body})
	return err
}

// The ledger validates every draft against the spec's closed attribute sets, so
// this proves the op.approve events of every kind of decision are valid events
// and that the chain they make verifies.
func TestDecisionsMakeValidLedgerEvents(t *testing.T) {
	ctx := context.Background()
	ad := &realLedger{}
	r := newRig(t, func(c *Config) { c.Ledger = ad })
	var err error
	if ad.l, err = ledger.Open(ctx, r.db, ledger.Config{Instance: "test", Redactor: redact.NewRegistry()}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ad.l.Close() })

	// A run's approval, consumed.
	req := r.mkReq(nil)
	a := r.mustCard(req)
	r.mustApprove(a)
	if err := r.consume(a, req); err != nil {
		t.Fatal(err)
	}
	// A critical approval (severity WARN).
	crit := r.mkReq(func(q *spec.Request) {
		q.Op, q.Target, q.Params = "repo.settings", spec.Target{Adapter: "github", Ref: "acme/shop"}, map[string]any{"setting": "visibility"}
		q.Requester.RunID = "r-9c21"
	})
	r.mustApprove(r.mustCard(crit))
	// The orchestrator's approval has no run id.
	orch := r.mkReq(func(q *spec.Request) { q.Requester = spec.Requester{Kind: "orchestrator", ID: "main"} })
	r.mustApprove(r.mustCard(orch))
	// A denial, with a reason that is not a secret.
	denied := r.mustCard(r.mkReq(func(q *spec.Request) { q.Requester.RunID = "r-0004" }))
	if _, err := r.e.Deny(ctx, DenyInput{ApprovalID: denied.ID, Actor: approver, Reason: "wrong target"}); err != nil {
		t.Fatal(err)
	}
	// A cancellation.
	cancelled := r.mustCard(r.mkReq(func(q *spec.Request) { q.Requester.RunID = "r-0005" }))
	if err := r.e.Atomic(ctx, func(ctx context.Context, tx *store.Tx) (Effects, error) {
		_, err := r.e.CancelTx(ctx, tx, CancelInput{RequestID: cancelled.RequestID, Reason: "cancelled by requester"})
		return Effects{}, err
	}); err != nil {
		t.Fatal(err)
	}

	rep, err := ledger.Verify(ctx, r.db, ledger.VerifyOptions{})
	if err != nil || !rep.OK() {
		t.Fatalf("verify: %v %v", err, rep.Problems())
	}
	var n int
	if err := r.db.SQL().QueryRow(`SELECT count(*) FROM ledger_events WHERE event_name = 'op.approve'`).Scan(&n); err != nil || n != 5 {
		t.Fatalf("op.approve events: %d %v", n, err)
	}
	var sev string
	if err := r.db.SQL().QueryRow(
		`SELECT json_extract(event, '$.severity_text') FROM ledger_events WHERE event_name = 'op.approve' AND run_id = 'r-9c21'`).Scan(&sev); err != nil || sev != "WARN" {
		t.Fatalf("critical severity %q %v", sev, err)
	}
	if err := r.db.SQL().QueryRow(`SELECT count(*) FROM ledger_events WHERE event_name = 'op.approve' AND run_id IS NULL`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("orchestrator op.approve without a run id: %d %v", n, err)
	}
}
