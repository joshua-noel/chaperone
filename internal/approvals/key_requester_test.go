package approvals

import (
	"context"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/spec"
)

const testKey = "k-0123456789abcdef"

func keyReq(r *rig, id string, mutate func(*spec.Request)) spec.Request {
	return r.mkReq(func(q *spec.Request) {
		q.Requester = spec.KeyRequester(id)
		if mutate != nil {
			mutate(q)
		}
	})
}

// A key's high op raises a card whose requester is the key: stored as a key, shown as a key, signed over the
// same request, and recorded in the ledger as the spec's projected orchestrator.
func TestAKeysHighOpRaisesACardStoredAsAKey(t *testing.T) {
	r := newRig(t)
	req := keyReq(r, testKey, nil)
	a := r.mustCard(req)
	if a.RequesterKind != "key" || a.RequesterKey != testKey || a.RunID != "" {
		t.Fatalf("card requester: %q %q run=%q", a.RequesterKind, a.RequesterKey, a.RunID)
	}
	var kind, keyID string
	if err := r.db.SQL().QueryRow(`SELECT requester_kind, key_id FROM approvals WHERE approval_id = ?`, a.ID).Scan(&kind, &keyID); err != nil || kind != "key" || keyID != testKey {
		t.Fatalf("row: %v %q %q", err, kind, keyID)
	}
	if !contains(a.CardText, "Key "+testKey+" wants to:", "Operation: deploy (class high)") {
		t.Fatalf("the card does not say a key asks:\n%s", a.CardText)
	}
	// The same key asking again for the same thing is the same card; another key gets its own.
	if again := r.request(keyReq(r, testKey, func(q *spec.Request) { q.Params = req.Params })); again.Created || again.Approval.ID != a.ID {
		t.Errorf("dedupe: %+v", again)
	}
	other := r.mustCard(keyReq(r, "k-fedcba9876543210", nil))
	if other.ID == a.ID {
		t.Error("two keys share a card")
	}
	// A run and a key that happen to share a name do not share a card.
	if run := r.mustCard(r.mkReq(func(q *spec.Request) { q.Params = req.Params })); run.ID == a.ID {
		t.Error("a run and a key share a card")
	}

	// Approving it records the decision against the key as the projected orchestrator, and consuming it needs
	// the same key: another key's request, or the same request from a run, is a hash mismatch.
	done := r.mustApprove(a)
	var found bool
	for _, ev := range r.led.all() {
		if ev.Name == "op.approve" && ev.Attributes["factory.request_id"] == a.RequestID {
			found = true
			if ev.Attributes["factory.requester.kind"] != "orchestrator" || ev.Attributes["factory.orchestrator.id"] != "key."+testKey {
				t.Errorf("op.approve names %v", ev.Attributes)
			}
		}
	}
	if !found {
		t.Error("no op.approve event")
	}
	wrong := req
	wrong.Requester = spec.KeyRequester("k-fedcba9876543210")
	wantRefusal(t, r.consume(done, wrong), CodeHashMismatch)
	asRun := req
	asRun.Requester = spec.Requester{Kind: "run", RunID: "r-7f3a", TokenJTI: "n8Gf3kQ2xV7bTz1LwA9cYd", Profile: "host-interim"}
	wantRefusal(t, r.consume(done, asRun), CodeHashMismatch)
	asOrch := req
	asOrch.Requester = spec.Requester{Kind: "orchestrator", ID: "main"}
	wantRefusal(t, r.consume(done, asOrch), CodeHashMismatch)
	if err := r.consume(done, req); err != nil {
		t.Fatalf("the key's own request: %v", err)
	}
}

// A key can never decide a card, its own or anyone's: the same POLICY_BREACH as a run token, and the stop names the key.
func TestAKeyThatTriesToDecideIsAPolicyBreach(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	a := r.mustCard(keyReq(r, testKey, nil))
	actor := Actor{Kind: ActorKey, ID: testKey}
	for step, run := range map[string]func() error{
		"begin": func() error {
			_, err := r.e.BeginDecision(ctx, BeginInput{ApprovalID: a.ID, Actor: actor, Origin: testOrigin})
			return err
		},
		"deny": func() error {
			_, err := r.e.Deny(ctx, DenyInput{ApprovalID: a.ID, Actor: actor, Reason: "x"})
			return err
		},
	} {
		if ref := wantRefusal(t, run(), CodeBreach); ref.Stop != StopBreach {
			t.Fatalf("%s: %+v", step, ref)
		}
	}
	_, stops, _ := r.snapshot()
	if len(stops) != 2 || stops[0].RequesterKind != "key" || stops[0].RequesterKey != testKey {
		t.Errorf("stops: %+v", stops)
	}
	if r.state(a.ID) != StatePending {
		t.Fatal("a key changed an approval")
	}
}

// The requester-kind check of the approvals table: a key row needs its key id and a run row cannot have one.
func TestApprovalRowsKeepRunsAndKeysApart(t *testing.T) {
	r := newRig(t)
	a := r.mustCard(keyReq(r, testKey, nil))
	for _, q := range []string{
		`UPDATE approvals SET requester_kind = 'run' WHERE approval_id = '` + a.ID + `'`,
		`UPDATE approvals SET key_id = 'k-00000000000000aa' WHERE approval_id = '` + a.ID + `'`,
		`UPDATE approvals SET requester_key = 'someone-else' WHERE approval_id = '` + a.ID + `'`,
	} {
		if _, err := r.db.SQL().Exec(q); err == nil {
			t.Errorf("accepted: %s", q)
		}
	}
	if _, err := r.db.SQL().Exec(`INSERT INTO approvals (approval_id, request_id, requester_kind, requester_key, project, op, op_hash, class,
        policy_version, request_json, checks_json, evidence_json, card_text, display_sha256, state, created_unix, request_expires_unix)
        VALUES ('a-keyless', 'q-keyless', 'key', 'k-1', 'p', 'deploy', 'sha256:a', 'high', 'p', '{}', '[]', '[]', 'c', 'sha256:b', 'pending', 1, 2)`); err == nil {
		t.Error("a key row without its key id was accepted")
	}
	if strings.TrimSpace(a.CardText) == "" {
		t.Fatal("empty card")
	}
}
