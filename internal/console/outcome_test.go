package console

import (
	"encoding/json"
	"strings"
	"testing"
)

// insertOp writes an op row that carries an approval, as the op state machine would leave it.
func insertOp(t *testing.T, ar *apprRig, approvalID, state, cause, denial string) {
	t.Helper()
	outcome := map[string]string{"succeeded": "succeeded", "refused": "refused", "failed": "failed", "unconfirmed": "unconfirmed"}[state]
	var oc any
	if outcome != "" {
		oc = outcome
	}
	if _, err := ar.db.SQL().Exec(`INSERT INTO ops (id, state, op, project, target_adapter, target_ref, params_json, op_hash, requester_kind, requester_key,
		orchestrator_id, class, reversibility, policy_version, requested_at, expires_at, updated_at, approval_id, outcome, cause_code, denial_json)
		VALUES (?, ?, 'pr.merge', 'acme-shop', 'github', 'o/r#5', '{}', 'sha256:'||hex(randomblob(32)), 'orchestrator', 'orchestrator:main',
		'main', 'gated', 'irreversible', 'p', 1, 2, 3, ?, ?, ?, ?)`,
		"q-"+strings.ToLower(approvalID[2:]), state, approvalID, oc, nilIfEmpty(cause), nilIfEmpty(denial)); err != nil {
		t.Fatal(err)
	}
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func TestOutcomeWords(t *testing.T) {
	for _, c := range []struct {
		o    opOutcome
		kind string
		want string
	}{
		{opOutcome{State: "succeeded"}, outcomeRan, "Done: it ran."},
		{opOutcome{State: "refused", Cause: "CI_STALE", Why: "the head is 1 commit behind main"}, outcomeNotRun, "Approved, but it did not run: the head is 1 commit behind main. Nothing was changed. The orchestrator has to ask again."},
		{opOutcome{State: "refused", Cause: "CI_STALE"}, outcomeNotRun, "did not run: CI_STALE."},
		{opOutcome{State: "expired", Cause: "OP_APPROVAL_EXPIRED"}, outcomeNotRun, "the approval ran out"},
		{opOutcome{State: "failed"}, outcomeFailed, "it failed"},
		{opOutcome{State: "unconfirmed"}, outcomeUnknown, "does not know the result"},
		{opOutcome{State: "allowed"}, outcomeWaiting, "Waiting for the orchestrator to start it"},
		{opOutcome{State: "executing"}, outcomeRunning, "Running"},
		{opOutcome{State: "pending_approval"}, outcomeWaiting, "Waiting for the orchestrator"},
		{opOutcome{}, outcomeNone, ""},
	} {
		kind, text := c.o.describe()
		if kind != c.kind || !strings.Contains(text, c.want) {
			t.Errorf("%+v: %q %q, want %q containing %q", c.o, kind, text, c.kind, c.want)
		}
	}
}

// An approved op that is then refused at release is not silent: the card's status line asks for the outcome and the
// Recent table names it.
func TestApprovedButNotRunIsShown(t *testing.T) {
	ar := newApprRig(t, nil)
	b, auth := ar.signedIn()
	card := ar.request(nil)
	bg := ar.begin(b, card.ID)
	if rec := ar.finish(b, card.ID, bg, auth.get(bg.options, pcOrigin.URL, opts{signCount: &zero})); rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}

	get := func() map[string]string {
		rec := b.do("GET", "/approvals/"+card.ID+"/outcome", nil, nil)
		if rec.Code != 200 {
			t.Fatalf("outcome: %d %s", rec.Code, rec.Body)
		}
		var out map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	// No op carries this approval (the engine alone, as in the other tests): nothing to follow.
	if o := get(); o["kind"] != outcomeNone {
		t.Fatalf("%v", o)
	}
	insertOp(t, ar, card.ID, "refused", "CI_STALE", `{"why":"the pull request head is 1 commit behind main","code":"CI_STALE"}`)
	o := get()
	if o["kind"] != outcomeNotRun || !strings.Contains(o["text"], "did not run: the pull request head is 1 commit behind main") {
		t.Fatalf("%v", o)
	}
	page := b.do("GET", "/approvals", nil, nil).Body.String()
	if !strings.Contains(page, `class="outcome outcome-not_run"`) || !strings.Contains(page, "Approved, but it did not run: the pull request head is 1 commit behind main") {
		t.Fatalf("Recent does not say the approved request did not run:\n%s", page)
	}
	// The same question from a browser that is not signed in is refused.
	if rec := ar.browser(pcOrigin).do("GET", "/approvals/"+card.ID+"/outcome", nil, nil); rec.Code != 401 {
		t.Fatalf("signed out: %d", rec.Code)
	}
}

func TestApprovedAndRunIsShown(t *testing.T) {
	ar := newApprRig(t, nil)
	b, auth := ar.signedIn()
	card := ar.request(nil)
	bg := ar.begin(b, card.ID)
	if rec := ar.finish(b, card.ID, bg, auth.get(bg.options, pcOrigin.URL, opts{signCount: &zero})); rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	insertOp(t, ar, card.ID, "succeeded", "", "")
	page := b.do("GET", "/approvals", nil, nil).Body.String()
	if !strings.Contains(page, `class="outcome outcome-ran"`) || !strings.Contains(page, "Done: it ran.") {
		t.Fatalf("%s", page)
	}
}
