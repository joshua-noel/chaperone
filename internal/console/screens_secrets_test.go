package console

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/approvals"
	"github.com/joshua-noel/chaperone/internal/vault"
)

const canaryA = "zx-canary-9d41c7e2-not-for-display-A"

func importForm(id, value string) url.Values {
	return url.Values{"action": {"import"}, "id": {id}, "kind": {"github-app-key"}, "project": {"acme-shop"}, "owner": {"gh"}, "value": {value}}
}

func (sr *scrRig) pendingSecretWrites() []*approvals.Approval {
	sr.t.Helper()
	out, err := sr.e.ListFor(context.Background(), "orchestrator", operatorID, approvals.StatePending, 20)
	if err != nil {
		sr.t.Fatal(err)
	}
	return out
}

// requestSecret posts the form and returns the id of the card it made.
func (sr *scrRig) requestSecret(b *browser, form url.Values) string {
	sr.t.Helper()
	before := len(sr.pendingSecretWrites())
	rec := hxPost(b, "/secrets/request", form)
	if rec.Code != http.StatusAccepted || rec.Header().Get("HX-Refresh") != "true" {
		sr.t.Fatalf("request: %d %q %s", rec.Code, rec.Header().Get("HX-Refresh"), rec.Body)
	}
	list := sr.pendingSecretWrites()
	if len(list) != before+1 {
		sr.t.Fatalf("%d pending secret writes after the request, want %d", len(list), before+1)
	}
	return list[0].ID // newest first
}

func (sr *scrRig) secretIDs() []string {
	sr.t.Helper()
	infos, err := sr.vault.List(context.Background())
	if err != nil {
		sr.t.Fatal(err)
	}
	var out []string
	for _, i := range infos {
		out = append(out, i.ID)
	}
	return out
}

func (sr *scrRig) secretValue(id string) string {
	sr.t.Helper()
	var got string
	if err := sr.vault.Use(context.Background(), id, func(v []byte) error { got = string(v); return nil }); err != nil {
		sr.t.Fatal(err)
	}
	return got
}

func TestSecretsScreenShowsMetadataNeverValues(t *testing.T) {
	sr := newScrRig(t)
	b, _ := sr.signedIn()
	if _, err := sr.vault.Import(context.Background(), vault.Meta{ID: "gh-app-key", Kind: "github-app-key", Project: "acme-shop", Owner: "gh"}, []byte(canaryA)); err != nil {
		t.Fatal(err)
	}
	info, _ := sr.vault.Info(context.Background(), "gh-app-key")
	page := get(t, b, "/secrets")
	mustHave(t, "secrets", page, "Vault", "gh-app-key", "github-app-key", "acme-shop", info.Fingerprint, "Import or rotate a secret",
		`hx-post="/secrets/request"`, "secrets.write", "critical", `id="secret-form"`)
	mustNotHave(t, "secrets", page, canaryA)
	if sr.reg.Len() == 0 {
		t.Fatal("the redaction registry does not know the secret")
	}
}

func TestSecretImportNeedsAFreshHelloApproval(t *testing.T) {
	sr := newScrRig(t)
	b, auth := sr.signedIn()
	id := sr.requestSecret(b, importForm("gh-app-key", canaryA))
	if got := sr.secretIDs(); len(got) != 0 {
		t.Fatalf("the vault holds %v before any approval", got)
	}

	// The card, rendered by the server, labelled critical, on the Secrets page.
	page := get(t, b, "/secrets")
	mustHave(t, "card", page, "waiting for your approval", `data-approval="`+id+`"`, "approval-critical", "CRITICAL", "store a secret named gh-app-key",
		"Approve with Windows Hello", `/approvals/approvals.js`, "Cancel and discard the value")
	mustNotHave(t, "card", page, canaryA)
	mustNotHave(t, "card", page, `hx-post="/secrets/`+id+`/commit"`) // not approved yet: no way to complete it

	// The session alone approves nothing.
	rec := hxPost(b, "/secrets/"+id+"/commit", url.Values{})
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "Not approved") || rec.Header().Get("HX-Retarget") != "#secrets-status" {
		t.Fatalf("commit before approval: %d %s", rec.Code, rec.Body)
	}
	if got := sr.secretIDs(); len(got) != 0 {
		t.Fatalf("an unapproved write stored %v", got)
	}

	// The approval is the only question: the same request that records it stores the value (review item 5).
	bg := sr.begin(b, id)
	fin := sr.finish(b, id, bg, auth.get(bg.options, pcOrigin.URL, opts{signCount: &zero}))
	if fin.Code != 200 {
		t.Fatalf("approve: %d %s", fin.Code, fin.Body)
	}
	mustHave(t, "finish", fin.Body.String(), `"stored":true`, "Secret stored", "gh-app-key")
	mustNotHave(t, "finish", fin.Body.String(), canaryA)
	if got := sr.secretValue("gh-app-key"); got != canaryA {
		t.Fatalf("the vault holds %q", got)
	}
	if info, err := sr.vault.Info(context.Background(), "gh-app-key"); err != nil || info.Kind != "github-app-key" || info.Project != "acme-shop" || info.Owner != "gh" {
		t.Fatalf("meta %+v %v", info, err)
	}
	if sr.state(id) != approvals.StateConsumed {
		t.Fatalf("state %s, want consumed", sr.state(id))
	}
	// Nothing is left to press, and the value is on no page.
	page = get(t, b, "/secrets")
	mustNotHave(t, "after", page, canaryA, `hx-post="/secrets/`+id+`/commit"`, "hx-confirm=\"Store the value")
	// Used once only.
	if rec = hxPost(b, "/secrets/"+id+"/commit", url.Values{}); rec.Code != http.StatusConflict {
		t.Fatalf("second commit: %d %s", rec.Code, rec.Body)
	}
	// The record: request, approval and result; loud alerts at each stage; no value anywhere.
	reqs, results := sr.events("op.request"), sr.events("op.result")
	if len(reqs) != 1 || attrString(reqs[0], "factory.op") != "secrets.write" || reqs[0].Project != "acme-shop" {
		t.Fatalf("op.request %+v", reqs)
	}
	if len(results) != 1 || attrString(results[0], "factory.outcome") != "succeeded" ||
		attrString(results[0], "factory.op_hash") != attrString(reqs[0], "factory.op_hash") {
		t.Fatalf("op.result %+v", results)
	}
	// The vault's own record (spec v0.1.1): which secret and what happened, under the result's execution_id, never the value.
	writes := sr.events("vault.write")
	if len(writes) != 1 || attrString(writes[0], "factory.secret.id") != "gh-app-key" || attrString(writes[0], "factory.secret.action") != "import" ||
		attrString(writes[0], "factory.secret.kind") != "github-app-key" || attrString(writes[0], "factory.outcome") != "succeeded" ||
		attrString(writes[0], "factory.execution_id") != attrString(results[0], "factory.execution_id") ||
		attrString(writes[0], "factory.orchestrator.id") != "operator" || attrString(results[0], "factory.orchestrator.id") != "operator" {
		t.Fatalf("vault.write %+v", writes)
	}
	if _, alerts := sr.snapshot(); len(alerts) != 3 || alerts[0].Stage != "requested" || alerts[1].Stage != "approved" || alerts[2].Stage != "executing" || alerts[0].Op != "secrets.write" {
		t.Fatalf("alerts %+v", alerts)
	}
	if !strings.Contains(sr.logs.String(), "secret written") {
		t.Error("the operator log does not record the write")
	}
	mustNotHave(t, "log", sr.logs.String(), canaryA)
}

func TestSecretRotate(t *testing.T) {
	sr := newScrRig(t)
	b, auth := sr.signedIn()
	old, err := sr.vault.Import(context.Background(), vault.Meta{ID: "ntfy-topic", Kind: "ntfy-topic", Owner: "notify"}, []byte("old-value-1"))
	if err != nil {
		t.Fatal(err)
	}
	id := sr.requestSecret(b, url.Values{"action": {"rotate"}, "id": {"ntfy-topic"}, "value": {"  new-value-2\r\n"}})
	card := sr.pendingSecretWrites()[0]
	mustHave(t, "rotate card", card.CardText, "secrets.write", "ntfy-topic")
	if card.Request.Project != "chaperone" || paramString(card.Request.Params, "kind") != "ntfy-topic" {
		t.Fatalf("a rotation takes its kind from the stored secret: %+v", card.Request)
	}
	sr.approveCard(b, auth, id) // stores the value by itself
	if st := sr.state(id); st != approvals.StateConsumed {
		t.Fatalf("state %s, want consumed", st)
	}
	if got := sr.secretValue("ntfy-topic"); got != "new-value-2" {
		t.Fatalf("value %q (surrounding whitespace is removed)", got)
	}
	now, _ := sr.vault.Info(context.Background(), "ntfy-topic")
	if now.Fingerprint == old.Fingerprint || now.Rotated.IsZero() {
		t.Fatalf("rotation not recorded: %+v", now)
	}
	if got := bodyOf(sr.events("op.request")[0]); !strings.Contains(got, "rotate secret ntfy-topic") {
		t.Fatalf("body %q", got)
	}
}

func TestSecretRequestIsValidatedBeforeAnyCardExists(t *testing.T) {
	sr := newScrRig(t)
	b, _ := sr.signedIn()
	if _, err := sr.vault.Import(context.Background(), vault.Meta{ID: "taken", Kind: "k"}, []byte("taken-value")); err != nil {
		t.Fatal(err)
	}
	huge := strings.Repeat("x", vault.MaxSecretSize+1)
	cases := []struct {
		name string
		form url.Values
		want int
	}{
		{"import over an existing id", importForm("taken", "secret-value"), http.StatusConflict},
		{"rotate an unknown id", url.Values{"action": {"rotate"}, "id": {"ghost"}, "value": {"ghost-value-1"}}, http.StatusNotFound},
		{"unknown action", url.Values{"action": {"delete"}, "id": {"taken"}, "value": {"taken-value-2"}}, http.StatusBadRequest},
		{"bad id", importForm("Bad/Id", "secret-value"), http.StatusBadRequest},
		{"device name", importForm("con", "secret-value"), http.StatusBadRequest},
		{"empty value", importForm("fresh", "   \r\n"), http.StatusBadRequest},
		{"bad kind", func() url.Values { f := importForm("fresh", "secret-value"); f.Set("kind", "Bad Kind"); return f }(), http.StatusBadRequest},
		{"control char in owner", func() url.Values { f := importForm("fresh", "secret-value"); f.Set("owner", "a\x01b"); return f }(), http.StatusBadRequest},
		{"value too large", importForm("fresh", huge), http.StatusRequestEntityTooLarge},
	}
	for _, c := range cases {
		rec := hxPost(b, "/secrets/request", c.form)
		if rec.Code != c.want || rec.Header().Get("HX-Retarget") != "#secret-form-status" {
			t.Errorf("%s: %d %q %s", c.name, rec.Code, rec.Header().Get("HX-Retarget"), rec.Body)
		}
		mustNotHave(t, c.name, rec.Body.String(), "secret-value")
	}
	if n := len(sr.pendingSecretWrites()); n != 0 {
		t.Fatalf("%d cards after refused requests", n)
	}
	if n := len(sr.con.scr.pend.m); n != 0 {
		t.Fatalf("%d values held after refused requests", n)
	}
}

func TestSecretCommitRefusals(t *testing.T) {
	// approved makes a card that is approved and whose value is still held but not stored: the state a failed first try
	// leaves. (An approval stores the value by itself; so the value is taken out of the held set while the approval is
	// granted, which makes that store a no-op, and put back.)
	approved := func(t *testing.T) (*scrRig, *browser, string) {
		sr := newScrRig(t)
		b, auth := sr.signedIn()
		id := sr.requestSecret(b, importForm("gh-app-key", canaryA))
		h := sr.con.scr.pend.take(id)
		sr.approveCard(b, auth, id)
		if err := sr.con.scr.pend.put(id, h); err != nil {
			t.Fatal(err)
		}
		return sr, b, id
	}
	commit := func(b *browser, id string) *httptest.ResponseRecorder {
		return hxPost(b, "/secrets/"+id+"/commit", url.Values{})
	}

	t.Run("a denied card's value is wiped at once", func(t *testing.T) {
		sr := newScrRig(t)
		b, _ := sr.signedIn()
		id := sr.requestSecret(b, importForm("gh-app-key", canaryA))
		h := sr.con.scr.pend.m[id]
		if rec := b.postH("/approvals/"+id+"/deny", []byte(`{"reason":"not mine"}`), b.csrf(), nil); rec.Code != 200 {
			t.Fatalf("deny: %d %s", rec.Code, rec.Body)
		}
		if sr.con.scr.pend.has(id) || h.value != nil {
			t.Fatalf("after deny: held %v, value wiped %v", sr.con.scr.pend.has(id), h.value == nil)
		}
	})
	t.Run("a denied card stores nothing", func(t *testing.T) {
		sr := newScrRig(t)
		b, _ := sr.signedIn()
		id := sr.requestSecret(b, importForm("gh-app-key", canaryA))
		if rec := b.postH("/approvals/"+id+"/deny", []byte(`{"reason":"not mine"}`), b.csrf(), nil); rec.Code != 200 {
			t.Fatalf("deny: %d %s", rec.Code, rec.Body)
		}
		if rec := commit(b, id); rec.Code != http.StatusConflict {
			t.Fatalf("commit of a denied card: %d %s", rec.Code, rec.Body)
		}
		if len(sr.secretIDs()) != 0 {
			t.Fatal("stored")
		}
	})
	t.Run("cancel discards the value", func(t *testing.T) {
		sr := newScrRig(t)
		b, _ := sr.signedIn()
		id := sr.requestSecret(b, importForm("gh-app-key", canaryA))
		if !sr.con.scr.pend.has(id) {
			t.Fatal("value not held")
		}
		rec := hxPost(b, "/secrets/"+id+"/cancel", url.Values{})
		if rec.Code != 200 || sr.con.scr.pend.has(id) || sr.state(id) != approvals.StateCancelled {
			t.Fatalf("cancel: %d %s held=%v state=%s", rec.Code, rec.Body, sr.con.scr.pend.has(id), sr.state(id))
		}
		if rec = hxPost(b, "/secrets/"+id+"/cancel", url.Values{}); rec.Code != http.StatusConflict {
			t.Fatalf("second cancel: %d", rec.Code)
		}
		if rec = commit(b, id); rec.Code != http.StatusConflict {
			t.Fatalf("commit after cancel: %d", rec.Code)
		}
	})
	t.Run("a restart loses the value, not the approval", func(t *testing.T) {
		sr, b, id := approved(t)
		sr.con.scr.pend = newPendingSecrets(sr.con.now) // chapd restarted
		rec := commit(b, id)
		if rec.Code != http.StatusGone || !strings.Contains(rec.Body.String(), "no longer held") {
			t.Fatalf("commit after a restart: %d %s", rec.Code, rec.Body)
		}
		if len(sr.secretIDs()) != 0 || sr.state(id) != approvals.StateApproved {
			t.Fatalf("stored %v, state %s", sr.secretIDs(), sr.state(id))
		}
		page := get(t, b, "/secrets")
		mustHave(t, "lost value", page, "no longer holds the value", "Cancel and discard the value")
		mustNotHave(t, "lost value", page, "Complete import")
	})
	t.Run("a value that is not the approved one is refused", func(t *testing.T) {
		sr, b, id := approved(t)
		sr.con.scr.pend.m[id].value[0] ^= 1
		rec := commit(b, id)
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "not the one that was approved") {
			t.Fatalf("commit: %d %s", rec.Code, rec.Body)
		}
		if len(sr.secretIDs()) != 0 || sr.state(id) != approvals.StateApproved {
			t.Fatalf("stored %v, state %s", sr.secretIDs(), sr.state(id))
		}
	})
	t.Run("an approval that ran out is refused", func(t *testing.T) {
		sr, b, id := approved(t)
		sr.advance(20 * time.Minute)
		rec := commit(b, id)
		if rec.Code != http.StatusGone || !strings.Contains(rec.Body.String(), approvals.CodeExpired) {
			t.Fatalf("commit after expiry: %d %s", rec.Code, rec.Body)
		}
		if len(sr.secretIDs()) != 0 {
			t.Fatal("stored")
		}
	})
	t.Run("the vault refusing the write is recorded as failed", func(t *testing.T) {
		sr, b, id := approved(t)
		if _, err := sr.vault.Import(context.Background(), vault.Meta{ID: "gh-app-key", Kind: "k"}, []byte("someone-else")); err != nil {
			t.Fatal(err)
		}
		rec := commit(b, id)
		if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "A secret with this id exists now") {
			t.Fatalf("commit: %d %s", rec.Code, rec.Body)
		}
		mustNotHave(t, "failed write", rec.Body.String(), canaryA, "someone-else")
		results := sr.events("op.result")
		if len(results) != 1 || attrString(results[0], "factory.outcome") != "failed" || attrString(results[0], "factory.cause_code") != "VAULT_WRITE_FAILED" {
			t.Fatalf("op.result %+v", results)
		}
		if got := sr.secretValue("gh-app-key"); got != "someone-else" {
			t.Fatalf("the existing secret was overwritten: %q", got)
		}
	})
}

// An approval stores the value in the same request. When that store cannot happen the operator is told in the answer to
// the approval (the page script prints it), and what is left is a button to try again, not a silent state.
func TestApprovalSaysWhenItCouldNotStoreTheSecret(t *testing.T) {
	t.Run("the value was lost in a restart", func(t *testing.T) {
		sr := newScrRig(t)
		b, auth := sr.signedIn()
		id := sr.requestSecret(b, importForm("gh-app-key", canaryA))
		sr.con.scr.pend = newPendingSecrets(sr.con.now) // chapd restarted
		bg := sr.begin(b, id)
		rec := sr.finish(b, id, bg, auth.get(bg.options, pcOrigin.URL, opts{signCount: &zero}))
		if rec.Code != 200 {
			t.Fatalf("approve: %d %s", rec.Code, rec.Body)
		}
		mustHave(t, "finish", rec.Body.String(), `"stored":false`, "no longer held")
		if sr.state(id) != approvals.StateApproved || len(sr.secretIDs()) != 0 {
			t.Fatalf("state %s, stored %v", sr.state(id), sr.secretIDs())
		}
	})
	t.Run("the vault refused the write", func(t *testing.T) {
		sr := newScrRig(t)
		b, auth := sr.signedIn()
		id := sr.requestSecret(b, importForm("gh-app-key", canaryA))
		if _, err := sr.vault.Import(context.Background(), vault.Meta{ID: "gh-app-key", Kind: "k"}, []byte("someone-else")); err != nil {
			t.Fatal(err)
		}
		bg := sr.begin(b, id)
		rec := sr.finish(b, id, bg, auth.get(bg.options, pcOrigin.URL, opts{signCount: &zero}))
		mustHave(t, "finish", rec.Body.String(), `"stored":false`, "The vault did not store the secret", "A secret with this id exists now")
		mustNotHave(t, "finish", rec.Body.String(), canaryA, "someone-else")
	})
	// A store that fails after the approval, for a reason that passes (the database refuses the consume), leaves the
	// approval unused. The answer must name the place that has the Try again button: /secrets, not the page the
	// approval was given on.
	failConsume := func(t *testing.T, sr *scrRig) {
		t.Helper()
		if _, err := sr.db.SQL().Exec(`CREATE TRIGGER fail_consume BEFORE UPDATE OF state ON approvals
			WHEN NEW.state = 'consumed' BEGIN SELECT RAISE(ABORT, 'test: the database refused'); END`); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("the store failed and the value is held again", func(t *testing.T) {
		sr := newScrRig(t)
		b, auth := sr.signedIn()
		id := sr.requestSecret(b, importForm("gh-app-key", canaryA))
		failConsume(t, sr)
		bg := sr.begin(b, id)
		rec := sr.finish(b, id, bg, auth.get(bg.options, pcOrigin.URL, opts{signCount: &zero}))
		if rec.Code != 200 {
			t.Fatalf("approve: %d %s", rec.Code, rec.Body)
		}
		mustHave(t, "finish", rec.Body.String(), `"stored":false`, "chapd could not use the approval", "The value is still held: open Secrets and press Try again.")
		mustNotHave(t, "finish", rec.Body.String(), canaryA, "reload the page", "The value is gone")
		if sr.state(id) != approvals.StateApproved || len(sr.secretIDs()) != 0 || !sr.con.scr.pend.has(id) {
			t.Fatalf("state %s, stored %v, held %v", sr.state(id), sr.secretIDs(), sr.con.scr.pend.has(id))
		}
		// The Secrets page has the button the message names, and it finishes the write with the same approval.
		mustHave(t, "secrets page", get(t, b, "/secrets"), "Try again: store gh-app-key")
		if _, err := sr.db.SQL().Exec(`DROP TRIGGER fail_consume`); err != nil {
			t.Fatal(err)
		}
		if rec := hxPost(b, "/secrets/"+id+"/commit", url.Values{}); rec.Code != 200 || sr.secretValue("gh-app-key") != canaryA {
			t.Fatalf("try again: %d %s", rec.Code, rec.Body)
		}
	})
	t.Run("the store failed and the value is lost", func(t *testing.T) {
		sr := newScrRig(t)
		b, auth := sr.signedIn()
		id := sr.requestSecret(b, importForm("gh-app-key", canaryA))
		// The held set already holds a full set of other values: after the store takes this card's value out, putting it
		// back finds the set full, so the value cannot be kept.
		for i := range maxHeldSecrets {
			sr.con.scr.pend.m[fmt.Sprintf("filler-%d", i)] = &heldSecret{value: []byte("filler"), until: sr.con.now().Add(time.Hour)}
		}
		failConsume(t, sr)
		bg := sr.begin(b, id)
		rec := sr.finish(b, id, bg, auth.get(bg.options, pcOrigin.URL, opts{signCount: &zero}))
		if rec.Code != 200 {
			t.Fatalf("approve: %d %s", rec.Code, rec.Body)
		}
		mustHave(t, "finish", rec.Body.String(), `"stored":false`, "chapd could not use the approval", "The value is gone", "submit the secret again")
		mustNotHave(t, "finish", rec.Body.String(), canaryA, "open Secrets and press Try again")
		if sr.state(id) != approvals.StateApproved || len(sr.secretIDs()) != 0 || sr.con.scr.pend.has(id) {
			t.Fatalf("state %s, stored %v, held %v", sr.state(id), sr.secretIDs(), sr.con.scr.pend.has(id))
		}
		page := get(t, b, "/secrets")
		mustHave(t, "lost value", page, "no longer holds the value")
		mustNotHave(t, "lost value", page, "Try again")
	})
	t.Run("a card that is not a console secret write gets no secret field", func(t *testing.T) {
		sr := newScrRig(t)
		b, auth := sr.signedIn()
		card := sr.request(nil)
		bg := sr.begin(b, card.ID)
		rec := sr.finish(b, card.ID, bg, auth.get(bg.options, pcOrigin.URL, opts{signCount: &zero}))
		if rec.Code != 200 || strings.Contains(rec.Body.String(), `"secret"`) {
			t.Fatalf("approve: %d %s", rec.Code, rec.Body)
		}
	})
}

func TestSecretRequestsAreCapped(t *testing.T) {
	sr := newScrRig(t)
	b, _ := sr.signedIn()
	sr.requestSecret(b, importForm("one", "value-one-1"))
	sr.requestSecret(b, importForm("two", "value-two-2"))
	// The engine allows two cards per requester; a third is refused and its value is not kept.
	rec := hxPost(b, "/secrets/request", importForm("three", "value-three-3"))
	if rec.Code < 400 || !strings.Contains(rec.Body.String(), approvals.CodePolicyRefused) || !strings.Contains(rec.Body.String(), "already has 2 approvals waiting") {
		t.Fatalf("third request: %d %s", rec.Code, rec.Body)
	}
	if n := len(sr.con.scr.pend.m); n != 2 {
		t.Fatalf("%d values held, want 2", n)
	}
}

func TestSecretsScreenWithoutAVault(t *testing.T) {
	sr := newScrRigOpts(t, false)
	b, _ := sr.signedIn()
	page := get(t, b, "/secrets")
	mustHave(t, "no vault", page, "running without a vault")
	mustNotHave(t, "no vault", page, "<form", "<textarea")
	rec := hxPost(b, "/secrets/request", importForm("x", "some-value-x"))
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "No vault") {
		t.Fatalf("request without a vault: %d %s", rec.Code, rec.Body)
	}
}

func TestUseScreensChecksItsInputs(t *testing.T) {
	r := newRig(t)
	if err := r.con.UseScreens(ScreensConfig{}); err == nil {
		t.Error("UseScreens without UseApprovals")
	}
	sr := newScrRig(t)
	cfg := sr.con.scr.cfg
	cfg.Policy = nil
	if err := sr.con.UseScreens(cfg); err == nil {
		t.Error("UseScreens without a policy")
	}
	cfg = sr.con.scr.cfg
	cfg.Record = nil
	if err := sr.con.UseScreens(cfg); err == nil {
		t.Error("UseScreens with a vault and no way to record")
	}
}
