package keys

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/store"
)

// K1: the keys an orchestrator owns are revoked with it (by chapd, not a human stop, ledgered), all of them or only
// those in the given projects, and the ones that are already revoked are left alone.
func TestRevokeOwnedRevokesTheKeysOfAnOwnerAndNothingElse(t *testing.T) {
	g := newRig(t)
	g.who = "operator"
	ctx := context.Background()
	_, a := g.issueAndClaim(nil)                                                             // main, acme-shop, agent scout
	_, b := g.issueAndClaim(func(x *Grant) { x.Holder = "bot" })                             // main, acme-shop
	_, c := g.issueAndClaim(func(x *Grant) { x.Holder, x.HolderKind = "bob", HolderPerson }) // main, person holder
	other, err := g.s.Issue(ctx, g.grant(func(x *Grant) { x.Owner, x.Claimant, x.Holder = "other", "orchestrator:other", "bot2" }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.s.Revoke(ctx, c.ID, "orchestrator:main", false); err != nil {
		t.Fatal(err)
	}
	before := len(g.led.named("op.request"))

	// A project the keys are not in: nothing happens.
	if err := g.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		return g.s.RevokeOwnedTx(ctx, tx, "main", []string{"elsewhere"}, "dropped")
	}); err != nil {
		t.Fatal(err)
	}
	if k, _ := g.s.Get(ctx, a.ID); k.State != "live" {
		t.Fatalf("a key in another project was revoked: %+v", k)
	}
	// The project the keys are in: both live ones, with no stop and an event each, as chapd.
	if err := g.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		return g.s.RevokeOwnedTx(ctx, tx, "main", []string{"acme-shop"}, "its orchestrator main no longer covers the project")
	}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{a.ID, b.ID} {
		k, _ := g.s.Get(ctx, id)
		if k.State != "revoked" || k.StoppedByHuman || k.RevokedBy != "chapd" || !strings.Contains(k.RevokeReason, "no longer covers") {
			t.Errorf("%s: %+v", id, k)
		}
	}
	if stopped, _ := g.s.AgentStopped(ctx, "main", "scout"); stopped {
		t.Error("revoking with the owner stopped the agent")
	}
	revokes := 0
	for _, e := range g.led.named("op.request")[before:] {
		if e.Attributes["factory.op"] == "keys.revoke" && e.Attributes["factory.orchestrator.id"] == "chapd" {
			revokes++
		}
	}
	if revokes != 2 {
		t.Errorf("%d keys.revoke events by chapd, want 2 (the already revoked key is left alone)", revokes)
	}
	// Another owner's key is untouched; revoking all (nil) takes the rest of this owner's.
	if err := g.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		return g.s.RevokeOwnedTx(ctx, tx, "main", nil, "x")
	}); err != nil {
		t.Fatal(err)
	}
	if k, _ := g.s.Get(ctx, other.ID); k.State == "revoked" {
		t.Errorf("another owner's key was revoked: %+v", k)
	}
}

// K2: cancelling an enrolment is in the ledger and names the approver.
func TestCancellingAnEnrolmentIsLedgeredWithTheApprover(t *testing.T) {
	g := newRig(t)
	ctx := context.Background()
	st, err := g.s.StartEnrolment(ctx, "acme-shop", "scout")
	if err != nil {
		t.Fatal(err)
	}
	if err := NewDecider(g.s, nil).CancelEnrol(ctx, "operator", st.ID); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range g.led.named("op.request") {
		if e.Attributes["factory.op"] == "keys.enrol.cancel" {
			found = true
			if e.Attributes["factory.orchestrator.id"] != "person.operator" || !strings.Contains(e.Body, "cancelled by person:operator") || !strings.Contains(e.Body, st.ID) {
				t.Errorf("the cancel event: %v %q", e.Attributes, e.Body)
			}
		}
	}
	if !found {
		t.Error("the cancel is not in the ledger")
	}
	// A cancel that did nothing writes nothing.
	n := len(g.led.named("op.request"))
	if err := NewDecider(g.s, nil).CancelEnrol(ctx, "operator", st.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("a second cancel: %v", err)
	}
	if len(g.led.named("op.request")) != n {
		t.Error("a refused cancel wrote to the ledger")
	}
}

// K3: the note for a refused enrolment start is limited per label, so one label's refusals do not hide another's,
// with a global cap so that trying many labels cannot flood the ledger.
func TestRefusedStartNotesAreLimitedPerLabelWithAGlobalCap(t *testing.T) {
	g := newRig(t)
	ctx := context.Background()
	refusals := func(label string) int {
		n := 0
		for _, e := range g.led.named("op.request") {
			if e.Attributes["factory.op"] == "keys.enrol" && strings.Contains(e.Body, " for "+label+":") {
				n++
			}
		}
		return n
	}
	// An attacker holds the real agent's label and keeps asking.
	if _, err := g.s.StartEnrolment(ctx, "acme-shop", "scout"); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		_, _ = g.s.StartEnrolment(ctx, "acme-shop", "scout")
	}
	if refusals("scout") != 1 {
		t.Fatalf("scout: %d notes, want 1", refusals("scout"))
	}
	// A refusal for another label in the same minute is written down all the same.
	if _, err := g.s.StartEnrolment(ctx, "acme-shop", "other"); err != nil {
		t.Fatal(err)
	}
	_, _ = g.s.StartEnrolment(ctx, "acme-shop", "other")
	if refusals("other") != 1 {
		t.Errorf("other: %d notes, want 1: the first label hid it", refusals("other"))
	}
	// Many labels cannot flood: at most refusedStartMax in a minute in all.
	g.now = g.now.Add(2 * time.Minute)
	for i := range 30 {
		label := "x" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		_, _ = g.s.StartEnrolment(ctx, "acme-shop", label)
		_, _ = g.s.StartEnrolment(ctx, "acme-shop", label)
	}
	total := 0
	for _, e := range g.led.named("op.request") {
		if e.Attributes["factory.op"] == "keys.enrol" {
			total++
		}
	}
	// The cap limits the refusals of labels that hold no slot; a clash on a label that holds one (at most
	// MaxPendingEnrolments of them) is outside it.
	if total > 2+refusedStartMax+MaxPendingEnrolments {
		t.Errorf("%d refusal notes: the global cap of %d a minute did not hold", total, refusedStartMax)
	}
}

// H1: a key whose project the new token does not cover, or that holds an op the new token's ops do not allow, is
// revoked with the re-issue (by chapd, no stop, the reason says what was lost); a key still inside the new scope stays.
func TestRevokeOwnedBeyondRevokesWhatTheNewScopeNoLongerReaches(t *testing.T) {
	g := newRig(t)
	ctx := context.Background()
	_, both := g.issueAndClaim(nil)                                                                             // pr.diff, pr.view
	_, diffOnly := g.issueAndClaim(func(x *Grant) { x.Holder, x.Ops = "bot", []string{"pr.diff"} })             // pr.diff
	_, viewOnly := g.issueAndClaim(func(x *Grant) { x.Holder, x.Ops = "bot3", []string{"pr.view"} })            // pr.view
	_, health := g.issueAndClaim(func(x *Grant) { x.Holder, x.Ops, x.Units = "bot4", []string{"health"}, nil }) // health
	run := func(projects, patterns []string) {
		t.Helper()
		if err := g.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
			return g.s.RevokeOwnedBeyondTx(ctx, tx, "main", projects, patterns)
		}); err != nil {
			t.Fatal(err)
		}
	}
	state := func(id string) string { k, _ := g.s.Get(ctx, id); return k.State }
	// Everything is still inside the scope: nothing happens (a pattern counts).
	run([]string{"acme-shop"}, []string{"pr.*", "health", "keys.issue"})
	for _, id := range []string{both.ID, diffOnly.ID, viewOnly.ID, health.ID} {
		if state(id) != "live" {
			t.Fatalf("%s was revoked by a re-issue that kept its project and ops", id)
		}
	}
	// pr.view is dropped: the keys that hold it go, the others stay.
	run([]string{"acme-shop"}, []string{"pr.diff", "health"})
	if state(both.ID) != "revoked" || state(viewOnly.ID) != "revoked" || state(diffOnly.ID) != "live" || state(health.ID) != "live" {
		t.Fatalf("after dropping pr.view: both=%s viewOnly=%s diffOnly=%s health=%s", state(both.ID), state(viewOnly.ID), state(diffOnly.ID), state(health.ID))
	}
	k, _ := g.s.Get(ctx, both.ID)
	if k.StoppedByHuman || k.RevokedBy != "chapd" || !strings.Contains(k.RevokeReason, "no longer holds pr.view") {
		t.Errorf("the revoked key: %+v", k)
	}
	if stopped, _ := g.s.AgentStopped(ctx, "main", "scout"); stopped {
		t.Error("the revoke stopped an agent")
	}
	// The project is dropped: what is left goes.
	run([]string{"other"}, []string{"pr.diff", "health"})
	if state(diffOnly.ID) != "revoked" || state(health.ID) != "revoked" {
		t.Errorf("after dropping the project: %s %s", state(diffOnly.ID), state(health.ID))
	}
}

// H2: an attacker with many labels uses up the global cap of refusal notes, but a clash on the label that holds a slot
// (the real agent's, squatted) is still written down, once a minute for that label.
func TestAClashOnALabelThatHoldsASlotIsNotedWhateverTheGlobalCapSays(t *testing.T) {
	g := newRig(t)
	ctx := context.Background()
	notes := func(label string) int {
		n := 0
		for _, e := range g.led.named("op.request") {
			if e.Attributes["factory.op"] == "keys.enrol" && strings.Contains(e.Body, " for "+label+":") {
				n++
			}
		}
		return n
	}
	// The squatter holds scout and four more slots; then a flood of refusals for other labels uses the cap up.
	for _, l := range []string{"scout", "s1", "s2", "s3", "s4"} {
		if _, err := g.s.StartEnrolment(ctx, "acme-shop", l); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 40 {
		_, _ = g.s.StartEnrolment(ctx, "acme-shop", "flood"+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	capped := 0
	for _, e := range g.led.named("op.request") {
		if e.Attributes["factory.op"] == "keys.enrol" {
			capped++
		}
	}
	if capped != refusedStartMax {
		t.Fatalf("the flood wrote %d notes, want the cap of %d", capped, refusedStartMax)
	}
	// The real agent starts its enrolment: its label is held, so it is a clash, and it is written down all the same.
	if _, err := g.s.StartEnrolment(ctx, "acme-shop", "scout"); err == nil {
		t.Fatal("expected a clash")
	}
	if notes("scout") != 1 {
		t.Errorf("the clash on scout was not written down: %d", notes("scout"))
	}
	// Once a minute for that label.
	_, _ = g.s.StartEnrolment(ctx, "acme-shop", "scout")
	if notes("scout") != 1 {
		t.Errorf("the clash was written twice in a minute: %d", notes("scout"))
	}
}
