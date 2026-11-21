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
	if total > 2+refusedStartMax {
		t.Errorf("%d refusal notes: the global cap of %d a minute did not hold", total, refusedStartMax)
	}
}
