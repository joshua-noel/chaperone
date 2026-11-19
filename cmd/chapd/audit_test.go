package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/console"
)

// A burst of refused ceremonies is one ledger event per second, and the next
// one reports how many were left out (spec v0.1.1, console.refused).
func TestRefusalGateCoalescesABurst(t *testing.T) {
	var g refusalGate
	t0 := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	if n, ok := g.allow(t0); !ok || n != 0 {
		t.Fatalf("first refusal: ledgered=%v suppressed=%d", ok, n)
	}
	for i := 1; i <= 3; i++ {
		if _, ok := g.allow(t0.Add(time.Duration(i) * 100 * time.Millisecond)); ok {
			t.Fatalf("refusal %d inside the second was ledgered", i)
		}
	}
	if n, ok := g.allow(t0.Add(1500 * time.Millisecond)); !ok || n != 3 {
		t.Fatalf("after the burst: ledgered=%v suppressed=%d, want true and 3", ok, n)
	}
	if n, ok := g.allow(t0.Add(3 * time.Second)); !ok || n != 0 {
		t.Fatalf("a quiet refusal: ledgered=%v suppressed=%d", ok, n)
	}
}

// The ledger says which kind of authenticator signed in and which one the first approver enrolled with (ADR-004
// amendment 15). The spec closes the attributes of console.login, so the facts travel in the body, and the real
// ledger's schema check accepts them.
func TestLedgerNamesTheAuthenticatorKind(t *testing.T) {
	e := newE2E(t)
	ctx := context.Background()
	var gate refusalGate
	key := console.Event{Attachment: "cross-platform", Transports: []string{"usb"}}
	login := key
	login.Name, login.ApproverID, login.ApproverSpecID, login.RPID, login.UserVerified = console.EventLogin, 1, "operator", "localhost", true
	e.app.audit(ctx, login, &gate)
	enrol := key
	enrol.Name, enrol.ApproverID, enrol.Bootstrap, enrol.Origin, enrol.UserVerified = console.EventEnrolled, 1, true, "http://localhost:55398", true
	enrol.Attachment, enrol.Transports, enrol.BackupEligible = "", nil, true // a browser that did not say, on a passkey that syncs
	e.app.audit(ctx, enrol, &gate)

	read := func(where string) string {
		var ev string
		if err := e.app.DB.SQL().QueryRow(`SELECT event FROM ledger_events WHERE ` + where).Scan(&ev); err != nil {
			t.Fatalf("%s: %v", where, err)
		}
		return ev
	}
	if ev := read(`event_name = 'console.login'`); !strings.Contains(ev, "authenticator=cross-platform; transports=usb; backup_eligible=false") {
		t.Errorf("console.login: %s", ev)
	}
	if ev := read(`event_name = 'op.request' AND event LIKE '%approvers.enroll%'`); !strings.Contains(ev, "authenticator=unreported; transports=none; backup_eligible=true") {
		t.Errorf("approvers.enroll: %s", ev)
	}
}
