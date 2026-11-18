package main

import (
	"context"
	"testing"

	"github.com/joshua-noel/chaperone/internal/console"
)

// A refused console ceremony (an origin_mismatch, say) is audited by the worker goroutine. Production leaves
// Config.now nil; calling it crashed chapd with a nil pointer. This runs the audit on a Build with no clock, as chapd
// runs, and reads the ledger back.
func TestRefusedCeremonyWithNoConfiguredClockIsLedgered(t *testing.T) {
	e := newE2E(t)
	if e.app.cfg.now != nil {
		t.Fatal("this test needs an App with no configured clock, as in production")
	}
	var gate refusalGate
	e.app.audit(context.Background(), console.Event{
		Name: console.EventRefused, Ceremony: "login", Reason: "origin_mismatch", Origin: "http://evil.example",
	}, &gate)
	var n int
	if err := e.app.DB.SQL().QueryRow(`SELECT count(*) FROM ledger_events WHERE event_name = 'console.refused'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("console.refused events: %d (%v), want 1", n, err)
	}
}
