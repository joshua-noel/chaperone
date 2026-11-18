package main

import (
	"testing"
	"time"
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
