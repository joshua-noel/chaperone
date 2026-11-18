package ops

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// anchorBackend is a LedgerBackend that can verify anchors and remembers what
// it was asked.
type anchorBackend struct {
	fakeLedgerBackend
	got   AnchorVerifyRequest
	calls int
	err   error
}

func (a *anchorBackend) VerifyAnchors(_ context.Context, req AnchorVerifyRequest) (any, error) {
	a.calls++
	a.got = req
	if a.err != nil {
		return nil, a.err
	}
	return map[string]any{"ok": true, "anchors_checked": len(req.Records)}, nil
}

func TestLedgerVerifyAnchorRoute(t *testing.T) {
	be := &anchorBackend{}
	g := mintRig(t, minted, be)
	st, body, _ := g.call("POST", "/v0/ledger/verify", orchTok, map[string]any{
		"against_export": true, "anchor": true,
		"anchor_records": []string{"line one", "line two"}, "anchor_keys": []string{"key"},
	})
	if st != 200 || be.calls != 1 {
		t.Fatalf("status %d, calls %d, body %v", st, be.calls, body)
	}
	if !be.got.AgainstExport || len(be.got.Records) != 2 || be.got.Records[1] != "line two" || len(be.got.Keys) != 1 || be.got.Keys[0] != "key" {
		t.Fatalf("backend got %+v", be.got)
	}

	// A plain verify does not touch the anchor path.
	be.calls = 0
	if st, _, _ := g.call("POST", "/v0/ledger/verify", orchTok, map[string]any{"against_export": true}); st != 200 || be.calls != 0 {
		t.Fatalf("plain verify: status %d, anchor calls %d", st, be.calls)
	}
}

func TestLedgerVerifyAnchorRefusals(t *testing.T) {
	be := &anchorBackend{}
	g := mintRig(t, minted, be)

	// Records without anchor: true.
	st, body, _ := g.call("POST", "/v0/ledger/verify", orchTok, map[string]any{"anchor_records": []string{"x"}})
	if st == 200 {
		t.Fatalf("records without anchor were accepted: %v", body)
	}
	mustDenial(t, body, CodeParamsInvalid)

	// Too many records.
	many := make([]string, MaxAnchorRecords+1)
	st, body, _ = g.call("POST", "/v0/ledger/verify", orchTok, map[string]any{"anchor": true, "anchor_records": many})
	if st == 200 || be.calls != 0 {
		t.Fatalf("too many records: status %d, calls %d", st, be.calls)
	}
	mustDenial(t, body, CodeParamsInvalid)

	// A malformed record is the caller's error.
	be.err = &AnchorInputError{Why: "anchor record 1 is not strict JSON"}
	st, body, _ = g.call("POST", "/v0/ledger/verify", orchTok, map[string]any{"anchor": true, "anchor_records": []string{"x"}})
	if st == 200 {
		t.Fatalf("a malformed record was accepted: %v", body)
	}
	mustDenial(t, body, CodeParamsInvalid)

	// A backend failure is "unavailable", not a verdict.
	be.err = context.DeadlineExceeded
	st, body, _ = g.call("POST", "/v0/ledger/verify", orchTok, map[string]any{"anchor": true})
	if st != 503 {
		t.Fatalf("backend failure answered %d: %v", st, body)
	}

	// A run token cannot ask.
	if st, _, _ := g.call("POST", "/v0/ledger/verify", runTok, map[string]any{"anchor": true}); st == 200 {
		t.Fatal("a run token verified anchors")
	}
}

func TestLedgerVerifyAnchorNeedsABackendThatHasAnchors(t *testing.T) {
	g := mintRig(t, minted, fakeLedgerBackend{})
	st, body, _ := g.call("POST", "/v0/ledger/verify", orchTok, map[string]any{"anchor": true})
	if st != 503 {
		t.Fatalf("status %d: %v", st, body)
	}
	b, _ := json.Marshal(body)
	if !strings.Contains(string(b), "anchors are not turned on") {
		t.Fatalf("body %s", b)
	}
}
