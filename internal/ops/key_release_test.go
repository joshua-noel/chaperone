package ops

import (
	"context"
	"net/http"
	"testing"

	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
)

// A key is checked once, when its token is read. The release of an op checks it again, inside the transaction
// that releases the op, so a key that is gone by then does not run the op (ADR-008). These two tests stand for the
// two ways that happens: a call that was in flight when the key was revoked, and an approved op whose key ran out
// while the card waited.

// A call that was verified before the revoke and submitted after it does not reach GitHub.
func TestCallInFlightWhenItsKeyIsRevokedDoesNotRun(t *testing.T) {
	g := newReadRig(t)
	g.ver.keys[keyTok] = keyCaller(PRReadOps, readRepo)
	n, _ := g.openPR("agent/a", ghtest.PROptions{})

	// Control: while the key lives, the call runs and reaches GitHub.
	st, body, _ := g.ask(keyTok, "pr.view", n, map[string]any{})
	if st != http.StatusOK || str(body, "outcome") != "succeeded" {
		t.Fatalf("control: %d %v", st, body)
	}
	before := g.s.Count("GET", "/pulls/")
	if before == 0 {
		t.Fatal("the control call did not reach GitHub")
	}

	// The key is revoked after the token was read and before the op is released.
	g.keyLive = func(id string) error {
		return &Refusal{Code: CodeTokenRevoked, Why: "key " + id + " was revoked, so the op it asked for does not run"}
	}
	st, body, _ = g.ask(keyTok, "pr.view", n, map[string]any{})
	if str(body, "outcome") == "succeeded" || str(body, "state") != "refused" {
		t.Fatalf("the call of a revoked key was not refused: %d %v", st, body)
	}
	if after := g.s.Count("GET", "/pulls/"); after != before {
		t.Errorf("a revoked key's call reached GitHub: %d -> %d", before, after)
	}
	var state, cause string
	if err := g.db.SQL().QueryRow(`SELECT state, COALESCE(cause_code,'') FROM ops WHERE requester_key = ? ORDER BY requested_at DESC, rowid DESC LIMIT 1`, "key:k-0123456789abcdef").Scan(&state, &cause); err != nil {
		t.Fatal(err)
	}
	if state != "refused" || cause != CodeTokenRevoked {
		t.Errorf("op after the revoke: state %s cause %s", state, cause)
	}
}

// An op that the owner approved is refused at release when its key has run out, and the approval is not spent.
func TestApprovedOpOfAnExpiredKeyDoesNotRun(t *testing.T) {
	g, f, ap := deployRig(t)
	k := keyCaller([]string{"deploy", "health"})
	k.Project = "acme-shop"
	g.ver.keys[keyTok] = k

	st, op, _ := g.call("POST", "/v0/approvals", keyTok, approvalReq("deploy", f.sha))
	if st != http.StatusAccepted || op["state"] != "pending_approval" {
		t.Fatalf("card: %d %v", st, op)
	}
	aid := str(op["approval"].(map[string]any), "id")

	// The key ran out while the card waited; the operator signs it anyway.
	g.keyLive = func(id string) error {
		return &Refusal{Code: CodeTokenExpired, Why: "key " + id + " has expired, so the op it asked for does not run"}
	}
	decide(t, g, ap, str(op, "id"), aid)
	if err := g.svc.Release(context.Background(), str(op, "id")); err != nil {
		t.Fatal(err)
	}
	var state, cause string
	if err := g.db.SQL().QueryRow(`SELECT state, COALESCE(cause_code,'') FROM ops WHERE id = ?`, str(op, "id")).Scan(&state, &cause); err != nil {
		t.Fatal(err)
	}
	if state != "refused" || cause != CodeTokenExpired {
		t.Fatalf("approved op of an expired key: state %s cause %s", state, cause)
	}
	if f.host.runs() != 0 {
		t.Error("the deploy of an expired key reached the host")
	}
	if len(ap.consumed) != 0 {
		t.Errorf("the refused release spent the approval: %v", ap.consumed)
	}
}

// An op of a key is never released without a key store to ask: it fails closed.
func TestOpOfAKeyIsNotReleasedWithoutAKeyStore(t *testing.T) {
	g := newReadRig(t)
	g.svc.keyLive = nil
	g.ver.keys[keyTok] = keyCaller(PRReadOps, readRepo)
	n, _ := g.openPR("agent/a", ghtest.PROptions{})
	before := g.s.Count("GET", "/pulls/")
	if st, body, _ := g.ask(keyTok, "pr.view", n, map[string]any{}); st == http.StatusOK {
		t.Fatalf("a key's call ran with no key store: %v", body)
	}
	if after := g.s.Count("GET", "/pulls/"); after != before {
		t.Errorf("reached GitHub: %d -> %d", before, after)
	}
}
