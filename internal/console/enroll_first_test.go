package console

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// firstTTL is the lifetime `chapd quickstart` gives the first address (cmd/chapd).
const firstTTL = 15 * time.Minute

func beginRefusedOrNot(t *testing.T, r *rig, tok string) int {
	t.Helper()
	req, _ := json.Marshal(map[string]string{"token": tok, "name": "x", "label": "y"})
	code, _ := r.browser(pcOrigin).post("/enroll/begin", req, "")
	return code
}

// The first address works at its last second and not one second later.
func TestFirstEnrollmentIsShortLived(t *testing.T) {
	ctx := context.Background()

	r := newRig(t)
	tok, err := IssueFirstEnrollment(ctx, r.db, firstTTL, r.now)
	if err != nil || tok == "" {
		t.Fatal(tok, err)
	}
	r.advance(firstTTL)
	if code := beginRefusedOrNot(t, r, tok); code != 200 {
		t.Fatalf("at the last second: %d, want 200", code)
	}

	r2 := newRig(t)
	tok2, err := IssueFirstEnrollment(ctx, r2.db, firstTTL, r2.now)
	if err != nil || tok2 == "" {
		t.Fatal(tok2, err)
	}
	r2.advance(firstTTL + 2*time.Second)
	code := beginRefusedOrNot(t, r2, tok2)
	if code != 403 {
		t.Fatalf("after the lifetime: %d, want 403", code)
	}
	if e := r2.last(); e.Name != EventRefused || e.Reason != ReasonEnrolment {
		t.Fatalf("last event %+v", e)
	}
}

// A first address is offered only while there is no approver, and it is spent by the first passkey.
func TestFirstEnrollmentOnlyWithoutApprover(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	tok, err := IssueFirstEnrollment(ctx, r.db, firstTTL, r.now)
	if err != nil || tok == "" {
		t.Fatal(tok, err)
	}
	b := r.browser(pcOrigin)
	if _, code, out := b.enrol(r, tok, opts{}); code != 200 {
		t.Fatal(code, out)
	}
	if n := countRows(t, r, "approvers"); n != 1 {
		t.Fatalf("approvers = %d", n)
	}
	before := countRows(t, r, "console_enrollments")
	again, err := IssueFirstEnrollment(ctx, r.db, firstTTL, r.now)
	if err != nil || again != "" {
		t.Fatalf("an address was offered with an approver present: %q %v", again, err)
	}
	if after := countRows(t, r, "console_enrollments"); after != before {
		t.Fatalf("a row was written for a refused issue (%d -> %d)", before, after)
	}
	// The spent address does nothing more.
	if code := beginRefusedOrNot(t, r, tok); code != 403 {
		t.Fatalf("a used address answered %d", code)
	}
}

// A restart issues a new address and the one printed before it stops working.
func TestFirstEnrollmentSpendsEarlierAddresses(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	old, err := IssueFirstEnrollment(ctx, r.db, firstTTL, r.now)
	if err != nil || old == "" {
		t.Fatal(old, err)
	}
	fresh, err := IssueFirstEnrollment(ctx, r.db, firstTTL, r.now)
	if err != nil || fresh == "" || fresh == old {
		t.Fatal(fresh, err)
	}
	if code := beginRefusedOrNot(t, r, old); code != 403 {
		t.Fatalf("the earlier address answered %d, want 403", code)
	}
	if code := beginRefusedOrNot(t, r, fresh); code != 200 {
		t.Fatalf("the new address answered %d, want 200", code)
	}
	// Only the hash is stored.
	var n int
	if err := r.db.SQL().QueryRow(`SELECT count(*) FROM console_enrollments WHERE hex(token_sha256) = upper(?)`, fresh).Scan(&n); err != nil || n != 0 {
		t.Fatal(n, err)
	}
}

// The token is in the address fragment: a browser never sends it to the server, so it is not in any request line,
// the server's logs or a Referer. The enrolment page itself carries no token.
func TestEnrollPageNeverHoldsTheToken(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	tok, err := IssueFirstEnrollment(ctx, r.db, firstTTL, r.now)
	if err != nil {
		t.Fatal(err)
	}
	rec := r.browser(pcOrigin).do("GET", "/enroll", nil, nil)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), tok) {
		t.Fatalf("enrol page: %d, holds the token: %v", rec.Code, strings.Contains(rec.Body.String(), tok))
	}
}
