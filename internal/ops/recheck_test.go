package ops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/redact"
)

// Review item 1: a waiting merge card is looked at again, read only, before the operator spends a Hello on it.
func TestRecheckFlagsAWaitingMergeThatWouldBeRefused(t *testing.T) {
	ap := &fakeApprovals{}
	g := newRig(t, rigOpts{enable: []string{"pr.merge", "deploy"}, approvals: ap})
	// A merge that needs a card: the adapter's dry run asks for an approval.
	g.ad.check = func(*Request) (CheckResult, error) {
		return CheckResult{NeedsApproval: true, ApprovalWhy: "tier medium"}, nil
	}
	st, op, _ := g.call("POST", "/v0/approvals", hiTok, approvalReq("pr.merge", sha1))
	if st != 202 || op["state"] != "pending_approval" {
		t.Fatalf("no waiting merge card: %d %v", st, op)
	}
	id := str(op, "id")
	ctx := context.Background()
	rows := func() int {
		var n int
		if err := g.db.SQL().QueryRow(`SELECT count(*) FROM fake_ledger`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := rows()

	// Still fine: the adapter's dry run passes (it asks for an approval, which this card already is).
	g.ad.check = func(*Request) (CheckResult, error) { return CheckResult{NeedsApproval: true}, nil }
	if r, err := g.svc.Recheck(ctx, id); err != nil || r.Stale {
		t.Fatalf("a card that would still run: %+v %v", r, err)
	}

	// Stale: another merge moved the base.
	g.ad.check = func(*Request) (CheckResult, error) {
		return CheckResult{}, &Refusal{Code: CodePolicyRefused, Why: "CI_STALE: base_current: head is 1 commit(s) behind main; run pr.update"}
	}
	r, err := g.svc.Recheck(ctx, id)
	if err != nil || !r.Stale || !strings.Contains(r.Why, "behind the base") || !strings.Contains(r.Why, "1 commit(s) behind main") {
		t.Fatalf("a stale card: %+v %v", r, err)
	}
	// Red CI.
	g.ad.check = func(*Request) (CheckResult, error) {
		return CheckResult{}, &Refusal{Code: CodePolicyRefused, Why: "CI_RED: verify: latest verify run concluded failure, not success"}
	}
	if r, _ := g.svc.Recheck(ctx, id); !r.Stale || !strings.Contains(r.Why, "failing") {
		t.Fatalf("red CI: %+v", r)
	}
	// GitHub unreachable: no verdict, an error, never a wrong flag.
	g.ad.check = func(*Request) (CheckResult, error) { return CheckResult{}, errors.New("github: timeout") }
	if r, err := g.svc.Recheck(ctx, id); err == nil || r.Stale {
		t.Fatalf("an unjudged card: %+v %v", r, err)
	}

	if rows() != before {
		t.Fatalf("Recheck wrote %d ledger rows: it must write nothing", rows()-before)
	}
	var state string
	if err := g.db.SQL().QueryRow(`SELECT state FROM ops WHERE id = ?`, id).Scan(&state); err != nil || state != "pending_approval" {
		t.Fatalf("Recheck changed the op: state %q %v", state, err)
	}
}

func TestRecheckLooksOnlyAtWaitingMerges(t *testing.T) {
	ap := &fakeApprovals{}
	g := newRig(t, rigOpts{enable: []string{"pr.merge", "deploy"}, approvals: ap})
	st, op, _ := g.call("POST", "/v0/approvals", hiTok, approvalReq("deploy", sha1))
	if st != 202 {
		t.Fatalf("no deploy card: %d %v", st, op)
	}
	n := g.ad.checks
	g.ad.check = func(*Request) (CheckResult, error) {
		return CheckResult{}, &Refusal{Code: CodePolicyRefused, Why: "CI_STALE: x"}
	}
	if r, err := g.svc.Recheck(context.Background(), str(op, "id")); err != nil || r.Stale {
		t.Fatalf("a deploy card must not be looked at: %+v %v", r, err)
	}
	if g.ad.checks != n {
		t.Fatal("the deploy adapter was asked")
	}
	if _, err := g.svc.Recheck(context.Background(), "q-nothere"); err == nil {
		t.Fatal("an unknown request is an error")
	}
}

// waitingMerge is a rig with one pr.merge card waiting for approval, and the id of its request.
func waitingMerge(t *testing.T) (*rig, string) {
	t.Helper()
	g := newRig(t, rigOpts{enable: []string{"pr.merge", "deploy"}, approvals: &fakeApprovals{}})
	g.ad.check = func(*Request) (CheckResult, error) { return CheckResult{NeedsApproval: true}, nil }
	st, op, _ := g.call("POST", "/v0/approvals", hiTok, approvalReq("pr.merge", sha1))
	if st != 202 || op["state"] != "pending_approval" {
		t.Fatalf("no waiting merge card: %d %v", st, op)
	}
	return g, str(op, "id")
}

// The policy can change while a card waits: the op is switched off, or the policy version moves. Release refuses both,
// so the look says so before the operator spends a Hello.
func TestRecheckFlagsAPolicyThatMovedOrSwitchedTheOpOff(t *testing.T) {
	cat, _, err := policy.Default()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	t.Run("op switched off", func(t *testing.T) {
		g, id := waitingMerge(t)
		g.turnOff("pr.merge")
		n := g.ad.checks
		r, err := g.svc.Recheck(ctx, id)
		if err != nil || !r.Stale || !strings.Contains(r.Why, "switched off") {
			t.Fatalf("a switched-off op: %+v %v", r, err)
		}
		if g.ad.checks != n {
			t.Fatal("the adapter was asked although the policy already refuses")
		}
	})

	t.Run("policy version moved", func(t *testing.T) {
		g, id := waitingMerge(t)
		// pr.merge stays on; another op is switched off, so the pack (and its version) differs from the one the card was asked under.
		g.svc.policy = policy.NewEngine(cat, packWith(t, cat, []string{"pr.merge"}, []string{"deploy"}), "")
		n := g.ad.checks
		r, err := g.svc.Recheck(ctx, id)
		if err != nil || !r.Stale || !strings.Contains(r.Why, "policy changed") {
			t.Fatalf("a moved policy version: %+v %v", r, err)
		}
		if g.ad.checks != n {
			t.Fatal("the adapter was asked although the policy already refuses")
		}
	})

	t.Run("project policy invalid", func(t *testing.T) {
		g, id := waitingMerge(t)
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "acme-shop.yaml"), []byte("not: [valid"), 0o600); err != nil {
			t.Fatal(err)
		}
		g.svc.policy = policy.NewEngine(cat, g.eff, dir)
		r, err := g.svc.Recheck(ctx, id)
		if err != nil || !r.Stale {
			t.Fatalf("an invalid policy: %+v %v", r, err)
		}
		// The same words as release: the policy is invalid, not "switched off".
		if !strings.Contains(r.Why, "acme-shop is invalid") || strings.Contains(r.Why, "switched off") {
			t.Fatalf("an invalid policy is reported as %q", r.Why)
		}
	})
}

// What the look returns is drawn by the console and logged by it, so it passes the leak checks release uses.
func TestRecheckRedactsAReasonAndAnErrorThatHoldASecret(t *testing.T) {
	const secret = "cnry-7d67d4cc000091f619c05d1d-not-a-pattern"
	reg := redact.NewRegistry()
	if err := reg.Set("canary", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	g, id := waitingMerge(t)
	g.svc.redactor = reg
	ctx := context.Background()

	g.ad.check = func(*Request) (CheckResult, error) {
		return CheckResult{}, &Refusal{Code: CodePolicyRefused, Why: "CI_RED: verify: log says " + secret}
	}
	r, err := g.svc.Recheck(ctx, id)
	if err != nil || !r.Stale {
		t.Fatalf("a leaking refusal is still a stale card: %+v %v", r, err)
	}
	if strings.Contains(r.Why, secret) || !strings.Contains(r.Why, CodeRedactionBlocked) {
		t.Fatalf("the refusal reached the console unredacted: %q", r.Why)
	}

	g.ad.check = func(*Request) (CheckResult, error) {
		return CheckResult{}, errors.New("github said: bad credential " + secret)
	}
	if _, err := g.svc.Recheck(ctx, id); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("the error is not masked: %v", err)
	}

	// A refusal with no secret is untouched.
	g.ad.check = func(*Request) (CheckResult, error) {
		return CheckResult{}, &Refusal{Code: CodePolicyRefused, Why: "CI_STALE: base_current: head is 1 commit(s) behind main"}
	}
	if r, _ := g.svc.Recheck(ctx, id); !strings.Contains(r.Why, "1 commit(s) behind main") {
		t.Fatalf("a clean refusal was changed: %q", r.Why)
	}
}

// Release binds the merge to the title on the card: a PR retitled after the card was made is refused. The look
// must hand the adapter the same approved evidence, or it passes a merge that release then refuses.
func TestRecheckFlagsAPRRetitledAfterTheCardWasMade(t *testing.T) {
	const secret = "cnry-7d67d4cc000091f619c05d1d-not-a-pattern"
	ap := &fakeApprovals{}
	g := newRig(t, rigOpts{enable: []string{"pr.merge", "deploy"}, approvals: ap})
	card := []Evidence{{Name: PRSubjectEvidence, Text: PRTitlePrefix + "docs: update notes\nAuthor: octo"}}
	title, leak := "docs: update notes", ""
	// The adapter as #76 makes it: with no approved evidence nothing is bound; with it, another title is refused with the
	// merge checks' own refusal (title_approved), built here by the same code that builds it at release.
	g.ad.check = func(r *Request) (CheckResult, error) {
		if bound := approvedTitle(r.ApprovedEvidence); bound != "" && bound != title {
			return CheckResult{}, realTitleRefusal("title_approved", leak)
		}
		return CheckResult{NeedsApproval: true, Evidence: card}, nil
	}
	st, op, _ := g.call("POST", "/v0/approvals", hiTok, approvalReq("pr.merge", sha1))
	if st != 202 || op["state"] != "pending_approval" {
		t.Fatalf("no waiting merge card: %d %v", st, op)
	}
	id := str(op, "id")
	ctx := context.Background()

	if r, err := g.svc.Recheck(ctx, id); err != nil || r.Stale {
		t.Fatalf("the title on the card is still the title: %+v %v", r, err)
	}

	title = "feat(cart): add a delivery fee" // retitled after the card was made
	r, err := g.svc.Recheck(ctx, id)
	if err != nil || !r.Stale || !r.NewCard || !strings.Contains(r.Why, "retitled") || strings.Contains(r.Why, "behind the base") {
		t.Fatalf("a retitled PR must be flagged as retitled, needing a new card: %+v %v", r, err)
	}

	// the reason carries PR-sourced text, so it is redacted like any other
	reg := redact.NewRegistry()
	if err := reg.Set("canary", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	g.svc.redactor = reg
	leak = " " + secret
	r, err = g.svc.Recheck(ctx, id)
	if err != nil || !r.Stale || strings.Contains(r.Why, secret) || !strings.Contains(r.Why, CodeRedactionBlocked) {
		t.Fatalf("a retitled PR whose title holds a secret: %+v %v", r, err)
	}

	// A card that cannot be read gives no verdict: an error, never "fine".
	ap.mu.Lock()
	clear(ap.byID)
	ap.mu.Unlock()
	if r, err := g.svc.Recheck(ctx, id); err == nil || r.Stale {
		t.Fatalf("an unreadable card: %+v %v", r, err)
	}
}

// realTitleRefusal is the refusal the merge checks return for a title that is not the approved one, built by the code
// that builds it (v.add, v.refuse, refusalOf), plus extra text after it.
func realTitleRefusal(check, extra string) error {
	var v PRVerdict
	v.add(check, false, titleEdited)
	v.refuse(StopCIStale)
	err := refusalOf(v)
	var ref *Refusal
	errors.As(err, &ref)
	ref.Why += extra
	return ref
}

// A retitled PR is refused under CI_STALE like a stale branch, but it is not one: the sentence names the title, and only
// a new card helps. A stale branch keeps its own sentence and is not marked as needing a new card.
func TestPlainRefusalOfARetitledPR(t *testing.T) {
	for _, check := range []string{"title_approved", "recheck_title"} {
		ref := realTitleRefusal(check, "").(*Refusal)
		if !strings.HasPrefix(ref.Why, StopCIStale+": "+check+": ") {
			t.Fatalf("the real refusal has changed shape: %q", ref.Why)
		}
		if got := plainRefusal(ref); !strings.Contains(got, "retitled") || !strings.Contains(got, "ask again for a new card") || strings.Contains(got, "behind the base") {
			t.Errorf("%s: %q", check, got)
		}
		if !retitled(ref) {
			t.Errorf("%s: not recognised as a retitled PR", check)
		}
	}
	stale := &Refusal{Code: CodePolicyRefused, Why: "CI_STALE: base_current: head is 1 commit(s) behind main; run pr.update"}
	if retitled(stale) || !strings.Contains(plainRefusal(stale), "behind the base") {
		t.Errorf("a stale branch: %q", plainRefusal(stale))
	}
}
