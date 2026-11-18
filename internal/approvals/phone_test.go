package approvals

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/spec"
)

const testPhoneOrigin = "https://pc.tail1234.ts.net"

func withPhone(c *Config) { c.PhoneOrigins = []string{testPhoneOrigin} }

var phoneBrowser = []byte("phone-browser")

// phoneApprove makes the whole phone path for a card: the right number, begin
// at the phone origin, finish with an honest verifier answering as the phone.
func (r *rig) phoneApprove(a *Approval) (*Approval, error) {
	r.t.Helper()
	ctx := context.Background()
	code, err := r.e.PCNumber(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	res, err := r.e.PhoneMatch(ctx, PhoneMatchInput{ApprovalID: a.ID, Actor: approver, Origin: testPhoneOrigin, Binding: phoneBrowser, Choice: code})
	if err != nil {
		return nil, err
	}
	if !res.Matched {
		r.t.Fatalf("the right number did not match: %+v", res)
	}
	ch, err := r.e.BeginDecision(ctx, BeginInput{ApprovalID: a.ID, Actor: approver, Origin: testPhoneOrigin, Binding: phoneBrowser})
	if err != nil {
		return nil, err
	}
	r.ver.mu.Lock()
	r.ver.channel = "phone"
	r.ver.mu.Unlock()
	return r.e.Approve(ctx, ApproveInput{ApprovalID: a.ID, ChallengeID: ch.ID, Actor: approver, Origin: testPhoneOrigin,
		Binding: phoneBrowser, Response: sigFor(ch.Raw)})
}

func TestPhoneNumbersAreStableAndHideTheCode(t *testing.T) {
	r := newRig(t, withPhone)
	ctx := context.Background()
	a := r.mustCard(r.mkReq(nil))

	code, err := r.e.PCNumber(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 2 || code[0] < '1' || code[0] > '9' || code[1] < '0' || code[1] > '9' {
		t.Fatalf("the PC number %q is not two digits from 10 to 99", code)
	}
	choices, err := r.e.PhoneChoices(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(choices[:], code) {
		t.Fatalf("the right number %s is not among the three the phone shows: %v", code, choices)
	}
	if choices[0] == choices[1] || choices[0] == choices[2] || choices[1] == choices[2] {
		t.Fatalf("the three numbers are not different: %v", choices)
	}
	for i := 0; i < 5; i++ { // a reload shows the same three in the same order
		again, err := r.e.PhoneChoices(ctx, a.ID)
		if err != nil || again != choices {
			t.Fatalf("reload %d: %v %v, want %v", i, again, err, choices)
		}
		if c2, _ := r.e.PCNumber(ctx, a.ID); c2 != code {
			t.Fatalf("the PC number changed: %s then %s", code, c2)
		}
	}
	// Another card has its own numbers.
	b := r.mustCard(r.mkReq(func(q *spec.Request) { q.Requester.RunID = "r-0002" }))
	if _, err := r.e.PCNumber(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
	// What is stored never changes.
	if _, err := r.db.SQL().ExecContext(ctx, `UPDATE approval_phone_numbers SET code = '99'`); err == nil {
		t.Fatal("a card's numbers were rewritten")
	}
	if _, err := r.db.SQL().ExecContext(ctx, `DELETE FROM approval_phone_numbers`); err == nil {
		t.Fatal("a card's numbers were deleted")
	}
}

func TestPhoneNumbersAreUniform(t *testing.T) {
	const n = 3000
	pos := [3]int{}
	first := map[string]int{}
	for i := 0; i < n; i++ {
		p := newPhoneNumbers()
		for k, c := range p.choices {
			if c == p.code {
				pos[k]++
			}
			if len(c) != 2 || c < "10" || c > "99" {
				t.Fatalf("%q is not from 10 to 99", c)
			}
		}
		first[p.code]++
	}
	for k, c := range pos {
		if c < n/3-250 || c > n/3+250 { // 6 sigma is about 150
			t.Fatalf("the right number sits at position %d in %d of %d draws; the order is not uniform", k, c, n)
		}
	}
	if len(first) < 85 {
		t.Fatalf("only %d of 90 numbers ever came up as the code in %d draws", len(first), n)
	}
}

func TestPhoneNumbersNeedThePhoneAndAPendingCard(t *testing.T) {
	r := newRig(t) // no phone
	ctx := context.Background()
	a := r.mustCard(r.mkReq(nil))
	if _, err := r.e.PCNumber(ctx, a.ID); err == nil {
		t.Fatal("a PC number exists without the phone channel")
	}
	if _, err := r.e.PhoneChoices(ctx, a.ID); err == nil {
		t.Fatal("phone choices exist without the phone channel")
	}

	r = newRig(t, withPhone)
	a = r.mustCard(r.mkReq(nil))
	r.mustApprove(a)
	_, err := r.e.PCNumber(ctx, a.ID)
	wantRefusal(t, err, CodeConsumed)
	_, err = r.e.PCNumber(ctx, "a-nonexistent1")
	wantRefusal(t, err, CodeNoSuchApproval)
}

func TestPhoneChannelNeedsPhoneOrigins(t *testing.T) {
	_, err := New(Config{DB: newRig(t).db, Ledger: &fakeLedger{}, Catalog: PhaseOneCatalog(), Channels: []string{"pc", "phone"}})
	if err == nil {
		t.Fatal("the phone channel was accepted with no phone origin")
	}
	r := newRig(t, withPhone)
	if !r.e.PhoneEnabled() || !r.e.channelAllowed("phone") || !r.e.channelAllowed("pc") {
		t.Fatal("PhoneOrigins did not switch the phone channel on")
	}
}

func TestOnePhoneAssertionApprovesAnyApproveTierOp(t *testing.T) {
	r := newRig(t, withPhone)
	for i, op := range []string{"deploy", "mail.send", "drive.share", "pr.merge", "data.apply", "pr.push.workflow",
		"secrets.write", "repo.settings", "host.scripts.refresh", "approvers.enroll"} {
		a := r.mustCard(r.mkReq(func(q *spec.Request) {
			q.Op, q.Requester.RunID = op, fmt.Sprintf("r-%04d", i+10)
			q.Params = map[string]any{"note": "x"}
		}))
		done, err := r.phoneApprove(a)
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if done.State != StateApproved || done.Record == nil || len(done.Record.Confirmations) != 1 ||
			done.Record.Confirmations[0].Channel != "phone" || len(done.Record.Shown.Channels) != 1 || done.Record.Shown.Channels[0] != "phone" {
			t.Fatalf("%s: not one phone confirmation: %+v", op, done.Record)
		}
		// The approval can then be used exactly once, as any other.
		if err := r.consume(done, done.Request); err != nil {
			t.Fatalf("%s: consume: %v", op, err)
		}
		wantRefusal(t, r.consume(done, done.Request), CodeConsumed)
	}
	var ch string
	if err := r.db.SQL().QueryRow(`SELECT channel FROM approval_assertions LIMIT 1`).Scan(&ch); err != nil || ch != "phone" {
		t.Fatalf("assertion channel = %q, %v", ch, err)
	}
	var phoneEvents int
	for _, ev := range r.led.all() {
		if ev.Name == "op.approve" && strings.Contains(ev.Body, "on phone") && strings.Contains(ev.Body, "number_matching=ok") {
			phoneEvents++
		}
	}
	if phoneEvents != 10 {
		t.Fatalf("%d ledger events say phone with number matching, want 10", phoneEvents)
	}
}

func TestPhoneNeedsTheRightNumberFirst(t *testing.T) {
	ctx := context.Background()
	begin := func(r *rig, a *Approval, binding []byte) error {
		_, err := r.e.BeginDecision(ctx, BeginInput{ApprovalID: a.ID, Actor: approver, Origin: testPhoneOrigin, Binding: binding})
		return err
	}
	t.Run("no number, no challenge", func(t *testing.T) {
		r := newRig(t, withPhone)
		a := r.mustCard(r.mkReq(nil))
		wantRefusal(t, begin(r, a, phoneBrowser), CodeNumberRequired)
		if r.state(a.ID) != StatePending {
			t.Fatal("the card changed")
		}
	})
	t.Run("the PC needs no number", func(t *testing.T) {
		r := newRig(t, withPhone)
		a := r.mustCard(r.mkReq(nil))
		r.mustApprove(a)
	})
	t.Run("a match is for one browser", func(t *testing.T) {
		r := newRig(t, withPhone)
		a := r.mustCard(r.mkReq(nil))
		code, _ := r.e.PCNumber(ctx, a.ID)
		if _, err := r.e.PhoneMatch(ctx, PhoneMatchInput{ApprovalID: a.ID, Actor: approver, Origin: testPhoneOrigin, Binding: phoneBrowser, Choice: code}); err != nil {
			t.Fatal(err)
		}
		wantRefusal(t, begin(r, a, []byte("another-browser")), CodeNumberRequired)
		if err := begin(r, a, phoneBrowser); err != nil {
			t.Fatalf("the matching browser was refused: %v", err)
		}
	})
	t.Run("a match is used by one begin", func(t *testing.T) {
		r := newRig(t, withPhone)
		a := r.mustCard(r.mkReq(nil))
		code, _ := r.e.PCNumber(ctx, a.ID)
		if _, err := r.e.PhoneMatch(ctx, PhoneMatchInput{ApprovalID: a.ID, Actor: approver, Origin: testPhoneOrigin, Binding: phoneBrowser, Choice: code}); err != nil {
			t.Fatal(err)
		}
		if err := begin(r, a, phoneBrowser); err != nil {
			t.Fatal(err)
		}
		wantRefusal(t, begin(r, a, phoneBrowser), CodeNumberRequired)
	})
	t.Run("a match runs out", func(t *testing.T) {
		r := newRig(t, withPhone)
		a := r.mustCard(r.mkReq(nil))
		code, _ := r.e.PCNumber(ctx, a.ID)
		if _, err := r.e.PhoneMatch(ctx, PhoneMatchInput{ApprovalID: a.ID, Actor: approver, Origin: testPhoneOrigin, Binding: phoneBrowser, Choice: code}); err != nil {
			t.Fatal(err)
		}
		r.advance(2*time.Minute + time.Second)
		wantRefusal(t, begin(r, a, phoneBrowser), CodeNumberRequired)
	})
	t.Run("a match is for one card", func(t *testing.T) {
		r := newRig(t, withPhone)
		a := r.mustCard(r.mkReq(nil))
		b := r.mustCard(r.mkReq(func(q *spec.Request) { q.Requester.RunID = "r-0002" }))
		code, _ := r.e.PCNumber(ctx, a.ID)
		if _, err := r.e.PhoneMatch(ctx, PhoneMatchInput{ApprovalID: a.ID, Actor: approver, Origin: testPhoneOrigin, Binding: phoneBrowser, Choice: code}); err != nil {
			t.Fatal(err)
		}
		wantRefusal(t, begin(r, b, phoneBrowser), CodeNumberRequired)
	})
	t.Run("a challenge begun on the PC cannot be finished as the phone", func(t *testing.T) {
		r := newRig(t, withPhone)
		a := r.mustCard(r.mkReq(nil))
		ch, err := r.e.BeginDecision(ctx, BeginInput{ApprovalID: a.ID, Actor: approver, Origin: testOrigin, Binding: []byte("browser")})
		if err != nil {
			t.Fatal(err)
		}
		r.ver.channel = "phone" // the verifier saw a phone credential
		_, err = r.e.Approve(ctx, ApproveInput{ApprovalID: a.ID, ChallengeID: ch.ID, Actor: approver, Origin: testOrigin,
			Binding: []byte("browser"), Response: sigFor(ch.Raw)})
		ref := wantRefusal(t, err, CodeAssertion)
		if ref.Why != "channel_mismatch" || r.state(a.ID) != StatePending {
			t.Fatalf("%+v", ref)
		}
	})
	t.Run("a challenge begun on the phone cannot be finished at the PC origin", func(t *testing.T) {
		r := newRig(t, withPhone)
		a := r.mustCard(r.mkReq(nil))
		code, _ := r.e.PCNumber(ctx, a.ID)
		if _, err := r.e.PhoneMatch(ctx, PhoneMatchInput{ApprovalID: a.ID, Actor: approver, Origin: testPhoneOrigin, Binding: phoneBrowser, Choice: code}); err != nil {
			t.Fatal(err)
		}
		ch, err := r.e.BeginDecision(ctx, BeginInput{ApprovalID: a.ID, Actor: approver, Origin: testPhoneOrigin, Binding: phoneBrowser})
		if err != nil {
			t.Fatal(err)
		}
		_, err = r.e.Approve(ctx, ApproveInput{ApprovalID: a.ID, ChallengeID: ch.ID, Actor: approver, Origin: testOrigin,
			Binding: phoneBrowser, Response: sigFor(ch.Raw)})
		wantRefusal(t, err, CodeChallenge)
	})
	t.Run("the match is refused at the PC origin", func(t *testing.T) {
		r := newRig(t, withPhone)
		a := r.mustCard(r.mkReq(nil))
		code, _ := r.e.PCNumber(ctx, a.ID)
		_, err := r.e.PhoneMatch(ctx, PhoneMatchInput{ApprovalID: a.ID, Actor: approver, Origin: testOrigin, Binding: phoneBrowser, Choice: code})
		wantRefusal(t, err, CodeAssertion)
	})
}

func TestAWrongNumberDeniesAndStartsTheCooldown(t *testing.T) {
	ctx := context.Background()
	for name, pick := range map[string]func(code string, choices [3]string) string{
		"a decoy": func(code string, choices [3]string) string {
			for _, c := range choices {
				if c != code {
					return c
				}
			}
			return ""
		},
		"a number that is not shown":  func(code string, _ [3]string) string { return wrongNumberNotIn(code) },
		"nothing":                     func(string, [3]string) string { return "" },
		"the right digits and a tail": func(code string, _ [3]string) string { return code + "0" },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, withPhone)
			req := r.mkReq(nil)
			a := r.mustCard(req)
			code, _ := r.e.PCNumber(ctx, a.ID)
			choices, _ := r.e.PhoneChoices(ctx, a.ID)
			res, err := r.e.PhoneMatch(ctx, PhoneMatchInput{ApprovalID: a.ID, Actor: approver, Origin: testPhoneOrigin,
				Binding: phoneBrowser, Choice: pick(code, choices)})
			if err != nil {
				t.Fatal(err)
			}
			if res.Matched || res.Denied == nil || res.Denied.State != StateDenied {
				t.Fatalf("a wrong number did not deny: %+v", res)
			}
			if !strings.Contains(res.Denied.Reason, "number matching failed") {
				t.Fatalf("reason = %q", res.Denied.Reason)
			}
			if r.state(a.ID) != StateDenied {
				t.Fatal("the card is not denied")
			}
			// The cooldown: the same action is refused, and the card cannot be decided.
			again := req
			again.RequestID = "q-again1"
			res2 := r.request(again)
			if res2.Refusal == nil || res2.Refusal.Code != CodeDenied || res2.Refusal.RetryAfter < 59*time.Minute {
				t.Fatalf("the same action was not refused for the cooldown: %+v", res2.Refusal)
			}
			if _, err := r.phoneApprove(a); err == nil {
				t.Fatal("a denied card was approved from the phone")
			}
			_, err = r.approve(a)
			wantRefusal(t, err, CodeDenied)
			// The operator's denial in the ledger and the op state machine's hook.
			var denied bool
			for _, ev := range r.led.all() {
				if ev.Name == "op.approve" && ev.Attributes["factory.decision"] == "denied" && strings.Contains(ev.Body, "number matching failed") {
					denied = true
				}
			}
			dec, _, _ := r.snapshot()
			if !denied || len(dec) != 1 || dec[0].Outcome != OutcomeDenied {
				t.Fatalf("denial not ledgered or not reported: %v %+v", denied, dec)
			}
			// After the cooldown the action may be asked for again.
			r.advance(61 * time.Minute)
			again.RequestID, again.ExpiresAt = "q-again2", ts(r.now().Add(time.Hour))
			if res := r.request(again); res.Refusal != nil {
				t.Fatalf("still refused after the cooldown: %+v", res.Refusal)
			}
		})
	}
}

func wrongNumberNotIn(code string) string {
	if code == "10" {
		return "11"
	}
	return "10"
}

func TestPhoneMatchRefusesATokenAndADecidedCard(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, withPhone)
	a := r.mustCard(r.mkReq(nil))
	code, _ := r.e.PCNumber(ctx, a.ID)
	for _, actor := range []Actor{{Kind: ActorRun, RunID: "r-7f3a"}, {Kind: ActorOrchestrator, ID: "main"}} {
		_, err := r.e.PhoneMatch(ctx, PhoneMatchInput{ApprovalID: a.ID, Actor: actor, Origin: testPhoneOrigin, Binding: phoneBrowser, Choice: code})
		wantRefusal(t, err, CodeBreach)
	}
	if r.state(a.ID) != StatePending {
		t.Fatal("a token changed the card")
	}
	_, stops, _ := r.snapshot()
	if len(stops) != 2 {
		t.Fatalf("%d stops raised, want 2 POLICY_BREACH", len(stops))
	}
	r.mustApprove(a)
	_, err := r.e.PhoneMatch(ctx, PhoneMatchInput{ApprovalID: a.ID, Actor: approver, Origin: testPhoneOrigin, Binding: phoneBrowser, Choice: code})
	wantRefusal(t, err, CodeConsumed)
	_, err = r.e.PhoneMatch(ctx, PhoneMatchInput{ApprovalID: "a-nonexistent1", Actor: approver, Origin: testPhoneOrigin, Binding: phoneBrowser, Choice: code})
	wantRefusal(t, err, CodeNoSuchApproval)
}
