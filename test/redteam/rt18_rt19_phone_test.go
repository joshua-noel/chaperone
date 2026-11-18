package redteam

// The phone (L1-22, ADR-004 section 5): the approve from a phone passkey with
// number matching, attacked at the engine with a real SQLite database, the real
// op-hash and challenge code, and, for RT-19, the real ntfy driver and its
// queue talking to a fake ntfy server. Red-team list:
// docs/manual-crosswalk.md. Threat model: TB5-S2, TB5-I1; F6, F7.
//
//	RT-18  phone push spoofing: a wake-up is not a way to approve. A forged
//	       push styled as a request, with a link, with an "Approve" claim, for a
//	       request that does not exist, replayed after the decision: none of it
//	       reaches an approval (the push has no link or action to follow, a
//	       card that does not exist has no numbers). The phone gets no
//	       challenge before its approver chose the number on the PC; a wrong
//	       number denies the card and starts the cooldown; a right number alone
//	       approves nothing; a match is for one card, one approver, one browser,
//	       one challenge, and runs out; a phone assertion cannot stand in for a
//	       PC one or the other way round.
//	       Over HTTP, with the real WebAuthn verifier and a software passkey:
//	       internal/console/phone_test.go (TestPhoneLookAlikeOriginsCollectNothing,
//	       TestCredentialsDoNotCrossOrigins, TestPhonePageAndRoutesAreForTheRightOrigin,
//	       TestPhoneEnrolmentTokenExpiresAndWorksOnce).
//	RT-19  notification and lock-screen leakage: a request that carries canary
//	       strings in recipient, subject and body is pushed as kind, project, 8
//	       hex of the op hash, expiry and a count, and nothing else.
//
// Mutation check (see mutation_test.go): the phone's number gate, the wrong-number
// denial, the channel cross-check and the push allowlist each have a mutation
// that turns the matching replay red.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/approvals"
	"github.com/joshua-noel/chaperone/internal/notify"
	"github.com/joshua-noel/chaperone/internal/notify/ntfytest"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

const phoneOrigin = "https://pc.tail1234.ts.net"

// phoneVerifier says "phone" for the phone origin and "pc" for every other, as
// the console's verifier does; lie makes it answer "phone" for everything, as a
// console bug could.
type phoneVerifier struct{ lie bool }

func (v phoneVerifier) VerifyAssertion(_ context.Context, in approvals.AssertionInput) (approvals.AssertionEvidence, error) {
	if string(in.Response) != string(engSig(in.Challenge)) {
		return approvals.AssertionEvidence{}, &approvals.AssertionError{Reason: "bad_signature"}
	}
	ch := "pc"
	if in.Origin == phoneOrigin || v.lie {
		ch = "phone"
	}
	return approvals.AssertionEvidence{Channel: ch, CredentialID: []byte("0123456789abcdef0123456789abcdef"), RPID: "x", Origin: in.Origin}, nil
}

// newPhoneEng is newEng with the phone channel on.
func newPhoneEng(t *testing.T, n notify.Notifier, v phoneVerifier) *eng {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ms, err := store.Migrations()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, ms); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL().ExecContext(ctx,
		`INSERT INTO approvers (id, user_handle, name, created_at) VALUES (1, randomblob(32), 'operator', '2026-10-24T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	x := &eng{t: t, db: db, led: &engLedger{}, notif: &engNotifier{}, decided: map[approvals.Outcome]int{},
		clock: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	x.policy.Store(engPolicy)
	var notifier notify.Notifier = x.notif
	if n != nil {
		notifier = n
	}
	x.e, err = approvals.New(approvals.Config{
		DB: db, Ledger: x.led, Catalog: approvals.PhaseOneCatalog(), Verifier: v, Notifier: notifier,
		PhoneOrigins: []string{phoneOrigin},
		Now:          x.now,
		OnDecided: func(_ context.Context, _ *store.Tx, d approvals.Decision) error {
			x.mu.Lock()
			x.decided[d.Outcome]++
			x.mu.Unlock()
			return nil
		},
		Stop: func(_ context.Context, _ *store.Tx, s approvals.Stop) error {
			x.mu.Lock()
			x.stops = append(x.stops, s)
			x.mu.Unlock()
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return x
}

var phoneBrowser = []byte("phone-browser")

func (x *eng) phoneBegin(a *approvals.Approval, binding []byte) (*approvals.Challenge, error) {
	return x.e.BeginDecision(context.Background(), approvals.BeginInput{ApprovalID: a.ID, Actor: operator, Origin: phoneOrigin, Binding: binding})
}

func (x *eng) phoneMatch(a *approvals.Approval, binding []byte, choice string) (approvals.PhoneMatchResult, error) {
	return x.e.PhoneMatch(context.Background(), approvals.PhoneMatchInput{ApprovalID: a.ID, Actor: operator, Origin: phoneOrigin, Binding: binding, Choice: choice})
}

func (x *eng) phoneAnswer(a *approvals.Approval, ch *approvals.Challenge, binding []byte) (*approvals.Approval, error) {
	return x.e.Approve(context.Background(), approvals.ApproveInput{ApprovalID: a.ID, ChallengeID: ch.ID, Actor: operator,
		Origin: phoneOrigin, Binding: binding, Response: engSig(ch.Raw)})
}

func TestRT18PhoneNeedsItsNumberToApprove(t *testing.T) {
	ctx := context.Background()

	t.Run("control: with the number the phone alone approves, and the card is then used once", func(t *testing.T) {
		x := newPhoneEng(t, nil, phoneVerifier{})
		a := x.card(x.req(nil))
		code, err := x.e.PCNumber(ctx, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		if res, err := x.phoneMatch(a, phoneBrowser, code); err != nil || !res.Matched {
			t.Fatalf("%+v %v", res, err)
		}
		if x.state(a) != approvals.StatePending {
			t.Fatal("the number alone approved the card")
		}
		ch, err := x.phoneBegin(a, phoneBrowser)
		if err != nil {
			t.Fatal(err)
		}
		done, err := x.phoneAnswer(a, ch, phoneBrowser)
		if err != nil || done.Record.Confirmations[0].Channel != "phone" {
			t.Fatalf("%v %+v", err, done)
		}
		if err := x.consume(done, done.Request); err != nil {
			t.Fatal(err)
		}
		wantCode(t, x.consume(done, done.Request), approvals.CodeConsumed)
	})

	t.Run("no number, no challenge", func(t *testing.T) {
		x := newPhoneEng(t, nil, phoneVerifier{})
		a := x.card(x.req(nil))
		for range 20 {
			_, err := x.phoneBegin(a, phoneBrowser)
			wantCode(t, err, approvals.CodeNumberRequired)
		}
		if x.state(a) != approvals.StatePending || x.led.named("op.approve") != 0 {
			t.Fatal("a phone began a decision without the number")
		}
	})

	t.Run("a number is for one card, one browser, one challenge, and runs out", func(t *testing.T) {
		x := newPhoneEng(t, nil, phoneVerifier{})
		a := x.card(x.req(nil))
		b := x.card(x.req(func(r *spec.Request) { r.Requester.RunID = "r-0002" }))
		codeA, _ := x.e.PCNumber(ctx, a.ID)
		if res, err := x.phoneMatch(a, phoneBrowser, codeA); err != nil || !res.Matched {
			t.Fatalf("%+v %v", res, err)
		}
		_, err := x.phoneBegin(b, phoneBrowser)
		wantCode(t, err, approvals.CodeNumberRequired) // another card
		_, err = x.phoneBegin(a, []byte("another-browser"))
		wantCode(t, err, approvals.CodeNumberRequired) // another browser
		if _, err := x.phoneBegin(a, phoneBrowser); err != nil {
			t.Fatal(err)
		}
		_, err = x.phoneBegin(a, phoneBrowser)
		wantCode(t, err, approvals.CodeNumberRequired) // one challenge per match

		if res, err := x.phoneMatch(a, phoneBrowser, codeA); err != nil || !res.Matched {
			t.Fatalf("%+v %v", res, err)
		}
		x.advance(3 * time.Minute)
		_, err = x.phoneBegin(a, phoneBrowser)
		wantCode(t, err, approvals.CodeNumberRequired) // it ran out
	})

	t.Run("the PC's number is no password for the PC and the phone's answer is not a PC approval", func(t *testing.T) {
		// A verifier (a console bug) that says "phone" for an assertion begun
		// at an origin that is not the phone's: refused, nothing approved.
		x := newPhoneEng(t, nil, phoneVerifier{lie: true})
		a := x.card(x.req(nil))
		ch, err := x.begin(a) // at the PC origin: needs no number
		if err != nil {
			t.Fatal(err)
		}
		_, err = x.answer(a, ch, engSig(ch.Raw))
		ref := wantCode(t, err, approvals.CodeAssertion)
		if ref.Why != "channel_mismatch" || x.state(a) != approvals.StatePending {
			t.Fatalf("%+v", ref)
		}
	})

	t.Run("a token cannot match a number either", func(t *testing.T) {
		x := newPhoneEng(t, nil, phoneVerifier{})
		a := x.card(x.req(nil))
		code, _ := x.e.PCNumber(ctx, a.ID)
		for _, actor := range []approvals.Actor{{Kind: approvals.ActorRun, RunID: "r-7f3a"}, {Kind: approvals.ActorOrchestrator, ID: "main"}} {
			_, err := x.e.PhoneMatch(ctx, approvals.PhoneMatchInput{ApprovalID: a.ID, Actor: actor, Origin: phoneOrigin, Binding: phoneBrowser, Choice: code})
			wantCode(t, err, approvals.CodeBreach)
		}
		if got := x.stopCodes(); len(got) != 2 || got[0] != approvals.StopBreach {
			t.Fatalf("stops %v", got)
		}
		_, err := x.phoneBegin(a, phoneBrowser)
		wantCode(t, err, approvals.CodeNumberRequired)
	})
}

func TestRT18WrongNumberDeniesAndStartsTheCooldown(t *testing.T) {
	ctx := context.Background()
	x := newPhoneEng(t, nil, phoneVerifier{})
	r := x.req(nil)
	a := x.card(r)
	code, _ := x.e.PCNumber(ctx, a.ID)
	choices, _ := x.e.PhoneChoices(ctx, a.ID)
	wrong := ""
	for _, c := range choices {
		if c != code {
			wrong = c
		}
	}
	res, err := x.phoneMatch(a, phoneBrowser, wrong)
	if err != nil || res.Matched || res.Denied == nil || x.state(a) != approvals.StateDenied {
		t.Fatalf("a wrong number did not deny: %+v %v", res, err)
	}
	// The right number afterwards is too late, and the same action is refused for the cooldown.
	_, err = x.phoneMatch(a, phoneBrowser, code)
	wantCode(t, err, approvals.CodeDenied)
	_, err = x.phoneBegin(a, phoneBrowser)
	wantCode(t, err, approvals.CodeDenied)
	again := r
	again.RequestID = "q-again1"
	got := x.request(again)
	if got.Refusal == nil || got.Refusal.Code != approvals.CodeDenied || got.Refusal.RetryAfter < 59*time.Minute {
		t.Fatalf("the same action was not refused for the cooldown: %+v", got.Refusal)
	}
	if x.decided[approvals.OutcomeDenied] != 1 || x.led.named("op.approve") != 1 {
		t.Fatalf("denied %d, op.approve events %d", x.decided[approvals.OutcomeDenied], x.led.named("op.approve"))
	}
}

func TestRT18GuessingTheNumberNeverApproves(t *testing.T) {
	// A blind tap on the phone page: one in three right, two in three a denial.
	// Either way nothing is approved: the right tap only allows a challenge.
	ctx := context.Background()
	x := newPhoneEng(t, nil, phoneVerifier{})
	right, denied := 0, 0
	for i := range 60 {
		a := x.card(x.req(func(r *spec.Request) { r.Requester.RunID = fmt.Sprintf("r-%04d", i) }))
		choices, _ := x.e.PhoneChoices(ctx, a.ID)
		res, err := x.phoneMatch(a, phoneBrowser, choices[i%3])
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case res.Matched:
			right++
		case res.Denied != nil:
			denied++
		}
		if st := x.state(a); st == approvals.StateApproved {
			t.Fatal("a tap approved a card")
		}
		if _, err := x.e.Sweep(ctx); err != nil {
			t.Fatal(err)
		}
		if res.Matched { // free the slot: the run cap bounds what agents queue
			if _, err := x.e.Deny(ctx, approvals.DenyInput{ApprovalID: a.ID, Actor: operator, Reason: "test cleanup"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if right+denied != 60 || right == 0 || denied == 0 {
		t.Fatalf("right %d denied %d of 60 blind taps", right, denied)
	}
}

func TestRT18ForgedPushIsNotAnApprovalPath(t *testing.T) {
	ctx := context.Background()
	srv := ntfytest.New(t)
	topic, err := notify.ParseTopic(strings.Repeat("ab", 16))
	if err != nil {
		t.Fatal(err)
	}
	driver, err := notify.NewNtfy(notify.NtfyConfig{Topic: topic, BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := notify.NewService(notify.ServiceConfig{Driver: driver, Now: func() time.Time { return time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close(context.Background()) })
	x := newPhoneEng(t, svc, phoneVerifier{})
	a := x.card(x.req(nil))

	// What the genuine push carries: no link, no action, no click target.
	msgs := waitMessages(t, srv, 1)
	allowed := map[string]bool{"topic": true, "title": true, "message": true, "priority": true}
	for k := range msgs[0].Fields {
		if !allowed[k] {
			t.Fatalf("the push carries the field %q: only topic, title, message and priority may travel", k)
		}
	}
	if strings.Contains(msgs[0].Message, "http") || strings.Contains(msgs[0].Message, "/") || strings.Contains(strings.ToLower(msgs[0].Message+msgs[0].Title), "approve ") {
		t.Fatalf("the push reads like a link or an approve button: %q %q", msgs[0].Title, msgs[0].Message)
	}

	// Forged push content is refused by the builder: nothing is sent for it.
	hash := "sha256:" + strings.Repeat("a", 64)
	exp := time.Date(2026, 10, 24, 12, 30, 0, 0, time.UTC)
	for name, w := range map[string]notify.Wake{
		"a phishing link as the project":    {Kind: "deploy", Project: "https://evil.example/approve", OpHash: hash, ExpiresAt: exp, Pending: 1},
		"an approve claim as the kind":      {Kind: "APPROVE NOW", Project: "acme-shop", OpHash: hash, ExpiresAt: exp, Pending: 1},
		"a link as the kind":                {Kind: "deploy http://evil.example", Project: "acme-shop", OpHash: hash, ExpiresAt: exp, Pending: 1},
		"a newline that fakes a second row": {Kind: "deploy", Project: "acme-shop\nApprove: tap here", OpHash: hash, ExpiresAt: exp, Pending: 1},
		"a hash that is a sentence":         {Kind: "deploy", Project: "acme-shop", OpHash: "approved by the operator", ExpiresAt: exp, Pending: 1},
		"a count of zero":                   {Kind: "deploy", Project: "acme-shop", OpHash: hash, ExpiresAt: exp, Pending: 0},
	} {
		if p, err := notify.Build(w); !errors.Is(err, notify.ErrInvalidWake) {
			t.Fatalf("%s: built a push %+v (%v)", name, p, err)
		}
		if err := svc.Notify(ctx, w); !errors.Is(err, notify.ErrInvalidWake) {
			t.Fatalf("%s: the service queued it: %v", name, err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if n := len(srv.Messages()); n != 1 {
		t.Fatalf("%d messages reached the server, want only the genuine one", n)
	}

	// A push for a request that does not exist leaves no card, no number, nothing to match.
	if err := svc.Notify(ctx, notify.Wake{Kind: "deploy", Project: "acme-shop", OpHash: "sha256:" + strings.Repeat("b", 64), ExpiresAt: exp, Pending: 1}); err != nil {
		t.Fatal(err)
	}
	if n, _ := x.e.PendingCount(ctx); n != 1 {
		t.Fatalf("%d cards pending after a forged push, want the one real card", n)
	}
	_, err = x.e.PhoneChoices(ctx, "a-doesnotexist")
	wantCode(t, err, approvals.CodeNoSuchApproval)
	_, err = x.e.PCNumber(ctx, "a-doesnotexist")
	wantCode(t, err, approvals.CodeNoSuchApproval)
	_, err = x.e.PhoneMatch(ctx, approvals.PhoneMatchInput{ApprovalID: "a-doesnotexist", Actor: operator, Origin: phoneOrigin, Binding: phoneBrowser, Choice: "10"})
	wantCode(t, err, approvals.CodeNoSuchApproval)

	// A genuine old push replayed after the decision opens nothing.
	x.mustApprove(a)
	_, err = x.e.PhoneChoices(ctx, a.ID)
	wantCode(t, err, approvals.CodeConsumed)
	_, err = x.phoneBegin(a, phoneBrowser)
	wantCode(t, err, approvals.CodeConsumed)

	// No approval came from any of it but the PC decision above.
	if x.led.named("op.approve") != 1 {
		t.Fatalf("%d op.approve events, want the one PC approval", x.led.named("op.approve"))
	}
}

func waitMessages(t *testing.T, srv *ntfytest.Server, n int) []ntfytest.Message {
	t.Helper()
	for range 100 {
		if m := srv.Messages(); len(m) >= n {
			return m
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("the push did not reach the server: %d messages, want %d", len(srv.Messages()), n)
	return nil
}

var messageShape = regexp.MustCompile(`^mail\.send acme-shop\nop ([0-9a-f]{8}), expires [0-9]{2}:[0-9]{2} UTC\n[0-9]+ pending$`)

func TestRT19NoParameterReachesAPush(t *testing.T) {
	ctx := context.Background()
	const (
		canaryTo   = "canary-recipient-7Hq2@evil.example"
		canarySubj = "canary-subject-Vx81"
		canaryBody = "canary-body-Zp04 wire the money"
		canaryWhy  = "canary-reason-Kd55"
	)
	canaries := []string{canaryTo, canarySubj, canaryBody, canaryWhy, "canary-"}

	srv := ntfytest.New(t)
	topic, err := notify.ParseTopic(strings.Repeat("cd", 16))
	if err != nil {
		t.Fatal(err)
	}
	driver, err := notify.NewNtfy(notify.NtfyConfig{Topic: topic, BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	svc, err := notify.NewService(notify.ServiceConfig{Driver: driver, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close(context.Background()) })
	x := newPhoneEng(t, svc, phoneVerifier{})

	mail := x.req(func(r *spec.Request) {
		r.Op, r.Target = "mail.send", spec.Target{Adapter: "gmail", Ref: "operator@example.test"}
		r.Params = map[string]any{"to": []any{canaryTo}, "subject": canarySubj, "body": canaryBody}
		r.Reason = canaryWhy
	})
	a := x.card(mail)

	// The control: the canary is in the card the approver reads.
	for _, c := range []string{canaryTo, canarySubj, canaryBody, canaryWhy} {
		if !strings.Contains(a.CardText, c) {
			t.Fatalf("the card does not show %q: the replay would prove nothing", c)
		}
	}

	msgs := waitMessages(t, srv, 1)
	if len(msgs) != 1 {
		t.Fatalf("%d pushes for one card", len(msgs))
	}
	m := msgs[0]
	// Everything that left the PC for the push provider: body, path, headers.
	var wire strings.Builder
	wire.Write(m.Raw)
	wire.WriteString(m.Path)
	for k, vs := range m.Header {
		wire.WriteString(k)
		wire.WriteString(strings.Join(vs, ","))
	}
	for _, c := range canaries {
		if strings.Contains(wire.String(), c) {
			t.Fatalf("%q reached the push provider: %s", c, m.Raw)
		}
	}
	// What the lock screen and the notification history show.
	if mm := messageShape.FindStringSubmatch(m.Message); mm == nil || !strings.HasPrefix(strings.TrimPrefix(a.OpHash, "sha256:"), mm[1]) {
		t.Fatalf("the push message is not kind, project, 8 hex, expiry, count: %q (op hash %s)", m.Message, a.OpHash)
	}
	if m.Title != "Chaperone: approval waiting" {
		t.Fatalf("title %q", m.Title)
	}
	for k := range m.Fields {
		if k != "topic" && k != "title" && k != "message" && k != "priority" {
			t.Fatalf("field %q in the push", k)
		}
	}

	// The same request again is one push (dedupe), and its denial is no push.
	x.card(mail)
	time.Sleep(150 * time.Millisecond)
	if n := len(srv.Messages()); n != 1 {
		t.Fatalf("%d pushes for one op hash", n)
	}

	// Defence in depth: should a caller ever hand the builder request text, it refuses.
	exp := now.Add(30 * time.Minute)
	hash := "sha256:" + strings.Repeat("c", 64)
	for _, c := range []string{canaryTo, canarySubj, canaryBody, canaryWhy} {
		for name, w := range map[string]notify.Wake{
			"as the kind":    {Kind: c, Project: "acme-shop", OpHash: hash, ExpiresAt: exp, Pending: 1},
			"as the project": {Kind: "mail.send", Project: c, OpHash: hash, ExpiresAt: exp, Pending: 1},
			"as the hash":    {Kind: "mail.send", Project: "acme-shop", OpHash: c, ExpiresAt: exp, Pending: 1},
		} {
			if p, err := notify.Build(w); err == nil {
				t.Fatalf("%q %s built a push: %+v", c, name, p)
			}
		}
	}
	if n, _ := x.e.PendingCount(ctx); n != 1 {
		t.Fatalf("%d pending", n)
	}
}

// Wake has no field for a parameter: the type itself is the first control.
func TestRT19WakeHasNoFieldForParameters(t *testing.T) {
	b, err := json.Marshal(notify.Wake{})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	_ = json.Unmarshal(b, &fields)
	want := map[string]bool{"Kind": true, "Project": true, "OpHash": true, "ExpiresAt": true, "Pending": true}
	if len(fields) != len(want) {
		t.Fatalf("Wake has fields %v", fields)
	}
	for k := range fields {
		if !want[k] {
			t.Fatalf("Wake has the field %s", k)
		}
	}
}
