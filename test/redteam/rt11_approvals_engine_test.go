package redteam

// The approvals engine (internal/approvals) attacked directly with a real
// SQLite database, a fake WebAuthn verifier and the real op-hash and challenge
// code. Each test names its red-team entry. Red-team list:
// docs/manual-crosswalk.md. Threat model: TB4-T2, TB4-E1.
//
//	RT-11  approval replay with a changed op: (a) B under A's approval, (b) a
//	       changed param, (g) swapped ids, (h) an assertion for another
//	       challenge, (e) another requester, (c) and (j) a consumed approval,
//	       serial and 20-way parallel, (d) expiry, (f) a policy change.
//	RT-13  a token decides: a run or the orchestrator begins, approves or denies.
//	RT-15  push-bomb: the pending caps (APPROVAL_FLOOD), dedupe, sticky deny, one
//	       wake-up per op hash, and a wake-up that carries no parameter.
//	RT-21  (part) a stored card edited after the fact (op hash, params, card
//	       text): refused by the table's trigger, and by the engine if the
//	       trigger is gone.
//
// Mutation check: remove the op-hash comparison in ConsumeTx
// (internal/approvals/consume.go); TestRT11ApprovalIsBoundToItsRequest turns red
// (see mutation_test.go).

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/approvals"
	"github.com/joshua-noel/chaperone/internal/notify"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

const (
	engOrigin = "http://localhost:55398"
	engPolicy = "baseline-2026.10.1"
)

type engLedger struct {
	mu     sync.Mutex
	events []approvals.LedgerEvent
}

func (l *engLedger) AppendTx(_ context.Context, _ *store.Tx, ev approvals.LedgerEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, ev)
	return nil
}

func (l *engLedger) named(name string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, e := range l.events {
		if e.Name == name {
			n++
		}
	}
	return n
}

// engVerifier accepts only "sig:" + hex(challenge): an assertion made for one
// challenge fails for every other.
type engVerifier struct{}

func engSig(challenge []byte) []byte { return []byte("sig:" + hex.EncodeToString(challenge)) }

func (engVerifier) VerifyAssertion(_ context.Context, in approvals.AssertionInput) (approvals.AssertionEvidence, error) {
	if string(in.Response) != string(engSig(in.Challenge)) {
		return approvals.AssertionEvidence{}, &approvals.AssertionError{Reason: "bad_signature"}
	}
	return approvals.AssertionEvidence{Channel: "pc", CredentialID: []byte("0123456789abcdef0123456789abcdef"), RPID: "localhost", Origin: in.Origin}, nil
}

type engNotifier struct {
	mu    sync.Mutex
	wakes []notify.Wake
}

func (n *engNotifier) Notify(_ context.Context, w notify.Wake) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.wakes = append(n.wakes, w)
	return nil
}

type eng struct {
	t     *testing.T
	db    *store.DB
	e     *approvals.Engine
	led   *engLedger
	notif *engNotifier
	mu    sync.Mutex
	clock time.Time
	seq   int
	stops []approvals.Stop
	// policy is the version the engine believes is in force.
	policy atomic.Value
	// decided counts OnDecided calls by outcome.
	decided map[approvals.Outcome]int
}

var operator = approvals.Actor{Kind: approvals.ActorApprover, ApproverRow: 1, ApproverID: "operator"}

func newEng(t *testing.T, chap approvals.Limits) *eng {
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
	x.e, err = approvals.New(approvals.Config{
		DB: db, Ledger: x.led, Catalog: approvals.PhaseOneCatalog(), Verifier: engVerifier{}, Notifier: x.notif, Limits: chap,
		Now:           x.now,
		PolicyVersion: func() string { return x.policy.Load().(string) },
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

func (x *eng) now() time.Time { x.mu.Lock(); defer x.mu.Unlock(); return x.clock }
func (x *eng) advance(d time.Duration) {
	x.mu.Lock()
	x.clock = x.clock.Add(d)
	x.mu.Unlock()
}
func (x *eng) stopCodes() []string {
	x.mu.Lock()
	defer x.mu.Unlock()
	var out []string
	for _, s := range x.stops {
		out = append(out, s.Code)
	}
	return out
}

func tsOf(t time.Time) string { return t.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z") }

// req builds a valid deploy request document with its op_hash. mutate may
// change it before the hash is computed.
func (x *eng) req(mutate func(*spec.Request)) spec.Request {
	x.t.Helper()
	x.mu.Lock()
	x.seq++
	n := x.seq
	now := x.clock
	x.mu.Unlock()
	r := spec.Request{
		SpecVersion: spec.SpecVersion, Type: "op.request", RequestID: fmt.Sprintf("q-%06d", n),
		Requester: spec.Requester{Kind: "run", RunID: "r-7f3a", TokenJTI: "n8Gf3kQ2xV7bTz1LwA9cYd", Profile: "host-interim"},
		Project:   rigProject, Op: "deploy", Target: spec.Target{Adapter: "wsl-host", Ref: "pilot"},
		Params: map[string]any{"sha": fmt.Sprintf("%040x", n)}, Reason: "Ship the fix.",
		RequestedAt: tsOf(now), ExpiresAt: tsOf(now.Add(time.Hour)),
	}
	if mutate != nil {
		mutate(&r)
	}
	h, err := spec.OpHash(r)
	if err != nil {
		x.t.Fatal(err)
	}
	r.OpHash = h
	return r
}

func checksOK() []spec.ApprovalCheck {
	return []spec.ApprovalCheck{{Name: "backup.fresh", Passed: true, Detail: "ok"}, {Name: "ci.green", Passed: true, Detail: "ok"}}
}

func (x *eng) request(r spec.Request) approvals.Result {
	x.t.Helper()
	var res approvals.Result
	err := x.e.Atomic(context.Background(), func(ctx context.Context, tx *store.Tx) (approvals.Effects, error) {
		var err error
		res, err = x.e.RequestTx(ctx, tx, approvals.RequestInput{Request: r, PolicyVersion: engPolicy, Checks: checksOK()})
		return res.Effects, err
	})
	if err != nil {
		x.t.Fatal(err)
	}
	return res
}

func (x *eng) card(r spec.Request) *approvals.Approval {
	x.t.Helper()
	res := x.request(r)
	if res.Refusal != nil {
		x.t.Fatalf("request refused: %v", res.Refusal)
	}
	return res.Approval
}

func (x *eng) begin(a *approvals.Approval) (*approvals.Challenge, error) {
	return x.e.BeginDecision(context.Background(), approvals.BeginInput{ApprovalID: a.ID, Actor: operator, Origin: engOrigin, Binding: []byte("browser")})
}

func (x *eng) answer(a *approvals.Approval, ch *approvals.Challenge, response []byte) (*approvals.Approval, error) {
	return x.e.Approve(context.Background(), approvals.ApproveInput{ApprovalID: a.ID, ChallengeID: ch.ID, Actor: operator,
		Origin: engOrigin, Binding: []byte("browser"), Response: response})
}

func (x *eng) approve(a *approvals.Approval) (*approvals.Approval, error) {
	ch, err := x.begin(a)
	if err != nil {
		return nil, err
	}
	return x.answer(a, ch, engSig(ch.Raw))
}

func (x *eng) mustApprove(a *approvals.Approval) *approvals.Approval {
	x.t.Helper()
	done, err := x.approve(a)
	if err != nil {
		x.t.Fatalf("approve: %v", err)
	}
	return done
}

func (x *eng) consume(a *approvals.Approval, r spec.Request) error {
	return x.e.Atomic(context.Background(), func(ctx context.Context, tx *store.Tx) (approvals.Effects, error) {
		return x.e.ConsumeTx(ctx, tx, approvals.ConsumeInput{ApprovalID: a.ID, Request: r})
	})
}

func wantCode(t *testing.T, err error, code string) *approvals.Refusal {
	t.Helper()
	var ref *approvals.Refusal
	if !errors.As(err, &ref) {
		t.Fatalf("got %v, want a refusal %s", err, code)
	}
	if ref.Code != code {
		t.Fatalf("refusal %s (%s), want %s", ref.Code, ref.Why, code)
	}
	return ref
}

func (x *eng) state(a *approvals.Approval) approvals.State {
	x.t.Helper()
	got, err := x.e.Get(context.Background(), a.ID)
	if err != nil || got == nil {
		x.t.Fatalf("get %s: %v", a.ID, err)
	}
	return got.State
}

// ---- RT-11 -----------------------------------------------------------------

func TestRT11ApprovalIsBoundToItsRequest(t *testing.T) {
	// The caps are not under test here: lift them so one run can hold many cards.
	x := newEng(t, approvals.Limits{PerRun: 50, PerProject: 50, Total: 100})
	reqA := x.req(nil)
	a := x.card(reqA)
	b := x.req(nil) // another deploy, another sha
	x.mustApprove(a)

	// Attacks: ask for the approved card to release something else.
	mutants := map[string]spec.Request{
		"request B (another sha)": b,
		"A with changed params (op_hash left stale)": func() spec.Request {
			m := reqA
			m.Params = map[string]any{"sha": strings.Repeat("e", 40)}
			return m
		}(),
		"A with another target": func() spec.Request {
			m := reqA
			m.Target = spec.Target{Adapter: "wsl-host", Ref: "prod"}
			return m
		}(),
		"A with another op": func() spec.Request {
			m := reqA
			m.Op = "mail.send"
			return m
		}(),
		"A under another request id": func() spec.Request {
			m := reqA
			m.RequestID = "q-999999"
			return m
		}(),
		"A from another run": func() spec.Request {
			m := reqA
			m.Requester.RunID = "r-0000"
			return m
		}(),
		"A from the orchestrator": func() spec.Request {
			m := reqA
			m.Requester = spec.Requester{Kind: "orchestrator", ID: "main"}
			return m
		}(),
	}
	for name, m := range mutants {
		t.Run(name, func(t *testing.T) {
			err := x.consume(a, m)
			wantCode(t, err, approvals.CodeHashMismatch)
			if st := x.state(a); st != approvals.StateApproved {
				t.Fatalf("a refused consume left the approval %s, want it unused", st)
			}
		})
	}

	// A decided card cannot be used for B by asking for B's own card either.
	bCard := x.card(b)
	if st := x.state(bCard); st != approvals.StatePending {
		t.Fatalf("B's card is %s: approving A decided B", st)
	}
	wantCode(t, x.consume(bCard, b), approvals.CodeApprovalRequired)

	// A challenge made for A cannot approve B, and a response made for one
	// challenge fails for another.
	chA := mustBegin(t, x, x.card(x.req(nil)))
	cardC := x.card(x.req(nil))
	_, err := x.answer(cardC, chA, engSig(chA.Raw))
	wantCode(t, err, approvals.CodeWrongRequest)
	cardD := x.card(x.req(nil))
	chD := mustBegin(t, x, cardD)
	_, err = x.answer(cardD, chD, engSig([]byte("another challenge")))
	wantCode(t, err, approvals.CodeAssertion)
	if st := x.state(cardD); st != approvals.StatePending {
		t.Fatalf("a wrong assertion decided the card: %s", st)
	}
	// A challenge is single use.
	cardE := x.card(x.req(nil))
	chE := mustBegin(t, x, cardE)
	if _, err := x.answer(cardE, chE, engSig(chE.Raw)); err != nil {
		t.Fatal(err)
	}
	_, err = x.answer(cardE, chE, engSig(chE.Raw))
	wantCode(t, err, approvals.CodeChallenge)

	// Control: the approved card does release exactly the request it was made for.
	if err := x.consume(a, reqA); err != nil {
		t.Fatalf("control: A under its own approval was refused: %v", err)
	}
	if st := x.state(a); st != approvals.StateConsumed {
		t.Fatalf("state %s", st)
	}
}

func mustBegin(t *testing.T, x *eng, a *approvals.Approval) *approvals.Challenge {
	t.Helper()
	ch, err := x.begin(a)
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

// ---- RT-11 (c), (j): replay -----------------------------------------------------------------

func TestRT11ReplayOfAConsumedApproval(t *testing.T) {
	x := newEng(t, approvals.Limits{})
	r := x.req(nil)
	a := x.card(r)
	x.mustApprove(a)
	if err := x.consume(a, r); err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		wantCode(t, x.consume(a, r), approvals.CodeConsumed)
		_ = i
	}

	// Twenty callers race for one approval: exactly one wins.
	r2 := x.req(nil)
	a2 := x.card(r2)
	x.mustApprove(a2)
	var wins, consumed, other atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := x.consume(a2, r2)
			var ref *approvals.Refusal
			switch {
			case err == nil:
				wins.Add(1)
			case errors.As(err, &ref) && ref.Code == approvals.CodeConsumed:
				consumed.Add(1)
			default:
				other.Add(1)
				t.Errorf("unexpected: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 || consumed.Load() != 19 || other.Load() != 0 {
		t.Fatalf("%d wins, %d consumed, %d other; want 1, 19, 0", wins.Load(), consumed.Load(), other.Load())
	}

	// A decided card cannot be decided again: approving twice, or approving a
	// denied card, is refused and changes nothing.
	r3 := x.req(nil)
	a3 := x.card(r3)
	x.mustApprove(a3)
	_, err := x.approve(a3)
	wantCode(t, err, approvals.CodeConsumed)
	r4 := x.req(nil)
	a4 := x.card(r4)
	if _, err := x.e.Deny(context.Background(), approvals.DenyInput{ApprovalID: a4.ID, Actor: operator, Reason: "no"}); err != nil {
		t.Fatal(err)
	}
	_, err = x.approve(a4)
	wantCode(t, err, approvals.CodeDenied)
	wantCode(t, x.consume(a4, r4), approvals.CodeDenied)
}

// ---- RT-13 -----------------------------------------------------------------

func TestRT13NoTokenCanDecide(t *testing.T) {
	x := newEng(t, approvals.Limits{})
	r := x.req(nil)
	a := x.card(r)
	tokens := []approvals.Actor{
		{Kind: approvals.ActorRun, RunID: "r-7f3a"},                     // the requester's own run
		{Kind: approvals.ActorRun, RunID: "r-0000"},                     // another run
		{Kind: approvals.ActorOrchestrator, ID: "main"},                 // The orchestrator
		{Kind: approvals.ActorApprover, ApproverRow: 0, ApproverID: ""}, // a forged approver without a row
	}
	for i, actor := range tokens {
		name := fmt.Sprintf("%s-%d", actor.Kind, i)
		t.Run(name, func(t *testing.T) {
			before := len(x.stopCodes())
			_, err := x.e.BeginDecision(context.Background(), approvals.BeginInput{ApprovalID: a.ID, Actor: actor, Origin: engOrigin, Binding: []byte("browser")})
			if actor.Kind == approvals.ActorApprover {
				if err == nil {
					t.Fatal("an approver without a row began a decision")
				}
				return
			}
			ref := wantCode(t, err, approvals.CodeBreach)
			if ref.Stop != approvals.StopBreach {
				t.Fatalf("stop %q", ref.Stop)
			}
			if got := x.stopCodes(); len(got) != before+1 || got[len(got)-1] != approvals.StopBreach {
				t.Fatalf("no POLICY_BREACH stop raised: %v", got)
			}
			// Approve with a valid challenge another (real) approver made: still refused.
			ch := mustBegin(t, x, a)
			_, err = x.e.Approve(context.Background(), approvals.ApproveInput{ApprovalID: a.ID, ChallengeID: ch.ID, Actor: actor, Origin: engOrigin,
				Binding: []byte("browser"), Response: engSig(ch.Raw)})
			wantCode(t, err, approvals.CodeBreach)
			_, err = x.e.Deny(context.Background(), approvals.DenyInput{ApprovalID: a.ID, Actor: actor, Reason: "token says no"})
			wantCode(t, err, approvals.CodeBreach)
		})
	}
	if st := x.state(a); st != approvals.StatePending {
		t.Fatalf("a token decided the card: %s", st)
	}
	if x.led.named("op.approve") != 0 {
		t.Fatal("a token's attempt produced an op.approve (decision) event")
	}
	wantCode(t, x.consume(a, r), approvals.CodeApprovalRequired)

	// Control: the operator can.
	x.mustApprove(a)
	if err := x.consume(a, r); err != nil {
		t.Fatal(err)
	}
}

// ---- RT-11 (d), (f): expiry and policy change -----------------------------------------------------------------

func TestRT11ExpiryAndPolicyChange(t *testing.T) {
	chap := approvals.Limits{RequestTTL: 30 * time.Minute, ApprovalTTL: 5 * time.Minute, ChallengeTTL: 2 * time.Minute}
	t.Run("an approval left unused expires", func(t *testing.T) {
		x := newEng(t, chap)
		r := x.req(nil)
		a := x.card(r)
		x.mustApprove(a)
		x.advance(8 * time.Minute) // past challenge + approval TTL (7 minutes)
		wantCode(t, x.consume(a, r), approvals.CodeExpired)
		if x.led.named("op.approve") == 0 {
			t.Fatal("no decision event")
		}
	})
	t.Run("an unanswered card expires and cannot be approved late", func(t *testing.T) {
		x := newEng(t, chap)
		r := x.req(nil)
		a := x.card(r)
		ch := mustBegin(t, x, a)
		x.advance(31 * time.Minute)
		_, err := x.answer(a, ch, engSig(ch.Raw))
		if err == nil {
			t.Fatal("a card was approved after its request expired")
		}
		wantCode(t, x.consume(a, r), approvals.CodeExpired)
		_, err = x.approve(a)
		wantCode(t, err, approvals.CodeExpired)
	})
	t.Run("a challenge answered late is refused", func(t *testing.T) {
		x := newEng(t, chap)
		a := x.card(x.req(nil))
		ch := mustBegin(t, x, a)
		x.advance(3 * time.Minute)
		_, err := x.answer(a, ch, engSig(ch.Raw))
		wantCode(t, err, approvals.CodeChallenge)
		if st := x.state(a); st != approvals.StatePending {
			t.Fatalf("state %s", st)
		}
	})
	t.Run("the request document's own expiry caps the card", func(t *testing.T) {
		x := newEng(t, chap)
		r := x.req(func(r *spec.Request) { r.ExpiresAt = tsOf(x.now().Add(2 * time.Minute)) })
		a := x.card(r)
		x.advance(3 * time.Minute)
		wantCode(t, x.consume(a, r), approvals.CodeExpired)
	})
	t.Run("the policy changes between the card and the decision", func(t *testing.T) {
		x := newEng(t, chap)
		a := x.card(x.req(nil))
		x.policy.Store("baseline-2026.10.2")
		_, err := x.approve(a)
		wantCode(t, err, approvals.CodePolicyRefused)
	})
	t.Run("the policy changes between the decision and the release", func(t *testing.T) {
		x := newEng(t, chap)
		r := x.req(nil)
		a := x.card(r)
		x.mustApprove(a)
		x.policy.Store("baseline-2026.10.2")
		wantCode(t, x.consume(a, r), approvals.CodePolicyRefused)
		if st := x.state(a); st != approvals.StateApproved {
			t.Fatalf("state %s: a refused release must not consume", st)
		}
	})
	t.Run("an expired card makes the op hash sticky", func(t *testing.T) {
		x := newEng(t, chap)
		r := x.req(nil)
		x.card(r)
		x.advance(31 * time.Minute)
		r2 := r
		r2.RequestID = "q-880000"
		r2.RequestedAt, r2.ExpiresAt = tsOf(x.now()), tsOf(x.now().Add(time.Hour))
		h, _ := spec.OpHash(r2)
		r2.OpHash = h
		res := x.request(r2)
		if res.Refusal == nil {
			t.Fatal("asking again right after an unanswered card made a new card")
		}
		if res.Refusal.RetryAfter <= 0 {
			t.Fatalf("no retry-after: %+v", res.Refusal)
		}
	})
}

// ---- RT-15 -----------------------------------------------------------------

func TestRT15PushBomb(t *testing.T) {
	t.Run("per-run cap raises APPROVAL_FLOOD", func(t *testing.T) {
		x := newEng(t, approvals.Limits{})
		x.card(x.req(nil))
		x.card(x.req(nil))
		for i := range 10 {
			res := x.request(x.req(nil))
			if res.Refusal == nil || res.Refusal.Code != approvals.CodePolicyRefused || res.Refusal.Stop != approvals.StopFlood || res.Refusal.RetryAfter <= 0 {
				t.Fatalf("request %d over the cap: %+v", i, res.Refusal)
			}
		}
		if n, _ := x.e.PendingCount(context.Background()); n != 2 {
			t.Fatalf("%d cards pending, want 2", n)
		}
		flood := 0
		for _, c := range x.stopCodes() {
			if c == approvals.StopFlood {
				flood++
			}
		}
		if flood != 10 {
			t.Fatalf("%d APPROVAL_FLOOD stops for 10 refused requests", flood)
		}
		if len(x.notif.wakes) != 2 {
			t.Fatalf("%d wake-ups for 2 cards: a refused request must not ping the phone", len(x.notif.wakes))
		}
	})
	t.Run("per-project and total caps hold across runs", func(t *testing.T) {
		x := newEng(t, approvals.Limits{})
		for i := range 5 {
			run := fmt.Sprintf("r-%04d", i)
			x.card(x.req(func(r *spec.Request) { r.Requester.RunID = run }))
		}
		res := x.request(x.req(func(r *spec.Request) { r.Requester.RunID = "r-9999" }))
		if res.Refusal == nil || res.Refusal.Stop != approvals.StopFlood || !strings.Contains(res.Refusal.Why, "this project") {
			t.Fatalf("%+v", res.Refusal)
		}
		// Another project may still ask until the total cap.
		for i := range 5 {
			run := fmt.Sprintf("r-1%03d", i)
			x.card(x.req(func(r *spec.Request) { r.Project = "other-shop"; r.Requester.RunID = run }))
		}
		res = x.request(x.req(func(r *spec.Request) { r.Project = "third-shop"; r.Requester.RunID = "r-8888" }))
		if res.Refusal == nil || res.Refusal.Stop != approvals.StopFlood || !strings.Contains(res.Refusal.Why, "Chaperone") {
			t.Fatalf("%+v", res.Refusal)
		}
	})
	t.Run("the same request twenty times is one card and one wake-up", func(t *testing.T) {
		x := newEng(t, approvals.Limits{})
		r := x.req(nil)
		first := x.card(r)
		for range 20 {
			again := r
			again.RequestID = fmt.Sprintf("q-7%05d", x.seq)
			x.mu.Lock()
			x.seq++
			x.mu.Unlock()
			h, _ := spec.OpHash(again)
			again.OpHash = h
			res := x.request(again)
			if res.Refusal != nil || res.Created || res.Approval.ID != first.ID {
				t.Fatalf("dedupe: %+v", res)
			}
		}
		if n, _ := x.e.PendingCount(context.Background()); n != 1 || len(x.notif.wakes) != 1 {
			t.Fatalf("%d cards, %d wake-ups", n, len(x.notif.wakes))
		}
	})
	t.Run("sticky deny: a denied action stays refused, but only that action", func(t *testing.T) {
		x := newEng(t, approvals.Limits{})
		r := x.req(nil)
		a := x.card(r)
		if _, err := x.e.Deny(context.Background(), approvals.DenyInput{ApprovalID: a.ID, Actor: operator, Reason: "no"}); err != nil {
			t.Fatal(err)
		}
		for i := range 5 {
			again := r
			again.RequestID = fmt.Sprintf("q-6%05d", i)
			h, _ := spec.OpHash(again)
			again.OpHash = h
			res := x.request(again)
			if res.Refusal == nil || res.Refusal.Code != approvals.CodeDenied || res.Refusal.RetryAfter <= 0 {
				t.Fatalf("attempt %d after a denial: %+v", i, res)
			}
		}
		// A different action is a new question.
		if res := x.request(x.req(nil)); res.Refusal != nil {
			t.Fatalf("a different action was refused: %+v", res.Refusal)
		}
		// After the cooldown the same action may be asked again.
		x.advance(61 * time.Minute)
		again := r
		again.RequestID = "q-650000"
		again.RequestedAt, again.ExpiresAt = tsOf(x.now()), tsOf(x.now().Add(time.Hour))
		h, _ := spec.OpHash(again)
		again.OpHash = h
		if res := x.request(again); res.Refusal != nil {
			t.Fatalf("still refused after the cooldown: %+v", res.Refusal)
		}
	})
	t.Run("a wake-up carries no parameter, no link", func(t *testing.T) {
		x := newEng(t, approvals.Limits{})
		secret := "do-not-leak-" + strings.Repeat("x", 20)
		r := x.req(func(r *spec.Request) { r.Params = map[string]any{"sha": strings.Repeat("a", 40), "note": secret} })
		_ = r
		x.card(x.req(func(r *spec.Request) {
			r.Reason = secret
			r.Params = map[string]any{"sha": strings.Repeat("b", 40)}
		}))
		x.notif.mu.Lock()
		defer x.notif.mu.Unlock()
		if len(x.notif.wakes) != 1 {
			t.Fatalf("%d wake-ups", len(x.notif.wakes))
		}
		w := x.notif.wakes[0]
		if fmt.Sprint(w) == "" || strings.Contains(fmt.Sprintf("%+v", w), secret) || strings.Contains(fmt.Sprintf("%+v", w), strings.Repeat("b", 40)) {
			t.Fatalf("the wake-up holds request content: %+v", w)
		}
		push, err := notify.Build(w)
		if err != nil {
			t.Fatal(err)
		}
		if s := fmt.Sprintf("%+v", push); strings.Contains(s, secret) || strings.Contains(s, "http") {
			t.Fatalf("the push holds content or a link: %s", s)
		}
	})
}

// ---- RT-21: stored card tampered -----------------------------------------------------------------

// A card edited in the database after it was shown (a bug, a bad migration,
// anything with write access) is caught before it can be approved or consumed.
// Two layers: the table's triggers refuse the edit; and if the triggers are
// dropped (the worst case: write access to the file), the engine re-derives the
// op hash and the card text from the stored request and refuses.
func TestRT21StoredCardTamperIsCaught(t *testing.T) {
	edit := map[string]string{
		"the op hash":     `UPDATE approvals SET op_hash = 'sha256:` + strings.Repeat("0", 64) + `' WHERE approval_id = ?`,
		"the params":      `UPDATE approvals SET request_json = replace(request_json, 'sha', 'sh_') WHERE approval_id = ?`,
		"the card text":   `UPDATE approvals SET card_text = card_text || ' (and send the money)' WHERE approval_id = ?`,
		"the display sum": `UPDATE approvals SET display_sha256 = 'sha256:` + strings.Repeat("1", 64) + `' WHERE approval_id = ?`,
	}
	for name, q := range edit {
		t.Run(name+" before the decision", func(t *testing.T) {
			x := newEng(t, approvals.Limits{})
			a := x.card(x.req(nil))
			tamper(t, x, q, a)
			_, err := x.begin(a)
			if err == nil {
				t.Fatal("a challenge was made for a tampered card")
			}
			var ref *approvals.Refusal
			if !errors.As(err, &ref) || (ref.Code != approvals.CodeHashMismatch && ref.Code != approvals.CodeDisplayMismatch) {
				t.Fatalf("%v", err)
			}
		})
		t.Run(name+" after the decision", func(t *testing.T) {
			x := newEng(t, approvals.Limits{})
			r := x.req(nil)
			a := x.card(r)
			x.mustApprove(a)
			tamper(t, x, q, a)
			err := x.consume(a, r)
			if err == nil {
				t.Fatal("a tampered approval was consumed")
			}
			var ref *approvals.Refusal
			if !errors.As(err, &ref) || (ref.Code != approvals.CodeHashMismatch && ref.Code != approvals.CodeDisplayMismatch) {
				t.Fatalf("%v", err)
			}
		})
	}
}

// tamper applies an edit the way an attacker with write access would: first
// as is (the trigger must refuse it), then with the immutability trigger gone.
func tamper(t *testing.T, x *eng, q string, a *approvals.Approval) {
	t.Helper()
	if _, err := x.db.SQL().Exec(q, a.ID); err == nil {
		t.Fatal("the database accepted an edit of a stored card")
	} else if !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("the edit failed for another reason: %v", err)
	}
	if _, err := x.db.SQL().Exec(`DROP TRIGGER approvals_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := x.db.SQL().Exec(q, a.ID); err != nil {
		t.Fatal(err)
	}
}
