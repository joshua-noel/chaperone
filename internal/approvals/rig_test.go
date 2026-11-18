package approvals

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/notify"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// fakeLedger records the events the engine appends. failNext makes the next
// append fail, to prove a decision rolls back with its ledger event.
type fakeLedger struct {
	mu       sync.Mutex
	events   []LedgerEvent
	failNext bool
}

func (l *fakeLedger) AppendTx(_ context.Context, _ *store.Tx, ev LedgerEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failNext {
		l.failNext = false
		return errors.New("ledger unavailable")
	}
	l.events = append(l.events, ev)
	return nil
}

func (l *fakeLedger) all() []LedgerEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]LedgerEvent(nil), l.events...)
}

// fakeVerifier accepts a response that is exactly "sig:" + the hex of the
// challenge it was asked about, so an assertion made for one challenge fails for any other.
type fakeVerifier struct {
	mu      sync.Mutex
	seen    []AssertionInput
	channel string
}

func sigFor(challenge []byte) []byte { return []byte("sig:" + hex.EncodeToString(challenge)) }

func (v *fakeVerifier) VerifyAssertion(_ context.Context, in AssertionInput) (AssertionEvidence, error) {
	v.mu.Lock()
	v.seen = append(v.seen, in)
	ch := v.channel
	v.mu.Unlock()
	if string(in.Response) != string(sigFor(in.Challenge)) {
		return AssertionEvidence{}, &AssertionError{Reason: "bad_signature"}
	}
	if ch == "" {
		ch = "pc"
	}
	return AssertionEvidence{Channel: ch, CredentialID: []byte("0123456789abcdef0123456789abcdef"), RPID: "localhost", Origin: in.Origin}, nil
}

type fakeNotifier struct {
	mu    sync.Mutex
	wakes []notify.Wake
}

func (n *fakeNotifier) Notify(_ context.Context, w notify.Wake) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.wakes = append(n.wakes, w)
	return nil
}

func (n *fakeNotifier) all() []notify.Wake {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]notify.Wake(nil), n.wakes...)
}

const (
	testOrigin = "http://localhost:55398"
	testPolicy = "baseline-2026.10.1"
)

type rig struct {
	t     *testing.T
	db    *store.DB
	e     *Engine
	led   *fakeLedger
	ver   *fakeVerifier
	notif *fakeNotifier

	mu      sync.Mutex
	clock   time.Time
	decided []Decision
	stops   []Stop
	alerts  []Alert
	seq     int
}

type rigOption func(*Config)

func newRig(t *testing.T, opts ...rigOption) *rig {
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
	r := &rig{t: t, db: db, led: &fakeLedger{}, ver: &fakeVerifier{}, notif: &fakeNotifier{},
		clock: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	cfg := Config{
		DB: db, Ledger: r.led, Catalog: PhaseOneCatalog(), Verifier: r.ver, Notifier: r.notif,
		Now: r.now,
		OnDecided: func(_ context.Context, _ *store.Tx, d Decision) error {
			r.mu.Lock()
			r.decided = append(r.decided, d)
			r.mu.Unlock()
			return nil
		},
		Stop: func(_ context.Context, _ *store.Tx, s Stop) error {
			r.mu.Lock()
			r.stops = append(r.stops, s)
			r.mu.Unlock()
			return nil
		},
		Alert: func(a Alert) { r.mu.Lock(); r.alerts = append(r.alerts, a); r.mu.Unlock() },
	}
	for _, o := range opts {
		o(&cfg)
	}
	if r.e, err = New(cfg); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *rig) now() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.clock }

func (r *rig) advance(d time.Duration) { r.mu.Lock(); r.clock = r.clock.Add(d); r.mu.Unlock() }

func (r *rig) snapshot() (decided []Decision, stops []Stop, alerts []Alert) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Decision(nil), r.decided...), append([]Stop(nil), r.stops...), append([]Alert(nil), r.alerts...)
}

var approver = Actor{Kind: ActorApprover, ApproverRow: 1, ApproverID: "operator"}

// mkReq builds a valid request document with its op_hash. mutate may change it
// before the hash is computed.
func (r *rig) mkReq(mutate func(*spec.Request)) spec.Request {
	r.t.Helper()
	r.mu.Lock()
	r.seq++
	n := r.seq
	r.mu.Unlock()
	now := r.now()
	req := spec.Request{
		SpecVersion: spec.SpecVersion, Type: "op.request", RequestID: fmt.Sprintf("q-%06d", n),
		Requester: spec.Requester{Kind: "run", RunID: "r-7f3a", TokenJTI: "n8Gf3kQ2xV7bTz1LwA9cYd", Profile: "host-interim"},
		Project:   "acme-shop", Op: "deploy", Target: spec.Target{Adapter: "wsl-host", Ref: "pilot"},
		Params:      map[string]any{"sha": fmt.Sprintf("%040x", n)},
		Reason:      "Ship the fix.",
		RequestedAt: ts(now), ExpiresAt: ts(now.Add(time.Hour)),
	}
	if mutate != nil {
		mutate(&req)
	}
	h, err := spec.OpHash(req)
	if err != nil {
		r.t.Fatal(err)
	}
	req.OpHash = h
	return req
}

func passed(names ...string) []spec.ApprovalCheck {
	var out []spec.ApprovalCheck
	for _, n := range names {
		out = append(out, spec.ApprovalCheck{Name: n, Passed: true, Detail: "ok"})
	}
	return out
}

// request makes a card the way the op state machine does: in one transaction, effects after the commit.
func (r *rig) request(req spec.Request) Result {
	r.t.Helper()
	var res Result
	err := r.e.Atomic(context.Background(), func(ctx context.Context, tx *store.Tx) (Effects, error) {
		var err error
		res, err = r.e.RequestTx(ctx, tx, RequestInput{Request: req, PolicyVersion: testPolicy, Checks: passed("backup.fresh", "ci.green")})
		return res.Effects, err
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return res
}

// mustCard requests a card and fails when none was made.
func (r *rig) mustCard(req spec.Request) *Approval {
	r.t.Helper()
	res := r.request(req)
	if res.Refusal != nil {
		r.t.Fatalf("request refused: %v", res.Refusal)
	}
	return res.Approval
}

// approve runs begin and finish for one card with an honest verifier.
func (r *rig) approve(a *Approval) (*Approval, error) {
	r.t.Helper()
	ch, err := r.e.BeginDecision(context.Background(), BeginInput{ApprovalID: a.ID, Actor: approver, Origin: testOrigin, Binding: []byte("browser")})
	if err != nil {
		return nil, err
	}
	return r.e.Approve(context.Background(), ApproveInput{ApprovalID: a.ID, ChallengeID: ch.ID, Actor: approver, Origin: testOrigin,
		Binding: []byte("browser"), Response: sigFor(ch.Raw)})
}

func (r *rig) mustApprove(a *Approval) *Approval {
	r.t.Helper()
	done, err := r.approve(a)
	if err != nil {
		r.t.Fatalf("approve: %v", err)
	}
	return done
}

func (r *rig) consume(a *Approval, req spec.Request) error {
	r.t.Helper()
	return r.e.Atomic(context.Background(), func(ctx context.Context, tx *store.Tx) (Effects, error) {
		return r.e.ConsumeTx(ctx, tx, ConsumeInput{ApprovalID: a.ID, Request: req})
	})
}

// wantRefusal fails unless err is a *Refusal with the code.
func wantRefusal(t *testing.T, err error, code string) *Refusal {
	t.Helper()
	var ref *Refusal
	if !errors.As(err, &ref) {
		t.Fatalf("got %v, want a refusal %s", err, code)
	}
	if ref.Code != code {
		t.Fatalf("refusal code %s (%s), want %s", ref.Code, ref.Why, code)
	}
	return ref
}

func (r *rig) state(id string) State {
	r.t.Helper()
	a, err := r.e.Get(context.Background(), id)
	if err != nil || a == nil {
		r.t.Fatalf("get %s: %v", id, err)
	}
	return a.State
}

func contains(s string, subs ...string) bool {
	for _, x := range subs {
		if !strings.Contains(s, x) {
			return false
		}
	}
	return true
}
