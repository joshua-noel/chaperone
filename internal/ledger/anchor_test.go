package ledger

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/notify"
	"github.com/joshua-noel/chaperone/internal/redact"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

type manualClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *manualClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type testSigner struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newTestSigner(t testing.TB) *testSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testSigner{priv: priv, pub: pub}
}

func (s *testSigner) KeyID() string { return KeyID(s.pub) }
func (s *testSigner) Sign(_ context.Context, msg []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, msg), nil
}

type fakeNotifier struct {
	mu   sync.Mutex
	got  []notify.Anchor
	fail error
}

func (n *fakeNotifier) NotifyAnchor(_ context.Context, a notify.Anchor) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.fail != nil {
		return n.fail
	}
	n.got = append(n.got, a)
	return nil
}

func (n *fakeNotifier) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.got)
}

type fakeAlerter struct {
	mu       sync.Mutex
	raised   []string
	resolved []string
}

func (f *fakeAlerter) Raise(_ context.Context, key, _ string) {
	f.mu.Lock()
	f.raised = append(f.raised, key)
	f.mu.Unlock()
}

func (f *fakeAlerter) Resolve(_ context.Context, key string) {
	f.mu.Lock()
	f.resolved = append(f.resolved, key)
	f.mu.Unlock()
}

func (f *fakeAlerter) raisedCount(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, k := range f.raised {
		if k == key {
			n++
		}
	}
	return n
}

type anchorEnv struct {
	t      *testing.T
	db     *store.DB
	l      *Ledger
	export string
	clk    *manualClock
	signer *testSigner
	notes  *fakeNotifier
	alerts *fakeAlerter
	a      *Anchors
}

// newAnchorEnv opens a ledger on a manual clock with a scheduler wired to
// fakes. instance picks the chain id (chaperone.<instance>).
func newAnchorEnv(t *testing.T, instance string, signer *testSigner) *anchorEnv {
	t.Helper()
	dir := t.TempDir()
	db := openDB(t, filepath.Join(dir, "state.db"))
	t.Cleanup(func() { db.Close() })
	clk := &manualClock{t: epoch}
	export := filepath.Join(dir, "export")
	l, err := Open(context.Background(), db, Config{Instance: instance, Version: "0.0.0", ExportDir: export, Redactor: redact.NewRegistry(), Clock: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	if signer == nil {
		signer = newTestSigner(t)
	}
	e := &anchorEnv{t: t, db: db, l: l, export: export, clk: clk, signer: signer, notes: &fakeNotifier{}, alerts: &fakeAlerter{}}
	e.a, err = NewAnchors(AnchorsConfig{Ledger: l, Signer: signer, Notifier: e.notes, Alerts: e.alerts, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *anchorEnv) append(n int, project string) {
	e.t.Helper()
	for i := range n {
		d := opReq(i)
		d.Project = project
		if _, err := e.l.Append(context.Background(), d); err != nil {
			e.t.Fatalf("append %d: %v", i, err)
		}
	}
}

func (e *anchorEnv) records() []AnchorRecord {
	e.t.Helper()
	recs, bad, torn, err := ReadAnchorRecords(AnchorsPath(e.export, e.l.Chain()))
	if err != nil || len(bad) > 0 || torn {
		e.t.Fatalf("records: %v %v torn=%v", err, bad, torn)
	}
	return recs
}

func (e *anchorEnv) anchorsRep(records []AnchorRecord, useFile bool) AnchorReport {
	e.t.Helper()
	opt := AnchorVerifyOptions{Chain: e.l.Chain(), Records: records, Keys: []ed25519.PublicKey{e.signer.pub}, Now: e.clk.Now()}
	if useFile {
		opt.ExportDir = e.export
	}
	rep, err := VerifyAnchors(context.Background(), e.db, opt)
	if err != nil {
		e.t.Fatal(err)
	}
	return rep
}

func anchorCodes(r AnchorReport) []string {
	var out []string
	for _, p := range r.Problems {
		out = append(out, p.Code)
	}
	return out
}

func hasAnchorCode(r AnchorReport, code string) bool {
	for _, p := range r.Problems {
		if p.Code == code {
			return true
		}
	}
	return false
}

func TestAnchorIsCreatedSignedAndDeliveredToBothPlaces(t *testing.T) {
	e := newAnchorEnv(t, "host1", nil)
	ctx := context.Background()
	e.append(5, "storefront")
	e.a.RunOnce(ctx)

	// The event: kind offline-copy, covering seq 4.
	evs, err := anchorEvents(ctx, e.db.SQL(), e.l.Chain(), -1)
	if err != nil || len(evs) != 1 {
		t.Fatalf("anchor events = %v, %v", evs, err)
	}
	if evs[0].HeadSeq != 4 || evs[0].Seq != 5 {
		t.Fatalf("anchor covers seq %d at seq %d, want 4 at 5", evs[0].HeadSeq, evs[0].Seq)
	}
	seq, hash, _ := e.l.Head(ctx)
	if seq != 5 {
		t.Fatalf("head seq = %d", seq)
	}

	// Place 1: the signed record in the backup set.
	recs := e.records()
	if len(recs) != 1 {
		t.Fatalf("records = %d", len(recs))
	}
	r := recs[0]
	if r.Chain != e.l.Chain() || r.HeadSeq != 4 || r.AnchorSeq != 5 || r.AnchorHash != hash || r.KeyID != e.signer.KeyID() {
		t.Fatalf("record = %+v (head hash %s)", r, hash)
	}
	if !r.Verify(e.signer.pub) {
		t.Fatal("the record's signature does not verify with the ledger key")
	}
	if r.Verify(newTestSigner(t).pub) {
		t.Fatal("the record verified under another key")
	}
	line, _ := r.Line()
	back, err := ParseAnchorRecord(line)
	if err != nil || back != r {
		t.Fatalf("round trip: %v %+v", err, back)
	}

	// Place 2: the phone gets chain, head_seq, head_hash (and the signature).
	if e.notes.count() != 1 {
		t.Fatalf("pushes = %d, want 1", e.notes.count())
	}
	got := e.notes.got[0]
	if got.Chain != e.l.Chain() || got.HeadSeq != r.HeadSeq || got.HeadHash != r.HeadHash || got.Sig != r.Sig || got.KeyID != r.KeyID {
		t.Fatalf("push = %+v, record = %+v", got, r)
	}
	if _, err := notify.BuildAnchor(got); err != nil {
		t.Fatalf("the push is not valid for notify: %v", err)
	}

	// The chain still verifies, and so do the anchors.
	if rep, err := e.l.Verify(ctx, true); err != nil || !rep.OK() {
		t.Fatalf("verify: %v %v", err, rep.Err())
	}
	if rep := e.anchorsRep(nil, true); !rep.OK() || rep.Checked != 1 {
		t.Fatalf("anchors: %+v", rep)
	}

	// A second pass the same day writes and sends nothing more.
	e.clk.advance(time.Hour)
	e.a.RunOnce(ctx)
	if n := len(e.records()); n != 1 || e.notes.count() != 1 {
		t.Fatalf("records = %d, pushes = %d after a second pass", n, e.notes.count())
	}
}

func TestAnchorDailyAndAfterDeploy(t *testing.T) {
	e := newAnchorEnv(t, "host1", nil)
	ctx := context.Background()
	e.append(3, "storefront")
	e.a.RunOnce(ctx) // anchor 1

	// Not due after 23 hours.
	e.clk.advance(23 * time.Hour)
	e.a.RunOnce(ctx)
	if len(e.records()) != 1 {
		t.Fatalf("anchored again before 24 h")
	}
	// Due after 24 hours.
	e.clk.advance(2 * time.Hour)
	e.a.RunOnce(ctx)
	if len(e.records()) != 2 || e.notes.count() != 2 {
		t.Fatalf("records = %d pushes = %d after a day", len(e.records()), e.notes.count())
	}

	// A finished deploy makes an anchor at once.
	e.exec(`INSERT INTO ops (id, state, op, project, target_adapter, target_ref, params_json, op_hash, requester_kind, requester_key, orchestrator_id,
		class, reversibility, policy_version, requested_at, expires_at, updated_at)
		VALUES ('q-dep001', 'succeeded', 'deploy', 'storefront', 'deploy', 'x', '{}', ?, 'orchestrator', 'orchestrator:o1', 'o1', 'high', 'compensable', '1', 0, 0, 0)`,
		"sha256:"+strings.Repeat("cd", 32))
	// A non-deploy result does not count.
	e.exec(`INSERT INTO ops (id, state, op, project, target_adapter, target_ref, params_json, op_hash, requester_kind, requester_key, orchestrator_id,
		class, reversibility, policy_version, requested_at, expires_at, updated_at)
		VALUES ('q-merge1', 'succeeded', 'pr.merge', 'storefront', 'pr', 'x', '{}', ?, 'orchestrator', 'orchestrator:o1', 'o1', 'high', 'compensable', '1', 0, 0, 0)`,
		"sha256:"+strings.Repeat("ef", 32))
	e.opResult("q-merge1")
	e.clk.advance(time.Minute)
	e.a.RunOnce(ctx)
	if len(e.records()) != 2 {
		t.Fatalf("a merge result made an anchor")
	}
	e.opResult("q-dep001")
	e.clk.advance(time.Minute)
	e.a.RunOnce(ctx)
	recs := e.records()
	if len(recs) != 3 || e.notes.count() != 3 {
		t.Fatalf("records = %d pushes = %d after a deploy", len(recs), e.notes.count())
	}
	// The deploy's result is covered by the new anchor.
	var resultSeq int64
	if err := e.db.SQL().QueryRow(`SELECT max(seq) FROM ledger_events WHERE event_name = 'op.result' AND chain = ?`, e.l.Chain()).Scan(&resultSeq); err != nil {
		t.Fatal(err)
	}
	if recs[2].HeadSeq < resultSeq {
		t.Fatalf("the post-deploy anchor covers seq %d, the deploy result is seq %d", recs[2].HeadSeq, resultSeq)
	}
	// The anchor event is exported in the same pass, inside the ExportEvery gap.
	if r, err := e.l.Verify(ctx, true); err != nil || !r.OK() || r.Chains[0].Unexported != 0 {
		t.Fatalf("the post-deploy anchor was not exported at once: %v %+v", err, r.Chains)
	}
	// And it does not repeat.
	e.clk.advance(time.Minute)
	e.a.RunOnce(ctx)
	if len(e.records()) != 3 {
		t.Fatalf("the same deploy made a second anchor")
	}
}

func (e *anchorEnv) exec(q string, args ...any) {
	e.t.Helper()
	if _, err := e.db.SQL().Exec(q, args...); err != nil {
		e.t.Fatalf("%s: %v", q, err)
	}
}

func (e *anchorEnv) opResult(id string) {
	e.t.Helper()
	_, err := e.l.Append(context.Background(), Draft{
		Name: "op.result", Project: "storefront",
		Attributes: map[string]any{
			"factory.request_id":      id,
			"factory.op_hash":         "sha256:" + strings.Repeat("ab", 32),
			"factory.execution_id":    "x-abc123",
			"factory.outcome":         "succeeded",
			"factory.policy_version":  "1",
			"factory.requester.kind":  "orchestrator",
			"factory.orchestrator.id": "o1",
		},
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

// The ticket's acceptance: a rewrite of every event before an anchor is
// detected by `chap ledger verify --anchor`, even when the rewritten chain is
// consistent with itself and so passes the ordinary verify.
func TestAnchorDetectsRewriteOfEveryEventBeforeIt(t *testing.T) {
	signer := newTestSigner(t)
	honest := newAnchorEnv(t, "host1", signer)
	ctx := context.Background()
	honest.append(8, "storefront")
	honest.a.RunOnce(ctx)
	copyOffBox := honest.records() // what the phone and the Drive copy hold

	// The attacker rebuilds the whole chain with other content: every event
	// before the anchor differs, and the new chain is internally consistent,
	// anchor event included.
	forged := newAnchorEnv(t, "host1", signer)
	forged.append(8, "other-project")
	if _, err := forged.l.Anchor(ctx, AnchorKindOffline, "forged"); err != nil {
		t.Fatal(err)
	}
	if rep, err := forged.l.Verify(ctx, false); err != nil || !rep.OK() {
		t.Fatalf("the forged chain should pass the ordinary verify: %v %v", err, rep.Err())
	}
	rep := forged.anchorsRep(copyOffBox, false)
	if rep.OK() || !hasAnchorCode(rep, ProblemAnchorRewritten) {
		t.Fatalf("a rewrite of every event before the anchor was not detected: %+v", rep.Problems)
	}
	// Both the covered head and the anchor event differ.
	n := 0
	for _, p := range rep.Problems {
		if p.Code == ProblemAnchorRewritten {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("rewritten findings = %d, want 2 (head and anchor event): %+v", n, rep.Problems)
	}

	// The honest chain is clean against the same copy.
	if rep := honest.anchorsRep(copyOffBox, true); !rep.OK() {
		t.Fatalf("the honest chain: %+v", rep.Problems)
	}
}

func TestAnchorDetectsRewriteInPlaceAndCutBack(t *testing.T) {
	e := newAnchorEnv(t, "host1", nil)
	ctx := context.Background()
	e.append(6, "storefront")
	e.a.RunOnce(ctx)
	e.append(4, "storefront")
	copyOffBox := e.records()

	// Cut the chain back below the anchor (guards dropped, head moved).
	cut := func() {
		for _, tr := range []string{"ledger_events_no_update", "ledger_events_no_delete", "ledger_chains_no_delete", "ledger_chains_guard"} {
			e.exec("DROP TRIGGER " + tr)
		}
		e.exec(`DELETE FROM ledger_events WHERE chain = ? AND seq >= 4`, e.l.Chain())
		e.exec(`UPDATE ledger_chains SET head_seq = 3, head_hash = (SELECT hash FROM ledger_events WHERE chain = ? AND seq = 3), exported_seq = -1 WHERE chain = ?`, e.l.Chain(), e.l.Chain())
	}
	cut()
	rep := e.anchorsRep(copyOffBox, false)
	if !hasAnchorCode(rep, ProblemAnchorCut) {
		t.Fatalf("a cut below the anchor was not detected: %v", anchorCodes(rep))
	}
}

func TestAnchorRewriteFromFirstEventIsDetected(t *testing.T) {
	e := newAnchorEnv(t, "host1", nil)
	ctx := context.Background()
	e.append(6, "storefront")
	e.a.RunOnce(ctx)
	copyOffBox := e.records()

	// Rewrite from event 0 and recompute every later hash and link, the anchor
	// event's own attributes included.
	for _, tr := range []string{"ledger_events_no_update", "ledger_events_no_delete", "ledger_chains_no_delete", "ledger_chains_guard"} {
		e.exec("DROP TRIGGER " + tr)
	}
	rs, err := e.db.SQL().Query(`SELECT seq, event FROM ledger_events WHERE chain = ? ORDER BY seq`, e.l.Chain())
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		seq  int64
		text string
	}
	var all []row
	for rs.Next() {
		var r row
		if err := rs.Scan(&r.seq, &r.text); err != nil {
			t.Fatal(err)
		}
		all = append(all, r)
	}
	rs.Close()
	prev := spec.ZeroHash
	for _, r := range all {
		m := mustTree(t, r.text)
		if r.seq == 0 {
			m["body"] = "rewritten"
		}
		if m["event_name"] == "ledger.anchor" { // keep the anchor consistent with the new chain
			attrs := m["attributes"].(map[string]any)
			attrs["factory.anchor.head_hash"] = prev
		}
		m["prev_hash"] = prev
		delete(m, "hash")
		h := mustEventHash(t, m)
		m["hash"] = h
		e.exec(`UPDATE ledger_events SET event = ?, hash = ?, prev_hash = ? WHERE chain = ? AND seq = ?`, mustJCS(t, m), h, prev, e.l.Chain(), r.seq)
		prev = h
	}
	e.exec(`UPDATE ledger_chains SET head_hash = ? WHERE chain = ?`, prev, e.l.Chain())

	// The ordinary verify is satisfied by the consistent forgery.
	if rep, err := e.l.Verify(ctx, false); err != nil || !rep.OK() {
		t.Fatalf("ordinary verify of the consistent forgery: %v %v", err, rep.Err())
	}
	rep := e.anchorsRep(copyOffBox, false)
	if !hasAnchorCode(rep, ProblemAnchorRewritten) {
		t.Fatalf("rewrite from the first event was not detected: %v", anchorCodes(rep))
	}
}

func TestVerifyAnchorsOtherProblems(t *testing.T) {
	signer := newTestSigner(t)
	e := newAnchorEnv(t, "host1", signer)
	ctx := context.Background()

	// No records at all is not a pass.
	e.append(3, "storefront")
	if rep := e.anchorsRep(nil, true); rep.OK() || !hasAnchorCode(rep, ProblemAnchorNone) {
		t.Fatalf("no records: %v", anchorCodes(rep))
	}
	e.a.RunOnce(ctx)
	good := e.records()[0]

	// A signature that does not verify.
	bad := good
	bad.HeadSeq++
	if rep := e.anchorsRep([]AnchorRecord{bad}, false); !hasAnchorCode(rep, ProblemAnchorSig) {
		t.Fatalf("edited record: %v", anchorCodes(rep))
	}
	// A key that was not supplied.
	other := newTestSigner(t)
	rep, err := VerifyAnchors(ctx, e.db, AnchorVerifyOptions{Chain: e.l.Chain(), Records: []AnchorRecord{good}, Keys: []ed25519.PublicKey{other.pub}, Now: e.clk.Now()})
	if err != nil || !hasAnchorCode(rep, ProblemAnchorKey) {
		t.Fatalf("unknown key: %v %v", err, rep.Problems)
	}
	// A record of another chain.
	foreign := good
	foreign.Chain = "chaperone.elsewhere"
	if rep := e.anchorsRep([]AnchorRecord{foreign}, false); !hasAnchorCode(rep, ProblemAnchorChain) {
		t.Fatalf("foreign chain: %v", anchorCodes(rep))
	}
	// An anchor event whose record was deleted from the file is found once the
	// grace period has passed, and not before.
	if err := os.Remove(AnchorsPath(e.export, e.l.Chain())); err != nil {
		t.Fatal(err)
	}
	if rep := e.anchorsRep(nil, true); hasAnchorCode(rep, ProblemAnchorMissing) {
		t.Fatalf("a fresh anchor without a record is inside the grace period")
	}
	e.clk.advance(7 * time.Hour)
	if rep := e.anchorsRep(nil, true); !hasAnchorCode(rep, ProblemAnchorMissing) {
		t.Fatalf("a missing record was not reported: %v", anchorCodes(rep))
	}
	// The copy from outside restores it.
	if rep := e.anchorsRep([]AnchorRecord{good}, true); !rep.OK() {
		t.Fatalf("with the off-box copy: %+v", rep.Problems)
	}
	// A garbled line in the file is named.
	if err := os.MkdirAll(filepath.Dir(AnchorsPath(e.export, e.l.Chain())), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(AnchorsPath(e.export, e.l.Chain()), []byte("not json\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if rep := e.anchorsRep([]AnchorRecord{good}, true); !hasAnchorCode(rep, ProblemAnchorRecord) {
		t.Fatalf("garbled line: %v", anchorCodes(rep))
	}
}

func TestAnchorRecordParsingIsStrict(t *testing.T) {
	e := newAnchorEnv(t, "host1", nil)
	e.append(2, "storefront")
	e.a.RunOnce(context.Background())
	line, _ := e.records()[0].Line()
	if _, err := ParseAnchorRecord(line); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(string) string{
		"extra member":  func(s string) string { return strings.Replace(s, `{"anchor_hash"`, `{"extra":1,"anchor_hash"`, 1) },
		"bad hash":      func(s string) string { return strings.Replace(s, `"sha256:`, `"sha257:`, 1) },
		"bad version":   func(s string) string { return strings.Replace(s, `"v":1`, `"v":2`, 1) },
		"short sig":     func(s string) string { return strings.Replace(s, `"sig":"`, `"sig":"AA`, 1)[:len(s)-3] + `"}` },
		"not an object": func(string) string { return `[1]` },
		"trailing":      func(s string) string { return s + " x" },
	} {
		if _, err := ParseAnchorRecord([]byte(mutate(string(line)))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAnchorDeliveryRetriesAndSurvivesRestart(t *testing.T) {
	e := newAnchorEnv(t, "host1", nil)
	ctx := context.Background()
	e.append(3, "storefront")
	e.notes.fail = errors.New("ntfy is down")
	e.a.RunOnce(ctx)
	if len(e.records()) != 1 || e.notes.count() != 0 {
		t.Fatalf("records = %d pushes = %d", len(e.records()), e.notes.count())
	}
	// Retries wait RetryEvery.
	e.notes.fail = nil
	e.clk.advance(time.Minute)
	e.a.RunOnce(ctx)
	if e.notes.count() != 0 {
		t.Fatal("retried before RetryEvery")
	}
	e.clk.advance(10 * time.Minute)
	e.a.RunOnce(ctx)
	if e.notes.count() != 1 {
		t.Fatalf("pushes = %d after the retry", e.notes.count())
	}

	// A restart (a new scheduler on the same database) repeats nothing.
	a2, err := NewAnchors(AnchorsConfig{Ledger: e.l, Signer: e.signer, Notifier: e.notes, Alerts: e.alerts, Now: e.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	a2.RunOnce(ctx)
	if len(e.records()) != 1 || e.notes.count() != 1 {
		t.Fatalf("restart: records = %d pushes = %d", len(e.records()), e.notes.count())
	}

	// A crash between the anchor event and its record: the record is made later
	// and a torn last line is repaired.
	e.clk.advance(25 * time.Hour)
	if _, err := e.l.Anchor(ctx, AnchorKindOffline, "crashed before delivery"); err != nil {
		t.Fatal(err)
	}
	path := AnchorsPath(e.export, e.l.Chain())
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"torn":`)
	f.Close()
	a2.RunOnce(ctx)
	recs := e.records() // fails the test on a torn or bad line
	if len(recs) != 2 {
		t.Fatalf("records = %d, want 2", len(recs))
	}
	if e.notes.count() != 2 {
		t.Fatalf("pushes = %d, want 2", e.notes.count())
	}
	if rep := e.anchorsRep(nil, true); !rep.OK() {
		t.Fatalf("%+v", rep.Problems)
	}
}

func TestExportRunsOnSchedule(t *testing.T) {
	e := newAnchorEnv(t, "host1", nil)
	ctx := context.Background()
	e.append(4, "storefront")
	e.a.RunOnce(ctx)
	rep, err := e.l.Verify(ctx, true)
	if err != nil || !rep.OK() {
		t.Fatalf("verify against export: %v %v", err, rep.Err())
	}
	if rep.Chains[0].ExportedThrough != 4 || rep.Chains[0].Unexported != 0 {
		t.Fatalf("exported through %d, %d unexported (the anchor event should be exported in the same pass)", rep.Chains[0].ExportedThrough, rep.Chains[0].Unexported)
	}
	// New events wait for the next ExportEvery, then follow.
	e.append(2, "storefront")
	e.clk.advance(time.Minute)
	e.a.RunOnce(ctx)
	if r, _ := e.l.Verify(ctx, true); r.Chains[0].Unexported == 0 {
		t.Fatal("exported again inside ExportEvery")
	}
	e.clk.advance(10 * time.Minute)
	e.a.RunOnce(ctx)
	if r, _ := e.l.Verify(ctx, true); r.Chains[0].Unexported != 0 || !r.OK() {
		t.Fatalf("not exported after ExportEvery: %+v %v", r.Chains[0], r.Err())
	}
}

// A missing export for 26 hours raises an alert, and a working one clears it.
func TestMissingExportRaisesAlertAfter26Hours(t *testing.T) {
	e := newAnchorEnv(t, "host1", nil)
	ctx := context.Background()
	e.append(3, "storefront")
	e.a.RunOnce(ctx)
	if n := e.alerts.raisedCount(AlertExportStale); n != 0 {
		t.Fatalf("alert raised on a healthy export")
	}

	// Break the export: the export root becomes a file, so no segment can be written.
	if err := os.RemoveAll(e.export); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.export, []byte("not a directory"), 0o640); err != nil {
		t.Fatal(err)
	}
	for h := 1; h <= 25; h++ {
		e.clk.advance(time.Hour)
		e.a.RunOnce(ctx)
	}
	if n := e.alerts.raisedCount(AlertExportStale); n != 0 {
		t.Fatalf("alert raised after 25 h without an export (%d)", n)
	}
	e.clk.advance(2 * time.Hour) // 27 h since the last good export
	e.a.RunOnce(ctx)
	if n := e.alerts.raisedCount(AlertExportStale); n != 1 {
		t.Fatalf("alerts after 27 h = %d, want 1", n)
	}
	// The alert repeats, but only every 30 minutes.
	e.clk.advance(10 * time.Minute)
	e.a.RunOnce(ctx)
	if n := e.alerts.raisedCount(AlertExportStale); n != 1 {
		t.Fatalf("alert repeated after 10 min (%d)", n)
	}
	e.clk.advance(30 * time.Minute)
	e.a.RunOnce(ctx)
	if n := e.alerts.raisedCount(AlertExportStale); n != 2 {
		t.Fatalf("alert did not repeat after 30 min (%d)", n)
	}

	// Repair it: the next export clears the alert.
	if err := os.Remove(e.export); err != nil {
		t.Fatal(err)
	}
	e.clk.advance(11 * time.Minute)
	e.a.RunOnce(ctx)
	found := false
	for _, k := range e.alerts.resolved {
		if k == AlertExportStale {
			found = true
		}
	}
	if !found {
		t.Fatalf("the alert was not resolved after the export worked again: %v", e.alerts.resolved)
	}
}

func TestExportMismatchAlertsAtOnce(t *testing.T) {
	e := newAnchorEnv(t, "host1", nil)
	ctx := context.Background()
	e.append(5, "storefront")
	e.a.RunOnce(ctx)
	days, _, err := segments(filepath.Join(e.export, e.l.Chain()))
	if err != nil || len(days) != 1 {
		t.Fatalf("segments = %v %v", days, err)
	}
	if err := os.Remove(filepath.Join(e.export, e.l.Chain(), days[0])); err != nil {
		t.Fatal(err)
	}
	e.clk.advance(11 * time.Minute)
	e.a.RunOnce(ctx)
	if n := e.alerts.raisedCount(AlertExportBroken); n != 1 {
		t.Fatalf("a deleted segment raised %d alerts, want 1", n)
	}
}

func TestAnchorNotDeliveredRaisesAlertAfter26Hours(t *testing.T) {
	e := newAnchorEnv(t, "host1", nil)
	ctx := context.Background()
	e.append(3, "storefront")
	e.notes.fail = errors.New("ntfy is down")
	for range 28 {
		e.a.RunOnce(ctx)
		e.clk.advance(time.Hour)
	}
	if n := e.alerts.raisedCount(AlertAnchorStale); n == 0 {
		t.Fatal("no alert after 27 h with no anchor on the phone")
	}
	e.notes.fail = nil
	e.clk.advance(11 * time.Minute)
	e.a.RunOnce(ctx)
	found := false
	for _, k := range e.alerts.resolved {
		if k == AlertAnchorStale {
			found = true
		}
	}
	if !found {
		t.Fatal("the alert was not resolved after delivery")
	}
}

func TestNewAnchorsRefusesIncompleteConfig(t *testing.T) {
	e := newAnchorEnv(t, "host1", nil)
	for name, cfg := range map[string]AnchorsConfig{
		"no ledger":   {Signer: e.signer, Notifier: e.notes},
		"no signer":   {Ledger: e.l, Notifier: e.notes},
		"no notifier": {Ledger: e.l, Signer: e.signer},
	} {
		if _, err := NewAnchors(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	dir := t.TempDir()
	db := openDB(t, filepath.Join(dir, "s.db"))
	defer db.Close()
	l, err := Open(context.Background(), db, Config{Instance: "x", Redactor: redact.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := NewAnchors(AnchorsConfig{Ledger: l, Signer: e.signer, Notifier: e.notes}); err == nil || !strings.Contains(err.Error(), "ExportDir") {
		t.Errorf("no export dir: %v", err)
	}
}

type secretUser struct{ secret string }

func (s secretUser) Use(_ context.Context, id string, fn func([]byte) error) error {
	if id != "ledger-key" {
		return fmt.Errorf("no secret %q", id)
	}
	return fn([]byte(s.secret))
}

func TestVaultAnchorSigner(t *testing.T) {
	seedKey := newTestSigner(t)
	seed := base64Seed(seedKey.priv.Seed())
	s, err := NewVaultAnchorSigner(context.Background(), secretUser{seed}, "ledger-key")
	if err != nil {
		t.Fatal(err)
	}
	if !s.Public().Equal(seedKey.pub) || s.KeyID() != KeyID(seedKey.pub) {
		t.Fatal("public key differs from the seed's")
	}
	sig, err := s.Sign(context.Background(), []byte("m"))
	if err != nil || !ed25519.Verify(seedKey.pub, []byte("m"), sig) {
		t.Fatalf("signature: %v", err)
	}
	for _, bad := range []string{"", "short", seed + "AAAA", strings.Repeat("!", len(seed))} {
		if _, err := NewVaultAnchorSigner(context.Background(), secretUser{bad}, "ledger-key"); err == nil {
			t.Errorf("accepted secret %q", bad)
		}
	}
	if _, err := NewVaultAnchorSigner(context.Background(), secretUser{seed}, "other"); err == nil {
		t.Error("accepted a missing secret")
	}
	if pub, err := ParsePublicKey(base64Seed(seedKey.pub)); err != nil || !pub.Equal(seedKey.pub) {
		t.Errorf("ParsePublicKey: %v", err)
	}
	if _, err := ParsePublicKey("nope"); err == nil {
		t.Error("ParsePublicKey accepted junk")
	}
}

func base64Seed(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
