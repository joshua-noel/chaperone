package ledger

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

func TestAppendBuildsAValidChain(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	r0, err := e.l.Append(ctx, opReq(0))
	if err != nil || r0.Seq != 0 {
		t.Fatalf("first append = %+v, %v", r0, err)
	}
	var r1 Receipt
	err = e.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		r1, err = e.l.AppendTx(ctx, tx, runReq(1))
		return err
	})
	if err != nil || r1.Seq != 1 {
		t.Fatalf("AppendTx = %+v, %v", r1, err)
	}
	e.append(3)
	e.mustVerifyClean(false)

	seq, hash, err := e.l.Head(ctx)
	if err != nil || seq != 4 {
		t.Fatalf("Head = %d %s %v", seq, hash, err)
	}

	// The stored event is the spec event: it validates, links to the previous
	// hash and derives trace_id from run_id, or from the chain when there is none.
	var text, prev string
	if err := e.db.SQL().QueryRow(`SELECT event, prev_hash FROM ledger_events WHERE seq = 1`).Scan(&text, &prev); err != nil {
		t.Fatal(err)
	}
	ev, err := spec.Load[spec.Event](spec.SchemaEvent, []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if ev.PrevHash != r0.Hash || prev != r0.Hash || ev.Hash != r1.Hash {
		t.Errorf("links: prev %s want %s, hash %s want %s", ev.PrevHash, r0.Hash, ev.Hash, r1.Hash)
	}
	if ev.TraceID != spec.TraceID("r-abcd1") || ev.Chain != "chaperone.test" || ev.Resource.ServiceName != "chaperone" {
		t.Errorf("envelope: %+v", ev)
	}
	if err := e.db.SQL().QueryRow(`SELECT event FROM ledger_events WHERE seq = 0`).Scan(&text); err != nil {
		t.Fatal(err)
	}
	ev0, _ := spec.Load[spec.Event](spec.SchemaEvent, []byte(text))
	if ev0.TraceID != spec.TraceID("chaperone.test") || ev0.PrevHash != spec.ZeroHash {
		t.Errorf("event 0: trace %s prev %s", ev0.TraceID, ev0.PrevHash)
	}
}

func TestAppendTxCommitsWithStateAndRollsBackWithIt(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.exec(`CREATE TABLE ledger_test_state (id INTEGER PRIMARY KEY, state TEXT NOT NULL) STRICT`)

	boom := errors.New("state change failed")
	err := e.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ledger_test_state VALUES (1, 'requested')`); err != nil {
			return err
		}
		if _, err := e.l.AppendTx(ctx, tx, opReq(1)); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	var n int
	e.db.SQL().QueryRow(`SELECT (SELECT count(*) FROM ledger_test_state) + (SELECT count(*) FROM ledger_events) + (SELECT count(*) FROM ledger_chains)`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d rows survived a rolled-back transaction", n)
	}

	// The next append starts at seq 0: the rollback left no gap.
	err = e.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ledger_test_state VALUES (1, 'requested')`); err != nil {
			return err
		}
		r, err := e.l.AppendTx(ctx, tx, opReq(1))
		if r.Seq != 0 {
			t.Errorf("seq after rollback = %d", r.Seq)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	e.mustVerifyClean(false)
}

func TestTriggersRefuseUpdateAndDelete(t *testing.T) {
	e := newEnv(t)
	e.append(3)
	for _, q := range []string{
		`UPDATE ledger_events SET event_name = 'denial' WHERE seq = 1`,
		`UPDATE ledger_events SET event = '{}'`,
		`DELETE FROM ledger_events WHERE seq = 1`,
		`DELETE FROM ledger_events`,
		`DELETE FROM ledger_chains`,
		`UPDATE ledger_chains SET head_seq = 1, head_hash = 'x'`,
		`UPDATE ledger_chains SET head_seq = 99, head_hash = 'x'`,
		`UPDATE ledger_chains SET exported_seq = 99, exported_hash = 'x'`,
		`UPDATE ledger_chains SET chain = 'chaperone.other'`,
	} {
		if _, err := e.db.SQL().Exec(q); err == nil || !strings.Contains(err.Error(), "refused") && !strings.Contains(err.Error(), "ledger_chains") {
			t.Errorf("%s: err = %v, want a trigger refusal", q, err)
		}
	}
	e.mustVerifyClean(false)
}

func TestSecondInsertWithSameSeqIsRefused(t *testing.T) {
	e := newEnv(t)
	e.append(2)
	_, err := e.db.SQL().Exec(`INSERT INTO ledger_events (chain, seq, hash, prev_hash, time_unix_nano, event_name, run_id, event) SELECT chain, seq, hash, prev_hash, time_unix_nano, event_name, run_id, event FROM ledger_events WHERE seq = 1`)
	if err == nil {
		t.Fatal("duplicate (chain, seq) was accepted")
	}
}

func TestConcurrentAppendsHaveNoGapOrDuplicate(t *testing.T) {
	e := newEnv(t)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 60 {
				var err error
				if g%2 == 0 {
					_, err = e.l.Append(context.Background(), opReq(g*100+i))
				} else {
					err = e.db.Immediate(context.Background(), func(ctx context.Context, tx *store.Tx) error {
						_, err := e.l.AppendTx(ctx, tx, opReq(g*100+i))
						return err
					})
				}
				if err != nil {
					t.Errorf("goroutine %d append %d: %v", g, i, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	rep := e.verify(false)
	if !rep.OK() {
		t.Fatal(rep.Err())
	}
	if rep.Chains[0].Events != 480 || rep.Chains[0].HeadSeq != 479 {
		t.Errorf("events %d head %d, want 480 / 479", rep.Chains[0].Events, rep.Chains[0].HeadSeq)
	}
}

func TestRejectedDraftsWriteNothing(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	big := runReq(1)
	big.Body = strings.Repeat("x", 1001)
	badAttr := opReq(1)
	badAttr.Attributes["factory.surprise"] = "x"
	missing := opReq(1)
	delete(missing.Attributes, "factory.op_hash")
	noProject := opReq(1)
	noProject.Project = ""
	runKindNoRun := opReq(1)
	runKindNoRun.Attributes["factory.requester.kind"] = "run"
	for name, d := range map[string]Draft{
		"unknown attribute":   badAttr,
		"missing attribute":   missing,
		"unknown event":       {Name: "op.frobnicate", Project: "storefront"},
		"body too long":       big,
		"no project":          noProject,
		"run kind, no run_id": runKindNoRun,
		"bad severity":        {Name: "op.request", Severity: "LOUD"},
		"bad span":            {Name: "op.request", SpanID: "nothex"},
	} {
		if _, err := e.l.Append(ctx, d); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: err = %v, want ErrRejected", name, err)
		}
		err := e.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
			_, err := e.l.AppendTx(ctx, tx, d)
			return err
		})
		if !errors.Is(err, ErrRejected) {
			t.Errorf("%s (tx): err = %v, want ErrRejected", name, err)
		}
	}
	// Nothing was written by any refused draft.
	var n int
	e.db.SQL().QueryRow(`SELECT count(*) FROM ledger_events`).Scan(&n)
	if n != 0 {
		t.Errorf("%d events written by refused drafts", n)
	}
	e.append(1)
	e.mustVerifyClean(false)
}

func TestRedactionHook(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	const secret = "hunter2-hunter2-hunter2"
	if err := e.reg.Set("canary", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	ghs := "ghs_" + strings.Repeat("A1b2C3d4", 8)

	d := opReq(1)
	d.Body = "merge used " + secret + " and " + ghs
	d.Attributes["factory.external_ref"] = "nope" // not allowed on op.request; checks the error is clean too
	_, err := e.l.Append(ctx, d)
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), ghs) {
		t.Fatalf("rejection error leaks the secret: %v", err)
	}

	d = opReq(2)
	d.Body = "merge used " + secret + " and " + ghs
	r, err := e.l.Append(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Redactions) != 2 {
		t.Fatalf("redactions = %+v", r.Redactions)
	}
	var text string
	e.db.SQL().QueryRow(`SELECT event FROM ledger_events WHERE seq = 0`).Scan(&text)
	if strings.Contains(text, secret) || strings.Contains(text, "ghs_") && !strings.Contains(text, "[REDACTED:github-token]") {
		t.Fatalf("stored event holds a secret: %s", text)
	}
	if !strings.Contains(text, "[REDACTED:canary]") {
		t.Errorf("stored event: %s", text)
	}
	e.mustVerifyClean(false)

	// A secret as an attribute name is masked before the validator can quote it.
	d = opReq(3)
	d.Attributes[secret] = "x"
	_, err = e.l.Append(ctx, d)
	if !errors.Is(err, ErrRejected) || strings.Contains(err.Error(), secret) {
		t.Fatalf("err = %v", err)
	}
}

func TestOpenValidatesConfig(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for name, cfg := range map[string]Config{
		"no instance":  {Redactor: e.reg},
		"bad instance": {Instance: "PC 1", Redactor: e.reg},
		"no redactor":  {Instance: "host1"},
	} {
		if l, err := Open(ctx, e.db, cfg); err == nil {
			l.Close()
			t.Errorf("%s: Open succeeded", name)
		}
	}
	if _, err := Open(ctx, nil, Config{Instance: "host1", Redactor: e.reg}); err == nil {
		t.Error("nil db accepted")
	}
}

func TestOpenOnUnmigratedDatabaseFailsClosed(t *testing.T) {
	db, err := store.Open(context.Background(), t.TempDir()+"/state.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := newEnv(t)
	if l, err := Open(context.Background(), db, Config{Instance: "host1", Redactor: e.reg}); err == nil {
		l.Close()
		t.Fatal("Open on a database without ledger tables succeeded")
	} else if !errors.Is(err, ErrUnavailable) {
		t.Errorf("err = %v, want ErrUnavailable", err)
	}
}

func TestClosedLedgerRefuses(t *testing.T) {
	e := newEnv(t)
	e.append(2)
	if err := e.l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.l.Append(context.Background(), opReq(9)); !errors.Is(err, ErrClosed) {
		t.Errorf("err = %v, want ErrClosed", err)
	}
	if err := e.l.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestReopenContinuesTheChain(t *testing.T) {
	e := newEnv(t)
	e.append(5)
	e.l.Close()
	l2, err := Open(context.Background(), e.db, Config{Instance: "test", Redactor: e.reg})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	r, err := l2.Append(context.Background(), opReq(5))
	if err != nil || r.Seq != 5 {
		t.Fatalf("append after reopen = %+v, %v", r, err)
	}
	e.mustVerifyClean(false)
}

func TestAnchor(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.l.Anchor(ctx, "offline-copy", "ntfy+backup"); !errors.Is(err, ErrRejected) {
		t.Fatalf("anchor on empty chain: %v", err)
	}
	e.append(3)
	r, err := e.l.Anchor(ctx, "offline-copy", "ntfy+backup")
	if err != nil || r.Seq != 3 {
		t.Fatalf("Anchor = %+v, %v", r, err)
	}
	var text string
	e.db.SQL().QueryRow(`SELECT event FROM ledger_events WHERE seq = 3`).Scan(&text)
	ev, err := spec.Load[spec.Event](spec.SchemaEvent, []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	var h2 string
	e.db.SQL().QueryRow(`SELECT hash FROM ledger_events WHERE seq = 2`).Scan(&h2)
	if ev.EventName != "ledger.anchor" || ev.Attributes["factory.anchor.head_hash"] != h2 || ev.Attributes["factory.anchor.head_seq"] != float64(2) {
		t.Errorf("anchor event: %+v", ev)
	}
	if _, err := e.l.Anchor(ctx, "carrier-pigeon", "x"); !errors.Is(err, ErrRejected) {
		t.Errorf("bad kind: %v", err)
	}
	e.mustVerifyClean(false)

	// A rewrite of everything before the anchor that re-chains the events
	// (the anchor event too) is caught by the anchor only if the anchor is
	// kept elsewhere; inside the ledger the anchor must still name a real hash.
	e.dropGuards()
	e.exec(`UPDATE ledger_events SET event = replace(event, ?, ?) WHERE seq = 3`, `"factory.anchor.head_seq":2`, `"factory.anchor.head_seq":1`)
	if rep := e.verify(false); !hasCode(rep, ProblemChain) {
		t.Errorf("edited anchor not detected: %v", codes(rep))
	}
}

func TestPreflight(t *testing.T) {
	e := newEnv(t)
	e.append(2)
	if err := e.l.Preflight(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.mustVerifyClean(false)
	if seq, _, _ := e.l.Head(context.Background()); seq != 1 {
		t.Errorf("preflight changed the head: %d", seq)
	}
	var n int
	e.db.SQL().QueryRow(`SELECT count(*) FROM store_meta WHERE key = 'ledger.preflight'`).Scan(&n)
	if n != 0 {
		t.Error("preflight left a row behind")
	}
}

// Append inside a store transaction would wait for the write gate its own
// caller holds; it is refused at once and AppendTx still works.
func TestAppendInsideATransactionIsRefused(t *testing.T) {
	e := newEnv(t)
	start := time.Now()
	err := e.db.Immediate(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		if _, err := e.l.Append(ctx, opReq(1)); !errors.Is(err, store.ErrNestedWrite) || !errors.Is(err, ErrUnavailable) {
			t.Errorf("Append inside Immediate = %v, want ErrNestedWrite (unavailable)", err)
		}
		_, err := e.l.AppendTx(ctx, tx, opReq(2))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("took %v: Append waited for the gate", time.Since(start))
	}
	if rep := e.verify(false); !rep.OK() || rep.Chains[0].Events != 1 {
		t.Fatalf("want exactly the AppendTx event, got %+v %v", rep.Chains, rep.Err())
	}
}
