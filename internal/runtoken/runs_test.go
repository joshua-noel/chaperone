package runtoken

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

func TestRegisterWritesRowAndEvents(t *testing.T) {
	e := newEnv(t)
	c := e.claims()
	rec, err := e.runs.Register(context.Background(), RegisterRequest{Control: e.ctl(actRunStart, c.RunID), Token: e.far.sign(t, typRun, c)})
	mustNil(t, err)
	if rec.State != "active" || rec.JTI != c.JTI || rec.Exp != c.Exp || rec.Project != "acme-shop" {
		t.Fatalf("record %+v", rec)
	}
	got, err := e.runs.Get(context.Background(), c.RunID)
	mustNil(t, err)
	if got.Claims.TaskScope.Branch != "agent/r-7f3a" || got.KID != "runner-1" {
		t.Fatalf("stored %+v", got)
	}
	if n := e.led.names(); !slices.Equal(n, []string{"grant", "run.start"}) {
		t.Fatalf("events %v", n)
	}
	g := e.led.find("grant")[0]
	if g.Attributes["factory.token.jti"] != c.JTI || g.RunID != c.RunID {
		t.Fatalf("grant %+v", g)
	}
}

func TestRegisterRefusals(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	c := e.claims()
	tok := e.far.sign(t, typRun, c)
	reg := func(ctl, tok string) error {
		_, err := e.runs.Register(ctx, RegisterRequest{Control: ctl, Token: tok})
		return err
	}
	ctlMod := func(mod func(m map[string]any)) string {
		m := e.ctlClaims(actRunStart, c.RunID)
		mod(m)
		return e.far.sign(t, typCtl, m)
	}
	bad := []struct {
		name string
		code string
		err  func() error
	}{
		{"control token with act run.end", CauseTokenInvalid, func() error { return reg(e.ctl(actRunEnd, c.RunID), tok) }},
		{"control token for another run", CauseTokenInvalid, func() error { return reg(e.ctl(actRunStart, "r-other"), tok) }},
		{"control token with the run typ", CauseTokenInvalid, func() error {
			return reg(e.far.sign(t, typRun, e.ctlClaims(actRunStart, c.RunID)), tok)
		}},
		{"run token given as control", CauseTokenInvalid, func() error { return reg(tok, tok) }},
		{"control token over 60 s", CauseTokenInvalid, func() error {
			return reg(ctlMod(func(m map[string]any) { m["exp"] = m["iat"].(int64) + 61 }), tok)
		}},
		{"control token expired", CauseTokenExpired, func() error {
			return reg(ctlMod(func(m map[string]any) { m["iat"], m["exp"] = e.clock.Unix()-100, e.clock.Unix()-50 }), tok)
		}},
		{"control token with an extra claim", CauseTokenInvalid, func() error {
			return reg(ctlMod(func(m map[string]any) { m["scope"] = "all" }), tok)
		}},
		{"control token with the wrong aud", CauseTokenInvalid, func() error {
			return reg(ctlMod(func(m map[string]any) { m["aud"] = "runner" }), tok)
		}},
		{"control token signed by the interim key", CauseTokenInvalid, func() error {
			m := e.ctlClaims(actRunStart, c.RunID)
			m["iss"] = e.intr.iss
			return reg(e.intr.sign(t, typCtl, m), tok)
		}},
		{"expired run token", CauseTokenExpired, func() error {
			x := c
			x.Iat, x.Exp = e.clock.Unix()-7200, e.clock.Unix()-60
			return reg(e.ctl(actRunStart, c.RunID), e.far.sign(t, typRun, x))
		}},
		{"branch outside the profile prefix", CauseScopeBranch, func() error {
			x := c
			x.TaskScope.Branch = "feature/x"
			return reg(e.ctl(actRunStart, c.RunID), e.far.sign(t, typRun, x))
		}},
	}
	for _, b := range bad {
		t.Run(b.name, func(t *testing.T) {
			wantCode(t, b.err(), b.code)
			if _, err := e.runs.Get(ctx, c.RunID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("a refused registration left a run behind: %v", err)
			}
		})
	}
	if len(e.led.names()) != 0 {
		t.Fatalf("refusals wrote events %v", e.led.names())
	}
}

func TestRegisterIsSingleUseAndNotRepeatable(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	c := e.claims()
	tok := e.far.sign(t, typRun, c)
	ctl := e.ctl(actRunStart, c.RunID)
	_, err := e.runs.Register(ctx, RegisterRequest{Control: ctl, Token: tok})
	mustNil(t, err)
	// The same control token again: single use.
	_, err = e.runs.Register(ctx, RegisterRequest{Control: ctl, Token: tok})
	if re := wantCode(t, err, CauseTokenInvalid); !strings.Contains(re.Detail, "already used") {
		t.Fatalf("detail %q", re.Detail)
	}
	// A fresh control token for the same run: conflict, nothing duplicated.
	_, err = e.runs.Register(ctx, RegisterRequest{Control: e.ctl(actRunStart, c.RunID), Token: tok})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("got %v, want ErrConflict", err)
	}
	if n := e.led.names(); len(n) != 2 {
		t.Fatalf("events %v", n)
	}
}

func TestRegisterRefusesInterimToken(t *testing.T) {
	e := newEnv(t)
	c := e.claims()
	c.Iss, c.Isolation, c.Profile = e.intr.iss, "host", spec.TokenProfile{Name: InterimProfile, Version: "0.0.0"}
	c.Budget.Minutes, c.Exp = 90, c.Iat+3600
	_, err := e.runs.Register(context.Background(), RegisterRequest{Control: e.ctl(actRunStart, c.RunID), Token: e.intr.sign(t, typRun, c)})
	wantCode(t, err, CauseTokenInvalid)
}

func TestLedgerFailureRollsRegistrationBack(t *testing.T) {
	e := newEnv(t)
	c := e.claims()
	e.led.failOn = "run.start"
	_, err := e.runs.Register(context.Background(), RegisterRequest{Control: e.ctl(actRunStart, c.RunID), Token: e.far.sign(t, typRun, c)})
	if err == nil {
		t.Fatal("registered although the ledger refused")
	}
	if _, err := e.runs.Get(context.Background(), c.RunID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("run row survived a failed ledger append: %v", err)
	}
	var n int
	_ = e.db.SQL().QueryRow(`SELECT COUNT(*) FROM control_jti`).Scan(&n)
	if n != 0 {
		t.Fatal("control jti survived the rollback")
	}
}

func TestEndRevokesOnTheNextRequest(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	c := e.claims()
	tok := e.register(c)
	_, err := e.verify(tok)
	mustNil(t, err)

	mustNil(t, e.end(c.RunID))
	// The very next request, same clock, same token.
	_, err = e.verify(tok)
	re := wantCode(t, err, CauseTokenRevoked)
	if re.Stop != StopTokenMisuse {
		t.Fatalf("stop %q", re.Stop)
	}
	rec, err := e.runs.Get(ctx, c.RunID)
	mustNil(t, err)
	if rec.State != "ended" || rec.EndReason != "run_end" || rec.EndedAt.IsZero() {
		t.Fatalf("record %+v", rec)
	}
	var n int
	_ = e.db.SQL().QueryRow(`SELECT COUNT(*) FROM revoked_jti WHERE jti = ? AND exp = ?`, c.JTI, c.Exp).Scan(&n)
	if n != 1 {
		t.Fatal("jti is not in revoked_jti until exp")
	}
	if want := []string{"grant", "run.start", "token.revoke", "run.end"}; !slices.Equal(e.led.names(), want) {
		t.Fatalf("events %v, want %v", e.led.names(), want)
	}
	if len(e.txEnd) != 1 || len(e.ended) != 1 || e.ended[0].RunID != c.RunID || e.ended[0].State != "ended" {
		t.Fatalf("hooks: tx %d after %d", len(e.txEnd), len(e.ended))
	}
	rv := e.led.find("token.revoke")[0]
	if rv.Attributes["factory.revoke.reason"] != "run_end" || rv.Attributes["factory.token.jti"] != c.JTI {
		t.Fatalf("token.revoke %+v", rv)
	}
	re2 := e.led.find("run.end")[0]
	if re2.Attributes["factory.outcome"] != "done" || re2.Attributes["factory.plan.minutes"] != int64(90) {
		t.Fatalf("run.end %+v", re2)
	}
}

func TestEndIsIdempotentAndChecksTheControlToken(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	c := e.claims()
	e.register(c)
	// Wrong act, wrong run, replay.
	wantCode(t, e.runs.End(ctx, EndRequest{Control: e.ctl(actRunStart, c.RunID), RunID: c.RunID}), CauseTokenInvalid)
	wantCode(t, e.runs.End(ctx, EndRequest{Control: e.ctl(actRunEnd, "r-other"), RunID: c.RunID}), CauseTokenInvalid)
	ctl := e.ctl(actRunEnd, c.RunID)
	mustNil(t, e.runs.End(ctx, EndRequest{Control: ctl, RunID: c.RunID}))
	wantCode(t, e.runs.End(ctx, EndRequest{Control: ctl, RunID: c.RunID}), CauseTokenInvalid)
	// A fresh control token for an ended run succeeds and changes nothing.
	mustNil(t, e.end(c.RunID))
	if len(e.ended) != 1 || len(e.led.find("run.end")) != 1 {
		t.Fatalf("second end ran the hooks again: %d, %v", len(e.ended), e.led.names())
	}
	// An unknown run.
	if err := e.end("r-nope1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
	// Bad requests are the caller's bug, not denials.
	if err := e.runs.End(ctx, EndRequest{Control: ctl, RunID: "bad"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v", err)
	}
	if err := e.runs.End(ctx, EndRequest{Control: ctl, RunID: c.RunID, Outcome: "killed"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("killed without a cause: %v", err)
	}
	if err := e.runs.End(ctx, EndRequest{Control: ctl, RunID: c.RunID, Outcome: "meh"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad outcome: %v", err)
	}
}

func TestEndLedgerAndHookFailuresKeepTheRunActive(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	c := e.claims()
	tok := e.register(c)
	e.led.failOn = "run.end"
	if err := e.end(c.RunID); err == nil {
		t.Fatal("ended although the ledger refused")
	}
	if _, err := e.verify(tok); err != nil {
		t.Fatalf("a failed end revoked the token: %v", err)
	}
	var n int
	_ = e.db.SQL().QueryRow(`SELECT COUNT(*) FROM revoked_jti`).Scan(&n)
	if n != 0 {
		t.Fatal("revoked_jti row survived the rollback")
	}
	if len(e.ended) != 0 {
		t.Fatal("AfterEnd ran for a rolled-back end")
	}
	// The TxEnd hook failing (approvals could not be cancelled) rolls back too.
	e.led.failOn = ""
	e.runs.cfg.TxEnd = func(context.Context, *store.Tx, RunRecord, EndInfo) error { return errors.New("approvals locked") }
	if err := e.end(c.RunID); err == nil {
		t.Fatal("ended although the end hook failed")
	}
	if _, err := e.verify(tok); err != nil {
		t.Fatalf("token revoked: %v", err)
	}
	_ = ctx
}

func TestOperatorRevoke(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	c := e.claims()
	tok := e.register(c)
	c2 := e.claims()
	c2.RunID, c2.Sub, c2.JTI = "r-2b2b", "run:r-2b2b", "bbbbbbbbbbbbbbbbbbbbbb"
	c2.TaskScope.Branch = "agent/r-2b2b"
	tok2 := e.register(c2)

	mustNil(t, e.runs.Revoke(ctx, c.RunID, StopOperatorStopRun))
	_, err := e.verify(tok)
	wantCode(t, err, CauseTokenRevoked)
	rv := e.led.find("token.revoke")[0]
	if rv.Attributes["factory.revoke.reason"] != "operator" || rv.Severity != "WARN" {
		t.Fatalf("token.revoke %+v", rv)
	}
	if _, ok := rv.Attributes["factory.cause_code"]; ok {
		t.Fatal("an operator revoke carries a cause_code (only reason stop may)")
	}
	run := e.led.find("run.end")[0]
	if run.Attributes["factory.outcome"] != "killed" || run.Attributes["factory.cause_code"] != StopOperatorStopRun {
		t.Fatalf("run.end %+v", run)
	}
	// A stop-table stop records reason stop with its code.
	n, err := e.runs.RevokeAll(ctx, StopOperatorStopAll)
	mustNil(t, err)
	if n != 1 {
		t.Fatalf("RevokeAll ended %d, want 1 (the other run was already ended)", n)
	}
	_, err = e.verify(tok2)
	wantCode(t, err, CauseTokenRevoked)
	if err := e.runs.Revoke(ctx, "r-nope1", StopOperatorStopRun); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	if err := e.runs.Revoke(ctx, c.RunID, "not a code"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}

func TestStopRevokeRecordsReasonStop(t *testing.T) {
	e := newEnv(t)
	c := e.claims()
	e.register(c)
	mustNil(t, e.runs.Revoke(context.Background(), c.RunID, "TOKEN_MISUSE"))
	rv := e.led.find("token.revoke")[0]
	if rv.Attributes["factory.revoke.reason"] != "stop" || rv.Attributes["factory.cause_code"] != "TOKEN_MISUSE" {
		t.Fatalf("token.revoke %+v", rv)
	}
}

func TestReaperEndsRunsPastExp(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a := e.claims()
	tokA := e.register(a)
	b := e.claims()
	b.RunID, b.Sub, b.JTI = "r-3c3c", "run:r-3c3c", "cccccccccccccccccccccc"
	b.TaskScope.Branch = "agent/r-3c3c"
	b.Exp = b.Iat + 600 // a short run
	e.register(b)

	n, err := e.runs.Reap(ctx)
	mustNil(t, err)
	if n != 0 {
		t.Fatalf("reaped %d before any exp", n)
	}
	e.clock = time.Unix(b.Exp, 0).UTC() // exp reached for b only
	n, err = e.runs.Reap(ctx)
	mustNil(t, err)
	if n != 1 {
		t.Fatalf("reaped %d, want 1", n)
	}
	rb, _ := e.runs.Get(ctx, b.RunID)
	if rb.State != "ended" || rb.EndCauseCode != StopTimeExceeded || rb.EndReason != "run_end" {
		t.Fatalf("b = %+v", rb)
	}
	ra, _ := e.runs.Get(ctx, a.RunID)
	if ra.State != "active" {
		t.Fatalf("a = %+v", ra)
	}
	run := e.led.find("run.end")[0]
	if run.Attributes["factory.outcome"] != "killed" || run.Attributes["factory.cause_code"] != StopTimeExceeded {
		t.Fatalf("run.end %+v", run)
	}
	if len(e.ended) != 1 || e.ended[0].RunID != b.RunID {
		t.Fatalf("AfterEnd %+v", e.ended)
	}

	// Restart after exp: a new chapd reaps what the old one never did.
	e.clock = time.Unix(a.Exp+1, 0).UTC()
	e.rebuild(true)
	// Before the reaper ran, the run is still active: its token past exp is TOKEN_EXPIRED.
	_, err = e.verify(tokA)
	wantCode(t, err, CauseTokenExpired)
	n, err = e.runs.Reap(ctx)
	mustNil(t, err)
	if n != 1 {
		t.Fatalf("restart reaped %d, want 1", n)
	}
	// Once the reaper has ended the run it is revoked, and revocation wins over expiry: the run is over, so the
	// answer is TOKEN_REVOKED (no restart step), not TOKEN_EXPIRED.
	_, err = e.verify(tokA)
	wantCode(t, err, CauseTokenRevoked)

	// Rows long past exp are purged; the run rows stay as history.
	e.clock = time.Unix(a.Exp+purgeMargin+1, 0).UTC()
	_, err = e.runs.Reap(ctx)
	mustNil(t, err)
	var jtis, ctls, runs int
	_ = e.db.SQL().QueryRow(`SELECT COUNT(*) FROM revoked_jti`).Scan(&jtis)
	_ = e.db.SQL().QueryRow(`SELECT COUNT(*) FROM control_jti`).Scan(&ctls)
	_ = e.db.SQL().QueryRow(`SELECT COUNT(*) FROM runs`).Scan(&runs)
	if jtis != 0 || ctls != 0 || runs != 2 {
		t.Fatalf("after purge: revoked_jti %d control_jti %d runs %d", jtis, ctls, runs)
	}
}

func TestRunReaperLoop(t *testing.T) {
	e := newEnv(t)
	c := e.claims()
	e.register(c)
	e.clock = time.Unix(c.Exp, 0).UTC()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		e.runs.RunReaper(ctx, time.Hour, func(err error) { t.Errorf("reaper: %v", err) })
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		rec, err := e.runs.Get(context.Background(), c.RunID)
		mustNil(t, err)
		if rec.State == "ended" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the reaper did not end the run on its first pass")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the reaper did not stop with its context")
	}
}

func TestListPagesNewestFirst(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	ids := []string{"r-aaaa", "r-bbbb", "r-cccc", "r-dddd", "r-eeee"}
	for i, id := range ids {
		c := e.claims()
		c.RunID, c.Sub, c.JTI, c.TaskScope.Branch = id, "run:"+id, strings.Repeat(string(rune('a'+i)), 22), "agent/"+id
		e.register(c)
		if i != 1 && i != 3 { // r-bbbb and r-dddd share a second with the next one
			e.clock = e.clock.Add(time.Second)
		}
	}
	mustNil(t, e.end("r-aaaa"))
	var got []string
	cursor := ""
	for pages := 0; pages < 10; pages++ {
		recs, next, err := e.runs.List(ctx, "", 2, cursor)
		mustNil(t, err)
		for _, r := range recs {
			got = append(got, r.RunID)
		}
		if next == "" {
			break
		}
		if len(recs) != 2 || next != recs[1].RunID {
			t.Fatalf("cursor %q for page %v", next, recs)
		}
		cursor = next
	}
	want := []string{"r-eeee", "r-dddd", "r-cccc", "r-bbbb", "r-aaaa"}
	if !slices.Equal(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
	active, next, err := e.runs.List(ctx, "active", 0, "")
	mustNil(t, err)
	if len(active) != 4 || next != "" || active[len(active)-1].RunID != "r-bbbb" {
		t.Fatalf("active %v next %q", active, next)
	}
	ended, _, err := e.runs.List(ctx, "ended", 10, "")
	mustNil(t, err)
	if len(ended) != 1 || ended[0].RunID != "r-aaaa" || ended[0].State != "ended" {
		t.Fatalf("ended %+v", ended)
	}
	// An exactly full last page has no cursor.
	_, next, err = e.runs.List(ctx, "", 5, "")
	mustNil(t, err)
	if next != "" {
		t.Fatalf("cursor %q after the last row", next)
	}
	for _, bad := range []func() error{
		func() error { _, _, err := e.runs.List(ctx, "paused", 0, ""); return err },
		func() error { _, _, err := e.runs.List(ctx, "", 501, ""); return err },
		func() error { _, _, err := e.runs.List(ctx, "", -1, ""); return err },
		func() error { _, _, err := e.runs.List(ctx, "", 0, "r-nope1"); return err },
	} {
		if err := bad(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("got %v, want ErrInvalid", err)
		}
	}
}
