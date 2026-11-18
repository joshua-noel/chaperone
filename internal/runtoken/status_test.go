package runtoken

import (
	"context"
	"errors"
	"testing"
	"time"
)

// status reads a run's status with a fresh run.status control token.
func (e *env) status(runID string) (RunStatus, error) {
	return e.runs.Status(context.Background(), e.ctl(actRunStatus, runID), runID)
}

func TestStatusOfAnActiveRun(t *testing.T) {
	e := newEnv(t)
	c := e.claims()
	e.register(c)
	st, err := e.status(c.RunID)
	mustNil(t, err)
	if st.State != "active" || !st.EndedAt.IsZero() || st.CauseCode != "" || st.ExpiresAt.Unix() != c.Exp {
		t.Fatalf("status %+v", st)
	}
	// A read changes nothing: no ledger event, the run is still verifiable.
	if n := e.led.names(); len(n) != 2 {
		t.Fatalf("events %v", n)
	}
}

func TestStatusShowsHowARunEnded(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		end   func(e *env, runID string) error
		cause string
	}{
		{"runner ended it", func(e *env, id string) error { return e.end(id) }, ""},
		{"operator stop", func(e *env, id string) error { return e.runs.Revoke(ctx, id, StopOperatorStopRun) }, StopOperatorStopRun},
		{"stop all", func(e *env, id string) error { _, err := e.runs.RevokeAll(ctx, StopOperatorStopAll); return err }, StopOperatorStopAll},
		{"a stop-table stop", func(e *env, id string) error { return e.runs.Revoke(ctx, id, "THRASH") }, "THRASH"},
		{"the reaper", func(e *env, id string) error {
			e.clock = e.clock.Add(2 * time.Hour)
			_, err := e.runs.Reap(ctx)
			return err
		}, "TIME_EXCEEDED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			c := e.claims()
			e.register(c)
			at := e.clock
			mustNil(t, tc.end(e, c.RunID))
			// The reaper moved the clock; the status call needs a live control token.
			st, err := e.status(c.RunID)
			mustNil(t, err)
			if st.State != "ended" || st.CauseCode != tc.cause || st.EndedAt.Before(at.Truncate(time.Second)) || st.ExpiresAt.Unix() != c.Exp {
				t.Fatalf("status %+v", st)
			}
		})
	}
}

func TestStatusReadsOnlyRunsOfItsOwnIssuer(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	c := e.claims()
	e.register(c)
	ctl := func(i issuer, act, id string) string {
		m := e.ctlClaims(act, id)
		m["iss"] = i.iss
		return i.sign(t, typCtl, m)
	}
	// A second pinned the runner: its token is valid, but the run is not its own.
	// The answer is the same as for a run that does not exist.
	_, err := e.runs.Status(ctx, ctl(e.oth, actRunStatus, c.RunID), c.RunID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("another issuer's run: %v", err)
	}
	_, err = e.runs.Status(ctx, ctl(e.far, actRunStatus, "r-nope1"), "r-nope1")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown run: %v", err)
	}
	// The owner still reads it, and the refused calls registered nothing.
	if _, err := e.status(c.RunID); err != nil {
		t.Fatal(err)
	}
	if n := e.led.names(); len(n) != 2 {
		t.Fatalf("events %v", n)
	}
}

func TestStatusRefusesWhatIsNotAStatusControlToken(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	c := e.claims()
	tok := e.register(c)
	read := func(control string) error {
		_, err := e.runs.Status(ctx, control, c.RunID)
		return err
	}
	ctlMod := func(mod func(m map[string]any)) string {
		m := e.ctlClaims(actRunStatus, c.RunID)
		mod(m)
		return e.far.sign(t, typCtl, m)
	}
	bad := []struct {
		name, code string
		control    string
	}{
		{"the run token itself", CauseTokenInvalid, tok},
		{"a control token for run.start", CauseTokenInvalid, e.ctl(actRunStart, c.RunID)},
		{"a control token for run.end", CauseTokenInvalid, e.ctl(actRunEnd, c.RunID)},
		{"a control token for another run", CauseTokenInvalid, e.ctl(actRunStatus, "r-other")},
		{"the run typ", CauseTokenInvalid, e.far.sign(t, typRun, e.ctlClaims(actRunStatus, c.RunID))},
		{"the orchestrator token", CauseTokenInvalid, "chap_orch_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"empty", CauseTokenInvalid, ""},
		{"expired", CauseTokenExpired, ctlMod(func(m map[string]any) { m["iat"], m["exp"] = e.clock.Unix()-100, e.clock.Unix()-50 })},
		{"over 60 s", CauseTokenInvalid, ctlMod(func(m map[string]any) { m["exp"] = m["iat"].(int64) + 61 })},
		{"an extra claim", CauseTokenInvalid, ctlMod(func(m map[string]any) { m["scope"] = "all" })},
		{"the wrong aud", CauseTokenInvalid, ctlMod(func(m map[string]any) { m["aud"] = "runner" })},
		{"signed by the interim key", CauseTokenInvalid, func() string {
			m := e.ctlClaims(actRunStatus, c.RunID)
			m["iss"] = e.intr.iss
			return e.intr.sign(t, typCtl, m)
		}()},
	}
	for _, b := range bad {
		t.Run(b.name, func(t *testing.T) { wantCode(t, read(b.control), b.code) })
	}
	// A run.status token does not end, or register, anything either.
	wantCode(t, e.runs.End(ctx, EndRequest{Control: e.ctl(actRunStatus, c.RunID), RunID: c.RunID}), CauseTokenInvalid)
	if _, err := e.verify(tok); err != nil {
		t.Fatalf("a refused read touched the run: %v", err)
	}
	if _, err := e.runs.Status(ctx, e.ctl(actRunStatus, c.RunID), "bad"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed run id: %v", err)
	}
}

func TestStatusControlTokenIsSingleUse(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	c := e.claims()
	e.register(c)
	ctl := e.ctl(actRunStatus, c.RunID)
	_, err := e.runs.Status(ctx, ctl, c.RunID)
	mustNil(t, err)
	_, err = e.runs.Status(ctx, ctl, c.RunID)
	wantCode(t, err, CauseTokenInvalid)
	// The same token cannot be replayed to end the run either (the act differs
	// and the jti is spent).
	wantCode(t, e.runs.End(ctx, EndRequest{Control: ctl, RunID: c.RunID}), CauseTokenInvalid)
	// A refused read (unknown run) spends its token too.
	other := e.ctl(actRunStatus, "r-nope1")
	_, err = e.runs.Status(ctx, other, "r-nope1")
	if !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	_, err = e.runs.Status(ctx, other, "r-nope1")
	wantCode(t, err, CauseTokenInvalid)
}
