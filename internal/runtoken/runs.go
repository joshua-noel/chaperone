package runtoken

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// Run states in the runs table.
const (
	stateActive = "active"
	stateEnded  = "ended"
)

const (
	// controlMaxLifetime is the longest a control token lives (ADR-005).
	controlMaxLifetime = 60
	// purgeMargin is how long past exp a revoked_jti or control_jti row stays.
	purgeMargin  = 60
	actRunStart  = "run.start"
	actRunEnd    = "run.end"
	actRunStatus = "run.status"
)

var (
	runIDRe  = regexp.MustCompile(`^r-[0-9a-z]{4,32}$`)
	jtiRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)
	causeRe  = regexp.MustCompile(`^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$`)
	outcomes = []string{"done", "failed", "killed", "blocked"}
)

// RunRecord is one row of the runs table.
type RunRecord struct {
	RunID        string
	JTI          string
	Project      string
	Issuer       string
	KID          string
	Interim      bool
	Iat, Exp     int64
	Claims       spec.RunTokenClaims // the grant recorded at registration
	State        string
	RegisteredAt time.Time
	EndedAt      time.Time // zero while active
	EndReason    string    // run_end, stop or operator
	EndCauseCode string
	// EndOutcome is how the run ended: done, failed, killed or blocked. Empty while active and for a run that
	// ended before migration 0009.
	EndOutcome string
}

// EndInfo says why a run ended, for the end hooks.
type EndInfo struct {
	// Reason is the token.revoke reason: run_end, stop or operator.
	Reason string
	// Cause is the stop-table code for a stop, operator or reaper end
	// (TIME_EXCEEDED, OPERATOR_STOP_RUN, ...); empty for a normal end.
	Cause string
}

// RunsConfig configures Runs.
type RunsConfig struct {
	DB       *store.DB
	Keys     *KeySet
	Profiles ProfileFunc
	Appender Appender
	Now      func() time.Time
	// TxEnd runs inside the transaction that ends a run, before its events
	// are appended: cancel the run's pending approvals here (status cancelled,
	// op.approve denied "run ended"). An error rolls the end back.
	TxEnd func(ctx context.Context, tx *store.Tx, run RunRecord, info EndInfo) error
	// AfterEnd runs after the end committed: revoke the run's GitHub
	// installation tokens, wipe caches, close open git-proxy streams. The
	// jti is already revoked, so a failure here never leaves the token live.
	AfterEnd func(ctx context.Context, run RunRecord, info EndInfo)
}

// Runs is the run registry: register, end, operator revoke and the reaper.
type Runs struct {
	cfg RunsConfig
	now func() time.Time
}

// NewRuns returns a Runs.
func NewRuns(cfg RunsConfig) (*Runs, error) {
	if cfg.DB == nil || cfg.Keys == nil || cfg.Appender == nil {
		return nil, errors.New("runtoken: Runs needs DB, Keys and Appender")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Runs{cfg: cfg, now: now}, nil
}

type ctlClaims struct {
	Iss   string `json:"iss"`
	Aud   string `json:"aud"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
	JTI   string `json:"jti"`
	Act   string `json:"act"`
	RunID string `json:"run_id"`
}

// verifyControl checks a control JWT (typ factory-ctl+jwt, signed by a
// non-interim key of the pinned set; aud chaperone; act as wanted; exp at most
// 60 s after iat and in the future; run_id naming the run the call is about).
// Single use is enforced when the caller consumes the jti inside its
// transaction.
func (r *Runs) verifyControl(token, act, runID string) (*ctlClaims, *Error) {
	jws, e := verifyJWS(token, typCtl, r.cfg.Keys)
	if e != nil {
		return nil, e
	}
	if jws.Key.Interim != nil {
		return nil, refuse(CauseTokenInvalid, "the interim key does not sign control tokens")
	}
	tree, err := spec.ParseStrict(jws.Payload)
	if err != nil {
		return nil, refuse(CauseTokenInvalid, "control claims are not strict JSON: %v", err)
	}
	var c ctlClaims
	dec := json.NewDecoder(bytes.NewReader(jws.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, refuse(CauseTokenInvalid, "control claims do not decode: %v", err)
	}
	if m, _ := tree.(map[string]any); len(m) != 7 {
		return nil, refuse(CauseTokenInvalid, "control token must carry exactly iss, aud, iat, exp, jti, act and run_id")
	}
	now := r.now().Unix()
	switch {
	case c.Iss != jws.Key.Issuer:
		return nil, refuse(CauseTokenInvalid, "control iss is not the issuer pinned for kid %q", jws.Key.KID)
	case c.Aud != "chaperone":
		return nil, refuse(CauseTokenInvalid, "control aud is not chaperone")
	case c.Act != act:
		return nil, refuse(CauseTokenInvalid, "control act is %q, this call needs %q", c.Act, act)
	case !jtiRe.MatchString(c.JTI):
		return nil, refuse(CauseTokenInvalid, "control jti is malformed")
	case !runIDRe.MatchString(c.RunID):
		return nil, refuse(CauseTokenInvalid, "control run_id is malformed")
	case runID != "" && c.RunID != runID:
		return nil, refuse(CauseTokenInvalid, "control token is for run %s, not %s", c.RunID, runID)
	case c.Iat < 1 || c.Exp <= c.Iat || c.Exp-c.Iat > controlMaxLifetime:
		return nil, refuse(CauseTokenInvalid, "control token must live at most %d s", controlMaxLifetime)
	case c.Iat > now+spec.ClockSkewSeconds:
		return nil, refuse(CauseTokenInvalid, "control iat is more than %d s in the future", spec.ClockSkewSeconds)
	case now >= c.Exp:
		return nil, refuse(CauseTokenExpired, "control token expired")
	}
	return &c, nil
}

// consumeControl records a control token's jti; a second use is refused.
func (r *Runs) consumeControl(ctx context.Context, tx *store.Tx, c *ctlClaims) error {
	res, err := tx.ExecContext(ctx,
		`INSERT INTO control_jti (jti, exp, seen) VALUES (?, ?, ?) ON CONFLICT (jti) DO NOTHING`,
		c.JTI, c.Exp, r.now().Unix())
	if err != nil {
		return fmt.Errorf("runtoken: record control jti: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return refuse(CauseTokenInvalid, "control token was already used")
	}
	return nil
}

// RegisterRequest is the body of POST /v0/runs: the control JWT (act
// run.start) and the run token the runner minted, both compact serialisations.
type RegisterRequest struct {
	Control string
	Token   string
}

// Register is the handler behind POST /v0/runs. It verifies the control token,
// then the run token (ADR-005 steps 1 to 6 and 8, from a non-interim key),
// binds them by run_id, and in one transaction records the control jti, the
// run row (the grant: the verified claims and their hash) and the grant and
// run.start events. A run that is registered twice is ErrConflict.
func (r *Runs) Register(ctx context.Context, req RegisterRequest) (*RunRecord, error) {
	rt, e := parseRunToken(req.Token, r.cfg.Keys, r.cfg.Profiles)
	if e != nil {
		return nil, e
	}
	if rt.Interim {
		return nil, refuse(CauseTokenInvalid, "interim tokens are registered by the interim issuer, not by POST /v0/runs")
	}
	ctl, e := r.verifyControl(req.Control, actRunStart, rt.Claims.RunID)
	if e != nil {
		return nil, e
	}
	if e := checkClaims(rt, r.now(), false); e != nil {
		return nil, e
	}
	var rec *RunRecord
	err := r.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		if err := r.consumeControl(ctx, tx, ctl); err != nil {
			return err
		}
		var err error
		rec, err = r.insertRun(ctx, tx, rt)
		return err
	})
	if err != nil {
		return nil, err
	}
	return rec, nil
}

// insertRun writes the run row and the grant and run.start events inside tx.
func (r *Runs) insertRun(ctx context.Context, tx *store.Tx, rt *RunToken) (*RunRecord, error) {
	c := rt.Claims
	var taken int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM runs WHERE run_id = ? OR jti = ?`, c.RunID, c.JTI).Scan(&taken)
	if err != nil {
		return nil, fmt.Errorf("runtoken: read runs: %w", err)
	}
	if taken > 0 {
		return nil, fmt.Errorf("%w: run %s or its jti is already registered", ErrConflict, c.RunID)
	}
	claimsJSON, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("runtoken: encode claims: %w", err)
	}
	now := r.now()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO runs (run_id, jti, project, profile_name, profile_version, issuer, kid, interim,
		                   iat, exp, claims_json, claims_sha256, state, registered_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)`,
		c.RunID, c.JTI, c.Project, c.Profile.Name, c.Profile.Version, c.Iss, rt.KID, boolInt(rt.Interim),
		c.Iat, c.Exp, string(claimsJSON), rt.grantSHA, now.Unix()); err != nil {
		return nil, fmt.Errorf("runtoken: insert run: %w", err)
	}
	for _, ev := range []Event{grantEvent(c), runStartEvent(c)} {
		if err := r.cfg.Appender.Append(ctx, tx, ev); err != nil {
			return nil, fmt.Errorf("runtoken: ledger %s: %w", ev.Name, err)
		}
	}
	return &RunRecord{
		RunID: c.RunID, JTI: c.JTI, Project: c.Project, Issuer: c.Iss, KID: rt.KID, Interim: rt.Interim,
		Iat: c.Iat, Exp: c.Exp, Claims: c, State: stateActive, RegisteredAt: time.Unix(now.Unix(), 0).UTC(),
	}, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// EndRequest is the body of POST /v0/runs/{id}/end.
type EndRequest struct {
	Control string // control JWT, act run.end, run_id equal to RunID
	RunID   string
	// Outcome is done, failed, killed or blocked; empty means done. killed
	// needs CauseCode, a stop-table code.
	Outcome   string
	CauseCode string
	// ActualTokens is what the runner metered. Chaperone does not meter model
	// tokens, so absent means 0; actual minutes are Chaperone's own clock from
	// registration to this call.
	ActualTokens int64
}

// End is the handler behind POST /v0/runs/{id}/end. In one transaction it
// consumes the control jti, marks the run ended, inserts the jti into
// revoked_jti, runs the TxEnd hook and appends token.revoke and run.end;
// after commit it calls AfterEnd. Ending an ended run succeeds and changes
// nothing, so the runner's crash recovery can repeat the call with a fresh
// control token. The next Verify of the run's token is TOKEN_REVOKED.
func (r *Runs) End(ctx context.Context, req EndRequest) error {
	outcome := req.Outcome
	if outcome == "" {
		outcome = "done"
	}
	switch {
	case !runIDRe.MatchString(req.RunID):
		return invalid("run id %q is malformed", req.RunID)
	case !slices.Contains(outcomes, outcome):
		return invalid("outcome %q is not one of %v", outcome, outcomes)
	case outcome == "killed" && !causeRe.MatchString(req.CauseCode):
		return invalid("outcome killed needs a stop-table cause_code")
	case outcome != "killed" && req.CauseCode != "" && !causeRe.MatchString(req.CauseCode):
		return invalid("cause_code %q is malformed", req.CauseCode)
	case req.ActualTokens < 0:
		return invalid("actual tokens is negative")
	}
	ctl, e := r.verifyControl(req.Control, actRunEnd, req.RunID)
	if e != nil {
		return e
	}
	return r.finish(ctx, req.RunID, EndInfo{Reason: revokeRunEnd}, outcome, req.CauseCode, req.ActualTokens, ctl)
}

// Revoke ends a run at once for an operator or a stop: stop is a stop-table
// code. OPERATOR_STOP_RUN and OPERATOR_STOP_ALL record token.revoke reason
// operator; any other code records reason stop with that cause. The run's
// next request is TOKEN_REVOKED. An ended run is left alone; an unknown run
// is ErrNotFound.
func (r *Runs) Revoke(ctx context.Context, runID, stop string) error {
	if !causeRe.MatchString(stop) {
		return invalid("stop code %q is malformed", stop)
	}
	return r.finish(ctx, runID, revokeInfo(stop), "killed", stop, 0, nil)
}

func revokeInfo(stop string) EndInfo {
	if stop == StopOperatorStopRun || stop == StopOperatorStopAll {
		return EndInfo{Reason: revokeOperator, Cause: stop}
	}
	return EndInfo{Reason: revokeStop, Cause: stop}
}

// RevokeAll revokes every active run (`chap runs revoke --all`, "Stop all")
// and returns how many it ended. It keeps going after a failure and returns
// the errors joined.
func (r *Runs) RevokeAll(ctx context.Context, stop string) (int, error) {
	ids, err := r.activeRunIDs(ctx, 0)
	if err != nil {
		return 0, err
	}
	var errs []error
	n := 0
	for _, id := range ids {
		switch err := r.Revoke(ctx, id, stop); {
		case err == nil:
			n++
		default:
			errs = append(errs, fmt.Errorf("run %s: %w", id, err))
		}
	}
	return n, errors.Join(errs...)
}

// Reap ends every active run whose exp has passed (ADR-005 fail-safes b and
// c): outcome killed, cause TIME_EXCEEDED, token.revoke reason run_end. Call
// it once when chapd starts and then on a timer ([Runs.RunReaper]). It also
// deletes revoked_jti and control_jti rows long past their exp.
func (r *Runs) Reap(ctx context.Context) (int, error) {
	now := r.now().Unix()
	ids, err := r.activeRunIDs(ctx, now)
	if err != nil {
		return 0, err
	}
	var errs []error
	n := 0
	for _, id := range ids {
		if err := r.finish(ctx, id, EndInfo{Reason: revokeRunEnd, Cause: StopTimeExceeded}, "killed", StopTimeExceeded, 0, nil); err != nil {
			errs = append(errs, fmt.Errorf("run %s: %w", id, err))
			continue
		}
		n++
	}
	// One write transaction, through the store's write gate like every other write.
	if err := r.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		for _, table := range []string{"revoked_jti", "control_jti"} {
			if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE exp < ?`, now-purgeMargin); err != nil {
				return fmt.Errorf("purge %s: %w", table, err)
			}
		}
		return nil
	}); err != nil {
		errs = append(errs, err)
	}
	return n, errors.Join(errs...)
}

// RunReaper calls Reap now and then every interval until ctx ends. A failed
// pass goes to onError (may be nil) and the loop goes on.
func (r *Runs) RunReaper(ctx context.Context, interval time.Duration, onError func(error)) {
	pass := func() {
		if _, err := r.Reap(ctx); err != nil && onError != nil && ctx.Err() == nil {
			onError(err)
		}
	}
	pass()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pass()
		}
	}
}

// activeRunIDs lists active runs; expiredBy > 0 keeps only those with
// exp <= expiredBy.
func (r *Runs) activeRunIDs(ctx context.Context, expiredBy int64) ([]string, error) {
	q, args := `SELECT run_id FROM runs WHERE state = 'active'`, []any(nil)
	if expiredBy > 0 {
		q, args = q+` AND exp <= ?`, []any{expiredBy}
	}
	rows, err := r.cfg.DB.SQL().QueryContext(ctx, q+` ORDER BY run_id`, args...)
	if err != nil {
		return nil, fmt.Errorf("runtoken: list runs: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("runtoken: list runs: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// finish ends one run in its own transaction. ctl, when set, is consumed in
// the same transaction.
func (r *Runs) finish(ctx context.Context, runID string, info EndInfo, outcome, cause string, tokens int64, ctl *ctlClaims) error {
	var rec RunRecord
	ended := false
	err := r.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		ended = false
		if ctl != nil {
			if err := r.consumeControl(ctx, tx, ctl); err != nil {
				return err
			}
		}
		var err error
		rec, err = scanRun(tx.QueryRowContext(ctx, runSelect+` WHERE run_id = ?`, runID))
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("%w: run %s", ErrNotFound, runID)
		case err != nil:
			return err
		case rec.State != stateActive:
			return nil // already ended: idempotent
		}
		now := r.now()
		if _, err := tx.ExecContext(ctx,
			`UPDATE runs SET state = 'ended', ended_at = ?, end_reason = ?, end_cause_code = ?, end_outcome = ? WHERE run_id = ? AND state = 'active'`,
			now.Unix(), info.Reason, nullIfEmpty(info.Cause), outcome, runID); err != nil {
			return fmt.Errorf("runtoken: end run: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO revoked_jti (jti, run_id, exp, revoked_at, reason, cause_code) VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT (jti) DO NOTHING`,
			rec.JTI, runID, rec.Exp, now.Unix(), info.Reason, nullIfEmpty(info.Cause)); err != nil {
			return fmt.Errorf("runtoken: revoke jti: %w", err)
		}
		rec.State, rec.EndedAt, rec.EndReason, rec.EndCauseCode, rec.EndOutcome = stateEnded, time.Unix(now.Unix(), 0).UTC(), info.Reason, info.Cause, outcome
		if r.cfg.TxEnd != nil {
			if err := r.cfg.TxEnd(ctx, tx, rec, info); err != nil {
				return fmt.Errorf("runtoken: end hook: %w", err)
			}
		}
		minutes := max(0, now.Sub(rec.RegisteredAt).Minutes())
		for _, ev := range []Event{
			tokenRevokeEvent(rec, info.Reason, info.Cause),
			runEndEvent(rec, outcome, cause, minutes, tokens),
		} {
			if err := r.cfg.Appender.Append(ctx, tx, ev); err != nil {
				return fmt.Errorf("runtoken: ledger %s: %w", ev.Name, err)
			}
		}
		ended = true
		return nil
	})
	if err != nil {
		return err
	}
	if ended && r.cfg.AfterEnd != nil {
		r.cfg.AfterEnd(ctx, rec, info)
	}
	return nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

const runSelect = `SELECT run_id, jti, project, issuer, kid, interim, iat, exp, claims_json, state,
	registered_at, ended_at, end_reason, end_cause_code, end_outcome FROM runs`

type rowScanner interface{ Scan(...any) error }

func scanRun(row rowScanner) (RunRecord, error) {
	var (
		rec               RunRecord
		interim           int
		claims            string
		registered        int64
		ended             sql.NullInt64
		reason, causeCode sql.NullString
		outcome           sql.NullString
	)
	if err := row.Scan(&rec.RunID, &rec.JTI, &rec.Project, &rec.Issuer, &rec.KID, &interim, &rec.Iat, &rec.Exp,
		&claims, &rec.State, &registered, &ended, &reason, &causeCode, &outcome); err != nil {
		return RunRecord{}, err
	}
	if err := json.Unmarshal([]byte(claims), &rec.Claims); err != nil {
		return RunRecord{}, fmt.Errorf("runtoken: stored claims of %s: %w", rec.RunID, err)
	}
	rec.Interim = interim == 1
	rec.RegisteredAt = time.Unix(registered, 0).UTC()
	if ended.Valid {
		rec.EndedAt = time.Unix(ended.Int64, 0).UTC()
	}
	rec.EndReason, rec.EndCauseCode, rec.EndOutcome = reason.String, causeCode.String, outcome.String
	return rec, nil
}

// Get returns the run row.
func (r *Runs) Get(ctx context.Context, runID string) (RunRecord, error) {
	rec, err := scanRun(r.cfg.DB.SQL().QueryRowContext(ctx, runSelect+` WHERE run_id = ?`, runID))
	if errors.Is(err, sql.ErrNoRows) {
		return RunRecord{}, fmt.Errorf("%w: run %s", ErrNotFound, runID)
	}
	return rec, err
}

// RunStatus is everything GET /v0/runs/{id} tells the runner about a run it
// registered, and nothing else (LF-2): its state, when and why it ended, and
// when its token expires.
type RunStatus struct {
	State     string    // active or ended
	EndedAt   time.Time // zero while active
	CauseCode string    // stop-table code of a stop, operator or reaper end; empty for a normal end
	ExpiresAt time.Time // the run token's exp
}

// Status is the handler behind GET /v0/runs/{id}. control is a control JWT
// (act run.status, run_id equal to runID) signed by a non-interim key of the
// pinned set. A caller reads only runs its own issuer registered: an unknown
// run and another issuer's run (an interim run is one: no interim key signs a
// control token) are both ErrNotFound, so one
// the runner cannot learn what another registered. The control jti is consumed in
// the same transaction as the read, whatever it finds, so a token reads once.
// Nothing is written to the ledger: a read does not change a run.
func (r *Runs) Status(ctx context.Context, control, runID string) (RunStatus, error) {
	if !runIDRe.MatchString(runID) {
		return RunStatus{}, invalid("run id %q is malformed", runID)
	}
	ctl, e := r.verifyControl(control, actRunStatus, runID)
	if e != nil {
		return RunStatus{}, e
	}
	var rec RunRecord
	missing := false
	err := r.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		missing = false
		if err := r.consumeControl(ctx, tx, ctl); err != nil {
			return err
		}
		var err error
		rec, err = scanRun(tx.QueryRowContext(ctx, runSelect+` WHERE run_id = ?`, runID))
		if errors.Is(err, sql.ErrNoRows) {
			missing = true
			return nil
		}
		return err
	})
	if err != nil {
		return RunStatus{}, err
	}
	if missing || rec.Issuer != ctl.Iss {
		return RunStatus{}, fmt.Errorf("%w: run %s", ErrNotFound, runID)
	}
	return RunStatus{
		State: rec.State, EndedAt: rec.EndedAt, CauseCode: rec.EndCauseCode,
		ExpiresAt: time.Unix(rec.Exp, 0).UTC(),
	}, nil
}

// Default and largest page of [Runs.List].
const (
	defaultListLimit = 100
	maxListLimit     = 500
)

// List pages through the runs table, newest registered first (ties by run_id,
// descending). state is "", "active" or "ended". limit is 1 to 500; 0 means
// 100. afterRunID is the cursor an earlier call returned: the page starts
// after that run. The returned cursor is the last run_id of a full page that
// has more rows after it, else "". An unknown cursor or state is ErrInvalid.
// It only reads.
func (r *Runs) List(ctx context.Context, state string, limit int, afterRunID string) ([]RunRecord, string, error) {
	if state != "" && state != stateActive && state != stateEnded {
		return nil, "", invalid("state %q is not active or ended", state)
	}
	if limit < 0 || limit > maxListLimit {
		return nil, "", invalid("limit must be 1 to %d", maxListLimit)
	}
	if limit == 0 {
		limit = defaultListLimit
	}
	q, args := runSelect+` WHERE 1 = 1`, []any{}
	if state != "" {
		q, args = q+` AND state = ?`, append(args, state)
	}
	if afterRunID != "" {
		var at int64
		err := r.cfg.DB.SQL().QueryRowContext(ctx, `SELECT registered_at FROM runs WHERE run_id = ?`, afterRunID).Scan(&at)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", invalid("cursor %q is not a run", afterRunID)
		} else if err != nil {
			return nil, "", fmt.Errorf("runtoken: list runs: %w", err)
		}
		q, args = q+` AND (registered_at < ? OR (registered_at = ? AND run_id < ?))`, append(args, at, at, afterRunID)
	}
	rows, err := r.cfg.DB.SQL().QueryContext(ctx, q+` ORDER BY registered_at DESC, run_id DESC LIMIT ?`, append(args, limit+1)...)
	if err != nil {
		return nil, "", fmt.Errorf("runtoken: list runs: %w", err)
	}
	defer rows.Close()
	var out []RunRecord
	for rows.Next() {
		rec, err := scanRun(rows)
		if err != nil {
			return nil, "", err
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("runtoken: list runs: %w", err)
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = out[limit-1].RunID
	}
	return out, next, nil
}
