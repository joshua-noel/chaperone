package redteam

// The wiring of cmd/chapd (wire.go), copied. chapd is `package main`, so its
// Build cannot be imported; the red-team rig needs the same token verifiers,
// backends and stop raiser behind the same ops.Server, with a spy adapter in
// place of every op's adapter. If cmd/chapd/wire.go changes, change this file.

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/ledger"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/runtoken"
	"github.com/joshua-noel/chaperone/internal/store"
	"github.com/joshua-noel/chaperone/internal/vault"
)

type ledgerSink struct{ l *ledger.Ledger }

func (s ledgerSink) draft(name, runID, project, severity string, attrs map[string]any, body string) ledger.Draft {
	if len(body) > 1000 {
		body = body[:1000]
	}
	return ledger.Draft{Name: name, RunID: runID, Project: project, Severity: severity, Attributes: attrs, Body: body}
}

func (s ledgerSink) AppendTx(ctx context.Context, tx *store.Tx, e ops.Event) error {
	_, err := s.l.AppendTx(ctx, tx, s.draft(e.Name, e.RunID, e.Project, e.Severity, e.Attributes, e.Body))
	return err
}

func (s ledgerSink) Append(ctx context.Context, tx *store.Tx, e runtoken.Event) error {
	_, err := s.l.AppendTx(ctx, tx, s.draft(e.Name, e.RunID, e.Project, e.Severity, e.Attributes, e.Body))
	return err
}

func tokenErr(err error) error {
	var te *runtoken.Error
	if !errors.As(err, &te) {
		return err
	}
	ve := &ops.VerifyError{Code: te.Code, Surface: te.Surface, Detail: te.Detail, OrchID: te.OrchID, Project: te.Project}
	if te.Run != nil {
		ve.Run = &ops.Caller{RunID: te.Run.RunID, Project: te.Run.Project, Profile: te.Run.Profile}
	}
	return ve
}

type runVerifier struct {
	v    *runtoken.Verifier
	stop func(ctx context.Context, e *runtoken.Error)
}

func (a runVerifier) VerifyRun(ctx context.Context, bearer string) (*ops.Caller, error) {
	t, err := a.v.Verify(ctx, bearer)
	if err != nil {
		var te *runtoken.Error
		if errors.As(err, &te) && te.Stop != "" && a.stop != nil {
			a.stop(ctx, te)
		}
		return nil, tokenErr(err)
	}
	c := t.Claims
	return &ops.Caller{
		Kind: ops.KindRun, RunID: c.RunID, JTI: c.JTI, Profile: c.Profile.Name, Interim: t.Interim,
		Project: c.Project, Repo: c.TaskScope.Repo, Base: c.TaskScope.Base, Branch: c.TaskScope.Branch,
		Paths: c.TaskScope.Paths, TokenOps: c.TaskScope.Ops, Expires: time.Unix(c.Exp, 0),
	}, nil
}

type orchVerifier struct{ o *runtoken.Orchestrators }

func (a orchVerifier) VerifyOrch(ctx context.Context, bearer string) (*ops.Caller, error) {
	p, err := a.o.Verify(ctx, bearer)
	if err != nil {
		return nil, tokenErr(err)
	}
	return &ops.Caller{
		Kind: ops.KindOrchestrator, OrchID: p.ID, Fingerprint: p.Fingerprint, Projects: p.Scope.Projects,
		ScopeOps: p.Scope.Ops, MintInterim: p.Scope.MintInterim, Expires: p.ExpiresAt,
	}, nil
}

func raiseTokenMisuse(l *ledger.Ledger, newID func() string, log *slog.Logger) func(context.Context, *runtoken.Error) {
	return func(ctx context.Context, e *runtoken.Error) {
		if e.Run == nil {
			return
		}
		_, err := l.Append(ctx, ledger.Draft{
			Name: "stop.raise", RunID: e.Run.RunID, Project: e.Run.Project, Severity: "WARN",
			Attributes: map[string]any{
				"factory.stop.id": newID(), "factory.cause_code": e.Stop, "factory.halts": "dependents", "factory.action": "quarantine",
			},
			Body: "token misuse: " + e.Code,
		})
		if err != nil {
			log.Error("could not record the TOKEN_MISUSE stop", "run", e.Run.RunID, "err", err)
		}
	}
}

type runsBackend struct{ r *runtoken.Runs }

func runView(rec runtoken.RunRecord) map[string]any {
	state := "active"
	if rec.State != "active" {
		state = "ended"
		if rec.EndReason == "operator" || rec.EndReason == "stop" {
			state = "revoked"
		}
	}
	v := map[string]any{
		"run_id": rec.RunID, "project": rec.Project, "profile": rec.Claims.Profile.Name, "state": state,
		"interim": rec.Interim, "expires_at": time.Unix(rec.Exp, 0).UTC().Format(time.RFC3339),
	}
	if !rec.EndedAt.IsZero() {
		v["ended_at"] = rec.EndedAt.UTC().Format(time.RFC3339)
		reason := rec.EndReason
		if rec.EndCauseCode != "" {
			reason += " " + rec.EndCauseCode
		}
		v["end_reason"] = reason
	}
	return v
}

func runsErr(err error) error {
	var te *runtoken.Error
	switch {
	case errors.As(err, &te):
		return &ops.VerifyError{Code: te.Code, Detail: te.Detail}
	case errors.Is(err, runtoken.ErrNotFound):
		return &ops.NotFoundError{Why: "no such run"}
	case errors.Is(err, runtoken.ErrConflict):
		return &ops.ConflictError{Why: "the run is already registered, or the control token was already used"}
	case errors.Is(err, runtoken.ErrInvalid):
		return &ops.VerifyError{Code: ops.CodeTokenInvalid, Detail: "the control request is malformed"}
	}
	return err
}

func (b runsBackend) Register(ctx context.Context, control, token string) (any, error) {
	rec, err := b.r.Register(ctx, runtoken.RegisterRequest{Control: control, Token: token})
	if err != nil {
		return nil, runsErr(err)
	}
	return runView(*rec), nil
}

func (b runsBackend) End(ctx context.Context, runID string, e ops.RunEnd) (any, error) {
	if err := b.r.End(ctx, runtoken.EndRequest{Control: e.Control, RunID: runID, Outcome: e.Outcome, CauseCode: e.CauseCode, ActualTokens: e.ActualTokens}); err != nil {
		return nil, runsErr(err)
	}
	rec, err := b.r.Get(ctx, runID)
	if err != nil {
		return nil, runsErr(err)
	}
	return runView(rec), nil
}

func (b runsBackend) Revoke(ctx context.Context, runID string) (any, error) {
	if err := b.r.Revoke(ctx, runID, runtoken.StopOperatorStopRun); err != nil {
		return nil, runsErr(err)
	}
	rec, err := b.r.Get(ctx, runID)
	if err != nil {
		return nil, runsErr(err)
	}
	return runView(rec), nil
}

func (b runsBackend) RevokeAll(ctx context.Context) (int, error) {
	return b.r.RevokeAll(ctx, runtoken.StopOperatorStopAll)
}

func (b runsBackend) List(ctx context.Context, state string, limit int, after string) (any, error) {
	recs, next, err := b.r.List(ctx, state, limit, after)
	if err != nil {
		return nil, runsErr(err)
	}
	items := make([]map[string]any, 0, len(recs))
	for _, r := range recs {
		items = append(items, runView(r))
	}
	var nc any
	if next != "" {
		nc = next
	}
	return map[string]any{"items": items, "next_cursor": nc}, nil
}

func (b runsBackend) Status(ctx context.Context, control, runID string) (any, error) {
	st, err := b.r.Status(ctx, control, runID)
	if err != nil {
		return nil, runsErr(err)
	}
	v := map[string]any{"state": st.State, "ended_at": nil, "cause_code": nil, "expires_at": st.ExpiresAt.UTC().Format(time.RFC3339)}
	if !st.EndedAt.IsZero() {
		v["ended_at"] = st.EndedAt.UTC().Format(time.RFC3339)
	}
	if st.CauseCode != "" {
		v["cause_code"] = st.CauseCode
	}
	return v, nil
}

type interimBackend struct{ i *runtoken.Interim }

func (b interimBackend) Mint(ctx context.Context, bearer string, req ops.DevTokenRequest) (any, error) {
	res, err := b.i.Mint(ctx, bearer, runtoken.MintRequest{
		Project: req.Project, Profile: req.Profile, Repo: req.Repo, Base: req.Base, Branch: req.Branch,
		Paths: req.Paths, Ops: req.Ops, Minutes: req.Minutes,
	})
	if err != nil {
		var te *runtoken.Error
		if errors.As(err, &te) {
			return nil, &ops.VerifyError{Code: te.Code, Surface: te.Surface, Detail: te.Detail}
		}
		if errors.Is(err, runtoken.ErrInvalid) {
			return nil, &ops.VerifyError{Code: ops.CodeParamsInvalid, Surface: "op", Detail: err.Error()}
		}
		return nil, err
	}
	return map[string]any{
		"token": res.Token, "run_id": res.Claims.RunID, "jti": res.Claims.JTI,
		"expires_at": time.Unix(res.Claims.Exp, 0).UTC().Format(time.RFC3339),
	}, nil
}

type ledgerBackend struct{ l *ledger.Ledger }

func (b ledgerBackend) Query(ctx context.Context, q ops.LedgerQuery) ([]json.RawMessage, *int64, error) {
	evs, err := b.l.Query(ctx, ledger.QueryParams{
		RunID: q.RunID, RequestID: q.RequestID, EventName: q.EventName, From: q.From, To: q.To,
		AfterSeq: q.AfterSeq, Limit: q.Limit,
	})
	if err != nil {
		return nil, nil, err
	}
	items := make([]json.RawMessage, 0, len(evs))
	for _, e := range evs {
		raw, err := json.Marshal(e)
		if err != nil {
			return nil, nil, err
		}
		items = append(items, raw)
	}
	var next *int64
	if len(evs) == q.Limit && len(evs) > 0 {
		n := evs[len(evs)-1].Seq
		next = &n
	}
	return items, next, nil
}

func (b ledgerBackend) Verify(ctx context.Context, againstExport bool) (any, error) {
	rep, err := b.l.Verify(ctx, againstExport)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": rep.OK(), "chain": b.l.Chain(), "head_seq": 0, "head_hash": "sha256:" + strings.Repeat("0", 64), "checked_export": againstExport, "problems": []string{}}, nil
}

type vaultBackend struct{ v *vault.Vault }

func (b vaultBackend) Status(ctx context.Context) (any, error) {
	infos, err := b.v.List(ctx)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(infos))
	for _, i := range infos {
		names = append(names, i.ID)
	}
	return map[string]any{"initialized": true, "secret_count": len(names), "names": names}, nil
}

func idMaker(prefix string) func() string {
	return func() string {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic("redteam: crypto/rand failed: " + err.Error())
		}
		const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
		out := make([]byte, len(b))
		for i, v := range b {
			out[i] = alphabet[int(v)%len(alphabet)]
		}
		return prefix + string(out)
	}
}
