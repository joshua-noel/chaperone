package runtoken

import (
	"bytes"
	"context"
	"errors"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/redact"
	"github.com/joshua-noel/chaperone/internal/store"
)

var mainScope = OrchScope{Projects: []string{"acme-shop"}, Ops: []string{"pr.open", "pr.merge", "branch.push", "deploy"}, MintInterim: true}

func (e *env) issueOrch(id string, scope OrchScope, days int) IssueResult {
	e.t.Helper()
	r, err := e.orch.Issue(context.Background(), IssueParams{ID: id, Scope: scope, Days: days})
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

func TestOrchIssueVerify(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	r := e.issueOrch("main", mainScope, 0)
	if !strings.HasPrefix(r.Token, OrchPrefix) || len(r.Token) != len(OrchPrefix)+43 || len(r.Fingerprint) != 8 {
		t.Fatalf("token shape %q fp %q", r.Token, r.Fingerprint)
	}
	if want := e.clock.Add(30 * 24 * time.Hour).Unix(); r.ExpiresAt.Unix() != want {
		t.Fatalf("default lifetime: expires %v", r.ExpiresAt)
	}
	p, err := e.orch.Verify(ctx, r.Token)
	mustNil(t, err)
	if p.ID != "main" || p.Fingerprint != r.Fingerprint || !p.Scope.MintInterim || !slices.Equal(p.Scope.Projects, []string{"acme-shop"}) {
		t.Fatalf("principal %+v", p)
	}
	if !IsOrchToken(r.Token) || IsOrchToken("eyJhbGciOi") {
		t.Fatal("IsOrchToken routes wrongly")
	}
}

func TestOrchScope(t *testing.T) {
	e := newEnv(t)
	p, err := e.orch.Verify(context.Background(), e.issueOrch("main", OrchScope{Projects: []string{"acme-shop"}, Ops: []string{"pr.open", "mail.*"}}, 1).Token)
	mustNil(t, err)
	mustNil(t, p.CheckOp("acme-shop", "pr.open"))
	mustNil(t, p.CheckOp("acme-shop", "mail.send"))
	re := wantCode(t, p.CheckOp("acme-shop", "deploy"), CauseOpNotInToken)
	if re.OrchID != "main" {
		t.Fatalf("OrchID %q", re.OrchID)
	}
	if re := wantCode(t, p.CheckOp("other-project", "pr.open"), CauseOpNotInToken); re.Project != "acme-shop" {
		t.Fatalf("Project %q", re.Project)
	}
	if got := p.EffectiveOps("acme-shop", []string{"pr.open", "deploy", "mail.send"}); !slices.Equal(got, []string{"pr.open", "mail.send"}) {
		t.Fatalf("effective %v", got)
	}
	if got := p.EffectiveOps("acme-shop", nil); len(got) != 0 {
		t.Fatalf("nil catalog enabled %v", got)
	}
	if got := p.EffectiveOps("other-project", []string{"pr.open"}); len(got) != 0 {
		t.Fatalf("other project enabled %v", got)
	}
}

func TestOrchExpiry(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	r := e.issueOrch("main", mainScope, 2)
	e.clock = r.ExpiresAt.Add(-time.Second)
	_, err := e.orch.Verify(ctx, r.Token)
	mustNil(t, err)
	e.clock = r.ExpiresAt
	_, err = e.orch.Verify(ctx, r.Token)
	if re := wantCode(t, err, CauseTokenExpired); re.OrchID != "main" || re.Project != "acme-shop" || re.Stop != StopTokenMisuse {
		t.Fatalf("%+v", re)
	}
}

func TestOrchThirtyDayCap(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	for _, days := range []int{31, -1, 365} {
		if _, err := e.orch.Issue(ctx, IssueParams{ID: "main", Scope: mainScope, Days: days}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("days=%d: %v", days, err)
		}
	}
	r := e.issueOrch("main", mainScope, 30)
	_, err := e.orch.Verify(ctx, r.Token)
	mustNil(t, err)
	// A row edited past the cap is refused at verify, not trusted.
	if _, err := e.db.SQL().Exec(`UPDATE orchestrators SET expires_at = issued_at + ?`, 31*24*3600); err != nil {
		t.Fatal(err)
	}
	_, err = e.orch.Verify(ctx, r.Token)
	wantCode(t, err, CauseTokenInvalid)
}

func TestOrchRotateAndRevoke(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	old := e.issueOrch("main", mainScope, 0)
	next := e.issueOrch("main", mainScope, 0)
	if old.Token == next.Token {
		t.Fatal("rotation reused the token")
	}
	_, err := e.orch.Verify(ctx, old.Token)
	wantCode(t, err, CauseTokenRevoked)
	_, err = e.orch.Verify(ctx, next.Token)
	mustNil(t, err)
	var by string
	_ = e.db.SQL().QueryRow(`SELECT revoked_by FROM orchestrators WHERE revoked_at IS NOT NULL`).Scan(&by)
	if by != "rotated" {
		t.Fatalf("revoked_by %q", by)
	}

	mustNil(t, e.orch.Revoke(ctx, "main", "chapd orch revoke"))
	// The very next request.
	_, err = e.orch.Verify(ctx, next.Token)
	if re := wantCode(t, err, CauseTokenRevoked); re.OrchID != "main" || re.Project != "acme-shop" || re.Stop != StopTokenMisuse {
		t.Fatalf("%+v", re)
	}
	if !slices.Equal(e.orchTx, []string{"main"}) {
		t.Fatalf("TxRevoke hook: %v", e.orchTx)
	}
	if err := e.orch.Revoke(ctx, "main", "again"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second revoke: %v", err)
	}
	if err := e.orch.Revoke(ctx, "main", " "); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty by: %v", err)
	}
	// A new token for the id works after a revoke.
	again := e.issueOrch("main", mainScope, 0)
	_, err = e.orch.Verify(ctx, again.Token)
	mustNil(t, err)
}

func TestOrchRevokeHookFailureRollsBack(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	r := e.issueOrch("main", mainScope, 0)
	e.orch.cfg.TxRevoke = func(context.Context, *store.Tx, string) error { return errors.New("approvals locked") }
	if err := e.orch.Revoke(ctx, "main", "console"); err == nil {
		t.Fatal("revoked although the hook failed")
	}
	_, err := e.orch.Verify(ctx, r.Token)
	mustNil(t, err)
}

func TestOrchRefusesBadTokens(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	good := e.issueOrch("main", mainScope, 0).Token
	flip := []byte(good)
	flip[len(flip)-1] ^= 1
	for name, tok := range map[string]string{
		"empty":            "",
		"no prefix":        strings.TrimPrefix(good, OrchPrefix),
		"too short":        good[:len(good)-1],
		"too long":         good + "A",
		"unknown value":    string(flip),
		"padding char":     good[:len(good)-1] + "=",
		"never issued":     OrchPrefix + strings.Repeat("A", 43),
		"a run token":      e.far.sign(t, typRun, e.claims()),
		"prefix in middle": " " + good,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := e.orch.Verify(ctx, tok)
			wantCode(t, err, CauseTokenInvalid)
		})
	}
}

// ADR-007 Verify: only the SHA-256 is stored; grep state.db for the plaintext
// finds nothing.
func TestOrchOnlyTheHashIsStored(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	r := e.issueOrch("main", mainScope, 0)
	secret := strings.TrimPrefix(r.Token, OrchPrefix)

	rows, err := e.db.SQL().QueryContext(ctx, `SELECT token_sha256, id, scope FROM orchestrators`)
	mustNil(t, err)
	defer rows.Close()
	for rows.Next() {
		var h, id, scope string
		mustNil(t, rows.Scan(&h, &id, &scope))
		if len(h) != 64 || h != sha256Hex(r.Token) || strings.Contains(h+id+scope, secret) {
			t.Fatalf("row %q %q %q", h, id, scope)
		}
	}
	// And in the files: checkpoint the WAL, then scan the database file and
	// the WAL for the plaintext and its base64 secret part.
	if _, err := e.db.SQL().ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal"} {
		b, err := os.ReadFile(e.db.Path() + suffix)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte(r.Token)) || bytes.Contains(b, []byte(secret)) {
			t.Fatalf("state.db%s holds the plaintext token", suffix)
		}
	}
	// The ledger events carry the fingerprint, never the token.
	for _, ev := range e.led.events {
		if strings.Contains(sprint(ev), secret) {
			t.Fatalf("event %s holds the token", ev.Name)
		}
	}
}

func TestOrchRedactionAndLedger(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	reg := redact.NewRegistry()
	e.orch.cfg.Redact = reg
	r := e.issueOrch("main", mainScope, 0)
	if out, res := reg.Redact("curl -H 'Authorization: Bearer " + r.Token + "'"); !res.Blocked() || strings.Contains(out, r.Token) {
		t.Fatalf("token not redacted: %q", out)
	}
	if got := e.led.names(); !slices.Equal(got, []string{"op.request", "op.result"}) {
		t.Fatalf("events %v", got)
	}
	req, res := e.led.find("op.request")[0], e.led.find("op.result")[0]
	if req.Attributes["factory.op"] != "orchestrator.issue" || req.RunID != "" || req.Project != "acme-shop" ||
		req.Attributes["factory.requester.kind"] != "orchestrator" || res.Attributes["factory.outcome"] != "succeeded" ||
		res.Attributes["factory.policy_version"] != "baseline-test" ||
		req.Attributes["factory.op_hash"] != res.Attributes["factory.op_hash"] || !strings.Contains(req.Body, r.Fingerprint) {
		t.Fatalf("events %+v %+v", req, res)
	}
	mustNil(t, e.orch.Revoke(ctx, "main", "console"))
	if got := e.led.find("op.request"); len(got) != 2 || got[1].Attributes["factory.op"] != "orchestrator.revoke" {
		t.Fatalf("revoke events %+v", got)
	}
}

func TestOrchLedgerFailureFailsClosed(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.led.failOn = "op.result"
	if _, err := e.orch.Issue(ctx, IssueParams{ID: "main", Scope: mainScope}); err == nil {
		t.Fatal("issued although the ledger refused")
	}
	if rows, _ := e.orch.List(ctx); len(rows) != 0 {
		t.Fatalf("a failed issue left %d rows", len(rows))
	}
	e.led.failOn = ""
	r := e.issueOrch("main", mainScope, 0)
	e.led.failOn = "op.result"
	if err := e.orch.Revoke(ctx, "main", "console"); err == nil {
		t.Fatal("revoked although the ledger refused")
	}
	_, err := e.orch.Verify(ctx, r.Token)
	mustNil(t, err)
}

func TestOrchIssueValidation(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	bad := []IssueParams{
		{ID: "Mixed-Case", Scope: mainScope},
		{ID: "", Scope: mainScope},
		{ID: "main", Scope: OrchScope{}},
		{ID: "main", Scope: OrchScope{Projects: []string{"acme-shop"}}},
		{ID: "main", Scope: OrchScope{Ops: []string{"pr.open"}}},
		{ID: "main", Scope: OrchScope{Projects: []string{"Bad Project"}, Ops: []string{"pr.open"}}},
		{ID: "main", Scope: OrchScope{Projects: []string{"acme-shop"}, Ops: []string{"*"}}},
		{ID: "main", Scope: OrchScope{Projects: []string{"acme-shop"}, Ops: []string{"PR.open"}}},
		{ID: "main", Scope: OrchScope{Projects: []string{"acme-shop", "acme-shop"}, Ops: []string{"pr.open"}}},
	}
	for i, p := range bad {
		if _, err := e.orch.Issue(ctx, p); !errors.Is(err, ErrInvalid) {
			t.Fatalf("case %d: %v", i, err)
		}
	}
}

func TestOrchList(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a := e.issueOrch("main", mainScope, 0)
	e.clock = e.clock.Add(time.Hour)
	b := e.issueOrch("main", mainScope, 1)
	rows, err := e.orch.List(ctx)
	mustNil(t, err)
	if len(rows) != 2 || rows[0].Fingerprint != b.Fingerprint || rows[1].Fingerprint != a.Fingerprint {
		t.Fatalf("rows %+v", rows)
	}
	if !rows[0].Live(e.clock) || rows[1].Live(e.clock) || rows[1].RevokedBy != "rotated" {
		t.Fatalf("liveness %+v", rows)
	}
	if rows[0].Live(e.clock.Add(25 * time.Hour)) {
		t.Fatal("an expired token is live")
	}
}

// The id "key.<id>" is how a custom key reaches the spec's ledger (spec.KeyRequester): no orchestrator may be
// called by it, or its events would pass for a key's.
func TestOrchestratorIdsCannotStartWithTheKeyPrefix(t *testing.T) {
	e := newEnv(t)
	o := e.orch
	for _, id := range []string{"key.k-0123456789abcdef", "key.x"} {
		_, err := o.Issue(context.Background(), IssueParams{ID: id, Scope: OrchScope{Projects: []string{"acme-shop"}, Ops: []string{"pr.merge"}}})
		if err == nil || !strings.Contains(err.Error(), "reserved for keys") {
			t.Errorf("%s: %v", id, err)
		}
	}
	if _, err := o.Issue(context.Background(), IssueParams{ID: "keymaker", Scope: OrchScope{Projects: []string{"acme-shop"}, Ops: []string{"pr.merge"}}}); err != nil {
		t.Errorf("an id that merely starts with key: %v", err)
	}
}

// The reserved ids are refused when a token is issued and again when it is verified: a row that got there another
// way (a database from before the ids were reserved, or an insert) never acts as the console's own identity
// ("operator" passes the gates that only a person's own Hello may pass) or as a name chapd records for keys, people,
// agents and enrolments.
func TestReservedOrchestratorIdsAreRefusedAtVerifyToo(t *testing.T) {
	ctx := context.Background()
	for _, id := range []string{"operator", "chapd", "key.k-0123456789abcdef", "person.operator", "agent.operator.scout", "enrol.en-0123456789abcdef"} {
		e := newEnv(t)
		r := e.issueOrch("main", mainScope, 0)
		if _, err := e.orch.Verify(ctx, r.Token); err != nil {
			t.Fatalf("control: %v", err)
		}
		if _, err := e.db.SQL().Exec(`UPDATE orchestrators SET id = ?`, id); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		_, err := e.orch.Verify(ctx, r.Token)
		if re := wantCode(t, err, CauseTokenInvalid); !strings.Contains(re.Error(), "reserved") && !strings.Contains(re.Error(), "must not start") {
			t.Errorf("%s: %v", id, re)
		}
		// Issue still refuses them.
		if _, err := e.orch.Issue(ctx, IssueParams{ID: id, Scope: mainScope}); !errors.Is(err, ErrInvalid) {
			t.Errorf("issue %s: %v", id, err)
		}
	}
}

// Issuing a token tells the owner of the keys, in the same transaction and before the old token is rotated out, the
// scope the new token will have, so that what it no longer reaches (a project, an operation) can be revoked with it.
func TestIssueGivesTheKeyOwnerTheNewScopeInTheSameTransaction(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	var seen []string
	var err error
	e.orch, err = NewOrchestrators(OrchConfig{
		DB: e.db, Appender: e.led, Now: func() time.Time { return e.clock },
		PolicyVersion: func() string { return e.policy },
		TxReissue: func(_ context.Context, tx *store.Tx, id string, sc OrchScope) error {
			var live int
			_ = tx.QueryRowContext(ctx, `SELECT count(*) FROM orchestrators WHERE id = ? AND revoked_at IS NULL`, id).Scan(&live)
			seen = append(seen, id+":"+strings.Join(sc.Projects, "+")+":"+strings.Join(sc.Ops, "+")+":live="+strconv.Itoa(live))
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.issueOrch("main", OrchScope{Projects: []string{"acme-shop", "acme-blog"}, Ops: []string{"pr.merge", "pr.view"}}, 0)
	e.issueOrch("main", OrchScope{Projects: []string{"acme-shop"}, Ops: []string{"pr.merge"}}, 0)
	want := []string{"main:acme-shop+acme-blog:pr.merge+pr.view:live=0", "main:acme-shop:pr.merge:live=1"}
	if strings.Join(seen, "|") != strings.Join(want, "|") {
		t.Errorf("the hook saw %v, want %v", seen, want)
	}
	// A hook that fails stops the issue and leaves the old token live.
	e.orch.cfg.TxReissue = func(context.Context, *store.Tx, string, OrchScope) error { return errors.New("no") }
	if _, err := e.orch.Issue(ctx, IssueParams{ID: "main", Scope: mainScope}); err == nil {
		t.Fatal("an issue went on after its hook failed")
	}
	var live int
	e.db.SQL().QueryRow(`SELECT count(*) FROM orchestrators WHERE id = 'main' AND revoked_at IS NULL`).Scan(&live)
	if live != 1 {
		t.Errorf("%d live tokens after the failed issue, want the old one", live)
	}
}
