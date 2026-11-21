package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/connectors/linear"
	"github.com/joshua-noel/chaperone/internal/connectors/linear/lineartest"
	"github.com/joshua-noel/chaperone/internal/ledger"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
	"github.com/joshua-noel/chaperone/internal/vault"
)

// linearE2E boots the real chapd (ledger, policy pack, project policy file,
// vault, op pipeline) over a fake Linear. The intake ops are switched on in a
// test baseline (they ship off) and the project file has the `linear:` block.
type linearE2E struct {
	*e2e
	fake *lineartest.Server
}

const intakeBlock = `project: acme-shop
linear:
  team: SHOP
  label: claude
  states:
    - Handed to engineering
    - In Progress
    - Blocked
    - Completed
`

func newLinearE2E(t *testing.T, enable bool, secrets bool) *linearE2E {
	t.Helper()
	return newLinearE2EWith(t, enable, secrets, intakeBlock, false)
}

// newLinearE2EWith is the rig with the project file's text, and with the
// Linear issue ops switched on in the test baseline when issueOps is set.
func newLinearE2EWith(t *testing.T, enable bool, secrets bool, project string, issueOps bool) *linearE2E {
	t.Helper()
	useTestWrapper(t)
	dir := t.TempDir()
	db := filepath.Join(dir, "state.db")
	keys := writeKeys(t, dir)
	ctx := context.Background()

	tokenFile := filepath.Join(dir, "home", "orchestrator.token")
	var out, errb bytes.Buffer
	if code := orchCmd([]string{"issue", "-db", db, "-project", "acme-shop", "-ops", "intake.*,issue.*", "-token-file", tokenFile, "-days", "1"}, &out, &errb); code != 0 {
		t.Fatalf("orch issue: %d %s", code, errb.String())
	}
	raw, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}

	vdb, err := store.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	vcfg := vault.Config{Dir: filepath.Join(dir, "vault"), KeyDir: filepath.Join(dir, "vault-keys"), DB: vdb, Wrapper: newWrapper()}
	if err := vault.Init(ctx, vcfg, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(ctx, vcfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close(); vdb.Close() })
	if secrets {
		for id, val := range map[string]string{linear.SecretClientID: lineartest.ClientID, linear.SecretClientSecret: lineartest.ClientSecret} {
			if _, err := v.Import(ctx, vault.Meta{ID: id, Kind: linear.SecretKind}, []byte(val+"\n")); err != nil {
				t.Fatal(err)
			}
		}
	}

	policyDir := filepath.Join(dir, "policy")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "acme-shop.yaml"), []byte(project), 0o644); err != nil {
		t.Fatal(err)
	}

	fake := lineartest.New(t)
	ep := linear.Endpoints{API: fake.URL + "/graphql", Token: fake.URL + "/oauth/token"}
	cfg := Config{DBPath: db, KeysPath: keys, Instance: "test", PolicyDir: policyDir, testVault: v, linearEndpoints: &ep}
	if !enable {
		// The shipped baseline has the intake ops on; this switches them off to test the OP_DISABLED path.
		cfg.baselineYAML = []byte(strings.NewReplacer(
			"intake.list:          { enabled: true", "intake.list:          { enabled: false",
			"intake.comment:       { enabled: true", "intake.comment:       { enabled: false",
			"intake.move:          { enabled: true", "intake.move:          { enabled: false",
			"intake.states:        { enabled: true", "intake.states:        { enabled: false",
		).Replace(string(policy.BaselineBytes())))
	}
	if issueOps {
		// The five Linear issue ops ship off; this test baseline switches them on.
		base := string(policy.BaselineBytes())
		if cfg.baselineYAML != nil {
			base = string(cfg.baselineYAML)
		}
		for _, op := range []string{"issue.get", "issue.list", "issue.label", "issue.move", "issue.link"} {
			old := op + ":" + strings.Repeat(" ", max(1, 21-len(op))) + "{ enabled: false"
			if !strings.Contains(base, old) {
				t.Fatalf("the baseline has no %q line to switch on", old)
			}
			base = strings.Replace(base, old, strings.Replace(old, "false", "true", 1), 1)
		}
		cfg.baselineYAML = []byte(base)
	}
	app, err := Build(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	e := &e2e{t: t, app: app, srv: httptest.NewServer(app.Handler()), db: db, token: strings.TrimSpace(string(raw))}
	t.Cleanup(func() { e.srv.Close(); app.Close() })
	l := &linearE2E{e2e: e, fake: fake}
	fake.AddIssue(lineartest.Issue{Identifier: "SHOP-1", Title: "Order market signs", Description: "Three A-frame signs.", Labels: []string{"claude"}})
	fake.AddIssue(lineartest.Issue{Identifier: "SHOP-3", Title: "Not for the orchestrator", Labels: []string{"personal"}})
	fake.AddIssue(lineartest.Issue{Identifier: "ENG-1", Title: "Mirror of a GitHub issue", TeamKey: "ENG", Labels: []string{"claude"}})
	return l
}

func (l *linearE2E) ask(op, ref string, params map[string]any) (int, map[string]any) {
	l.t.Helper()
	if params == nil {
		params = map[string]any{}
	}
	return l.call("POST", "/v0/ops", l.token, map[string]any{
		"op": op, "project": "acme-shop", "target": map[string]any{"adapter": "linear", "ref": ref}, "params": params,
	})
}

// events returns the ledger events of one request, in order.
func (l *linearE2E) events(requestID string) []spec.Event {
	l.t.Helper()
	evs, err := l.app.Ledger.Query(context.Background(), ledger.QueryParams{RequestID: requestID, Limit: 50})
	if err != nil {
		l.t.Fatal(err)
	}
	return evs
}

func attr(e spec.Event, k string) string {
	s, _ := e.Attributes[k].(string)
	return s
}

func TestIntakeAllowedOpsAreLedgered(t *testing.T) {
	l := newLinearE2E(t, true, true)

	st, op := l.ask("intake.list", "board", nil)
	if st != 200 || op["state"] != "succeeded" {
		t.Fatalf("list: %d %v", st, op)
	}
	res := op["result"].(map[string]any)
	if items := res["items"].([]any); len(items) != 1 || items[0].(map[string]any)["identifier"] != "SHOP-1" || res["untrusted_text"] != true {
		t.Fatalf("list result: %v", res)
	}
	evs := l.events(op["id"].(string))
	if len(evs) != 2 || evs[0].EventName != "op.request" || evs[1].EventName != "op.result" || attr(evs[1], "factory.outcome") != "succeeded" {
		t.Fatalf("list events: %+v", evs)
	}
	if attr(evs[0], "factory.op") != "intake.list" || evs[0].Attributes["factory.orchestrator.id"] != "main" || evs[0].RunID != "" {
		t.Errorf("request event: %+v", evs[0])
	}

	st, op = l.ask("intake.comment", "SHOP-1", map[string]any{"body": "Picked up by the orchestrator\nhttps://github.com/example-org/storefront/issues/401"})
	if st != 200 || op["state"] != "succeeded" {
		t.Fatalf("comment: %d %v", st, op)
	}
	evs = l.events(op["id"].(string))
	if len(evs) != 2 || attr(evs[1], "factory.outcome") != "succeeded" || !strings.HasPrefix(attr(evs[1], "factory.external_ref"), "https://linear.app/") {
		t.Fatalf("comment events: %+v", evs)
	}
	if got := l.fake.Issue("SHOP-1").Comments; len(got) != 1 || !strings.HasPrefix(got[0].Body, "Picked up by the orchestrator") {
		t.Fatalf("Linear got %+v", got)
	}

	st, op = l.ask("intake.move", "SHOP-1", map[string]any{"state": "Handed to engineering"})
	if st != 200 || op["state"] != "succeeded" || l.fake.Issue("SHOP-1").State != "Handed to engineering" {
		t.Fatalf("move: %d %v state %s", st, op, l.fake.Issue("SHOP-1").State)
	}
	for _, s := range []string{"In Progress", "Blocked", "Completed"} {
		if st, op := l.ask("intake.move", "SHOP-1", map[string]any{"state": s}); st != 200 || op["state"] != "succeeded" {
			t.Fatalf("move to %s: %d %v", s, st, op)
		}
	}
	// The label stays through every move: the connector has no way to remove it.
	if got := l.fake.Issue("SHOP-1"); got.State != "Completed" || len(got.Labels) != 1 || got.Labels[0] != "claude" {
		t.Errorf("issue after the moves: %+v", got)
	}

	st, op = l.ask("intake.states", "board", nil)
	if st != 200 || op["state"] != "succeeded" {
		t.Fatalf("states: %d %v", st, op)
	}

	// Nothing in the ledger holds issue text, a comment, or a credential.
	all, err := l.app.Ledger.Query(context.Background(), ledger.QueryParams{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := json.Marshal(all)
	for _, bad := range []string{"Order market signs", "Three A-frame", "Picked up by the orchestrator", lineartest.ClientSecret, lineartest.ClientID, "lin_oauth_"} {
		if strings.Contains(string(blob), bad) {
			t.Errorf("the ledger holds %q", bad)
		}
	}
	rep, err := l.app.Ledger.Verify(context.Background(), false)
	if err != nil || !rep.OK() {
		t.Fatalf("ledger verify: %v %v", err, rep.Problems())
	}
}

func TestIntakeDenialsAreLedgered(t *testing.T) {
	l := newLinearE2E(t, true, true)
	for name, c := range map[string]struct {
		op, ref string
		params  map[string]any
		cause   string
	}{
		"another team's item":     {"intake.comment", "ENG-1", map[string]any{"body": "hi"}, "SCOPE_PATH"},
		"another team's board":    {"intake.list", "ENG", nil, "SCOPE_PATH"},
		"item without the label":  {"intake.comment", "SHOP-3", map[string]any{"body": "hi"}, "OP_POLICY_REFUSED"},
		"a state not in policy":   {"intake.move", "SHOP-1", map[string]any{"state": "Backlog"}, "OP_POLICY_REFUSED"},
		"a label param":           {"intake.move", "SHOP-1", map[string]any{"state": "Blocked", "labels": []any{}}, "OP_PARAMS_INVALID"},
		"a made-up op parameter":  {"intake.list", "board", map[string]any{"team": "ENG"}, "OP_PARAMS_INVALID"},
		"a bad identifier":        {"intake.comment", "ops-1", map[string]any{"body": "hi"}, "OP_PARAMS_INVALID"},
		"a secret in the comment": {"intake.comment", "SHOP-1", map[string]any{"body": "key " + lineartest.ClientSecret}, "REDACTION_BLOCKED"},
	} {
		st, body := l.ask(c.op, c.ref, c.params)
		if st != 403 && st != 400 {
			t.Errorf("%s: status %d %v", name, st, body)
			continue
		}
		mustValidDenial(t, body, c.cause)
	}
	if n := l.fake.Count("IntakeComment") + l.fake.Count("IntakeSetState"); n != 0 {
		t.Errorf("%d writes reached Linear", n)
	}
	var denials int
	rows, err := l.app.DB.SQL().Query(`SELECT event_name FROM ledger_events WHERE event_name = 'denial'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		denials++
	}
	if denials < 7 {
		t.Errorf("only %d denial events", denials)
	}
	// The secret in a comment was never stored or echoed.
	blob, _ := os.ReadFile(l.db)
	if bytes.Contains(blob, []byte(lineartest.ClientSecret)) {
		t.Error("the client secret is in state.db")
	}
}

// The label is taken off after the op was allowed and before the write: the op
// ends `failed`, the ledger says so, and Linear never saw the comment.
func TestIntakeLabelRemovedBeforeTheWriteEndsFailed(t *testing.T) {
	l := newLinearE2E(t, true, true)
	// How many reads one comment takes (submit, release, execute) is the
	// pipeline's business: measure it, then take the label off on the last.
	if st, op := l.ask("intake.comment", "SHOP-1", map[string]any{"body": "first"}); st != 200 || op["state"] != "succeeded" {
		t.Fatalf("first comment: %d %v", st, op)
	}
	perOp := l.fake.Count("IntakeGuard")
	if perOp < 2 {
		t.Fatalf("a comment read the issue %d times", perOp)
	}
	l.fake.OnGuard = func(s *lineartest.Server, n int) {
		if n == 2*perOp {
			s.SetLabels("SHOP-1", "personal")
		}
	}
	st, op := l.ask("intake.comment", "SHOP-1", map[string]any{"body": "second"})
	if st != 200 || op["state"] != "failed" {
		t.Fatalf("second comment: %d %v", st, op)
	}
	if got := l.fake.Issue("SHOP-1").Comments; len(got) != 1 {
		t.Errorf("Linear has %d comments, want only the first", len(got))
	}
	evs := l.events(op["id"].(string))
	if len(evs) != 2 || attr(evs[1], "factory.outcome") != "failed" {
		t.Fatalf("events: %+v", evs)
	}
	if res, _ := op["result"].(map[string]any); !strings.Contains(res["error"].(string), "label") {
		t.Errorf("result: %v", op["result"])
	}
}

func TestIntakeOpsRefuseWhenOffAndWithoutTheSecrets(t *testing.T) {
	l := newLinearE2E(t, false, true) // a baseline with the intake ops switched off
	st, body := l.ask("intake.list", "board", nil)
	if st != 403 {
		t.Fatalf("status %d %v", st, body)
	}
	mustValidDenial(t, body, "OP_DISABLED")
	if len(l.fake.Requests()) != 0 {
		t.Error("a disabled op reached Linear")
	}

	l = newLinearE2E(t, true, false) // the shipped baseline (on), but the vault has no Linear secrets
	st, body = l.ask("intake.comment", "SHOP-1", map[string]any{"body": "hi"})
	if st != 403 {
		t.Fatalf("status %d %v", st, body)
	}
	mustValidDenial(t, body, "OP_POLICY_REFUSED")
	if !strings.Contains(body["why"].(string), "not connected") {
		t.Errorf("why: %v", body["why"])
	}
}

func TestIntakeRateLimitPerMinuteComesFromThePolicyPack(t *testing.T) {
	l := newLinearE2E(t, true, true)
	var last int
	for range 7 {
		last, _ = l.ask("intake.states", "board", nil)
		// identical requests are one op while it is live; each finishes at once
	}
	if last != 429 {
		t.Errorf("the seventh intake.states in a minute got %d, want 429", last)
	}
}

func TestLinearFlagsAreValidated(t *testing.T) {
	for _, c := range []struct {
		cfg linearConfig
		ok  bool
	}{
		{linearConfig{}, true},
		{linearConfig{PollInterval: linear.DefaultPollInterval}, true},
		{linearConfig{PollInterval: linear.MinPollInterval}, true},
		{linearConfig{PollInterval: linear.MinPollInterval - 1}, false},
		{linearConfig{PollInterval: -1}, false},
		{linearConfig{HourlyBudget: -1}, false},
	} {
		if err := c.cfg.validate(); (err == nil) != c.ok {
			t.Errorf("%+v: %v", c.cfg, err)
		}
	}
}
