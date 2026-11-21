package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/connectors/sentry"
	"github.com/joshua-noel/chaperone/internal/connectors/sentry/sentrytest"
	"github.com/joshua-noel/chaperone/internal/ledger"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
	"github.com/joshua-noel/chaperone/internal/vault"
)

// sentryE2E boots the real chapd (ledger, policy pack, project policy file,
// vault, op pipeline) over a fake Sentry. The errors.* ops are switched on in a
// test baseline (they ship off) and the project file has the `sentry:` block.
// The connector sends every request to the fake through the test HTTP client, and
// still holds the project's base URL to the policy rule.
type sentryE2E struct {
	*e2e
	fake *sentrytest.Server
}

const (
	sentryToken  = "sntryu_0123456789abcdef0123456789abcdef0123456789abcdef"
	sentrySecret = "sensitive-4f9c2d71b3a8e605"

	sentryBlock = `project: acme-shop
sentry:
  base_url: https://sentry.example.com
  organization: acme
  projects: [web]
  assignees: [dev@example.com]
`
)

var errorsOps = []string{"errors.list", "errors.get", "errors.resolve", "errors.unresolve", "errors.assign", "errors.comment"}

func newSentryE2E(t *testing.T, enable, secret bool, project string) *sentryE2E {
	t.Helper()
	useTestWrapper(t)
	dir := t.TempDir()
	db := filepath.Join(dir, "state.db")
	keys := writeKeys(t, dir)
	ctx := context.Background()

	tokenFile := filepath.Join(dir, "home", "orchestrator.token")
	var out, errb bytes.Buffer
	if code := orchCmd([]string{"issue", "-db", db, "-project", "acme-shop", "-ops", "errors.*", "-token-file", tokenFile, "-days", "1"}, &out, &errb); code != 0 {
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
	if secret {
		if _, err := v.Import(ctx, vault.Meta{ID: sentry.SecretToken, Kind: sentry.SecretKind}, []byte(sentryToken+"\n")); err != nil {
			t.Fatal(err)
		}
	}

	policyDir := filepath.Join(dir, "policy")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "acme-shop.yaml"), []byte(project), 0o644); err != nil {
		t.Fatal(err)
	}

	fake := sentrytest.New(t)
	fake.SetToken(sentryToken)
	cfg := Config{DBPath: db, KeysPath: keys, Instance: "test", PolicyDir: policyDir, testVault: v, sentryHTTP: fake.HTTPClient()}
	if enable {
		// The six ops ship off; this test baseline switches them on.
		base := string(policy.BaselineBytes())
		for _, op := range errorsOps {
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
	s := &sentryE2E{e2e: e, fake: fake}
	ev := &sentrytest.Event{
		ID: "0123456789abcdef0123456789abcdef", Date: "2026-11-20T09:30:00Z", Sensitive: sentrySecret,
		Exceptions: []sentrytest.Exception{{Type: "ValueError", Value: "bad", Frames: []sentrytest.Frame{{Filename: "app/cart.py", Function: "total", Line: 120, InApp: true}}}},
	}
	fake.AddIssue(sentrytest.Issue{ID: "1001", ShortID: "WEB-1A", Title: "ValueError: bad total", Culprit: "app.cart in total", Project: "web", Event: ev})
	fake.AddIssue(sentrytest.Issue{ID: "1004", ShortID: "BILLING-1", Title: "Not for the orchestrator", Project: "billing", Event: ev})
	return s
}

func (s *sentryE2E) ask(op, ref string, params map[string]any) (int, map[string]any) {
	s.t.Helper()
	if params == nil {
		params = map[string]any{}
	}
	return s.call("POST", "/v0/ops", s.token, map[string]any{
		"op": op, "project": "acme-shop", "target": map[string]any{"adapter": "sentry", "ref": ref}, "params": params,
	})
}

func TestSentryOpsRunEndToEndAndTheLedgerHoldsNoText(t *testing.T) {
	s := newSentryE2E(t, true, true, sentryBlock)

	st, op := s.ask("errors.list", "web", nil)
	if st != 200 || op["state"] != "succeeded" {
		t.Fatalf("list: %d %v", st, op)
	}
	res := op["result"].(map[string]any)
	if items := res["items"].([]any); len(items) != 1 || items[0].(map[string]any)["id"] != "1001" || res["untrusted_text"] != true {
		t.Fatalf("list result: %v", res)
	}

	st, op = s.ask("errors.get", "1001", nil)
	if st != 200 || op["state"] != "succeeded" {
		t.Fatalf("get: %d %v", st, op)
	}
	if blob, _ := json.Marshal(op); strings.Contains(string(blob), sentrySecret) || !strings.Contains(string(blob), `"function":"total"`) {
		t.Errorf("get result: %s", blob)
	}

	if st, op = s.ask("errors.assign", "1001", map[string]any{"to": "dev@example.com"}); st != 200 || op["state"] != "succeeded" {
		t.Fatalf("assign: %d %v", st, op)
	}
	if st, op = s.ask("errors.comment", "1001", map[string]any{"body": "Picked up by the orchestrator."}); st != 200 || op["state"] != "succeeded" {
		t.Fatalf("comment: %d %v", st, op)
	}
	st, op = s.ask("errors.resolve", "1001", nil)
	if st != 200 || op["state"] != "succeeded" || s.fake.Issue("1001").Status != "resolved" {
		t.Fatalf("resolve: %d %v status %s", st, op, s.fake.Issue("1001").Status)
	}
	evs := s.events(op["id"].(string))
	if len(evs) != 2 || evs[0].EventName != "op.request" || evs[1].EventName != "op.result" || attr(evs[1], "factory.outcome") != "succeeded" ||
		attr(evs[1], "factory.external_ref") != "https://sentry.example.com/organizations/acme/issues/1001/" {
		t.Fatalf("resolve events: %+v", evs)
	}
	if st, op = s.ask("errors.unresolve", "1001", nil); st != 200 || op["state"] != "succeeded" || s.fake.Issue("1001").Status != "unresolved" {
		t.Fatalf("unresolve: %d %v", st, op)
	}
	if got := s.fake.Issue("1001"); got.Assignee != "dev@example.com" || len(got.Notes) != 1 {
		t.Errorf("Sentry has %+v", got)
	}

	// Nothing in the ledger holds an issue's text, a note, an event's secret or the token.
	all, err := s.app.Ledger.Query(context.Background(), ledger.QueryParams{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := json.Marshal(all)
	for _, bad := range []string{"ValueError", "app.cart", "Picked up by the orchestrator", sentrySecret, sentryToken, "sntryu_"} {
		if strings.Contains(string(blob), bad) {
			t.Errorf("the ledger holds %q", bad)
		}
	}
	if raw, _ := os.ReadFile(s.db); bytes.Contains(raw, []byte(sentryToken)) {
		t.Error("the auth token is in state.db")
	}
	rep, err := s.app.Ledger.Verify(context.Background(), false)
	if err != nil || !rep.OK() {
		t.Fatalf("ledger verify: %v %v", err, rep.Problems())
	}
	for _, c := range s.fake.Credentials() {
		if c != sentryToken {
			t.Errorf("Sentry was sent the credential %q", c)
		}
	}
}

func TestSentryDenialsAreLedgered(t *testing.T) {
	s := newSentryE2E(t, true, true, sentryBlock)
	for name, c := range map[string]struct {
		op, ref string
		params  map[string]any
		cause   string
	}{
		"a project the policy does not list": {"errors.list", "billing", nil, "SCOPE_PATH"},
		"a member the policy does not list":  {"errors.assign", "1001", map[string]any{"to": "stranger@example.com"}, "OP_POLICY_REFUSED"},
		"a mention in a note":                {"errors.comment", "1001", map[string]any{"body": "look @alice"}, "OP_POLICY_REFUSED"},
		"a secret in a note":                 {"errors.comment", "1001", map[string]any{"body": "key " + "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"}, "REDACTION_BLOCKED"},
		"an issue of another project":        {"errors.resolve", "1004", nil, "SCOPE_PATH"},
		"a made-up param":                    {"errors.get", "1001", map[string]any{"expand": "request"}, "OP_PARAMS_INVALID"},
		"a bad issue id":                     {"errors.get", "WEB-1A", nil, "OP_PARAMS_INVALID"},
	} {
		st, body := s.ask(c.op, c.ref, c.params)
		if st != 403 && st != 400 {
			t.Errorf("%s: status %d %v", name, st, body)
			continue
		}
		mustValidDenial(t, body, c.cause)
	}
	if n := s.fake.WriteCalls(); n != 0 {
		t.Errorf("%d writes reached Sentry", n)
	}
}

func TestSentryOpsRefuseWhenOffWithoutABlockAndWithoutTheToken(t *testing.T) {
	// The shipped baseline has them off.
	s := newSentryE2E(t, false, true, sentryBlock)
	st, body := s.ask("errors.list", "web", nil)
	if st != 403 {
		t.Fatalf("status %d %v", st, body)
	}
	mustValidDenial(t, body, "OP_DISABLED")
	if len(s.fake.Requests()) != 0 {
		t.Error("a disabled op reached Sentry")
	}

	// On, but the project's file has no sentry block.
	s = newSentryE2E(t, true, true, "project: acme-shop\n")
	st, body = s.ask("errors.list", "web", nil)
	if st != 403 {
		t.Fatalf("status %d %v", st, body)
	}
	mustValidDenial(t, body, "OP_POLICY_REFUSED")
	if !strings.Contains(body["why"].(string), "no valid sentry: block") || len(s.fake.Requests()) != 0 {
		t.Errorf("why: %v, %d requests", body["why"], len(s.fake.Requests()))
	}

	// On, with a block that cannot be used: the ops refuse with the reason, and the project's other ops work.
	s = newSentryE2E(t, true, true, strings.Replace(sentryBlock, "https://sentry.example.com", "http://sentry.example.com", 1))
	st, body = s.ask("errors.list", "web", nil)
	if st != 403 {
		t.Fatalf("status %d %v", st, body)
	}
	mustValidDenial(t, body, "OP_POLICY_REFUSED")
	if why := body["why"].(string); !strings.Contains(why, "base_url") || !strings.Contains(why, "acme-shop.yaml") {
		t.Errorf("why: %v", why)
	}
	if len(s.fake.Requests()) != 0 {
		t.Error("an op with an unusable block reached Sentry")
	}

	// On, with a block, but the vault holds no token.
	s = newSentryE2E(t, true, false, sentryBlock)
	st, body = s.ask("errors.resolve", "1001", nil)
	if st != 403 {
		t.Fatalf("status %d %v", st, body)
	}
	mustValidDenial(t, body, "OP_POLICY_REFUSED")
	if !strings.Contains(body["why"].(string), "not connected") || len(s.fake.Requests()) != 0 {
		t.Errorf("why: %v, %d requests", body["why"], len(s.fake.Requests()))
	}
}

// chapd says at start, once and at Warn, that a project file has an unusable
// sentry block: the Sentry operations are off for that project, the other ops
// work. It starts either way.
func TestStartWarnsOnceAboutAnUnusableSentryBlock(t *testing.T) {
	dir := t.TempDir()
	db, keys := filepath.Join(dir, "state.db"), writeKeys(t, dir)
	policyDir := filepath.Join(dir, "policy")
	if err := os.MkdirAll(policyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := "project: storefront\nsentry:\n  base_url: https://192.0.2.7\n  organization: acme\n  projects: [web]\n"
	if err := os.WriteFile(filepath.Join(policyDir, "storefront.yaml"), []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	log := &syncBuf{}
	app, err := Build(context.Background(), Config{DBPath: db, KeysPath: keys, Instance: "test", PolicyDir: policyDir,
		Log: slog.New(slog.NewTextHandler(log, nil))})
	if err != nil {
		t.Fatal(err) // a bad block must not stop chapd from starting
	}
	app.Close()
	out := log.String()
	if n := strings.Count(out, "unusable sentry block"); n != 1 {
		t.Fatalf("the start-up log says it %d times, want once:\n%s", n, out)
	}
	for _, want := range []string{"level=WARN", "project=storefront", "file=storefront.yaml", "Sentry operations", "base_url"} {
		if !strings.Contains(out, want) {
			t.Errorf("the warning does not hold %q:\n%s", want, out)
		}
	}
}

// events returns the ledger events of one request, in order.
func (s *sentryE2E) events(requestID string) []spec.Event {
	s.t.Helper()
	evs, err := s.app.Ledger.Query(context.Background(), ledger.QueryParams{RequestID: requestID, Limit: 50})
	if err != nil {
		s.t.Fatal(err)
	}
	return evs
}
