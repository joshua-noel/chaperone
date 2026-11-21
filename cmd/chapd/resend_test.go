package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/approvals"
	"github.com/joshua-noel/chaperone/internal/connectors/google"
	"github.com/joshua-noel/chaperone/internal/connectors/resend"
	"github.com/joshua-noel/chaperone/internal/connectors/resend/resendtest"
	"github.com/joshua-noel/chaperone/internal/ledger"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/store"
	"github.com/joshua-noel/chaperone/internal/vault"
)

// resendE2E boots the real chapd (ledger, policy pack, project policy file, vault,
// approvals engine with the Hello stand-in, op pipeline) over a fake Resend. The two
// ops ship off; the test baseline switches them on. The project file has the
// `resend:` block. The connector sends every request to the fake through the test
// HTTP client and still sends to one fixed address.
type resendE2E struct {
	*e2e
	fake *resendtest.Server
}

const (
	resendSendKey   = "re_chapdtest-sending-key-0123456789abcdef"
	resendStatusKey = "re_chapdtest-status-key-0123456789abcdef0"
	// resendBody and resendSubject are text the ledger must never hold.
	resendBody    = "The deploy of 4f2a finished. Nothing needs doing: marker-3c9d."
	resendSubject = "Deploy finished marker-77a1"
	resendEmailID = "49a3999c-0ce1-4ea6-ab68-afcd6dc2e794"

	resendProject = `project: acme-shop
resend:
  senders: [alerts@mail.example.com]
  allow_recipients: [ops@example.com, "@team.example.com"]
  max_recipients: 3
`
)

// newResendE2E builds the rig. enable switches both ops on in the test baseline;
// keys says which vault secrets exist: "send", "status" or both.
func newResendE2E(t *testing.T, enable bool, keys []string, project string) *resendE2E {
	t.Helper()
	useTestWrapper(t)
	dir := t.TempDir()
	db := filepath.Join(dir, "state.db")
	runKeys := writeKeys(t, dir)
	ctx := context.Background()

	tokenFile := filepath.Join(dir, "home", "orchestrator.token")
	var out, errb bytes.Buffer
	if code := orchCmd([]string{"issue", "-db", db, "-project", "acme-shop", "-ops", "mail.*", "-token-file", tokenFile, "-days", "1"}, &out, &errb); code != 0 {
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
	for _, k := range keys {
		id, val := resend.SecretSendKey, resendSendKey
		if k == "status" {
			id, val = resend.SecretStatusKey, resendStatusKey
		}
		if _, err := v.Import(ctx, vault.Meta{ID: id, Kind: resend.SecretKind}, []byte(val+"\n")); err != nil {
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

	fake := resendtest.New(t)
	fake.AddKey(resendSendKey, resendtest.SendingAccess, "mail.example.com")
	fake.AddKey(resendStatusKey, resendtest.FullAccess, "")
	fake.AddEmail(resendtest.Email{
		ID: resendEmailID, From: "alerts@mail.example.com", To: []string{"ops@example.com"}, Subject: resendSubject, Text: resendBody,
		LastEvent: "delivered", CreatedAt: "2026-04-03 22:13:42.674981+00",
	})
	cfg := Config{
		DBPath: db, KeysPath: runKeys, Instance: "test", PolicyDir: policyDir, testVault: v, resendHTTP: fake.HTTPClient(),
		approvalVerifier: &helloStandIn{}, notifier: &wakeLog{},
	}
	if enable {
		// The two ops ship off; this test baseline switches them on.
		base := string(policy.BaselineBytes())
		for _, op := range []string{"mail.send", "mail.status"} {
			old := regexp.MustCompile(`(?m)^  ` + regexp.QuoteMeta(op) + `:(\s+)\{ enabled: false`)
			if !old.MatchString(base) {
				t.Fatalf("the baseline has no %s line to switch on", op)
			}
			base = old.ReplaceAllString(base, "  "+op+":${1}{ enabled: true")
		}
		cfg.baselineYAML = []byte(base)
	}
	app, err := Build(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.SQL().Exec(`INSERT INTO approvers (id, user_handle, name, created_at) VALUES (1, randomblob(32), 'operator', '2026-10-24T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	e := &e2e{t: t, app: app, srv: httptest.NewServer(app.Handler()), db: db, token: strings.TrimSpace(string(raw))}
	t.Cleanup(func() { e.srv.Close(); app.Close() })
	return &resendE2E{e2e: e, fake: fake}
}

func resendMail(extra map[string]any) map[string]any {
	p := map[string]any{"to": []any{"ops@example.com"}, "cc": []any{"dev@team.example.com"}, "subject": resendSubject, "body": resendBody}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

func (s *resendE2E) body(op, adapter, ref string, params map[string]any) map[string]any {
	if params == nil {
		params = map[string]any{}
	}
	return map[string]any{"op": op, "project": "acme-shop", "reason": "tell the team", "target": map[string]any{"adapter": adapter, "ref": ref}, "params": params}
}

func (s *resendE2E) ask(op, adapter, ref string, params map[string]any) (int, map[string]any) {
	s.t.Helper()
	return s.call("POST", "/v0/ops", s.token, s.body(op, adapter, ref, params))
}

func (s *resendE2E) waitState(id, want string) map[string]any {
	s.t.Helper()
	var last map[string]any
	for range 300 {
		_, last = s.call("GET", "/v0/ops/"+id, s.token, nil)
		if last["state"] == want {
			return last
		}
		time.Sleep(20 * time.Millisecond)
	}
	s.t.Fatalf("op %s is %v, want %s: %v", id, last["state"], want, last)
	return nil
}

// approve is the operator's side: begin a decision and answer its challenge.
func (s *resendE2E) approve(approvalID string) {
	s.t.Helper()
	ctx := context.Background()
	in := approvals.BeginInput{ApprovalID: approvalID, Actor: operator, Origin: testOrigin, Binding: []byte("browser")}
	ch, err := s.app.Approvals.BeginDecision(ctx, in)
	if err != nil {
		s.t.Fatal(err)
	}
	if _, err := s.app.Approvals.Approve(ctx, approvals.ApproveInput{ApprovalID: approvalID, ChallengeID: ch.ID, Actor: operator,
		Origin: testOrigin, Binding: []byte("browser"), Response: answerFor(ch.Raw)}); err != nil {
		s.t.Fatal(err)
	}
}

// A message through Resend needs a card, the card shows the whole message and the
// evidence that binds it, and nothing is sent until the operator signs. Then the
// message goes once, as the card said, and the ledger holds no text of it and no key.
func TestResendMailSendNeedsACardAndGoesOnceAsApproved(t *testing.T) {
	s := newResendE2E(t, true, []string{"send"}, resendProject)
	const sender = "alerts@mail.example.com"

	// Asked for directly, a high op is refused with a request line: no card yet, nothing sent.
	st, body := s.ask("mail.send", "resend", sender, resendMail(nil))
	if st != 403 {
		t.Fatalf("direct send: %d %v", st, body)
	}
	mustValidDenial(t, body, "OP_APPROVAL_REQUIRED")
	if len(s.fake.Requests()) != 0 {
		t.Fatal("a message reached Resend before any approval")
	}

	// The card.
	req := s.body("mail.send", "resend", sender, resendMail(nil))
	req["kind"] = "op"
	st, op := s.call("POST", "/v0/approvals", s.token, req)
	if st != 202 || op["state"] != "pending_approval" || op["class"] != "high" || op["reversibility"] != "irreversible" {
		t.Fatalf("request: %d %v", st, op)
	}
	opID, _ := op["id"].(string)
	aid := approvalOf(t, op)
	card, err := s.app.Approvals.Get(context.Background(), aid)
	if err != nil || card == nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		sender, "ops@example.com", "dev@team.example.com", resendSubject, resendBody, // what is sent
		"Sent from account", "mail.send message", "Sent through: Resend", "Body: ", "SHA-256", "Request to Resend: ", // the card and its evidence
	} {
		if !strings.Contains(card.CardText, want) {
			t.Errorf("the card does not show %q:\n%s", want, card.CardText)
		}
	}
	if len(s.fake.Requests()) != 0 {
		t.Fatal("a message reached Resend while the card was pending")
	}

	// The operator signs; the message goes once.
	s.approve(aid)
	final := s.waitState(opID, "succeeded")
	sent := s.fake.Sent()
	if len(sent) != 1 || s.fake.WritesApplied() != 1 {
		t.Fatalf("Resend has %d messages", len(sent))
	}
	m := sent[0].Email
	if m.From != sender || m.Subject != resendSubject || m.Text != resendBody || m.HTML != "" ||
		len(m.To) != 1 || m.To[0] != "ops@example.com" || len(m.Cc) != 1 || m.Cc[0] != "dev@team.example.com" || len(m.Bcc) != 0 {
		t.Errorf("Resend got %+v", m)
	}
	if strings.Join(sent[0].Fields, ",") != "cc,from,subject,text,to" {
		t.Errorf("the body held the fields %v", sent[0].Fields)
	}
	res := final["result"].(map[string]any)
	if res["message_id"] != sent[0].ID || res["untrusted_text"] != true || final["external_ref"] != "resend:email/"+sent[0].ID {
		t.Errorf("result: %v ref %v", res, final["external_ref"])
	}
	reqs := s.fake.Requests()
	if len(reqs) != 1 || !strings.HasPrefix(reqs[0].IdempotencyKey, "chaperone-mail-send/x-") || reqs[0].Path != "/emails" {
		t.Errorf("requests: %+v", reqs)
	}
	for _, c := range s.fake.Credentials() {
		if c != resendSendKey {
			t.Errorf("Resend was sent the credential %q", c)
		}
	}

	// The ledger and the database hold no word of the message and no key.
	all, err := s.app.Ledger.Query(context.Background(), ledger.QueryParams{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := json.Marshal(all)
	for _, bad := range []string{"marker-3c9d", "marker-77a1", resendSendKey, "re_chapdtest"} {
		if strings.Contains(string(blob), bad) {
			t.Errorf("the ledger holds %q", bad)
		}
	}
	if raw, _ := os.ReadFile(s.db); bytes.Contains(raw, []byte(resendSendKey)) {
		t.Error("the API key is in state.db")
	}
	if rep, err := s.app.Ledger.Verify(context.Background(), false); err != nil || !rep.OK() {
		t.Fatalf("ledger verify: %v %v", err, rep.Problems())
	}
}

// Refusals come before any card and before Resend is reached, and are ledgered.
func TestResendMailSendRefusalsComeBeforeACard(t *testing.T) {
	s := newResendE2E(t, true, []string{"send"}, resendProject)
	const sender = "alerts@mail.example.com"
	for name, c := range map[string]struct {
		adapter, ref string
		params       map[string]any
		cause        string
		why          string
	}{
		"a recipient the policy does not list": {"resend", sender, resendMail(map[string]any{"to": []any{"stranger@evil.example.org"}}), "OP_POLICY_REFUSED", "recipients_allowlisted"},
		"a sender the policy does not list":    {"resend", "ceo@mail.example.com", resendMail(nil), "OP_POLICY_REFUSED", "sender_listed"},
		"more recipients than the cap":         {"resend", sender, resendMail(map[string]any{"to": []any{"a@team.example.com", "b@team.example.com", "c@team.example.com"}}), "OP_POLICY_REFUSED", "recipient_cap"},
		"an attachment":                        {"resend", sender, resendMail(map[string]any{"attachments": []any{}}), "OP_PARAMS_INVALID", "no attachments"},
		"html":                                 {"resend", sender, resendMail(map[string]any{"html": "<b>x</b>"}), "OP_PARAMS_INVALID", "unknown param"},
		"a secret in the body":                 {"resend", sender, resendMail(map[string]any{"body": "key ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"}), "REDACTION_BLOCKED", "secret"},
		"a service nobody serves":              {"smtp", sender, resendMail(nil), "OP_PARAMS_INVALID", "no adapter for target.adapter"},
	} {
		req := s.body("mail.send", c.adapter, c.ref, c.params)
		req["kind"] = "op"
		st, body := s.call("POST", "/v0/approvals", s.token, req)
		if st != 403 && st != 400 {
			t.Errorf("%s: status %d %v", name, st, body)
			continue
		}
		mustValidDenial(t, body, c.cause)
		if why, _ := body["why"].(string); !strings.Contains(why, c.why) || strings.Contains(why, "evil.example.org") || strings.Contains(why, "ceo@") {
			t.Errorf("%s: why = %q", name, why)
		}
	}
	if len(s.fake.Requests()) != 0 {
		t.Errorf("%d requests reached Resend", len(s.fake.Requests()))
	}
	if cards, _ := s.app.Approvals.Pending(context.Background()); len(cards) != 0 {
		t.Errorf("%d cards were made for refused requests", len(cards))
	}
}

// One name, two connectors: the target picks. The Gmail target reaches Gmail's
// adapter (which refuses a project with no google block) and never Resend.
func TestMailSendTargetPicksTheConnector(t *testing.T) {
	s := newResendE2E(t, true, []string{"send"}, resendProject)
	req := s.body("mail.send", "google", "operator@example.com", resendMail(nil))
	req["kind"] = "op"
	st, body := s.call("POST", "/v0/approvals", s.token, req)
	if st != 403 {
		t.Fatalf("status %d %v", st, body)
	}
	mustValidDenial(t, body, "OP_POLICY_REFUSED")
	if why, _ := body["why"].(string); !strings.Contains(why, "google.mail.allow_recipients") {
		t.Errorf("the Gmail adapter did not answer: %v", why)
	}
	if len(s.fake.Requests()) != 0 {
		t.Error("a Gmail request reached Resend")
	}
}

func TestResendOpsRefuseWhenOffWithoutABlockAndWithoutAKey(t *testing.T) {
	const sender = "alerts@mail.example.com"
	req := func(s *resendE2E) (int, map[string]any) {
		r := s.body("mail.send", "resend", sender, resendMail(nil))
		r["kind"] = "op"
		return s.call("POST", "/v0/approvals", s.token, r)
	}
	// The shipped baseline has both off.
	s := newResendE2E(t, false, []string{"send", "status"}, resendProject)
	st, body := s.ask("mail.status", "resend", resendEmailID, nil)
	if st != 403 {
		t.Fatalf("status %d %v", st, body)
	}
	mustValidDenial(t, body, "OP_DISABLED")
	st, body = req(s)
	if st != 403 {
		t.Fatalf("status %d %v", st, body)
	}
	mustValidDenial(t, body, "OP_DISABLED")
	if len(s.fake.Requests()) != 0 {
		t.Error("a disabled op reached Resend")
	}

	// On, but the project's file has no resend block.
	s = newResendE2E(t, true, []string{"send", "status"}, "project: acme-shop\n")
	for _, st := range []func() (int, map[string]any){func() (int, map[string]any) { return req(s) }, func() (int, map[string]any) { return s.ask("mail.status", "resend", resendEmailID, nil) }} {
		code, body := st()
		if code != 403 {
			t.Fatalf("status %d %v", code, body)
		}
		mustValidDenial(t, body, "OP_POLICY_REFUSED")
		if !strings.Contains(body["why"].(string), "no valid resend: block") {
			t.Errorf("why: %v", body["why"])
		}
	}

	// On, with a block that cannot be used: the Resend side refuses with the reason.
	s = newResendE2E(t, true, []string{"send", "status"}, strings.Replace(resendProject, "[alerts@mail.example.com]", "[Alerts@mail.example.com]", 1))
	st, body = req(s)
	if st != 403 {
		t.Fatalf("status %d %v", st, body)
	}
	mustValidDenial(t, body, "OP_POLICY_REFUSED")
	if why := body["why"].(string); !strings.Contains(why, "senders") || !strings.Contains(why, "acme-shop.yaml") {
		t.Errorf("why: %v", why)
	}

	// On, with a block, but the vault holds no sending key; and no status key.
	s = newResendE2E(t, true, nil, resendProject)
	st, body = req(s)
	if st != 403 {
		t.Fatalf("status %d %v", st, body)
	}
	mustValidDenial(t, body, "OP_POLICY_REFUSED")
	if !strings.Contains(body["why"].(string), "resend-api-key") {
		t.Errorf("why: %v", body["why"])
	}
	st, body = s.ask("mail.status", "resend", resendEmailID, nil)
	if st != 403 {
		t.Fatalf("status %d %v", st, body)
	}
	mustValidDenial(t, body, "OP_POLICY_REFUSED")
	if why := body["why"].(string); !strings.Contains(why, "resend-status-key") || !strings.Contains(why, "full_access") {
		t.Errorf("why: %v", why)
	}
	if len(s.fake.Requests()) != 0 {
		t.Error("an op with no key reached Resend")
	}
}

func TestResendStatusRunsEndToEndWithTheStatusKey(t *testing.T) {
	s := newResendE2E(t, true, []string{"send", "status"}, resendProject)
	st, op := s.ask("mail.status", "resend", resendEmailID, nil)
	if st != 200 || op["state"] != "succeeded" {
		t.Fatalf("status: %d %v", st, op)
	}
	res := op["result"].(map[string]any)
	if res["last_event"] != "delivered" || res["email"] != resendEmailID || res["sender"] != "alerts@mail.example.com" {
		t.Errorf("result: %v", res)
	}
	if all, _ := json.Marshal(op); strings.Contains(string(all), "marker-3c9d") || strings.Contains(string(all), "marker-77a1") {
		t.Errorf("the result holds the email's text: %s", all)
	}
	creds := s.fake.Credentials()
	if len(creds) != 1 || creds[0] != resendStatusKey {
		t.Errorf("Resend was sent %v", creds)
	}
	// An email of another sender is refused, in the pipeline too.
	s.fake.AddEmail(resendtest.Email{ID: "11111111-2222-4333-8444-555555555555", From: "ceo@private.example.net", Subject: "private-subject", LastEvent: "opened"})
	st, op = s.ask("mail.status", "resend", "11111111-2222-4333-8444-555555555555", nil)
	if all, _ := json.Marshal(op); st != 200 || op["state"] != "failed" || strings.Contains(string(all), "private") || strings.Contains(string(all), "opened") {
		t.Errorf("another sender's email: %d %s", st, all)
	}
	if blob, _ := json.Marshal(op); strings.Contains(string(blob), resendStatusKey) {
		t.Error("the status key is in a result")
	}
}

// installResend puts the Resend side behind the same name as Gmail's adapter and
// turns nothing on.
func TestInstallResendJoinsGmailBehindOneNameAndTurnsNothingOn(t *testing.T) {
	useTestWrapper(t)
	dir := t.TempDir()
	db := filepath.Join(dir, "state.db")
	if code, _, stderr := runVault(t, "init", "-db", db); code != 0 {
		t.Fatalf("vault init: %d %s", code, stderr)
	}
	ctx := context.Background()
	d, err := store.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	v, err := vault.Open(ctx, vault.Config{Dir: filepath.Join(dir, "vault"), KeyDir: filepath.Join(dir, "vault-keys"), DB: d, Wrapper: newWrapper()})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	cat, base, err := policy.Default()
	if err != nil {
		t.Fatal(err)
	}
	a := &App{vault: v, Reg: v.Registry(), Policy: policy.NewEngine(cat, base, ""), log: slog.Default()}
	ads := map[string]ops.Adapter{}
	if err := a.installGoogle(ads); err != nil {
		t.Fatal(err)
	}
	gmail := ads["mail.send"]
	if _, ok := gmail.(*google.Gmail); !ok {
		t.Fatalf("mail.send is %T before Resend", gmail)
	}
	if err := a.installResend(ads); err != nil {
		t.Fatal(err)
	}
	by, ok := ads["mail.send"].(ops.ByTarget)
	if !ok || len(by) != 2 || by["google"] != gmail || by["resend"] == nil {
		t.Fatalf("mail.send = %T %v: want Gmail and Resend behind one name", ads["mail.send"], ads["mail.send"])
	}
	if ads["mail.status"] == nil || ads["drive.share"] == nil {
		t.Fatalf("adapters: %v", ads)
	}
	eff := a.Policy.For("storefront")
	if eff.Enabled("mail.send") || eff.Enabled("mail.status") {
		t.Fatal("installing the adapters turned an op on")
	}
	// Another adapter that is not Gmail's under the name stops chapd.
	other := map[string]ops.Adapter{"mail.send": ops.ByTarget{}}
	if err := a.installResend(other); err == nil {
		t.Error("an adapter that is not Gmail's was replaced")
	}
	// No vault: nothing is installed.
	none := map[string]ops.Adapter{}
	if err := (&App{}).installResend(none); err != nil || len(none) != 0 {
		t.Fatalf("%v %v", err, none)
	}
}

// chapd says at start, once and at Warn, that a project file has an unusable
// resend block. It starts either way.
func TestStartWarnsOnceAboutAnUnusableResendBlock(t *testing.T) {
	dir := t.TempDir()
	db, keys := filepath.Join(dir, "state.db"), writeKeys(t, dir)
	policyDir := filepath.Join(dir, "policy")
	if err := os.MkdirAll(policyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := "project: storefront\nresend:\n  senders: [\"*@mail.example.com\"]\n  allow_recipients: [ops@example.com]\n"
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
	if n := strings.Count(out, "unusable resend block"); n != 1 {
		t.Fatalf("the start-up log says it %d times, want once:\n%s", n, out)
	}
	for _, want := range []string{"level=WARN", "project=storefront", "file=storefront.yaml", "Resend side", "senders"} {
		if !strings.Contains(out, want) {
			t.Errorf("the warning does not hold %q:\n%s", want, out)
		}
	}
}
