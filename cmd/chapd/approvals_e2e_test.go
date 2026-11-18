package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/approvals"
	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
	"github.com/joshua-noel/chaperone/internal/notify"
	"github.com/joshua-noel/chaperone/internal/notify/ntfytest"
	"github.com/joshua-noel/chaperone/internal/store"
	"github.com/joshua-noel/chaperone/internal/vault"
)

// helloStandIn stands in for the console's WebAuthn check: it accepts a response
// that is exactly "hello:" + the hex of the challenge it is asked about, once.
// An assertion made for another challenge, or made before, is refused, as a real
// authenticator's signature over another challenge would be.
type helloStandIn struct {
	mu   sync.Mutex
	used map[string]bool
}

func answerFor(challenge []byte) []byte { return []byte("hello:" + hex.EncodeToString(challenge)) }

func (h *helloStandIn) VerifyAssertion(_ context.Context, in approvals.AssertionInput) (approvals.AssertionEvidence, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.used == nil {
		h.used = map[string]bool{}
	}
	want := string(answerFor(in.Challenge))
	if string(in.Response) != want || h.used[want] {
		return approvals.AssertionEvidence{}, &approvals.AssertionError{Reason: "bad_signature"}
	}
	h.used[want] = true
	return approvals.AssertionEvidence{Channel: "pc", CredentialID: []byte("stand-in-credential-0001"), RPID: "localhost", Origin: in.Origin}, nil
}

type wakeLog struct {
	mu    sync.Mutex
	wakes []notify.Wake
}

func (w *wakeLog) Notify(_ context.Context, wk notify.Wake) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.wakes = append(w.wakes, wk)
	return nil
}

func (w *wakeLog) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.wakes)
}

type apprE2E struct {
	*e2e
	gh    *ghtest.Server
	repo  *ghtest.Repo
	base  string
	wakes *wakeLog
	now   *clock
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

const testOrigin = "http://localhost:55398"

var operator = approvals.Actor{Kind: approvals.ActorApprover, ApproverRow: 1, ApproverID: "operator"}

// newApprE2E boots the real chapd (real ledger, policy pack and policy/ folder,
// real approvals engine, real op pipeline) over a fake GitHub, with the Windows
// Hello stand-in as the engine's verifier.
func newApprE2E(t *testing.T, opts ...func(cfg *Config, dir, db string)) *apprE2E {
	t.Helper()
	dir := t.TempDir()
	db := filepath.Join(dir, "state.db")
	keys := writeKeys(t, dir)

	s := ghtest.New(t)
	in := s.AddInstallation(7, "example-org", map[string]string{
		"contents": "write", "pull_requests": "write", "checks": "read", "deployments": "write", "metadata": "read",
	})
	const base = "feat/d1-private-pilot" // the base of policy/storefront.yaml
	repo := in.AddRepo("storefront", base)
	c, err := gh.New(gh.Config{AppID: s.AppID(), Keys: gh.StaticKey{Key: s.Key()}, BaseURL: s.URL(), Now: s.Now})
	if err != nil {
		t.Fatal(err)
	}

	tokenFile := filepath.Join(dir, "home", "orchestrator.token")
	var out, errb bytes.Buffer
	if code := orchCmd([]string{"issue", "-db", db, "-project", "storefront", "-ops", "pr.merge", "-token-file", tokenFile, "-days", "1"}, &out, &errb); code != 0 {
		t.Fatalf("orch issue: %d %s", code, errb.String())
	}
	raw, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	policyDir, err := filepath.Abs(filepath.Join("..", "..", "policy"))
	if err != nil {
		t.Fatal(err)
	}

	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	wakes := &wakeLog{}
	cfg := Config{
		DBPath: db, KeysPath: keys, Instance: "test", PolicyDir: policyDir, github: c,
		approvalVerifier: &helloStandIn{}, notifier: wakes, now: clk.Now,
	}
	for _, o := range opts {
		o(&cfg, dir, db)
	}
	app, err := Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.SQL().Exec(`INSERT INTO approvers (id, user_handle, name, created_at) VALUES (1, randomblob(32), 'operator', '2026-10-24T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(func() { srv.Close(); app.Close() })
	e := &e2e{t: t, app: app, srv: srv, db: db, token: strings.TrimSpace(string(raw))}
	return &apprE2E{e2e: e, gh: s, repo: repo, base: base, wakes: wakes, now: clk}
}

// mediumPR opens a PR that touches a code path (medium tier: it needs a card),
// with green CI on its head.
func (e *apprE2E) mediumPR(branch string) (n int, head string) {
	e.repo.Branch(branch, e.base)
	head = e.repo.Commit(branch)
	n = e.repo.OpenPR(ghtest.PROptions{Title: "feat: change the app", Head: branch, Base: e.base})
	e.repo.SetFiles(n, ghtest.File{Filename: "src/app.py"})
	e.repo.SetCheck(head, ghtest.Check{Name: "verify", AppID: gh.GitHubActionsAppID, Status: "completed", Conclusion: "success"})
	// policy/storefront.yaml has pr.local_ci mode `also`: the App's own local-ci check is needed besides verify.
	e.repo.SetCheck(head, ghtest.Check{Name: "local-ci", AppID: ghtest.OwnAppID, Status: "completed", Conclusion: "success"})
	return n, head
}

func (e *apprE2E) mergeBody(n int, head string) map[string]any {
	return map[string]any{
		"op": "pr.merge", "project": "storefront", "reason": "ship the change",
		"target": map[string]any{"adapter": "github", "ref": "example-org/storefront#" + strconv.Itoa(n)},
		"params": map[string]any{"base": e.base, "head_sha": head, "method": "squash"},
	}
}

func (e *apprE2E) merges() int { return e.gh.Count("PUT", "/merge") }

// request asks for the card the way `chap request` does.
func (e *apprE2E) request(n int, head string) (int, map[string]any) {
	body := e.mergeBody(n, head)
	body["kind"] = "op"
	return e.call("POST", "/v0/approvals", e.token, body)
}

func (e *apprE2E) waitState(id, want string) map[string]any {
	e.t.Helper()
	var last map[string]any
	for range 300 {
		_, last = e.call("GET", "/v0/ops/"+id, e.token, nil)
		if last["state"] == want {
			return last
		}
		time.Sleep(20 * time.Millisecond)
	}
	e.t.Fatalf("op %s is %v, want %s: %v", id, last["state"], want, last)
	return nil
}

func (e *apprE2E) card(approvalID string) *approvals.Approval {
	e.t.Helper()
	a, err := e.app.Approvals.Get(context.Background(), approvalID)
	if err != nil || a == nil {
		e.t.Fatalf("approval %s: %v %v", approvalID, a, err)
	}
	return a
}

// helloApprove is the operator's side: read the card, ask for a decision, answer
// the challenge with the given assertion.
func (e *apprE2E) helloApprove(approvalID string, answer func(*approvals.Challenge) []byte) (*approvals.Approval, error) {
	ctx := context.Background()
	ch, err := e.app.Approvals.BeginDecision(ctx, approvals.BeginInput{ApprovalID: approvalID, Actor: operator, Origin: testOrigin, Binding: []byte("browser")})
	if err != nil {
		return nil, err
	}
	return e.app.Approvals.Approve(ctx, approvals.ApproveInput{ApprovalID: approvalID, ChallengeID: ch.ID, Actor: operator,
		Origin: testOrigin, Binding: []byte("browser"), Response: answer(ch)})
}

func wantRefusal(t *testing.T, err error, code string) {
	t.Helper()
	var ref *approvals.Refusal
	if !errors.As(err, &ref) || ref.Code != code {
		t.Fatalf("got %v, want refusal %s", err, code)
	}
}

func approvalOf(t *testing.T, op map[string]any) string {
	t.Helper()
	a, _ := op["approval"].(map[string]any)
	id, _ := a["id"].(string)
	if id == "" {
		t.Fatalf("the op has no approval: %v", op)
	}
	return id
}

// A medium-tier pr.merge makes a card; a fresh Hello assertion over that
// card's challenge approves it; the merge runs exactly once. A stale assertion
// approves nothing, and nothing can use the approval a second time.
func TestE2EApprovedMergeRunsExactlyOnce(t *testing.T) {
	e := newApprE2E(t)
	n, head := e.mediumPR("agent/medium")

	// 1. Asked for directly, a medium PR is refused with a request line: no card yet.
	st, body := e.call("POST", "/v0/ops", e.token, e.mergeBody(n, head))
	if st != 403 {
		t.Fatalf("direct merge: %d %v", st, body)
	}
	mustValidDenial(t, body, "OP_APPROVAL_REQUIRED")
	if e.merges() != 0 {
		t.Fatal("a merge reached GitHub before any approval")
	}

	// 2. The card: pending, on the Approvals screen's list, with one wake-up.
	st, op := e.request(n, head)
	if st != 202 || op["state"] != "pending_approval" {
		t.Fatalf("request: %d %v", st, op)
	}
	opID, _ := op["id"].(string)
	aid := approvalOf(t, op)
	card := e.card(aid)
	if card.State != approvals.StatePending || card.Op != "pr.merge" || card.Project != "storefront" || !strings.Contains(card.CardText, head) {
		t.Fatalf("card: %+v\n%s", card, card.CardText)
	}
	// The headline names the pull request by its title, read from the adapter's evidence (review item 2).
	if !strings.Contains(card.CardText, "\n  merge pull request #"+strconv.Itoa(n)+` "feat: change the app" into `) || !strings.Contains(card.CardText, "\nEVIDENCE: pull request\n") {
		t.Fatalf("card does not name the pull request:\n%s", card.CardText)
	}
	if pend, err := e.app.Approvals.Pending(context.Background()); err != nil || len(pend) != 1 || pend[0].ID != aid {
		t.Fatalf("pending: %v %v", pend, err)
	}
	if e.app.pendingCount(context.Background()) != 1 {
		t.Error("the host bus would not report the waiting card")
	}
	for range 100 { // the notifier sends from a worker
		if e.wakes.count() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e.wakes.count() != 1 {
		t.Fatalf("wake-ups: %d, want 1", e.wakes.count())
	}
	if w := e.wakes.wakes[0]; w.Kind != "pr.merge" || w.Project != "storefront" || w.Pending != 1 {
		t.Errorf("wake-up: %+v", w)
	}
	// The same request again is the same op: no second card, no second push.
	if st, again := e.request(n, head); st != 202 || again["id"] != op["id"] {
		t.Errorf("dedupe: %d %v", st, again["id"])
	}
	if cards, _ := e.app.Approvals.Pending(context.Background()); len(cards) != 1 {
		t.Errorf("%d cards after the same request twice", len(cards))
	}
	if e.merges() != 0 {
		t.Fatal("a merge ran while the card was pending")
	}

	// 3. A stale assertion (made over an earlier challenge) approves nothing.
	old, err := e.app.Approvals.BeginDecision(context.Background(), approvals.BeginInput{ApprovalID: aid, Actor: operator, Origin: testOrigin, Binding: []byte("browser")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.helloApprove(aid, func(*approvals.Challenge) []byte { return answerFor(old.Raw) })
	wantRefusal(t, err, approvals.CodeAssertion)
	if e.card(aid).State != approvals.StatePending || e.merges() != 0 {
		t.Fatal("a stale assertion approved or ran something")
	}

	// 4. A fresh assertion approves it, and the merge runs.
	done, err := e.helloApprove(aid, func(ch *approvals.Challenge) []byte { return answerFor(ch.Raw) })
	if err != nil {
		t.Fatal(err)
	}
	if done.State != approvals.StateApproved || done.Approver != "operator" {
		t.Fatalf("approved card: %+v", done)
	}
	final := e.waitState(opID, "succeeded")
	if merged, _ := e.repo.Merged(n); !merged || e.merges() != 1 {
		t.Fatalf("merged=%v, merge calls %d", merged, e.merges())
	}
	if final["approval"].(map[string]any)["state"] != "consumed" {
		t.Errorf("the approval is %v, want consumed", final["approval"])
	}
	if got := e.card(aid); got.State != approvals.StateConsumed {
		t.Errorf("card state %s", got.State)
	}

	// 5. Once only: no replay of the assertion, no second decision, no second
	// release, no re-submission with the approval id.
	if _, err := e.app.Approvals.Approve(context.Background(), approvals.ApproveInput{ApprovalID: aid, ChallengeID: old.ID, Actor: operator,
		Origin: testOrigin, Binding: []byte("browser"), Response: answerFor(old.Raw)}); err == nil {
		t.Error("an old challenge approved a consumed card")
	}
	_, err = e.helloApprove(aid, func(ch *approvals.Challenge) []byte { return answerFor(ch.Raw) })
	wantRefusal(t, err, approvals.CodeConsumed)
	if err := e.app.Ops.Release(context.Background(), opID); err != nil {
		t.Fatal(err)
	}
	resume := e.mergeBody(n, head)
	resume["approval_id"] = aid
	st, body = e.call("POST", "/v0/ops", e.token, resume)
	if st != 409 {
		t.Fatalf("resubmission: %d %v", st, body)
	}
	mustValidDenial(t, body, "APPROVAL_CONSUMED")
	if e.merges() != 1 {
		t.Fatalf("merge calls: %d, want exactly 1", e.merges())
	}
	if e.gh.LiveTokens() != 0 {
		t.Errorf("%d installation tokens left live", e.gh.LiveTokens())
	}

	// 6. The ledger holds the decision and verifies.
	var approves int
	if err := e.app.DB.SQL().QueryRow(`SELECT count(*) FROM ledger_events WHERE event_name = 'op.approve'`).Scan(&approves); err != nil || approves != 1 {
		t.Errorf("op.approve events: %d %v", approves, err)
	}
	rep, err := e.app.Ledger.Verify(context.Background(), false)
	if err != nil || !rep.OK() {
		t.Fatalf("ledger verify: %v %v", err, rep.Problems())
	}
}

// The operator signs a card that names the PR's title. If the author retitles the PR before the merge is released,
// the squash commit header would be words he never saw: chapd refuses (a new request is needed) and merges nothing.
func TestE2ERetitledPRIsNotMergedUnderTheApprovedCard(t *testing.T) {
	e := newApprE2E(t)
	n, head := e.mediumPR("agent/retitled") // the PR reads "feat: change the app"
	st, op := e.request(n, head)
	if st != 202 {
		t.Fatalf("request: %d %v", st, op)
	}
	opID, _ := op["id"].(string)
	aid := approvalOf(t, op)
	if card := e.card(aid); !strings.Contains(card.CardText, ` "feat: change the app" into `) {
		t.Fatalf("the card does not show the title:\n%s", card.CardText)
	}

	e.repo.SetTitle(n, "fix: hotfix") // a good title: only the approval differs
	if _, err := e.helloApprove(aid, func(ch *approvals.Challenge) []byte { return answerFor(ch.Raw) }); err != nil {
		t.Fatal(err)
	}
	refused := e.waitState(opID, "refused")
	if refused["denial"] == nil {
		t.Errorf("a refused op has no denial body: %v", refused)
	}
	if merged, _ := e.repo.Merged(n); merged || e.merges() != 0 {
		t.Fatalf("the PR merged=%v under another title, merge calls %d", merged, e.merges())
	}
	if e.gh.LiveTokens() != 0 {
		t.Errorf("%d installation tokens left live", e.gh.LiveTokens())
	}
}

// A denial is sticky: the same request is refused for the cooldown, no card is
// made, and the PR is never merged.
func TestE2EDenyIsSticky(t *testing.T) {
	e := newApprE2E(t)
	n, head := e.mediumPR("agent/denied")

	st, op := e.request(n, head)
	if st != 202 {
		t.Fatalf("request: %d %v", st, op)
	}
	opID, _ := op["id"].(string)
	aid := approvalOf(t, op)

	// A token cannot decide; only the console's approver can, and a denial needs a reason.
	_, err := e.app.Approvals.Deny(context.Background(), approvals.DenyInput{ApprovalID: aid, Actor: approvals.Actor{Kind: approvals.ActorOrchestrator, ID: "main"}, Reason: "x"})
	wantRefusal(t, err, approvals.CodeBreach)
	if e.card(aid).State != approvals.StatePending {
		t.Fatal("a token decided a card")
	}
	if _, err := e.app.Approvals.Deny(context.Background(), approvals.DenyInput{ApprovalID: aid, Actor: operator}); err == nil {
		t.Fatal("a denial without a reason")
	}

	if _, err := e.app.Approvals.Deny(context.Background(), approvals.DenyInput{ApprovalID: aid, Actor: operator, Reason: "not this change"}); err != nil {
		t.Fatal(err)
	}
	denied := e.waitState(opID, "denied")
	if denied["denial"] == nil {
		t.Errorf("a denied op has no denial body: %v", denied)
	}
	mustValidDenial(t, denied["denial"].(map[string]any), "OP_APPROVAL_DENIED")

	// Asking again, by either door, is refused without a card.
	st, body := e.request(n, head)
	if st != 403 {
		t.Fatalf("second request: %d %v", st, body)
	}
	mustValidDenial(t, body, "OP_APPROVAL_DENIED")
	if st, body = e.call("POST", "/v0/ops", e.token, e.mergeBody(n, head)); st != 403 {
		t.Fatalf("direct request after a denial: %d %v", st, body)
	}
	if cards, _ := e.app.Approvals.Pending(context.Background()); len(cards) != 0 {
		t.Errorf("%d cards after a denial", len(cards))
	}
	// A denied card cannot be approved afterwards.
	_, err = e.helloApprove(aid, func(ch *approvals.Challenge) []byte { return answerFor(ch.Raw) })
	wantRefusal(t, err, approvals.CodeDenied)
	if merged, _ := e.repo.Merged(n); merged || e.merges() != 0 {
		t.Fatalf("the denied PR merged=%v, merge calls %d", merged, e.merges())
	}
}

// A card nobody answers expires with its op, and the sweep that expires an
// approval that went unused does not stop on an op that is no longer waiting.
func TestE2EExpirySweepMovesTheOp(t *testing.T) {
	e := newApprE2E(t)
	n, head := e.mediumPR("agent/unanswered")
	st, op := e.request(n, head)
	if st != 202 {
		t.Fatalf("request: %d %v", st, op)
	}
	opID, _ := op["id"].(string)
	aid := approvalOf(t, op)

	e.now.advance(31 * time.Minute) // past the request's window
	if cnt, err := e.app.Approvals.Sweep(context.Background()); err != nil || cnt != 1 {
		t.Fatalf("sweep: %d %v", cnt, err)
	}
	if got := e.card(aid); got.State != approvals.StateExpired {
		t.Fatalf("card %s", got.State)
	}
	e.waitState(opID, "expired")
	if e.merges() != 0 {
		t.Fatal("an expired card merged")
	}

	// An approval that went unused expires while its op is `allowed`: the hook
	// leaves that op alone instead of failing the sweep.
	n2, head2 := e.mediumPR("agent/unused")
	_, op2 := e.request(n2, head2)
	id2 := op2["id"].(string)
	card2 := e.card(approvalOf(t, op2))
	if _, err := e.app.DB.SQL().Exec(`UPDATE ops SET state = 'allowed' WHERE id = ?`, id2); err != nil {
		t.Fatal(err)
	}
	err := e.app.DB.Immediate(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		return e.app.bridge.onDecided(ctx, tx, approvals.Decision{Approval: *card2, Outcome: approvals.OutcomeExpired, Reason: "expired"})
	})
	if err != nil {
		t.Fatalf("an unused approval's expiry failed the transaction: %v", err)
	}
}

// The console's routes are on: the Approvals screen and the L1-20 screens answer
// (a sign-in redirect, not a 404) once UseApprovals and UseScreens have run.
func TestE2EConsoleRoutesAreOn(t *testing.T) {
	e := newApprE2E(t)
	for _, p := range []string{"/approvals", "/", "/runs", "/ledger", "/secrets", "/catalog"} {
		req, _ := http.NewRequest("GET", e.srv.URL+p, nil)
		req.Host = "localhost:55398"
		resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			t.Errorf("GET %s: 404, the route is not wired", p)
		}
		if resp.StatusCode == http.StatusOK && p != "/" {
			t.Errorf("GET %s without a session answered 200", p)
		}
	}
}

// With -ntfy-topic-secret, the wake-up goes to ntfy over the topic held in the
// vault, and carries the kind, the project, the short hash and the count: no
// parameter.
func TestE2EWakeUpGoesToNtfyOverTheVaultTopic(t *testing.T) {
	useTestWrapper(t) // DPAPI does not exist on Linux CI: every vault test here uses the AES test wrapper
	const topic = "0123456789abcdef0123456789abcdef"
	ntfy := ntfytest.New(t)
	e := newApprE2E(t, func(cfg *Config, dir, db string) {
		ctx := context.Background()
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
		if _, err := v.Import(ctx, vault.Meta{ID: "ntfy-topic", Kind: "ntfy-topic"}, []byte(topic+"\n")); err != nil {
			t.Fatal(err)
		}
		cfg.notifier, cfg.testVault = nil, v
		cfg.NtfyTopicSecretID, cfg.NtfyURL = "ntfy-topic", ntfy.URL
	})
	n, head := e.mediumPR("agent/phone")
	if st, op := e.request(n, head); st != 202 {
		t.Fatalf("request: %d %v", st, op)
	}
	var msgs []ntfytest.Message
	for range 200 {
		if msgs = ntfy.MessagesFor(topic); len(msgs) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(msgs) != 1 {
		t.Fatalf("ntfy got %d messages for the topic", len(msgs))
	}
	if body := string(msgs[0].Raw); strings.Contains(body, head) || strings.Contains(body, "src/app.py") || !strings.Contains(msgs[0].Message, "pr.merge") {
		t.Errorf("push: %s", body)
	}
}
