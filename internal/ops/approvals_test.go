package ops

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// fakeApprovals stands in for the approvals engine (L1-12). Create runs inside
// the op's transaction, like the real one.
type fakeApprovals struct {
	mu        sync.Mutex
	n         int
	byID      map[string]ApprovalInfo
	cancelled []string
	consumed  []string
	refuse    *Refusal
}

func (f *fakeApprovals) Create(_ context.Context, _ *store.Tx, in ApprovalInput) (ApprovalInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refuse != nil {
		return ApprovalInfo{}, f.refuse
	}
	if f.byID == nil {
		f.byID = map[string]ApprovalInfo{}
	}
	f.n++
	info := ApprovalInfo{
		ID: fmt.Sprintf("a-%06d", f.n), RequestID: in.RequestID, Op: in.Op, OpHash: in.OpHash, State: "pending",
		Class: in.Class, Critical: in.Critical, PolicyVersion: in.PolicyVer, CreatedAt: time.Unix(1790000000, 0).UTC(),
		ExpiresAt: in.ExpiresAt, OwnerKey: in.Caller.Key(), Evidence: in.Evidence,
	}
	f.byID[info.ID] = info
	return info, nil
}

func (f *fakeApprovals) Lookup(_ context.Context, id string) (ApprovalInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a, ok := f.byID[id]; ok {
		return a, nil
	}
	return ApprovalInfo{}, ErrApprovalNotFound
}

func (f *fakeApprovals) List(_ context.Context, owner, state string, _ int, _ string) ([]ApprovalInfo, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []ApprovalInfo
	for _, a := range f.byID {
		if a.OwnerKey == owner && (state == "" || a.State == state) {
			out = append(out, a)
		}
	}
	return out, "", nil
}

func (f *fakeApprovals) CancelTx(_ context.Context, _ *store.Tx, id, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancelled = append(f.cancelled, id+": "+reason)
	a := f.byID[id]
	a.State = "cancelled"
	f.byID[id] = a
	return nil
}

// ConsumeTx spends a card once, as the real engine does.
func (f *fakeApprovals) ConsumeTx(_ context.Context, _ *store.Tx, id string, _ spec.Request) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.byID[id]
	if a.State == "consumed" {
		return &Refusal{Code: CodeApprovalConsumed, Why: "this approval has already released an op"}
	}
	a.State = "consumed"
	f.byID[id] = a
	f.consumed = append(f.consumed, id)
	return nil
}

func (f *fakeApprovals) set(id, state string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.byID[id]
	a.State = state
	f.byID[id] = a
}

func approvalReq(op, sha string) map[string]any {
	params := map[string]any{"sha": sha}
	adapter := "wsl-host"
	if op == "pr.merge" {
		params = map[string]any{"base": "main", "head_sha": sha, "method": "squash"}
		adapter = "github"
	}
	return map[string]any{
		"kind": "op", "op": op, "reason": "needed", "target": map[string]any{"adapter": adapter, "ref": "pilot"}, "params": params,
	}
}

func opReq(op, sha string) map[string]any {
	m := approvalReq(op, sha)
	delete(m, "kind")
	delete(m, "reason")
	return m
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func policyDefault(t *testing.T) (*policy.Catalog, *policy.Pack, error) {
	t.Helper()
	return policy.Default()
}

func newEngine(t *testing.T, cat *policy.Catalog, enable ...string) *policy.Engine {
	t.Helper()
	return policy.NewEngine(cat, enabledPack(t, cat, enable...), "")
}

// A high-class op asked for directly is refused with the request line; the
// card is created by POST /v0/approvals; the console decides; chapd releases.
func TestApprovalFlow(t *testing.T) {
	ap := &fakeApprovals{}
	g := newRig(t, rigOpts{enable: []string{"deploy", "repo.settings"}, approvals: ap})

	st, body, _ := g.call("POST", "/v0/ops", hiTok, opReq("deploy", sha1))
	if st != 403 {
		t.Fatalf("status %d: %v", st, body)
	}
	d := mustDenial(t, body, "OP_APPROVAL_REQUIRED")
	req := d["request"].(map[string]any)
	if req["possible"] != true || req["command"] != `chap request op deploy --target wsl-host:pilot --params '{"sha":"`+sha1+`"}' --reason "<why deploy is needed>"` {
		t.Errorf("request: %v", req)
	}

	st, op, hdr := g.call("POST", "/v0/approvals", hiTok, approvalReq("deploy", sha1))
	if st != 202 || op["state"] != "pending_approval" || hdr.Get("Location") != "/v0/ops/"+str(op, "id") {
		t.Fatalf("%d %v", st, op)
	}
	approval := op["approval"].(map[string]any)
	aid := str(approval, "id")
	if approval["critical"] != false || approval["class"] != "high" {
		t.Errorf("approval: %v", approval)
	}
	if len(g.ad.executions()) != 0 {
		t.Fatal("nothing may run before the operator decides")
	}

	// The same request again is the same op: no second card.
	st, again, _ := g.call("POST", "/v0/approvals", hiTok, approvalReq("deploy", sha1))
	if st != 202 || again["id"] != op["id"] || ap.n != 1 {
		t.Errorf("dedupe: %d %v (cards: %d)", st, again["id"], ap.n)
	}

	// An approval for deploy A cannot release deploy B.
	st, body, _ = g.call("POST", "/v0/ops", hiTok, withApproval(opReq("deploy", sha2), aid))
	if st != 409 {
		t.Fatalf("status %d: %v", st, body)
	}
	mustDenial(t, body, "APPROVAL_HASH_MISMATCH")

	// The console approves (inside the engine's transaction), then releases.
	ap.set(aid, "approved")
	if err := g.db.Immediate(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		return g.svc.Decided(ctx, tx, str(op, "id"), aid, Decision{Approved: true})
	}); err != nil {
		t.Fatal(err)
	}
	// Resubmitting under the approval is the idempotent resume: it releases the
	// allowed op, the same op comes back, and the engine's own release finds
	// nothing left to do (no second run).
	st, resumed, _ := g.call("POST", "/v0/ops", hiTok, withApproval(opReq("deploy", sha1), aid))
	if st != 200 || resumed["id"] != op["id"] || len(g.ad.executions()) != 1 {
		t.Errorf("resume: %d %v executions %d", st, resumed["id"], len(g.ad.executions()))
	}
	if err := g.svc.Release(context.Background(), str(op, "id")); err != nil {
		t.Fatal(err)
	}
	waitState(t, g, hiTok, str(op, "id"), "succeeded")
	if n := len(g.ad.executions()); n != 1 {
		t.Fatalf("executions = %d", n)
	}

	// The release spent the approval in the same commit that started the op:
	// asking under it again is APPROVAL_CONSUMED.
	if len(ap.consumed) != 1 || ap.consumed[0] != aid {
		t.Errorf("consumed approvals: %v", ap.consumed)
	}
	st, body, _ = g.call("POST", "/v0/ops", hiTok, withApproval(opReq("deploy", sha1), aid))
	if st != 409 {
		t.Fatalf("status %d", st)
	}
	mustDenial(t, body, "APPROVAL_CONSUMED")
	// Another caller cannot use it.
	st, body, _ = g.call("POST", "/v0/ops", orchTok, withApproval(withProject(opReq("deploy", sha1)), aid))
	if st != 400 {
		t.Fatalf("another caller's approval: %d %v", st, body)
	}
	mustDenial(t, body, "OP_PARAMS_INVALID")
}

// The op is released with the evidence of the card the operator approved: an adapter can bind what it does to the
// text he saw (pr.merge: the PR title).
func TestReleaseHandsTheApprovedEvidenceToTheAdapter(t *testing.T) {
	ap := &fakeApprovals{}
	g := newRig(t, rigOpts{enable: []string{"deploy"}, approvals: ap})
	card := []Evidence{{Name: "pull request", Text: "Title: feat: x\nAuthor: octo"}}
	g.ad.check = func(*Request) (CheckResult, error) {
		return CheckResult{Checks: []Check{{Name: "fake", Passed: true}}, Evidence: card}, nil
	}
	seen := make(chan []Evidence, 2)
	g.ad.execute = func(_ context.Context, r *Request) (Outcome, error) {
		seen <- r.ApprovedEvidence
		return Outcome{Result: map[string]any{"ok": true}}, nil
	}
	st, op, _ := g.call("POST", "/v0/approvals", hiTok, approvalReq("deploy", sha1))
	if st != 202 {
		t.Fatalf("%d %v", st, op)
	}
	aid := str(op["approval"].(map[string]any), "id")
	ap.set(aid, "approved")
	if err := g.db.Immediate(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		return g.svc.Decided(ctx, tx, str(op, "id"), aid, Decision{Approved: true})
	}); err != nil {
		t.Fatal(err)
	}
	if err := g.svc.Release(context.Background(), str(op, "id")); err != nil {
		t.Fatal(err)
	}
	waitState(t, g, hiTok, str(op, "id"), "succeeded")
	select {
	case got := <-seen:
		if len(got) != 1 || got[0] != card[0] {
			t.Fatalf("the adapter was handed %+v, want the card's evidence %+v", got, card)
		}
	default:
		t.Fatal("the adapter never ran")
	}
}

func withApproval(m map[string]any, id string) map[string]any {
	m["approval_id"] = id
	return m
}

func withProject(m map[string]any) map[string]any {
	m["project"] = "acme-shop"
	return m
}

func waitState(t *testing.T, g *rig, token, id, want string) {
	t.Helper()
	var got any
	for range 100 {
		_, body, _ := g.call("GET", "/v0/ops/"+id, token, nil)
		if got = body["state"]; got == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("op %s is %v, want %s", id, got, want)
}

func TestApprovalDeniedAndPolicyMoved(t *testing.T) {
	ap := &fakeApprovals{}
	g := newRig(t, rigOpts{enable: []string{"deploy"}, approvals: ap})
	_, op, _ := g.call("POST", "/v0/approvals", hiTok, approvalReq("deploy", sha1))
	if err := g.db.Immediate(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		return g.svc.Decided(ctx, tx, str(op, "id"), "a-000001", Decision{Reason: "not now"})
	}); err != nil {
		t.Fatal(err)
	}
	_, got, _ := g.call("GET", "/v0/ops/"+str(op, "id"), hiTok, nil)
	if got["state"] != "denied" {
		t.Fatalf("state %v", got["state"])
	}
	mustDenial(t, got["denial"].(map[string]any), "OP_APPROVAL_DENIED")
	if err := g.svc.Release(context.Background(), str(op, "id")); err != nil || len(g.ad.executions()) != 0 {
		t.Errorf("a denied op must not run: %v", err)
	}

	// An approved op whose policy changed before release is refused: the
	// approval was given under another policy_version.
	_, op2, _ := g.call("POST", "/v0/approvals", hiTok, approvalReq("deploy", sha2))
	if err := g.db.Immediate(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		return g.svc.Decided(ctx, tx, str(op2, "id"), "a-000002", Decision{Approved: true})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.db.SQL().Exec(`UPDATE ops SET policy_version = 'baseline-old+000000000000' WHERE id = ?`, str(op2, "id")); err != nil {
		t.Fatal(err)
	}
	_ = g.svc.Release(context.Background(), str(op2, "id"))
	_, got, _ = g.call("GET", "/v0/ops/"+str(op2, "id"), hiTok, nil)
	if got["state"] != "refused" || len(g.ad.executions()) != 0 {
		t.Errorf("policy moved: state %v executions %d", got["state"], len(g.ad.executions()))
	}
}

func TestApprovalCapsAndFlood(t *testing.T) {
	ap := &fakeApprovals{}
	g := newRig(t, rigOpts{enable: []string{"deploy"}, approvals: ap})
	for i, sha := range []string{sha1, sha2} {
		if st, body, _ := g.call("POST", "/v0/approvals", hiTok, approvalReq("deploy", sha)); st != 202 {
			t.Fatalf("request %d: %d %v", i, st, body)
		}
	}
	st, body, hdr := g.call("POST", "/v0/approvals", hiTok, approvalReq("deploy", "2222222222222222222222222222222222222222"))
	if st != 429 {
		t.Fatalf("third pending request: %d %v", st, body)
	}
	mustDenial(t, body, "OP_POLICY_REFUSED")
	if hdr.Get("Retry-After") == "" {
		t.Error("no Retry-After")
	}
	stops := g.led.rows(t, g.db, "stop.raise")
	if len(stops) != 1 || stops[0]["attrs"].(map[string]any)["factory.cause_code"] != "APPROVAL_FLOOD" {
		t.Errorf("APPROVAL_FLOOD stop not raised: %v", stops)
	}
	if ap.n != 2 {
		t.Errorf("%d cards created, want 2", ap.n)
	}
}

func TestApprovalsUnavailable(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"deploy"}}) // no engine
	st, body, _ := g.call("POST", "/v0/ops", hiTok, opReq("deploy", sha1))
	if st != 403 {
		t.Fatalf("%d", st)
	}
	d := mustDenial(t, body, "OP_APPROVAL_REQUIRED")
	if d["request"].(map[string]any)["possible"] != false {
		t.Errorf("with no engine asking is not possible yet: %v", d["request"])
	}
	st, body, _ = g.call("POST", "/v0/approvals", hiTok, approvalReq("deploy", sha1))
	if st != http.StatusServiceUnavailable {
		t.Fatalf("%d %v", st, body)
	}
	d = mustDenial(t, body, "APPROVAL_UNAVAILABLE")
	if d["thrash"].(map[string]any)["count"].(float64) != 1 {
		t.Errorf("approval-side faults never count as thrash: %v", d["thrash"])
	}
	_, status, _ := g.call("GET", "/v0/status", hiTok, nil)
	if status["approvals"] != "unavailable" {
		t.Errorf("status approvals = %v", status["approvals"])
	}
}

func TestCriticalOpsAlert(t *testing.T) {
	ap := &fakeApprovals{}
	g := newRig(t, rigOpts{enable: []string{"repo.settings"}, approvals: ap})
	req := approvalReq("repo.settings", sha1)
	req["project"] = "acme-shop"
	req["target"] = map[string]any{"adapter": "github", "ref": "acme/shop"}
	st, op, _ := g.call("POST", "/v0/approvals", orchTok, req)
	if st != 202 {
		t.Fatalf("%d %v", st, op)
	}
	if op["class"] != "critical" || op["approval"].(map[string]any)["critical"] != true {
		t.Errorf("op: %v", op)
	}
	al := g.alertList()
	if len(al) != 1 || al[0].Kind != AlertRequest || al[0].Op != "repo.settings" {
		t.Fatalf("alerts after request: %v", al)
	}
	if err := g.db.Immediate(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		return g.svc.Decided(ctx, tx, str(op, "id"), "a-000001", Decision{Approved: true})
	}); err != nil {
		t.Fatal(err)
	}
	if err := g.svc.Release(context.Background(), str(op, "id")); err != nil {
		t.Fatal(err)
	}
	al = g.alertList()
	if len(al) != 2 || al[1].Kind != AlertExecution {
		t.Errorf("alerts after execution: %v", al)
	}
	for _, r := range g.led.rows(t, g.db, "op.request") {
		if r["name"] == "op.request" {
			var sev string
			if err := g.db.SQL().QueryRow(`SELECT severity FROM fake_ledger WHERE seq = ?`, r["seq"]).Scan(&sev); err != nil || sev != "WARN" {
				t.Errorf("a critical op.request is logged loudly: severity %q %v", sev, err)
			}
		}
	}
}

// The operator spent a Hello on an op that is then refused at release: he is told (an alert), with the cause, and
// the op row keeps the reason the console shows. An op that ran raises none.
func TestApprovedOpRefusedAtReleaseAlertsTheOperator(t *testing.T) {
	ap := &fakeApprovals{}
	g := newRig(t, rigOpts{enable: []string{"deploy"}, approvals: ap})
	_, op, _ := g.call("POST", "/v0/approvals", hiTok, approvalReq("deploy", sha1))
	if err := g.db.Immediate(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		return g.svc.Decided(ctx, tx, str(op, "id"), "a-000001", Decision{Approved: true})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.db.SQL().Exec(`UPDATE ops SET policy_version = 'baseline-old+000000000000' WHERE id = ?`, str(op, "id")); err != nil {
		t.Fatal(err)
	}
	_ = g.svc.Release(context.Background(), str(op, "id"))
	var state, cause, denial string
	if err := g.db.SQL().QueryRow(`SELECT state, coalesce(cause_code, ''), coalesce(denial_json, '') FROM ops WHERE id = ?`, str(op, "id")).Scan(&state, &cause, &denial); err != nil {
		t.Fatal(err)
	}
	if state != "refused" || cause == "" || !strings.Contains(denial, "policy changed") {
		t.Fatalf("op row: state %q cause %q denial %q", state, cause, denial)
	}
	var got []Alert
	for _, a := range g.alertList() {
		if a.Kind == AlertApprovedNotRun {
			got = append(got, a)
		}
	}
	if len(got) != 1 || got[0].Op != "deploy" || got[0].RequestID != str(op, "id") || !strings.HasPrefix(got[0].Detail, cause+": ") || !strings.Contains(got[0].Detail, "policy changed") {
		t.Fatalf("alerts: %+v (cause %q)", g.alertList(), cause)
	}

	// An approved op that runs raises no such alert.
	g2 := newRig(t, rigOpts{enable: []string{"deploy"}, approvals: ap})
	_, op2, _ := g2.call("POST", "/v0/approvals", hiTok, approvalReq("deploy", sha2))
	if err := g2.db.Immediate(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		return g2.svc.Decided(ctx, tx, str(op2, "id"), "a-000002", Decision{Approved: true})
	}); err != nil {
		t.Fatal(err)
	}
	if err := g2.svc.Release(context.Background(), str(op2, "id")); err != nil {
		t.Fatal(err)
	}
	for _, a := range g2.alertList() {
		if a.Kind == AlertApprovedNotRun {
			t.Errorf("an op that ran raised %+v", a)
		}
	}
}

// The commonest way an approved op does not run: the requester never comes back and chapd's sweep expires it. The
// operator is told then too; a card nobody approved raises nothing.
func TestSweepExpiryOfAnApprovedOpAlertsTheOperator(t *testing.T) {
	ap := &fakeApprovals{}
	g := newRig(t, rigOpts{enable: []string{"deploy"}, approvals: ap})
	_, approved, _ := g.call("POST", "/v0/approvals", hiTok, approvalReq("deploy", sha1))
	if err := g.db.Immediate(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		return g.svc.Decided(ctx, tx, str(approved, "id"), "a-000001", Decision{Approved: true})
	}); err != nil {
		t.Fatal(err)
	}
	_, unapproved, _ := g.call("POST", "/v0/approvals", hiTok, approvalReq("deploy", sha2))
	g.advance(16 * time.Minute)
	if n, err := g.svc.Sweep(context.Background()); err != nil || n != 2 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	var got []Alert
	for _, a := range g.alertList() {
		if a.Kind == AlertApprovedNotRun {
			got = append(got, a)
		}
	}
	if len(got) != 1 || got[0].RequestID != str(approved, "id") || got[0].RequestID == str(unapproved, "id") || !strings.Contains(got[0].Detail, causeExpired) {
		t.Fatalf("alerts: %+v", g.alertList())
	}
}

func TestAlertDetailIsOneLine(t *testing.T) {
	got := oneLine("CI_STALE: head\nmoved\r\n\u2028and\x00more\ttabs")
	if strings.ContainsAny(got, "\n\r\u2028\x00\t") || !strings.Contains(got, "head moved") {
		t.Fatalf("%q", got)
	}
}

func TestCancelAndRunEnd(t *testing.T) {
	ap := &fakeApprovals{}
	g := newRig(t, rigOpts{enable: []string{"deploy"}, approvals: ap})
	_, op, _ := g.call("POST", "/v0/approvals", hiTok, approvalReq("deploy", sha1))
	st, got, _ := g.call("POST", "/v0/ops/"+str(op, "id")+"/cancel", hiTok, nil)
	if st != 200 || got["state"] != "cancelled" || len(ap.cancelled) != 1 {
		t.Fatalf("cancel: %d %v %v", st, got["state"], ap.cancelled)
	}
	if st, body, _ := g.call("POST", "/v0/ops/"+str(op, "id")+"/cancel", hiTok, nil); st != 409 || body["type"] != "conflict" {
		t.Errorf("second cancel: %d %v", st, body)
	}
	// Run end cancels the run's pending ops in the end transaction.
	_, op2, _ := g.call("POST", "/v0/approvals", hiTok, approvalReq("deploy", sha2))
	if err := g.db.Immediate(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		return g.svc.CancelRunOps(ctx, tx, "r-9b2c", "run ended")
	}); err != nil {
		t.Fatal(err)
	}
	_, got, _ = g.call("GET", "/v0/ops/"+str(op2, "id"), hiTok, nil)
	if got["state"] != "cancelled" {
		t.Errorf("state %v", got["state"])
	}
}
