package main

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/approvals"
	"github.com/joshua-noel/chaperone/internal/keys"
	"github.com/joshua-noel/chaperone/internal/localtime"
	"github.com/joshua-noel/chaperone/internal/policy"
)

// Tracer 2 of custom keys, end to end on the real chapd (real ledger, policy pack, approvals engine and op pipeline,
// over a fake GitHub), with the Windows Hello stand-in as the verifier: "the agent asks, you tap".
//
//	scout enrols (a code, the owner's card) -> scout holds a request-only key -> scout asks for access (ten identical
//	asks are one) -> the owner narrows and grants (a card, the owner's own Hello) -> scout claims the key, which
//	replaces the request-only one -> the owner extends it with one tap -> a human stop keeps scout stopped.

type agentE2E struct {
	*apprE2E
}

func newAgentE2E(t *testing.T) *agentE2E {
	t.Helper()
	e := newApprE2E(t, func(cfg *Config, dir, db string) {
		cfg.baselineYAML = []byte(strings.NewReplacer(
			"keys.issue:           { enabled: false", "keys.issue:           { enabled: true",
			"keys.request:         { enabled: false, rate_per_minute: 6 }", "keys.request:         { enabled: true, rate_per_minute: 60 }",
			"keys.extend:          { enabled: false", "keys.extend:          { enabled: true",
		).Replace(string(policy.BaselineBytes())))
	})
	return &agentE2E{apprE2E: e}
}

func (e *agentE2E) waitOp(opID, want string) {
	e.t.Helper()
	var last string
	for range 400 {
		st, err := e.app.Ops.OpState(context.Background(), opID)
		if err != nil {
			e.t.Fatal(err)
		}
		if last = st; st == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	e.t.Fatalf("op %s is %s, want %s", opID, last, want)
}

// signAs signs a card with the Hello of the given approver.
func (e *agentE2E) signAs(who approvals.Actor, approvalID string) error {
	ctx := context.Background()
	ch, err := e.app.Approvals.BeginDecision(ctx, approvals.BeginInput{ApprovalID: approvalID, Actor: who, Origin: testOrigin, Binding: []byte("browser")})
	if err != nil {
		return err
	}
	_, err = e.app.Approvals.Approve(ctx, approvals.ApproveInput{ApprovalID: approvalID, ChallengeID: ch.ID, Actor: who,
		Origin: testOrigin, Binding: []byte("browser"), Response: answerFor(ch.Raw)})
	return err
}

// enrol runs the whole enrolment of an agent for the operator and returns the request-only key's id and token.
func (e *agentE2E) enrol(label string) (keyID, token string) {
	e.t.Helper()
	st, start := e.call("POST", "/v0/agents/enrolments", "", map[string]any{"project": "storefront", "label": label})
	if st != http.StatusCreated {
		e.t.Fatalf("start enrolment: %d %v", st, start)
	}
	id, _ := start["id"].(string)
	device, _ := start["device_code"].(string)
	card, err := e.app.KeyDecider.ApproveEnrol(context.Background(), "operator", start["user_code"].(string))
	if err != nil {
		e.t.Fatal(err)
	}
	if st, poll := e.call("POST", "/v0/agents/enrolments/"+id+"/poll", "", map[string]any{"device_code": device}); st != 200 || poll["state"] != "pending" || poll["token"] != nil {
		e.t.Fatalf("poll before the card is signed: %d %v", st, poll)
	}
	if err := e.signAs(operator, card.ApprovalID); err != nil {
		e.t.Fatal(err)
	}
	e.waitOp(card.OpID, "succeeded")
	st, poll := e.call("POST", "/v0/agents/enrolments/"+id+"/poll", "", map[string]any{"device_code": device})
	if st != 200 || poll["state"] != "claimed" {
		e.t.Fatalf("poll after the card is signed: %d %v", st, poll)
	}
	token, _ = poll["token"].(string)
	key, _ := poll["key"].(map[string]any)
	keyID, _ = key["id"].(string)
	if !strings.HasPrefix(token, "chap_key_") || keyID == "" {
		e.t.Fatalf("no key in the poll: %v", poll)
	}
	if st, again := e.call("POST", "/v0/agents/enrolments/"+id+"/poll", "", map[string]any{"device_code": device}); st != http.StatusConflict {
		e.t.Errorf("a second poll hands over again: %d %v", st, again)
	}
	return keyID, token
}

func (e *agentE2E) ask(token string, params map[string]any, reason string) (int, map[string]any) {
	return e.call("POST", "/v0/ops", token, map[string]any{
		"op": "keys.request", "reason": reason,
		"target": map[string]any{"adapter": "chaperone", "ref": "key-request"}, "params": params,
	})
}

func scoutAsk() map[string]any {
	return map[string]any{
		"ops": []any{"pr.diff", "pr.view"}, "units": []any{"example-org/storefront"}, "ttl_hours": 24, "rate_per_hour": 300,
	}
}

func resultOf(m map[string]any) map[string]any { r, _ := m["result"].(map[string]any); return r }

func TestE2EAgentAsksOwnerTaps(t *testing.T) {
	e := newAgentE2E(t)
	ctx := context.Background()
	n, _ := e.mediumPR("agent/for-scout")

	// 1. Enrolment: a request-only key, and nothing in the ledger or the key list holds a token.
	boot, bootTok := e.enrol("scout")
	_, k := e.call("GET", "/v0/keys/self", bootTok, nil)
	if k["grant_kind"] != "bootstrap" || k["owner"] != "person:operator" || k["holder"] != "scout" || len(k["ops"].([]any)) != 0 {
		t.Fatalf("the request-only key: %v", k)
	}

	// 2. It holds no op: the whole catalog is OP_NOT_IN_TOKEN for it, except the one thing it is for.
	for _, op := range e.app.Policy.Catalog().Ops() {
		if op == keys.OpRequest {
			continue
		}
		st, body := e.call("POST", "/v0/ops", bootTok, map[string]any{
			"op": op, "project": "storefront", "target": map[string]any{"adapter": "chaperone", "ref": "x"}, "params": map[string]any{},
		})
		if st != http.StatusForbidden {
			t.Errorf("%s under a request-only key: %d %v", op, st, body)
			continue
		}
		mustValidDenial(t, body, "OP_NOT_IN_TOKEN")
	}
	if st, _ := e.view(bootTok, n); st != http.StatusForbidden {
		t.Errorf("pr.view under a request-only key: %d", st)
	}

	// 3. Ten identical asks are one request, one waiting item for the owner (a cap on requests).
	var id string
	for i := range 10 {
		st, op := e.ask(bootTok, scoutAsk(), "scout reads pull requests for its review")
		if st != http.StatusOK || resultOf(op)["request_id"] == nil {
			t.Fatalf("ask %d: %d %v", i, st, op)
		}
		got := resultOf(op)["request_id"].(string)
		if id == "" {
			id = got
		}
		if got != id {
			t.Fatalf("ask %d made another request: %s, not %s", i, got, id)
		}
	}
	var pending int
	e.app.DB.SQL().QueryRow(`SELECT count(*) FROM key_requests WHERE state = 'pending'`).Scan(&pending)
	if pending != 1 {
		t.Fatalf("%d pending requests after ten identical asks", pending)
	}
	list, _ := e.app.KeyDecider.Pending(ctx, "operator")
	if len(list) != 1 || list[0].ID != id || list[0].Reason == "" {
		t.Fatalf("the owner's list: %+v", list)
	}
	// Another person sees nothing of it.
	if other, _ := e.app.KeyDecider.Pending(ctx, "gilliano"); len(other) != 0 {
		t.Errorf("another person's list: %+v", other)
	}
	if _, err := e.app.KeyDecider.Request(ctx, "gilliano", id); err == nil {
		t.Error("another person read the request")
	}

	// 4. The owner narrows (drops pr.diff, 8 hours, 100 an hour): a card says exactly that, and nothing exists yet.
	if _, err := e.app.KeyDecider.Grant(ctx, "operator", id, &keys.Narrowing{Ops: []string{"pr.view", "pr.diff", "deploy"}}); err == nil {
		t.Error("a grant added an op that was not asked for")
	}
	if _, err := e.app.KeyDecider.Grant(ctx, "operator", id, &keys.Narrowing{TTLHours: 48}); err == nil {
		t.Error("a grant lasted longer than the ask")
	}
	card, err := e.app.KeyDecider.Grant(ctx, "operator", id, &keys.Narrowing{Ops: []string{"pr.view"}, TTLHours: 8, Rate: 100})
	if err != nil {
		t.Fatal(err)
	}
	text := e.card(card.ApprovalID).CardText
	for _, want := range []string{"agent scout", "pr.view", "ops removed: pr.diff", "shortened from 1 day to 8 hours", "rate lowered from 300 to 100",
		"the agent wrote: \"scout reads pull requests for its review\"", "you alone decide, with your own Windows Hello"} {
		if !strings.Contains(text, want) {
			t.Errorf("the card does not say %q:\n%s", want, text)
		}
	}
	var keysNow int
	e.app.DB.SQL().QueryRow(`SELECT count(*) FROM keys WHERE grant_kind = 'self'`).Scan(&keysNow)
	if keysNow != 0 {
		t.Fatalf("%d granted keys before the card was signed", keysNow)
	}
	// A second tap while the card waits makes no second card.
	if _, err := e.app.KeyDecider.Grant(ctx, "operator", id, nil); err == nil || !strings.Contains(err.Error(), "already waiting") {
		t.Errorf("a second card for one request: %v", err)
	}

	// 5. The owner's own Hello, no second approver: the key row exists, as a self grant.
	if err := e.signAs(operator, card.ApprovalID); err != nil {
		t.Fatal(err)
	}
	e.waitOp(card.OpID, "succeeded")
	st, rq := e.call("GET", "/v0/keys/requests/"+id, bootTok, nil)
	if st != 200 || rq["state"] != "granted" || rq["key_id"] == "" {
		t.Fatalf("the request after the card: %d %v", st, rq)
	}
	granted, removed := rq["granted"].(map[string]any), rq["removed"].(map[string]any)
	if g := granted["ops"].([]any); len(g) != 1 || g[0] != "pr.view" || granted["ttl_hours"].(float64) != 8 || granted["rate_per_hour"].(float64) != 100 {
		t.Errorf("granted: %v", granted)
	}
	if r := removed["ops"].([]any); len(r) != 1 || r[0] != "pr.diff" || removed["ttl_hours"].(float64) != 16 {
		t.Errorf("removed: %v", removed)
	}
	scoutKey := rq["key_id"].(string)

	// 6. The agent claims it (any key of the agent may; nobody else), once. The request-only key is replaced.
	if st, _ := e.call("POST", "/v0/keys/"+scoutKey+"/claim", e.token, nil); st != http.StatusNotFound {
		t.Errorf("another orchestrator claimed the agent's key: %d", st)
	}
	st, claimed := e.call("POST", "/v0/keys/"+scoutKey+"/claim", bootTok, nil)
	if st != 200 {
		t.Fatalf("claim: %d %v", st, claimed)
	}
	scoutTok, _ := claimed["token"].(string)
	if st, body := e.view(bootTok, n); st != http.StatusForbidden && st != http.StatusUnauthorized {
		t.Errorf("the replaced request-only key still works: %d %v", st, body)
	} else if why, _ := body["why"].(string); strings.Contains(why, "stopped by a human") {
		t.Errorf("replacing a key stopped the agent: %s", why)
	}
	if st, view := e.view(scoutTok, n); st != 200 || view["outcome"] != "succeeded" {
		t.Fatalf("pr.view under the granted key: %d %v", st, view)
	}
	if st, body := e.call("POST", "/v0/ops", scoutTok, map[string]any{
		"op": "pr.diff", "project": "storefront", "target": map[string]any{"adapter": "github", "ref": "example-org/storefront#" + strconv.Itoa(n)}, "params": map[string]any{},
	}); st != http.StatusForbidden {
		t.Errorf("the op that was narrowed away: %d %v", st, body)
	} else {
		mustValidDenial(t, body, "OP_NOT_IN_TOKEN")
	}
	_ = boot

	// 7. One-tap extend: a card with the old and the new expiry, the scope untouched.
	_, before := e.call("GET", "/v0/keys/self", scoutTok, nil)
	if _, err := e.app.KeyDecider.Extend(ctx, "gilliano", scoutKey, 24); err == nil {
		t.Error("another person extended the key")
	}
	if _, err := e.app.KeyDecider.Extend(ctx, "operator", scoutKey, 24*31); err == nil {
		t.Error("an extension past the 30 day cap was refused to nobody")
	}
	xc, err := e.app.KeyDecider.Extend(ctx, "operator", scoutKey, 24)
	if err != nil {
		t.Fatal(err)
	}
	xtext := e.card(xc.ApprovalID).CardText
	for _, want := range []string{"It now ends:", "It will end:", "What the key can do does not change: pr.view", localtime.Label() + " time"} {
		if !strings.Contains(xtext, want) {
			t.Errorf("the extension card does not say %q:\n%s", want, xtext)
		}
	}
	_, still := e.call("GET", "/v0/keys/self", scoutTok, nil)
	if still["expires_at"] != before["expires_at"] {
		t.Fatal("the key was extended before the card was signed")
	}
	if err := e.signAs(operator, xc.ApprovalID); err != nil {
		t.Fatal(err)
	}
	e.waitOp(xc.OpID, "succeeded")
	_, after := e.call("GET", "/v0/keys/self", scoutTok, nil)
	was, _ := time.Parse(time.RFC3339, before["expires_at"].(string))
	now, _ := time.Parse(time.RFC3339, after["expires_at"].(string))
	if now.Sub(was) != 24*time.Hour {
		t.Errorf("expiry moved by %s, want 24h (%v -> %v)", now.Sub(was), before["expires_at"], after["expires_at"])
	}
	if after["rate_per_hour"] != before["rate_per_hour"] || strings.Join(strs(after["ops"]), ",") != "pr.view" {
		t.Errorf("an extension changed the scope: %v -> %v", before, after)
	}

	// 8. The agent asks for more time itself: the same card, answered with one tap.
	st, op := e.ask(scoutTok, map[string]any{"kind": "extend", "key": "self", "ttl_hours": 12}, "the review is taking longer than planned")
	if st != 200 || resultOf(op)["request_id"] == nil {
		t.Fatalf("extend ask: %d %v", st, op)
	}
	extID := resultOf(op)["request_id"].(string)
	xc2, err := e.app.KeyDecider.Grant(ctx, "operator", extID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.signAs(operator, xc2.ApprovalID); err != nil {
		t.Fatal(err)
	}
	e.waitOp(xc2.OpID, "succeeded")
	if _, r := e.call("GET", "/v0/keys/requests/"+extID, scoutTok, nil); r["state"] != "granted" {
		t.Errorf("the extension request: %v", r)
	}

	// 9. A human stop keeps the agent stopped: it cannot ask again, and it cannot be enrolled again without the owner.
	// Only the owner stops an agent, at the console: an orchestrator's token cannot even see the key, so its revoke is
	// refused and changes nothing.
	if st, body := e.call("POST", "/v0/keys/"+scoutKey+"/revoke", e.token, nil); st != http.StatusNotFound {
		t.Fatalf("an orchestrator revoked its owner's agent key: %d %v", st, body)
	}
	if st, body := e.call("GET", "/v0/keys/self", scoutTok, nil); st != 200 || body["state"] != "live" {
		t.Fatalf("the refused revoke changed the key: %d %v", st, body)
	}
	if k, err := e.app.KeyDecider.Revoke(ctx, "operator", scoutKey); err != nil || k.State != "revoked" || !k.StoppedByHuman {
		t.Fatalf("revoke at the console: %+v %v", k, err)
	}
	st, body := e.ask(scoutTok, scoutAsk(), "scout asks again")
	if st != http.StatusForbidden && st != http.StatusUnauthorized {
		t.Fatalf("a stopped agent asked: %d %v", st, body)
	}
	mustValidDenial(t, body, "TOKEN_REVOKED")
	if !strings.Contains(body["why"].(string), "stopped by a human: ask your owner") {
		t.Errorf("the stopped agent is told: %v", body["why"])
	}
	_, start := e.call("POST", "/v0/agents/enrolments", "", map[string]any{"project": "storefront", "label": "scout"})
	if _, err := e.app.KeyDecider.ApproveEnrol(ctx, "operator", start["user_code"].(string)); err == nil || !strings.Contains(err.Error(), "stopped by a human: ask your owner") {
		t.Errorf("a stopped agent was enrolled again: %v", err)
	}

	// 10. Everything is in the ledger, no token is, and the chain verifies.
	for _, tok := range []string{bootTok, scoutTok} {
		var inLedger int
		e.app.DB.SQL().QueryRow(`SELECT count(*) FROM ledger_events WHERE event LIKE '%` + strings.TrimPrefix(tok, "chap_key_") + `%'`).Scan(&inLedger)
		if inLedger != 0 {
			t.Errorf("a key is in the ledger")
		}
	}
	var asks, extends int
	e.app.DB.SQL().QueryRow(`SELECT count(*) FROM ledger_events WHERE event_name = 'op.request' AND event LIKE '%keys.request%'`).Scan(&asks)
	e.app.DB.SQL().QueryRow(`SELECT count(*) FROM ledger_events WHERE event LIKE '%keys.extend%'`).Scan(&extends)
	if asks < 10 || extends == 0 {
		t.Errorf("ledger: %d key requests, %d extensions", asks, extends)
	}
	rep, err := e.app.Ledger.Verify(ctx, false)
	if err != nil || !rep.OK() {
		t.Fatalf("ledger verify: %v %v", err, rep.Problems())
	}
}

func strs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

// Self-delegation is the owner's alone: a card for an agent's key signed by another approver makes no key, and
// the owner's Hello on the same kind of card does.
func TestE2EOnlyTheOwnerSignsTheirAgentsKey(t *testing.T) {
	e := newAgentE2E(t)
	ctx := context.Background()
	if _, err := e.app.DB.SQL().Exec(`INSERT INTO approvers (id, user_handle, name, created_at) VALUES (2, randomblob(32), 'gilliano', '2026-10-24T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	gilliano := approvals.Actor{Kind: approvals.ActorApprover, ApproverRow: 2, ApproverID: "gilliano"}
	_, bootTok := e.enrol("scout")
	_, op := e.ask(bootTok, scoutAsk(), "scout reads pull requests")
	id := resultOf(op)["request_id"].(string)
	card, err := e.app.KeyDecider.Grant(ctx, "operator", id, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.signAs(gilliano, card.ApprovalID); err != nil {
		t.Fatal(err) // the card can be signed; the op then refuses what it was signed for
	}
	e.waitOp(card.OpID, "failed")
	var keysNow int
	e.app.DB.SQL().QueryRow(`SELECT count(*) FROM keys WHERE grant_kind = 'self'`).Scan(&keysNow)
	if keysNow != 0 {
		t.Fatalf("%d keys made from a card the owner did not sign", keysNow)
	}
	_, rq := e.call("GET", "/v0/keys/requests/"+id, bootTok, nil)
	if rq["state"] != "pending" {
		t.Errorf("the request after a wrong signer: %v", rq)
	}
}

func (e *agentE2E) view(token string, n int) (int, map[string]any) {
	return e.call("POST", "/v0/ops", token, map[string]any{
		"op": "pr.view", "project": "storefront",
		"target": map[string]any{"adapter": "github", "ref": "example-org/storefront#" + strconv.Itoa(n)}, "params": map[string]any{},
	})
}

// selfKey enrols an agent, lets it ask, grants the ask as asked, and returns the id and token of the key it claims.
func (e *agentE2E) selfKey(label string) (string, string) {
	e.t.Helper()
	ctx := context.Background()
	_, boot := e.enrol(label)
	st, op := e.ask(boot, scoutAsk(), "reads pull requests")
	id, _ := resultOf(op)["request_id"].(string)
	if st != 200 || id == "" {
		e.t.Fatalf("ask: %d %v", st, op)
	}
	card, err := e.app.KeyDecider.Grant(ctx, "operator", id, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.signAs(operator, card.ApprovalID); err != nil {
		e.t.Fatal(err)
	}
	e.waitOp(card.OpID, "succeeded")
	_, rq := e.call("GET", "/v0/keys/requests/"+id, boot, nil)
	kid, _ := rq["key_id"].(string)
	st, cl := e.call("POST", "/v0/keys/"+kid+"/claim", boot, nil)
	if st != 200 {
		e.t.Fatalf("claim %s: %d %v", kid, st, cl)
	}
	return kid, cl["token"].(string)
}

// P2-1, the scenario of the review: an orchestrator that holds only pr.merge (no keys.* operation) sees nothing of
// the owner's agents, reads none of their words, and cannot revoke their keys, so it cannot stop them for good.
func TestE2EAnOrchestratorHoldingOnlyPrMergeSeesNothingOfTheOwnersAgents(t *testing.T) {
	e := newAgentE2E(t)
	kid, tok := e.selfKey("scout")
	if st, _ := e.ask(tok, map[string]any{"ops": []any{"pr.view"}, "units": []any{"example-org/storefront"}, "ttl_hours": 4}, "SECRET-PLAN: reading the PR for the acquisition"); st != 200 {
		t.Fatalf("ask: %d", st)
	}
	st, list := e.call("GET", "/v0/keys", e.token, nil)
	if items, _ := list["items"].([]any); st != http.StatusOK || len(items) != 0 {
		t.Errorf("the orchestrator lists keys of the owner's agents: %d %v", st, list)
	}
	st, rqs := e.call("GET", "/v0/keys/requests", e.token, nil)
	if items, _ := rqs["items"].([]any); st != http.StatusOK || len(items) != 0 || strings.Contains(strings.Join(strs(rqs["items"]), ""), "SECRET-PLAN") {
		t.Errorf("the orchestrator reads the agent's requests: %d %v", st, rqs)
	}
	if st, body := e.call("GET", "/v0/keys/"+kid, e.token, nil); st != http.StatusNotFound {
		t.Errorf("the orchestrator reads the owner's key: %d %v", st, body)
	}
	if st, body := e.call("POST", "/v0/keys/"+kid+"/revoke", e.token, nil); st != http.StatusNotFound {
		t.Fatalf("the orchestrator's revoke: %d %v", st, body)
	}
	// Nothing changed: the agent still works, is not stopped, and can be enrolled again after a revoke at the console.
	if st, body := e.call("GET", "/v0/keys/self", tok, nil); st != 200 || body["state"] != "live" {
		t.Errorf("the key after the refused revoke: %d %v", st, body)
	}
	var stopped int
	e.app.DB.SQL().QueryRow(`SELECT count(*) FROM key_agents`).Scan(&stopped)
	if stopped != 0 {
		t.Errorf("%d agents stopped", stopped)
	}
}

// P3-1: a label too long for the ledger's id is refused when the agent starts its enrolment, not when it claims.
func TestE2EAnOverLongLabelIsRefusedAtEnrolment(t *testing.T) {
	e := newAgentE2E(t)
	st, body := e.call("POST", "/v0/agents/enrolments", "", map[string]any{"project": "storefront", "label": "s" + strings.Repeat("x", 59)})
	if st != http.StatusBadRequest || !strings.Contains(body["why"].(string), "at most 40 characters") {
		t.Errorf("a 60-character label: %d %v", st, body)
	}
	// The longest allowed label enrols and claims its own key.
	if _, tok := e.enrol("s" + strings.Repeat("x", keys.MaxLabel-1)); tok == "" {
		t.Error("the longest label did not enrol")
	}
}

// P3-2: the agent's reason reaches the owner without bidirectional or zero-width characters.
func TestE2EAReasonWithBidiControlsIsStoredClean(t *testing.T) {
	e := newAgentE2E(t)
	_, boot := e.enrol("scout")
	if st, op := e.ask(boot, scoutAsk(), "please \u202egnirotinom\u202c read only\u200b"); st != 200 {
		t.Fatalf("ask: %d %v", st, op)
	}
	list, err := e.app.KeyDecider.Pending(context.Background(), "operator")
	if err != nil || len(list) != 1 {
		t.Fatalf("pending: %v %v", list, err)
	}
	if strings.ContainsAny(list[0].Reason, "\u202e\u202c\u200b") || !strings.Contains(list[0].Reason, "read only") {
		t.Errorf("the reason reaches the owner as %q", list[0].Reason)
	}
}
