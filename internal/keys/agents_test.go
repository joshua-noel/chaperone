package keys

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/spec"
)

// Tracer 2 of custom keys: agent enrolment, key requests (de-duplication, caps, the stopped-agent rule), the
// decision matrix, self-delegation and extending a key.

const operatorOwner = "person:operator"

// boot issues and claims a request-only key for the agent label of owner and returns its id and token.
func (g *rig) boot(owner, label string) (string, string) {
	g.t.Helper()
	ctx := context.Background()
	gr := g.grant(func(x *Grant) {
		x.Kind, x.Owner, x.Holder, x.Ops, x.Units = GrantBootstrap, owner, label, nil, nil
		x.TTLHours, x.Rate, x.Claimant = BootstrapHours, BootstrapRate, agentClaimant(owner, label)
	})
	k, err := g.s.Issue(ctx, gr)
	if err != nil {
		g.t.Fatal(err)
	}
	tok, info, err := g.s.Claim(ctx, k.ID, agentClaimant(owner, label))
	if err != nil {
		g.t.Fatal(err)
	}
	return info.ID, tok
}

func nreq(keyID string, mod func(*NewRequest)) NewRequest {
	n := NewRequest{
		Kind: reqNew, Project: "acme-shop", Owner: operatorOwner, Holder: "scout", RequesterKeyID: keyID,
		Ops: []string{"pr.diff", "pr.view"}, Units: []string{"acme/shop"}, TTLHours: 24, Rate: 300, Reason: "scout reads pull requests", RequestOp: "q-000001",
	}
	if mod != nil {
		mod(&n)
	}
	return n
}

func mustRefusal(t *testing.T, err error) *ops.Refusal {
	t.Helper()
	var ref *ops.Refusal
	if !errors.As(err, &ref) {
		t.Fatalf("want a refusal, got %v", err)
	}
	return ref
}

// ---- requests: de-duplication, caps -----------------------------------------------

func TestTenIdenticalAsksAreOneRequestWhateverTheReason(t *testing.T) {
	g := newRig(t)
	g.who = "operator"
	ctx := context.Background()
	key, _ := g.boot(operatorOwner, "scout")
	var first string
	for i := range 10 {
		v, dup, err := g.s.CreateRequest(ctx, nreq(key, func(n *NewRequest) { n.Reason = fmt.Sprintf("reason number %d", i); n.NeededToday = i == 5 }))
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = v.ID
		} else if v.ID != first || !dup {
			t.Fatalf("ask %d: id %s dup %t, want %s true", i, v.ID, dup, first)
		}
	}
	list, _ := g.s.ListRequests(ctx, operatorOwner, "", true)
	if len(list) != 1 || list[0].Reason != "reason number 0" || list[0].NeededToday {
		t.Fatalf("the one request: %+v", list)
	}
	// A different ask is another request.
	if v, dup, err := g.s.CreateRequest(ctx, nreq(key, func(n *NewRequest) { n.TTLHours = 8 })); err != nil || dup || v.ID == first {
		t.Errorf("a different ask: %v %t %s", err, dup, v.ID)
	}
	// The database says the same: a second pending row for one ask cannot exist.
	_, err := g.db.SQL().Exec(`INSERT INTO key_requests (id, kind, project, owner_id, holder, requester_key_id, ops_json, units_json, ttl_hours, rate_per_hour, reason,
        scope_hash, request_op_id, state, created_at, expires_at) SELECT 'kr-0000000000000001', kind, project, owner_id, holder, requester_key_id, ops_json, units_json, ttl_hours,
        rate_per_hour, reason, scope_hash, request_op_id, 'pending', created_at, expires_at FROM key_requests WHERE id = ?`, first)
	if err == nil {
		t.Error("the database let one ask wait twice")
	}
}

func TestRequestCapsAreTheSpecsAndRefuseWithTheRateRefusal(t *testing.T) {
	ctx := context.Background()
	t.Run("three waiting per agent", func(t *testing.T) {
		g := newRig(t)
		key, _ := g.boot(operatorOwner, "scout")
		for h := 1; h <= 3; h++ {
			if _, _, err := g.s.CreateRequest(ctx, nreq(key, func(n *NewRequest) { n.TTLHours = h })); err != nil {
				t.Fatal(err)
			}
		}
		_, _, err := g.s.CreateRequest(ctx, nreq(key, func(n *NewRequest) { n.TTLHours = 4 }))
		ref := mustRefusal(t, err)
		if ref.Status != 429 || ref.RetryAfter < 1 || !strings.Contains(ref.Why, "3 requests waiting") {
			t.Errorf("refusal: %+v", ref)
		}
		// Answering one makes room.
		list, _ := g.s.ListRequests(ctx, operatorOwner, "scout", true)
		if _, err := g.s.Deny(ctx, list[0].ID, "operator", "no"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := g.s.CreateRequest(ctx, nreq(key, func(n *NewRequest) { n.TTLHours = 5 })); err != nil {
			t.Errorf("after an answer: %v", err)
		}
	})
	t.Run("six new an hour per agent", func(t *testing.T) {
		g := newRig(t)
		key, _ := g.boot(operatorOwner, "scout")
		for h := 1; h <= 6; h++ {
			v, _, err := g.s.CreateRequest(ctx, nreq(key, func(n *NewRequest) { n.TTLHours = h }))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := g.s.Withdraw(ctx, v.ID, key); err != nil {
				t.Fatal(err)
			}
			g.now = g.now.Add(time.Minute)
		}
		_, _, err := g.s.CreateRequest(ctx, nreq(key, func(n *NewRequest) { n.TTLHours = 7 }))
		ref := mustRefusal(t, err)
		if ref.Status != 429 || !strings.Contains(ref.Why, "6 keys an hour") || ref.RetryAfter < 50*60 || ref.RetryAfter > 3600 {
			t.Errorf("refusal: %+v", ref)
		}
		g.now = g.now.Add(time.Hour)
		if _, _, err := g.s.CreateRequest(ctx, nreq(key, func(n *NewRequest) { n.TTLHours = 7 })); err != nil {
			t.Errorf("an hour later: %v", err)
		}
	})
	t.Run("ten waiting per owner, twenty in all", func(t *testing.T) {
		g := newRig(t)
		keys := map[string]string{}
		for i := range 5 {
			label := fmt.Sprintf("agent%d", i)
			keys[label], _ = g.boot(operatorOwner, label)
		}
		n := 0
		for i := range 5 {
			label := fmt.Sprintf("agent%d", i)
			for h := 1; h <= 3; h++ {
				_, _, err := g.s.CreateRequest(ctx, nreq(keys[label], func(r *NewRequest) { r.Holder, r.TTLHours = label, h }))
				if n < 10 && err != nil {
					t.Fatalf("request %d: %v", n, err)
				}
				if n >= 10 && err == nil {
					t.Fatalf("request %d got past the owner's cap of 10", n)
				}
				if n >= 10 && !strings.Contains(err.Error(), "already wait for operator") {
					t.Fatalf("request %d: %v", n, err)
				}
				n++
			}
		}
		// Twenty in all, across owners.
		other := map[string]string{}
		for i := range 4 {
			owner := fmt.Sprintf("person:p%d", i)
			other[owner], _ = g.boot(owner, "scout")
		}
		made := 10
		for i := range 4 {
			owner := fmt.Sprintf("person:p%d", i)
			for h := 1; h <= 3; h++ {
				_, _, err := g.s.CreateRequest(ctx, nreq(other[owner], func(r *NewRequest) { r.Owner, r.TTLHours = owner, h }))
				if made < 20 && err != nil {
					t.Fatalf("request %d: %v", made, err)
				}
				if made >= 20 && (err == nil || !strings.Contains(err.Error(), "20 requests already wait in all")) {
					t.Fatalf("request %d: %v", made, err)
				}
				made++
			}
		}
	})
}

func TestRequestRefusalsCallTheLoopingHookOnTheThird(t *testing.T) {
	g := newRig(t)
	g.who = "operator"
	ctx := context.Background()
	key, _ := g.boot(operatorOwner, "scout")
	var told []Looping
	g.s.cfg.OnLooping = func(_ context.Context, l Looping) { told = append(told, l) }
	for h := 1; h <= 3; h++ {
		if _, _, err := g.s.CreateRequest(ctx, nreq(key, func(n *NewRequest) { n.TTLHours = h })); err != nil {
			t.Fatal(err)
		}
	}
	refuse := func() {
		t.Helper()
		_, err := g.s.Precheck(ctx, nreq(key, func(n *NewRequest) { n.TTLHours = 9 }))
		mustRefusal(t, err)
		// the pipeline writes the refused op down; two refusals are on record before the third
	}
	seq := 0
	record := func(n int) {
		for range n {
			_, err := g.db.SQL().Exec(`INSERT INTO ops (id, state, op, project, target_adapter, target_ref, params_json, op_hash, requester_kind, requester_key,
                class, reversibility, policy_version, requested_at, expires_at, updated_at, key_id, owner_id)
                VALUES (?, 'denied', 'keys.request', 'acme-shop', 'chaperone', 'key-request', '{}', ?, 'key', ?, 'routine', 'reversible', 'v', ?, ?, ?, ?, ?)`,
				fmt.Sprintf("q-8%07d", seq), fmt.Sprintf("sha256:%064d", seq), "key:"+key, g.now.Unix(), g.now.Unix()+60, g.now.Unix(), key, operatorOwner)
			seq++
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	refuse()
	if len(told) != 0 {
		t.Fatalf("the hook was called on the first refusal: %+v", told)
	}
	record(1)
	refuse()
	if len(told) != 0 {
		t.Fatalf("the hook was called on the second refusal: %+v", told)
	}
	record(1)
	refuse()
	if len(told) != 1 || told[0].Holder != "scout" || told[0].Owner != operatorOwner || told[0].KeyID != key || told[0].Refusals != 3 {
		t.Fatalf("the hook on the third refusal: %+v", told)
	}
}

func TestADeniedAskIsRefusedForAnHourAndAnotherAskIsNot(t *testing.T) {
	g := newRig(t)
	g.who = "operator"
	ctx := context.Background()
	key, _ := g.boot(operatorOwner, "scout")
	v, _, err := g.s.CreateRequest(ctx, nreq(key, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.s.Deny(ctx, v.ID, "operator", "not for this job"); err != nil {
		t.Fatal(err)
	}
	_, _, err = g.s.CreateRequest(ctx, nreq(key, func(n *NewRequest) { n.Reason = "please" }))
	ref := mustRefusal(t, err)
	if !strings.Contains(ref.Why, "operator denied this exact request") || !strings.Contains(ref.Why, "not for this job") {
		t.Errorf("the sticky denial says: %s", ref.Why)
	}
	if _, _, err := g.s.CreateRequest(ctx, nreq(key, func(n *NewRequest) { n.TTLHours = 2 })); err != nil {
		t.Errorf("a different ask: %v", err)
	}
	g.now = g.now.Add(61 * time.Minute)
	if _, _, err := g.s.CreateRequest(ctx, nreq(key, nil)); err != nil {
		t.Errorf("after the hour: %v", err)
	}
	// The denial is final: a request is answered once.
	if _, err := g.s.Deny(ctx, v.ID, "operator", "again"); !errors.Is(err, ErrRequestState) {
		t.Errorf("a second answer: %v", err)
	}
}

func TestNeededTodayChangesNeitherTheOrderNorTheLimits(t *testing.T) {
	g := newRig(t)
	g.who = "operator"
	ctx := context.Background()
	key, _ := g.boot(operatorOwner, "scout")
	var ids []string
	for h := 1; h <= 3; h++ {
		v, _, err := g.s.CreateRequest(ctx, nreq(key, func(n *NewRequest) { n.TTLHours, n.NeededToday = h, h == 3 }))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, v.ID)
		g.now = g.now.Add(time.Minute)
	}
	d := NewDecider(g.s, nil)
	pending, _ := d.Pending(ctx, "operator")
	if len(pending) != 3 || pending[0].ID != ids[0] || pending[2].ID != ids[2] || !pending[2].NeededToday {
		t.Fatalf("the owner's order: %+v", pending)
	}
	// "Needed today" does not lift the cap either.
	_, _, err := g.s.CreateRequest(ctx, nreq(key, func(n *NewRequest) { n.TTLHours, n.NeededToday = 4, true }))
	mustRefusal(t, err)
}

func TestAStoppedAgentCannotAskAndTheAskedOwnerIsNotBothered(t *testing.T) {
	g := newRig(t)
	g.who = "operator"
	ctx := context.Background()
	key, _ := g.boot(operatorOwner, "scout")
	v, _, err := g.s.CreateRequest(ctx, nreq(key, nil))
	if err != nil {
		t.Fatal(err)
	}
	// A human revoke of the agent's key stops it and cancels what waits for its owner.
	if _, err := g.s.Revoke(ctx, key, "orchestrator:main", true); err != nil {
		t.Fatal(err)
	}
	if got, _ := g.s.GetRequest(ctx, v.ID); got.State != "cancelled" {
		t.Errorf("a waiting ask of a stopped agent is %s", got.State)
	}
	if pending, _ := g.s.ListRequests(ctx, operatorOwner, "", true); len(pending) != 0 {
		t.Errorf("a stopped agent's ask still waits: %+v", pending)
	}
	// Even a key of that agent that still lives cannot ask (a stop is the agent's, not one key's).
	_, _, err = g.s.CreateRequest(ctx, nreq(key, func(n *NewRequest) { n.TTLHours = 3 }))
	ref := mustRefusal(t, err)
	if ref.Code != ops.CodeTokenRevoked || !strings.Contains(ref.Why, "stopped by a human: ask your owner") {
		t.Errorf("refusal: %+v", ref)
	}
	// Another owner's agent of the same name is not stopped.
	other, _ := g.boot("person:other", "scout")
	if _, _, err := g.s.CreateRequest(ctx, nreq(other, func(n *NewRequest) { n.Owner = "person:other" })); err != nil {
		t.Errorf("another owner's agent: %v", err)
	}
}

func TestAnExpiredRequestIsMarkedExpired(t *testing.T) {
	g := newRig(t)
	g.who = "operator"
	ctx := context.Background()
	key, _ := g.boot(operatorOwner, "scout")
	v, _, err := g.s.CreateRequest(ctx, nreq(key, nil))
	if err != nil {
		t.Fatal(err)
	}
	g.now = g.now.Add(RequestLife + time.Minute)
	if got, _ := g.s.GetRequest(ctx, v.ID); got.State != "expired" {
		t.Errorf("read after its deadline: %s", got.State)
	}
	if _, err := g.s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	var state string
	g.db.SQL().QueryRow(`SELECT state FROM key_requests WHERE id = ?`, v.ID).Scan(&state)
	if state != "expired" {
		t.Errorf("written down as %s", state)
	}
	// The same ask may be made again: the expired one no longer holds the place.
	if v2, dup, err := g.s.CreateRequest(ctx, nreq(key, nil)); err != nil || dup || v2.ID == v.ID {
		t.Errorf("asking again: %v %t", err, dup)
	}
}

// ---- the grant matrix --------------------------------------------------------------------------

type fakeAccess struct {
	allow func(owner string, opList []string) bool
}

func (f fakeAccess) Within(_ context.Context, owner, _ string, opList, _ []string) error {
	if !f.allow(owner, opList) {
		return rule("%s's own access does not cover %s", ownerName(owner), strings.Join(opList, ", "))
	}
	return nil
}

func newRequestAdapter(t *testing.T, g *rig) *RequestAdapter {
	t.Helper()
	cat, _, err := policy.Default()
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewRequestAdapter(RequestConfig{
		Store: g.s, Catalog: cat, Enabled: func(string, string) bool { return true },
		Project: func(p string) (ops.PRProject, bool) {
			if p == "acme-shop" {
				return ops.PRProject{Repo: "acme/shop", Base: "main"}, true
			}
			return ops.PRProject{}, false
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func agentCaller(keyID, owner, label string) *ops.Caller {
	return &ops.Caller{Kind: ops.KindKey, KeyID: keyID, Project: "acme-shop", KeyOwner: owner, KeyHolder: label, KeyHolderKind: HolderAgent}
}

func askReq(c *ops.Caller, reason string, p map[string]any) *ops.Request {
	return &ops.Request{ID: "q-000777", Op: OpRequest, Project: "acme-shop", Params: p, Reason: reason, Caller: c,
		Target: spec.Target{Adapter: "chaperone", Ref: "key-request"}}
}

func TestOnlyAnAgentsKeyAsksAndNeverWithoutAReason(t *testing.T) {
	g := newRig(t)
	g.who = "operator"
	a := newRequestAdapter(t, g)
	ctx := context.Background()
	key, _ := g.boot(operatorOwner, "scout")
	good := map[string]any{"ops": []any{"pr.view"}, "units": []any{"acme/shop"}}
	person := &ops.Caller{Kind: ops.KindKey, KeyID: key, Project: "acme-shop", KeyOwner: operatorOwner, KeyHolder: "scout", KeyHolderKind: HolderPerson}
	for name, c := range map[string]*ops.Caller{
		"a person's key": person, "an orchestrator": {Kind: ops.KindOrchestrator, OrchID: "main"}, "a run": {Kind: ops.KindRun, RunID: "r-1"},
	} {
		if _, err := a.Check(ctx, askReq(c, "why", good)); err == nil || !strings.Contains(err.Error(), "only an agent's key") {
			t.Errorf("%s asked: %v", name, err)
		}
	}
	for name, tc := range map[string]struct {
		reason string
		params map[string]any
		want   string
	}{
		"no reason":          {"  ", good, "a reason is required"},
		"unknown param":      {"why", map[string]any{"ops": []any{"pr.view"}, "units": []any{"acme/shop"}, "owner": "person:evil"}, "unknown param"},
		"a critical op":      {"why", map[string]any{"ops": []any{"repo.settings"}}, "can never be in a key"},
		"keys.issue":         {"why", map[string]any{"ops": []any{"keys.issue"}}, "can never be in a key"},
		"too long":           {"why", map[string]any{"ops": []any{"pr.view"}, "units": []any{"acme/shop"}, "ttl_hours": float64(24 * 31)}, "at most 30 days"},
		"risky op too long":  {"why", map[string]any{"ops": []any{"deploy"}, "ttl_hours": float64(24 * 8)}, "at most 7 days"},
		"another repository": {"why", map[string]any{"ops": []any{"pr.view"}, "units": []any{"evil/repo"}}, "cannot cover"},
		"rate raised":        {"why", map[string]any{"ops": []any{"pr.view"}, "units": []any{"acme/shop"}, "rate_per_hour": float64(900)}, "calls an hour"},
		"preset with ops":    {"why", map[string]any{"preset": PresetReadOnly, "ops": []any{"pr.view"}}, "not both"},
	} {
		if _, err := a.Check(ctx, askReq(agentCaller(key, operatorOwner, "scout"), tc.reason, tc.params)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v (want %q)", name, err, tc.want)
		}
	}
	if _, err := a.Check(ctx, askReq(agentCaller(key, operatorOwner, "scout"), "why", good)); err != nil {
		t.Errorf("a good ask: %v", err)
	}
}

func TestSameAsMeReadOnlyIsExpandedByTheServerAndStoredAsOps(t *testing.T) {
	g := newRig(t)
	g.who = "operator"
	a := newRequestAdapter(t, g)
	ctx := context.Background()
	key, _ := g.boot(operatorOwner, "scout")
	out, err := a.Execute(ctx, askReq(agentCaller(key, operatorOwner, "scout"), "read everything I can read", map[string]any{"preset": PresetReadOnly}))
	if err != nil || out.Failed {
		t.Fatalf("%v %+v", err, out)
	}
	v, _ := g.s.GetRequest(ctx, out.Result["request_id"].(string))
	for _, want := range []string{"health", "logs", "pr.checks", "pr.diff", "pr.files", "pr.view"} {
		if !contains(v.Ops, want) {
			t.Errorf("read-only misses %s: %v", want, v.Ops)
		}
	}
	if contains(v.Ops, "deploy") {
		t.Errorf("read-only holds a risky op: %v", v.Ops)
	}
	if len(v.Units) != 1 || v.Units[0] != "acme/shop" {
		t.Errorf("units: %v", v.Units)
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestARequestOutsideTheOwnersAccessIsRefusedWithTheOwnersName(t *testing.T) {
	g := newRig(t)
	g.who = "operator"
	g.s.cfg.Access = fakeAccess{allow: func(_ string, opList []string) bool { return !contains(opList, "deploy") }}
	a := newRequestAdapter(t, g)
	key, _ := g.boot(operatorOwner, "scout")
	_, err := a.Check(context.Background(), askReq(agentCaller(key, operatorOwner, "scout"), "why", map[string]any{"ops": []any{"deploy"}}))
	ref := mustRefusal(t, err)
	if !strings.Contains(ref.Why, "operator's own access does not cover deploy") {
		t.Errorf("refusal: %s", ref.Why)
	}
	// Within the owner's access it is asked.
	if _, err := a.Check(context.Background(), askReq(agentCaller(key, operatorOwner, "scout"), "why", map[string]any{"ops": []any{"health"}})); err != nil {
		t.Errorf("within access: %v", err)
	}
	// An owner that is not a person has no access to give an agent.
	if err := (PersonAccess{}).Within(context.Background(), "main", "p", nil, nil); err == nil {
		t.Error("an orchestrator id was taken for a person")
	}
}

// issueAs builds the keys.issue request of the console for a stored request.
func (g *rig) issueFor(rq ops.KeyRequestInfo, mod func(p map[string]any)) *ops.Request {
	g.t.Helper()
	req := issueReq(g, nil)
	p := map[string]any{
		"request": rq.ID, "owner": rq.Owner, "holder": rq.Holder, "holder_kind": "agent",
		"ops": anyList(rq.Ops), "units": anyList(rq.Units), "ttl_hours": float64(rq.TTLHours), "rate_per_hour": float64(rq.RatePerHour),
	}
	if mod != nil {
		mod(p)
	}
	req.Params, req.Caller = p, &ops.Caller{Kind: ops.KindOrchestrator, OrchID: ops.OperatorID}
	return req
}

func anyList(l []string) []any {
	out := make([]any, len(l))
	for i, s := range l {
		out[i] = s
	}
	return out
}

func TestAGrantCanOnlyNarrowAndRowsOfTheMatrixHold(t *testing.T) {
	g := newRig(t)
	g.who = "operator"
	issue := newAdapter(t, g, nil)
	ctx := context.Background()
	key, _ := g.boot(operatorOwner, "scout")
	rq, _, err := g.s.CreateRequest(ctx, nreq(key, nil))
	if err != nil {
		t.Fatal(err)
	}

	// Row: the scope is within the owner's access -> the owner alone decides, and it can only narrow.
	for name, tc := range map[string]struct {
		mod  func(p map[string]any)
		want string
	}{
		"an op added":       {func(p map[string]any) { p["ops"] = []any{"pr.diff", "pr.files", "pr.view"} }, "pr.files was not asked for"},
		"another unit":      {func(p map[string]any) { p["units"] = []any{"acme/other"} }, "acme/other was not asked for"},
		"more time":         {func(p map[string]any) { p["ttl_hours"] = float64(48) }, "more than the 24 asked for"},
		"a faster rate":     {func(p map[string]any) { p["rate_per_hour"] = float64(301) }, "calls an hour"},
		"another agent":     {func(p map[string]any) { p["holder"] = "other" }, "is from agent scout"},
		"another owner":     {func(p map[string]any) { p["owner"] = "person:evil" }, "not evil"},
		"a person's key":    {func(p map[string]any) { p["holder_kind"] = "person" }, "is from agent scout"},
		"nothing kept":      {func(p map[string]any) { p["ops"] = []any{} }, "list of names"},
		"an unknown param":  {func(p map[string]any) { p["claimant"] = "orchestrator:main" }, "unknown param"},
		"a critical op":     {func(p map[string]any) { p["ops"] = []any{"repo.settings"} }, "was not asked for"},
		"an unsorted list":  {func(p map[string]any) { p["ops"] = []any{"pr.view", "pr.diff"} }, "sorted order"},
		"a missing request": {func(p map[string]any) { p["request"] = "kr-ffffffffffffffff" }, "no key request"},
	} {
		_, err := issue.Check(ctx, g.issueFor(rq, tc.mod))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v (want %q)", name, err, tc.want)
		}
	}
	// Only the operator (the console) answers a request: a script's orchestrator token cannot, whatever it names.
	bad := g.issueFor(rq, nil)
	bad.Caller = &ops.Caller{Kind: ops.KindOrchestrator, OrchID: "main"}
	if _, err := issue.Check(ctx, bad); err == nil || !strings.Contains(err.Error(), "made at the console") {
		t.Errorf("an orchestrator answered a request: %v", err)
	}
	for _, c := range []*ops.Caller{agentCaller(key, operatorOwner, "scout"), {Kind: ops.KindRun, RunID: "r"}} {
		bad.Caller = c
		if _, err := issue.Check(ctx, bad); err == nil {
			t.Errorf("%s answered a request", c.Kind)
		}
	}
	// ... and the console cannot make a direct key: at the console a key answers a request or an enrolment.
	direct := issueReq(g, nil)
	direct.Caller = &ops.Caller{Kind: ops.KindOrchestrator, OrchID: ops.OperatorID}
	if _, err := issue.Check(ctx, direct); err == nil || !strings.Contains(err.Error(), "answer an agent's request or an enrolment") {
		t.Errorf("a direct key as the operator: %v", err)
	}

	// Narrowed: fewer ops, shorter, slower. The card says what was removed.
	narrow := g.issueFor(rq, func(p map[string]any) {
		p["ops"], p["ttl_hours"], p["rate_per_hour"] = []any{"pr.view"}, float64(8), float64(100)
	})
	res, err := issue.Check(ctx, narrow)
	if err != nil {
		t.Fatal(err)
	}
	text := res.Evidence[0].Text
	for _, want := range []string{"ops removed: pr.diff", "shortened from 1 day to 8 hours", "rate lowered from 300 to 100", "you alone decide, with your own Windows Hello"} {
		if !strings.Contains(text, want) {
			t.Errorf("card lacks %q:\n%s", want, text)
		}
	}

	// Row: the owner's own Hello signs it (the approver id is "operator" in the rig's approval) -> a self grant.
	out, err := issue.Execute(ctx, narrow)
	if err != nil || out.Failed {
		t.Fatalf("execute: %v %+v", err, out)
	}
	k, _ := g.s.Get(ctx, out.Result["key_id"].(string))
	if k.GrantKind != GrantSelf || k.Owner != operatorOwner || k.Holder != "scout" || strings.Join(k.Ops, ",") != "pr.view" || k.RatePerHour != 100 || k.GrantedBy != "operator" {
		t.Errorf("the key: %+v", k)
	}
	got, _ := g.s.GetRequest(ctx, rq.ID)
	if got.State != "granted" || got.KeyID != k.ID || got.Removed == nil || len(got.Removed.Ops) != 1 || got.Removed.Ops[0] != "pr.diff" || got.Removed.TTLHours != 16 {
		t.Errorf("the request after the grant: %+v", got)
	}
	// A request is answered once: the same card cannot make a second key, and a new op finds it answered.
	if _, err := issue.Check(ctx, g.issueFor(rq, nil)); err == nil || !strings.Contains(err.Error(), "no longer waiting") {
		t.Errorf("a second answer: %v", err)
	}
}

func TestSelfDelegationNeedsTheOwnersOwnSignatureAndTheAccessRowRefuses(t *testing.T) {
	ctx := context.Background()
	t.Run("another approver's signature makes no key", func(t *testing.T) {
		g := newRig(t)
		issue := newAdapter(t, g, nil)
		key, _ := g.boot(operatorOwner, "scout")
		rq, _, _ := g.s.CreateRequest(ctx, nreq(key, nil))
		g.who = "gilliano" // another person signs the card
		req := g.issueFor(rq, nil)
		// the rig's approval is signed by "operator"; make the owner someone else
		_ = req
		out, err := issue.Execute(ctx, req)
		if err != nil || !out.Failed || !strings.Contains(out.Result["error"].(string), "only operator signs it; the card was signed by gilliano") {
			t.Fatalf("execute: %v %+v", err, out)
		}
		if countKeys(t, g.db) != 1 { // the request-only key only
			t.Error("a key was made from a card the owner did not sign")
		}
		if got, _ := g.s.GetRequest(ctx, rq.ID); got.State != "pending" {
			t.Errorf("the request is %s", got.State)
		}
	})
	t.Run("outside the owner's access: refused at the card", func(t *testing.T) {
		g := newRig(t)
		g.s.cfg.Access = fakeAccess{allow: func(string, []string) bool { return true }}
		issue := newAdapter(t, g, nil)
		key, _ := g.boot(operatorOwner, "scout")
		rq, _, _ := g.s.CreateRequest(ctx, nreq(key, nil))
		g.s.cfg.Access = fakeAccess{allow: func(string, []string) bool { return false }} // the owner's access shrank after the ask
		if _, err := issue.Check(ctx, g.issueFor(rq, nil)); err == nil || !strings.Contains(err.Error(), "operator's own access does not cover") {
			t.Errorf("refused as: %v", err)
		}
	})
	t.Run("a withdrawn request cannot be granted", func(t *testing.T) {
		g := newRig(t)
		issue := newAdapter(t, g, nil)
		key, _ := g.boot(operatorOwner, "scout")
		rq, _, _ := g.s.CreateRequest(ctx, nreq(key, nil))
		req := g.issueFor(rq, nil)
		if _, err := g.s.Withdraw(ctx, rq.ID, key); err != nil {
			t.Fatal(err)
		}
		if _, err := issue.Check(ctx, req); err == nil || !strings.Contains(err.Error(), "no longer waiting") {
			t.Errorf("a withdrawn request was granted: %v", err)
		}
	})
	t.Run("a sensitive key for an own agent is capped at 7 days", func(t *testing.T) {
		g := newRig(t)
		issue := newAdapter(t, g, nil)
		key, _ := g.boot(operatorOwner, "scout")
		rq, _, err := g.s.CreateRequest(ctx, nreq(key, func(n *NewRequest) { n.Ops, n.Units, n.TTLHours = []string{"deploy"}, nil, 24*7 }))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := issue.Check(ctx, g.issueFor(rq, nil)); err != nil {
			t.Errorf("7 days with a risky op: %v", err)
		}
		// a row that asks for more cannot exist at all
		if _, _, err := g.s.CreateRequest(ctx, nreq(key, func(n *NewRequest) { n.Ops, n.Units, n.TTLHours = []string{"deploy"}, nil, 24*8 })); err == nil {
			// the store does not judge the scope (the adapter does): the card still refuses it
			rq2, _ := g.s.ListRequests(ctx, operatorOwner, "scout", true)
			for _, r := range rq2 {
				if r.TTLHours == 24*8 {
					if _, err := issue.Check(ctx, g.issueFor(r, nil)); err == nil {
						t.Error("an 8 day key with a risky op was carded")
					}
				}
			}
		}
	})
}

// ---- the claim replaces the agent's other keys ---------------------------------------------------

func TestClaimingAnAgentsKeyReplacesItsOthersAndOnlyTheAgentClaims(t *testing.T) {
	g := newRig(t)
	g.who = "operator"
	ctx := context.Background()
	boot, bootTok := g.boot(operatorOwner, "scout")
	gr := g.grant(func(x *Grant) {
		x.Kind, x.Owner, x.Holder, x.Claimant = GrantSelf, operatorOwner, "scout", agentClaimant(operatorOwner, "scout")
	})
	k, err := g.s.Issue(ctx, gr)
	if err != nil {
		t.Fatal(err)
	}
	// Until it is claimed, the old key still works (no gap), and another agent's claim finds nothing.
	if _, err := g.s.VerifyKey(ctx, bootTok); err != nil {
		t.Fatalf("the request-only key before the claim: %v", err)
	}
	if _, _, err := g.s.Claim(ctx, k.ID, agentClaimant(operatorOwner, "other")); !errors.Is(err, ErrNotFound) {
		t.Errorf("another agent claimed: %v", err)
	}
	if _, _, err := g.s.Claim(ctx, k.ID, "orchestrator:main"); !errors.Is(err, ErrNotFound) {
		t.Errorf("an orchestrator claimed an agent's key: %v", err)
	}
	if _, _, err := g.s.Claim(ctx, k.ID, agentClaimant(operatorOwner, "scout")); err != nil {
		t.Fatal(err)
	}
	old, _ := g.s.Get(ctx, boot)
	if old.State != "revoked" || old.StoppedByHuman || !strings.Contains(old.RevokeReason, "replaced by "+k.ID) {
		t.Errorf("the request-only key after the claim: %+v", old)
	}
	if stopped, _ := g.s.AgentStopped(ctx, operatorOwner, "scout"); stopped {
		t.Error("replacing a key stopped the agent")
	}
}

// ---- enrolment ------------------------------------------------------------------------------------

func TestEnrolmentIsBoundedAndKeepsOnlyHashes(t *testing.T) {
	g := newRig(t)
	g.who = "operator"
	ctx := context.Background()
	g.s.cfg.EnrolProject = func(p string) bool { return p == "acme-shop" }
	if _, err := g.s.StartEnrolment(ctx, "other-shop", "scout"); err == nil || !strings.Contains(err.Error(), "does not turn keys.request on") {
		t.Errorf("a project without keys.request: %v", err)
	}
	for _, bad := range []string{"Scout", "", "a b", strings.Repeat("a", 64)} {
		if _, err := g.s.StartEnrolment(ctx, "acme-shop", bad); err == nil {
			t.Errorf("label %q accepted", bad)
		}
	}
	st, err := g.s.StartEnrolment(ctx, "acme-shop", "scout")
	if err != nil {
		t.Fatal(err)
	}
	if len(st.UserCode) != 9 || st.UserCode[4] != '-' || len(st.DeviceCode) != 43 {
		t.Errorf("codes: %q %q", st.UserCode, st.DeviceCode)
	}
	var stored string
	g.db.SQL().QueryRow(`SELECT id||project||label||user_code_sha256||device_sha256||state FROM key_enrolments`).Scan(&stored)
	if strings.Contains(stored, st.DeviceCode) || strings.Contains(stored, strings.ReplaceAll(st.UserCode, "-", "")) {
		t.Error("a code is stored in the clear")
	}
	if _, err := g.s.StartEnrolment(ctx, "acme-shop", "scout"); err == nil || !strings.Contains(err.Error(), "already waits") {
		t.Errorf("a second enrolment for one label: %v", err)
	}
	for i := 1; i < MaxPendingEnrolments; i++ {
		if _, err := g.s.StartEnrolment(ctx, "acme-shop", fmt.Sprintf("agent%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	_, err = g.s.StartEnrolment(ctx, "acme-shop", "onemore")
	var ref *EnrolRefusal
	if !errors.As(err, &ref) || ref.Status != 429 {
		t.Errorf("past the cap: %v", err)
	}
	// The code is found as printed or typed carelessly; a wrong one is not found.
	for _, typed := range []string{st.UserCode, strings.ToLower(st.UserCode), strings.ReplaceAll(st.UserCode, "-", " ")} {
		if v, err := g.s.EnrolmentByCode(ctx, typed); err != nil || v.Label != "scout" || v.Project != "acme-shop" {
			t.Errorf("code %q: %v %+v", typed, err, v)
		}
	}
	if _, err := g.s.EnrolmentByCode(ctx, "AAAA-AAAA"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a wrong code: %v", err)
	}
	// A wrong device code is "no such enrolment", never a hint.
	if _, err := g.s.PollEnrolment(ctx, st.ID, strings.Repeat("x", 43)); !errors.Is(err, ErrNotFound) {
		t.Errorf("a wrong device code: %v", err)
	}
	if p, err := g.s.PollEnrolment(ctx, st.ID, st.DeviceCode); err != nil || p.State != "pending" || p.Token != "" {
		t.Errorf("poll: %v %+v", err, p)
	}
	// Ten minutes later the code is dead, for the owner and for the agent.
	g.now = g.now.Add(EnrolLife + time.Second)
	if _, err := g.s.EnrolmentByCode(ctx, st.UserCode); !errors.Is(err, ErrNotFound) {
		t.Errorf("an expired code: %v", err)
	}
	if p, err := g.s.PollEnrolment(ctx, st.ID, st.DeviceCode); err != nil || p.State != "expired" {
		t.Errorf("poll after expiry: %v %+v", err, p)
	}
}

type fakeOperator struct {
	calls  []map[string]any
	ops    []string
	states map[string]string
}

func (f *fakeOperator) RequestAsOperator(_ context.Context, _, op, _ string, _ spec.Target, params map[string]any) (ops.OperatorCard, error) {
	f.calls, f.ops = append(f.calls, params), append(f.ops, op)
	id := fmt.Sprintf("q-%06d", len(f.calls))
	return ops.OperatorCard{OpID: id, ApprovalID: "a-" + id[2:], State: "pending_approval"}, nil
}

func (f *fakeOperator) OpState(_ context.Context, id string) (string, error) {
	return f.states[id], nil
}

func TestWrongEnrolmentCodesAreCountedAndLockTheBox(t *testing.T) {
	g := newRig(t)
	g.who = "operator"
	ctx := context.Background()
	d := NewDecider(g.s, &fakeOperator{})
	st, _ := g.s.StartEnrolment(ctx, "acme-shop", "scout")
	for i := range wrongCodeLimit {
		if _, err := d.LookupEnrol(ctx, "operator", fmt.Sprintf("AAAA-AAA%c", 'A'+i)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("wrong code %d: %v", i, err)
		}
	}
	// Even the right code is refused while the box is locked, and another person is not locked out.
	if _, err := d.LookupEnrol(ctx, "operator", st.UserCode); !errors.Is(err, ErrCodeLocked) {
		t.Errorf("the right code while locked: %v", err)
	}
	if _, err := d.LookupEnrol(ctx, "gilliano", st.UserCode); err != nil {
		t.Errorf("another person: %v", err)
	}
	g.now = g.now.Add(wrongCodeWindow + time.Second)
	st, _ = g.s.StartEnrolment(ctx, "acme-shop", "scout") // the first one expired with the window: a new one waits
	if _, err := d.LookupEnrol(ctx, "operator", st.UserCode); err != nil {
		t.Errorf("after the window: %v", err)
	}
}

func TestEnrolmentCardIsBoundToTheCodesAgentAndOwner(t *testing.T) {
	g := newRig(t)
	g.who = "operator"
	ctx := context.Background()
	op := &fakeOperator{}
	d := NewDecider(g.s, op)
	st, _ := g.s.StartEnrolment(ctx, "acme-shop", "scout")
	card, err := d.ApproveEnrol(ctx, "operator", st.UserCode)
	if err != nil || card.ApprovalID == "" {
		t.Fatalf("%v %+v", err, card)
	}
	p := op.calls[0]
	if op.ops[0] != OpIssue || p["enrolment"] == "" || p["owner"] != operatorOwner || p["holder"] != "scout" || p["holder_kind"] != "agent" ||
		p["ttl_hours"] != float64(BootstrapHours) || p["rate_per_hour"] != float64(BootstrapRate) || len(p["ops"].([]any)) != 0 {
		t.Errorf("params of the enrolment card: %v", p)
	}
}

func TestADecisionOfAnotherPersonOrAWidenedFormMakesNoCard(t *testing.T) {
	g := newRig(t)
	g.who = "operator"
	ctx := context.Background()
	op := &fakeOperator{}
	d := NewDecider(g.s, op)
	key, _ := g.boot(operatorOwner, "scout")
	rq, _, _ := g.s.CreateRequest(ctx, nreq(key, nil))
	if _, err := d.Grant(ctx, "gilliano", rq.ID, nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("another person granted: %v", err)
	}
	if _, err := d.Deny(ctx, "gilliano", rq.ID, "no"); !errors.Is(err, ErrNotFound) {
		t.Errorf("another person denied: %v", err)
	}
	for name, n := range map[string]*Narrowing{
		"op added": {Ops: []string{"pr.view", "deploy"}}, "unit added": {Units: []string{"x/y"}}, "longer": {TTLHours: 25}, "faster": {Rate: 301},
		"nothing kept": {Ops: []string{}}, "an op twice is fine but empty is not": {Ops: []string{}},
	} {
		if _, err := d.Grant(ctx, "operator", rq.ID, n); err == nil {
			t.Errorf("%s: a card was made", name)
		}
	}
	if len(op.calls) != 0 {
		t.Fatalf("%d cards for refused forms", len(op.calls))
	}
	card, err := d.Grant(ctx, "operator", rq.ID, &Narrowing{Ops: []string{"pr.view"}, TTLHours: 12})
	if err != nil || card.OpID == "" {
		t.Fatal(err)
	}
	// While that card waits no second one is made; once it ended unsigned, the owner may try again.
	op.states = map[string]string{card.OpID: "pending_approval"}
	if _, err := d.Grant(ctx, "operator", rq.ID, nil); err == nil || !strings.Contains(err.Error(), "already waiting") {
		t.Errorf("a second card: %v", err)
	}
	op.states = map[string]string{card.OpID: "denied"}
	if _, err := d.Grant(ctx, "operator", rq.ID, nil); err != nil {
		t.Errorf("after the card was denied: %v", err)
	}
}

// ---- extend ----------------------------------------------------------------------------------------

func (g *rig) selfKey(mod func(*Grant)) ops.KeyInfo {
	g.t.Helper()
	ctx := context.Background()
	gr := g.grant(func(x *Grant) {
		x.Kind, x.Owner, x.Holder, x.Claimant = GrantSelf, operatorOwner, "scout", agentClaimant(operatorOwner, "scout")
		if mod != nil {
			mod(x)
		}
	})
	k, err := g.s.Issue(ctx, gr)
	if err != nil {
		g.t.Fatal(err)
	}
	_, info, err := g.s.Claim(ctx, k.ID, agentClaimant(operatorOwner, "scout"))
	if err != nil {
		g.t.Fatal(err)
	}
	return info
}

func (g *rig) extend(keyID string, hours int) (ops.KeyInfo, error) {
	ap, rq := g.approved()
	return g.s.Extend(context.Background(), ExtendGrant{KeyID: keyID, Hours: hours, Owner: operatorOwner, ApprovalID: ap, RequestID: rq, GrantedBy: "operator"})
}

func TestExtendingMovesOnlyTheExpiryAndStaysInsideTheCap(t *testing.T) {
	g := newRig(t)
	g.who = "operator"
	ctx := context.Background()
	k := g.selfKey(nil) // 24 hours, routine ops
	before, _ := g.s.Get(ctx, k.ID)
	got, err := g.extend(k.ID, 24)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := time.Parse(time.RFC3339, before.ExpiresAt)
	a, _ := time.Parse(time.RFC3339, got.ExpiresAt)
	if a.Sub(b) != 24*time.Hour {
		t.Errorf("moved by %s", a.Sub(b))
	}
	if strings.Join(got.Ops, ",") != strings.Join(before.Ops, ",") || strings.Join(got.Units, ",") != strings.Join(before.Units, ",") || got.RatePerHour != before.RatePerHour || got.Sensitive != before.Sensitive || got.IssuedAt != before.IssuedAt {
		t.Errorf("scope changed: %+v -> %+v", before, got)
	}
	// 30 days from the day it was made, in all: 24h + 24h so far, 28 more days fit, 29 do not.
	if _, err := g.extend(k.ID, 24*29); err == nil || !strings.Contains(err.Error(), "at most 30 days from the day it was made") {
		t.Errorf("past the cap: %v", err)
	}
	if _, err := g.extend(k.ID, 24*28); err != nil {
		t.Errorf("up to the cap: %v", err)
	}
	if _, err := g.extend(k.ID, 1); err == nil {
		t.Error("an hour past the cap")
	}
	// The database refuses the same, whatever the code says.
	if _, err := g.db.SQL().Exec(`UPDATE keys SET expires_at = issued_at + 31 * 86400 WHERE id = ?`, k.ID); err == nil {
		t.Error("the database let a key live past 30 days")
	}
	for _, h := range []int{0, -1, 721} {
		if _, err := g.extend(k.ID, h); err == nil {
			t.Errorf("%d hours accepted", h)
		}
	}
}

func TestASensitiveKeyIsExtendedOnlyToSevenDaysInAll(t *testing.T) {
	g := newRig(t)
	g.who = "operator"
	k := g.selfKey(func(x *Grant) { x.Ops, x.Units, x.Sensitive, x.TTLHours = []string{"deploy"}, nil, true, 24 })
	if _, err := g.extend(k.ID, 24*6+1); err == nil || !strings.Contains(err.Error(), "at most 7 days") {
		t.Errorf("past 7 days: %v", err)
	}
	if _, err := g.extend(k.ID, 24*6); err != nil {
		t.Errorf("to 7 days: %v", err)
	}
}

func TestOnlyALiveSelfGrantedAgentKeyIsExtendedAndOncePerOp(t *testing.T) {
	g := newRig(t)
	g.who = "operator"
	ctx := context.Background()
	// A request-only key, a script owner's key and another owner's key are not the owner's to extend here.
	boot, _ := g.boot(operatorOwner, "helper")
	if _, err := g.extend(boot, 24); err == nil || !strings.Contains(err.Error(), "granted their own agent") {
		t.Errorf("a request-only key: %v", err)
	}
	_, scripted := g.issueAndClaim(nil)
	if _, err := g.extend(scripted.ID, 24); err == nil {
		t.Error("a script owner's key was extended")
	}
	k := g.selfKey(nil)
	ap, rq := g.approved()
	other := ExtendGrant{KeyID: k.ID, Hours: 24, Owner: "person:evil", ApprovalID: ap, RequestID: rq, GrantedBy: "evil"}
	if _, err := g.s.Extend(ctx, other); err == nil || !strings.Contains(err.Error(), "another owner") {
		t.Errorf("another owner extended: %v", err)
	}
	// One op, one extension: the same op run twice adds the hours once.
	grant := ExtendGrant{KeyID: k.ID, Hours: 24, Owner: operatorOwner, ApprovalID: ap, RequestID: rq, GrantedBy: "operator"}
	first, err := g.s.Extend(ctx, grant)
	if err != nil {
		t.Fatal(err)
	}
	second, err := g.s.Extend(ctx, grant)
	if err != nil || second.ExpiresAt != first.ExpiresAt {
		t.Errorf("the retried op: %v %s vs %s", err, second.ExpiresAt, first.ExpiresAt)
	}
	// Revoked and expired keys are not extended.
	if _, err := g.s.Revoke(ctx, k.ID, "key:"+k.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := g.extend(k.ID, 24); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Errorf("a revoked key: %v", err)
	}
	k2 := g.selfKey(func(x *Grant) { x.Holder = "other" })
	g.now = g.now.Add(48 * time.Hour)
	ap2, rq2 := g.approved()
	if _, err := g.s.Extend(ctx, ExtendGrant{KeyID: k2.ID, Hours: 24, Owner: operatorOwner, ApprovalID: ap2, RequestID: rq2, GrantedBy: "operator"}); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("an expired key: %v", err)
	}
}

func TestAnExtensionAnswersItsRequestAndNeverGrantsMoreThanWasAsked(t *testing.T) {
	g := newRig(t)
	g.who = "operator"
	ctx := context.Background()
	k := g.selfKey(nil)
	ext := NewAdapterForTest(t, g)
	rq, _, err := g.s.CreateRequest(ctx, nreq(k.ID, func(n *NewRequest) {
		n.Kind, n.ExtendsKey, n.Ops, n.Units, n.TTLHours, n.Rate, n.Holder = reqExtend, k.ID, k.Ops, k.Units, 12, k.RatePerHour, "scout"
	}))
	if err != nil {
		t.Fatal(err)
	}
	p := func(hours int) *ops.Request {
		_, rid := g.approved()
		return &ops.Request{ID: rid, Op: OpExtend, Project: "acme-shop", Caller: &ops.Caller{Kind: ops.KindOrchestrator, OrchID: ops.OperatorID},
			Params: map[string]any{"key": k.ID, "extend_hours": float64(hours), "owner": operatorOwner, "holder": "scout", "request": rq.ID}}
	}
	if _, err := ext.Check(ctx, p(13)); err == nil || !strings.Contains(err.Error(), "more than the 12 asked for") {
		t.Errorf("more than asked: %v", err)
	}
	// A key, a script's orchestrator and a run cannot extend a key.
	for _, c := range []*ops.Caller{agentCaller(k.ID, operatorOwner, "scout"), {Kind: ops.KindOrchestrator, OrchID: "main"}, {Kind: ops.KindRun, RunID: "r"}} {
		req := p(12)
		req.Caller = c
		if _, err := ext.Check(ctx, req); err == nil || !strings.Contains(err.Error(), "extended at the console") {
			t.Errorf("%s extended a key: %v", c.Kind, err)
		}
	}
	res, err := ext.Check(ctx, p(6))
	if err != nil || !strings.Contains(res.Evidence[0].Text, "It will end:") {
		t.Fatalf("%v %+v", err, res)
	}
	req := p(6)
	out, err := ext.Execute(ctx, req)
	if err != nil || out.Failed {
		t.Fatalf("%v %+v", err, out)
	}
	got, _ := g.s.GetRequest(ctx, rq.ID)
	if got.State != "granted" || got.Granted == nil || got.Granted.TTLHours != 6 || got.Removed == nil || got.Removed.TTLHours != 6 {
		t.Errorf("the extension request: %+v", got)
	}
}

// NewAdapterForTest builds the keys.extend adapter on the rig's fake approvals.
func NewAdapterForTest(t *testing.T, g *rig) *ExtendAdapter {
	t.Helper()
	a, err := NewExtendAdapter(g.s, func(_ context.Context, requestID string) (string, string, error) {
		var id string
		err := g.db.SQL().QueryRow(`SELECT approval_id FROM approvals WHERE request_id = ?`, requestID).Scan(&id)
		return id, "operator", err
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}
