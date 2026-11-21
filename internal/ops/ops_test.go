package ops

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// ---- acceptance: OP_NOT_IN_TOKEN, OP_DISABLED -----------------------------

func TestOpNotInToken(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"health", "mail.send", "pr.merge"}})
	// mail.send is enabled in policy but not in the run's token.
	st, body, _ := g.call("POST", "/v0/ops", runTok, map[string]any{
		"op": "mail.send", "target": map[string]any{"adapter": "gmail", "ref": "list-1"}, "params": map[string]any{"subject": "x"},
	})
	if st != http.StatusForbidden {
		t.Fatalf("status %d: %v", st, body)
	}
	d := mustDenial(t, body, "OP_NOT_IN_TOKEN")
	if d["run_id"] != "r-7f3a" || d["profile"] != "code" || d["project"] != "acme-shop" {
		t.Errorf("run denial identity wrong: %v", d)
	}
	if _, has := d["orchestrator_id"]; has {
		t.Error("a run's denial must not carry orchestrator_id")
	}
	if n := opCount(t, g.db, `state = 'denied' AND cause_code = 'OP_NOT_IN_TOKEN'`); n != 1 {
		t.Errorf("denied op rows = %d, want 1", n)
	}
	if len(g.led.rows(t, g.db, "op.request")) != 1 || len(g.led.rows(t, g.db, "denial")) != 1 {
		t.Errorf("want one op.request and one denial event, ledger: %v", g.led.rows(t, g.db, ""))
	}

	// pr.merge IS in the token, but the profile "code" ceiling does not allow it.
	st, body, _ = g.call("POST", "/v0/ops", runTok, prMerge(sha1))
	if st != http.StatusForbidden {
		t.Fatalf("status %d", st)
	}
	mustDenial(t, body, "OP_NOT_IN_TOKEN")

	// Orchestrator: an op outside its scope, and a project outside its scope.
	st, body, _ = g.call("POST", "/v0/ops", orchTok, map[string]any{
		"op": "mail.send", "project": "acme-shop", "target": map[string]any{"adapter": "gmail", "ref": "list-1"}, "params": map[string]any{},
	})
	if st != http.StatusForbidden {
		t.Fatalf("orch op status %d", st)
	}
	d = mustDenial(t, body, "OP_NOT_IN_TOKEN")
	if d["orchestrator_id"] != "main" {
		t.Errorf("orchestrator_id missing: %v", d)
	}
	for _, k := range []string{"run_id", "profile"} {
		if _, has := d[k]; has {
			t.Errorf("orchestrator denial carries %s", k)
		}
	}
	other := mergeOrch(sha1)
	other["project"] = "other-shop"
	st, body, _ = g.call("POST", "/v0/ops", orchTok, other)
	if st != http.StatusForbidden {
		t.Fatalf("orch project status %d: %v", st, body)
	}
	mustDenial(t, body, "OP_NOT_IN_TOKEN")
}

func TestOpDisabledByDefault(t *testing.T) {
	g := newRig(t, rigOpts{}) // nothing enabled: the shipped default
	st, body, _ := g.call("POST", "/v0/ops", runTok, health())
	if st != http.StatusForbidden {
		t.Fatalf("status %d: %v", st, body)
	}
	d := mustDenial(t, body, "OP_DISABLED")
	if d["policy_version"] == nil || !strings.HasPrefix(d["policy_version"].(string), "baseline-") {
		t.Errorf("policy_version missing on a policy denial: %v", d["policy_version"])
	}
	if g.ad.checks != 0 || len(g.ad.executions()) != 0 {
		t.Error("a disabled op must never reach its adapter")
	}
	// An orchestrator asking for a disabled op is OP_DISABLED too.
	orchHealth := health()
	orchHealth["project"] = "acme-shop"
	st, body, _ = g.call("POST", "/v0/ops", orchTok, orchHealth)
	if st != http.StatusForbidden {
		t.Fatalf("status %d", st)
	}
	mustDenial(t, body, "OP_DISABLED")
}

// ---- policy_version on every op.result -------------------------------------

func TestPolicyVersionOnEveryResult(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"health", "pr.open"}})
	_, st, _ := g.call("GET", "/v0/status", runTok, nil)
	want := str(st, "policy_version")
	if want == "" {
		t.Fatal("status has no policy_version")
	}

	code, body, _ := g.call("POST", "/v0/ops", runTok, health())
	if code != 200 || body["state"] != "succeeded" {
		t.Fatalf("health: %d %v", code, body)
	}
	if body["policy_version"] != want || body["outcome"] != "succeeded" || str(body, "execution_id") == "" || str(body, "external_ref") == "" {
		t.Errorf("op view incomplete: %v", body)
	}
	// A refused result (precondition) also carries it.
	g.ad.check = func(r *Request) (CheckResult, error) {
		if r.Op == "pr.open" {
			return CheckResult{}, nil
		}
		return CheckResult{}, nil
	}
	g.ad.execute = func(context.Context, *Request) (Outcome, error) { return Outcome{Failed: true}, nil }
	code, body, _ = g.call("POST", "/v0/ops", runTok, map[string]any{
		"op": "pr.open", "target": map[string]any{"adapter": "github", "ref": "acme/shop"},
		"params": map[string]any{"title": "t", "head": "agent/r-7f3a", "base": "main"},
	})
	if code != 200 || body["state"] != "failed" {
		t.Fatalf("pr.open: %d %v", code, body)
	}
	results := g.led.rows(t, g.db, "op.result")
	if len(results) != 2 {
		t.Fatalf("want 2 op.result events, got %d", len(results))
	}
	for _, r := range results {
		attrs := r["attrs"].(map[string]any)
		if attrs["factory.policy_version"] != want {
			t.Errorf("op.result without the policy version: %v", attrs)
		}
	}
}

// ---- thrash ---------------------------------------------------------------

func TestRepeatedDenialsIncrementThrash(t *testing.T) {
	g := newRig(t, rigOpts{}) // health disabled: same denial every time
	var counts []float64
	var flags []bool
	for range 4 {
		st, body, _ := g.call("POST", "/v0/ops", runTok, health())
		if st != http.StatusForbidden {
			t.Fatalf("status %d", st)
		}
		d := mustDenial(t, body, "OP_DISABLED")
		th := d["thrash"].(map[string]any)
		counts = append(counts, th["count"].(float64))
		flags = append(flags, th["flagged"].(bool))
		if th["window_seconds"].(float64) != 300 {
			t.Errorf("window = %v", th["window_seconds"])
		}
		g.advance(time.Second)
	}
	for i, c := range counts {
		if c != float64(i+1) {
			t.Errorf("counts = %v, want 1,2,3,4", counts)
			break
		}
	}
	if flags[0] || flags[1] || !flags[2] || !flags[3] {
		t.Errorf("flagged = %v, want false,false,true,true (threshold 3)", flags)
	}
	// A different attempt starts its own count.
	_, body, _ := g.call("POST", "/v0/ops", runTok, map[string]any{
		"op": "logs", "target": map[string]any{"adapter": "pilot", "ref": "web"}, "params": map[string]any{"source": "web"},
	})
	if body["thrash"].(map[string]any)["count"].(float64) != 1 {
		t.Errorf("a different (surface, action) must start at 1: %v", body["thrash"])
	}
	// The window forgets old denials.
	g.advance(10 * time.Minute)
	_, body, _ = g.call("POST", "/v0/ops", runTok, health())
	if body["thrash"].(map[string]any)["count"].(float64) != 1 {
		t.Errorf("count after the window = %v", body["thrash"])
	}
	// Another caller does not share the counter.
	_, body, _ = g.call("POST", "/v0/ops", orchTok, map[string]any{
		"op": "health", "project": "acme-shop", "target": map[string]any{"adapter": "pilot", "ref": "readiness"}, "params": map[string]any{},
	})
	if body["thrash"].(map[string]any)["count"].(float64) != 1 {
		t.Errorf("orchestrator shares the run's counter: %v", body["thrash"])
	}
	// The ledger denial events carry the count.
	for _, r := range g.led.rows(t, g.db, "denial") {
		if r["attrs"].(map[string]any)["factory.thrash.count"] == nil {
			t.Error("denial event without thrash count")
		}
	}
}

// ---- rate limits ----------------------------------------------------------

func TestPerCallerRateLimit(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"health"}})
	rate := g.engine.For("acme-shop").Rate("health")
	// Distinct params so the idempotency rule does not merge the calls.
	call := func(i int) (int, map[string]any, http.Header) {
		return g.call("POST", "/v0/ops", runTok, map[string]any{
			"op": "health", "target": map[string]any{"adapter": "pilot", "ref": "readiness"}, "params": map[string]any{"n": float64(i)},
		})
	}
	for i := range rate {
		if st, body, _ := call(i); st != 200 {
			t.Fatalf("call %d: %d %v", i, st, body)
		}
		g.advance(time.Second)
	}
	st, body, hdr := call(99)
	if st != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429: %v", st, body)
	}
	mustDenial(t, body, "OP_POLICY_REFUSED")
	if hdr.Get("Retry-After") == "" {
		t.Error("no Retry-After")
	}
	if !strings.Contains(str(body, "why"), "rate limit") {
		t.Errorf("why = %v", body["why"])
	}
	g.advance(61 * time.Second)
	if st, body, _ := call(100); st != 200 {
		t.Fatalf("after the window: %d %v", st, body)
	}
}

// ---- auth middleware -------------------------------------------------------

func TestAuthRouting(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"health"}})
	// No token, garbage token: unidentified, not a denial, nothing ledgered.
	before := ledgerCount(t, g.db)
	for name, tok := range map[string]string{"none": "", "garbage": "garbage", "unknown orch": OrchPrefix + "nope"} {
		st, body, _ := g.call("GET", "/v0/status", tok, nil)
		if st != 401 || body["type"] != "auth_error" || body["cause_code"] != "TOKEN_INVALID" {
			t.Errorf("%s: %d %v", name, st, body)
		}
	}
	if ledgerCount(t, g.db) != before {
		t.Error("an unidentified caller must not write to any run's ledger")
	}

	// Two Authorization headers, a comma-joined value, a token in the query.
	req := func(mut func(*http.Request)) (int, string) {
		r, _ := http.NewRequest("GET", g.http.URL+"/v0/status", nil)
		mut(r)
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode, resp.Header.Get("Content-Type")
	}
	for name, mut := range map[string]func(*http.Request){
		"two headers": func(r *http.Request) {
			r.Header.Add("Authorization", "Bearer "+runTok)
			r.Header.Add("Authorization", "Bearer "+orchTok)
		},
		"comma joined": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+runTok+", Bearer "+orchTok) },
		"space joined": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+runTok+" "+orchTok) },
		"query token": func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+runTok)
			r.URL.RawQuery = "access_token=" + orchTok
		},
		"basic outside git": func(r *http.Request) { r.SetBasicAuth("x", runTok) },
	} {
		if st, _ := req(mut); st != 401 {
			t.Errorf("%s: status %d, want 401", name, st)
		}
	}

	// Prefix routing: each verifier sees only its own kind.
	var runSeen, orchSeen []string
	g.srv.cfg.Auth.Run = verifierFunc{run: func(b string) (*Caller, error) {
		runSeen = append(runSeen, b)
		return g.ver.VerifyRun(context.Background(), b)
	}}
	g.srv.cfg.Auth.Orch = verifierFunc{orch: func(b string) (*Caller, error) {
		orchSeen = append(orchSeen, b)
		return g.ver.VerifyOrch(context.Background(), b)
	}}
	g.call("GET", "/v0/status", runTok, nil)
	g.call("GET", "/v0/status", orchTok, nil)
	if len(runSeen) != 1 || runSeen[0] != runTok || len(orchSeen) != 1 || orchSeen[0] != orchTok {
		t.Errorf("routing wrong: run verifier saw %v, orchestrator verifier saw %v", runSeen, orchSeen)
	}
	st, body, _ := g.call("GET", "/v0/status", orchTok, nil)
	if st != 200 || body["requester"].(map[string]any)["kind"] != "orchestrator" {
		t.Errorf("orchestrator status: %d %v", st, body)
	}
}

// approver_credentials is for the orchestrator only (`chap doctor`), and a
// count failure is a retryable 503, never a wrong number.
func TestStatusApproverCredentials(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"health"}})
	if _, body, _ := g.call("GET", "/v0/status", orchTok, nil); body["approver_credentials"] != nil {
		t.Errorf("unconfigured: %v", body)
	}
	n, fail := 2, error(nil)
	g.srv.cfg.ApproverCredentials = func(context.Context) (int, error) { return n, fail }
	if st, body, _ := g.call("GET", "/v0/status", orchTok, nil); st != 200 || body["approver_credentials"] != float64(2) {
		t.Errorf("orchestrator: %d %v", st, body)
	}
	if st, body, _ := g.call("GET", "/v0/status", runTok, nil); st != 200 || body["approver_credentials"] != nil {
		t.Errorf("run token must not see the count: %d %v", st, body)
	}
	fail = errors.New("db closed")
	if st, _, _ := g.call("GET", "/v0/status", orchTok, nil); st != 503 {
		t.Errorf("count failure: status %d, want 503", st)
	}
}

type verifierFunc struct {
	run  func(string) (*Caller, error)
	orch func(string) (*Caller, error)
}

func (v verifierFunc) VerifyRun(_ context.Context, b string) (*Caller, error)  { return v.run(b) }
func (v verifierFunc) VerifyOrch(_ context.Context, b string) (*Caller, error) { return v.orch(b) }

func TestForeignHostIsRefused(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"health"}})
	req, _ := http.NewRequest("GET", g.http.URL+"/v0/status", nil)
	req.Host = "evil.example"
	req.Header.Set("Authorization", "Bearer "+runTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("status %d, want 421 (DNS rebinding defence)", resp.StatusCode)
	}
}

func TestRecognisedButRefusedTokenGetsFullDenial(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"health"}})
	g.ver.errs[orchTok] = &VerifyError{Code: CodeTokenRevoked, Detail: "the orchestrator token was revoked", OrchID: "main", Project: "acme-shop"}
	st, body, _ := g.call("GET", "/v0/status", orchTok, nil)
	if st != 401 {
		t.Fatalf("status %d", st)
	}
	d := mustDenial(t, body, "TOKEN_REVOKED")
	if d["orchestrator_id"] != "main" || d["surface"] != "token" {
		t.Errorf("denial: %v", d)
	}
	evs := g.led.rows(t, g.db, "denial")
	if len(evs) != 1 || evs[0]["run_id"] != "" || evs[0]["orch"] != "main" {
		t.Errorf("denial event: %v", evs)
	}

	g.ver.errs[runTok] = &VerifyError{Code: CodeTokenExpired, Detail: "the run token expired",
		Run: &Caller{RunID: "r-7f3a", Project: "acme-shop", Profile: "code"}}
	st, body, _ = g.call("GET", "/v0/status", runTok, nil)
	if st != 401 {
		t.Fatalf("status %d", st)
	}
	d = mustDenial(t, body, "TOKEN_EXPIRED")
	if d["run_id"] != "r-7f3a" || d["profile"] != "code" {
		t.Errorf("denial: %v", d)
	}
}

// ---- orchestrator requests ledgered without run_id -------------------------

func TestOrchestratorEventsCarryNoRunID(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"health", "pr.merge"}})
	st, body, _ := g.call("POST", "/v0/ops", orchTok, mergeOrch(sha1))
	if st != 200 || body["state"] != "succeeded" {
		t.Fatalf("%d %v", st, body)
	}
	req := body["requester"].(map[string]any)
	if req["kind"] != "orchestrator" || req["orchestrator_id"] != "main" || req["run_id"] != nil || req["profile"] != nil {
		t.Errorf("requester view: %v", req)
	}
	for _, r := range g.led.rows(t, g.db, "") {
		if r["run_id"] != "" {
			t.Errorf("orchestrator event %v has a run_id", r["name"])
		}
		if r["orch"] != "main" {
			t.Errorf("orchestrator event %v lacks orchestrator_id", r["name"])
		}
	}
}

// ---- request validation ----------------------------------------------------

func TestParamsInvalid(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"health"}})
	cases := map[string]any{
		"not json":         "nope",
		"array":            "[]",
		"unknown member":   map[string]any{"op": "health", "target": map[string]any{"adapter": "pilot", "ref": "r"}, "params": map[string]any{}, "run_id": "r-other"},
		"duplicate key":    `{"op":"health","op":"health","target":{"adapter":"pilot","ref":"r"},"params":{}}`,
		"big number":       `{"op":"health","target":{"adapter":"pilot","ref":"r"},"params":{"n":9007199254740993}}`,
		"project differs":  map[string]any{"op": "health", "project": "other-shop", "target": map[string]any{"adapter": "pilot", "ref": "r"}, "params": map[string]any{}},
		"wrong op_hash":    map[string]any{"op": "health", "op_hash": "sha256:" + strings.Repeat("0", 64), "target": map[string]any{"adapter": "pilot", "ref": "r"}, "params": map[string]any{}},
		"unknown op kind":  map[string]any{"op": "nuke.all", "target": map[string]any{"adapter": "pilot", "ref": "r"}, "params": map[string]any{}},
		"no params":        map[string]any{"op": "health", "target": map[string]any{"adapter": "pilot", "ref": "r"}},
		"bad target":       map[string]any{"op": "health", "target": map[string]any{"adapter": "Pilot", "ref": "r"}, "params": map[string]any{}},
		"kind on ops":      map[string]any{"op": "health", "kind": "op", "target": map[string]any{"adapter": "pilot", "ref": "r"}, "params": map[string]any{}},
		"bad approval id":  map[string]any{"op": "health", "approval_id": "x", "target": map[string]any{"adapter": "pilot", "ref": "r"}, "params": map[string]any{}},
		"reason too long":  map[string]any{"op": "health", "reason": strings.Repeat("x", 501), "target": map[string]any{"adapter": "pilot", "ref": "r"}, "params": map[string]any{}},
		"bad traceparent":  map[string]any{"op": "health", "traceparent": "00-zz", "target": map[string]any{"adapter": "pilot", "ref": "r"}, "params": map[string]any{}},
		"dry_run not bool": map[string]any{"op": "health", "dry_run": "yes", "target": map[string]any{"adapter": "pilot", "ref": "r"}, "params": map[string]any{}},
	}
	for name, body := range cases {
		st, out, _ := g.call("POST", "/v0/ops", runTok, body)
		if st != 400 {
			t.Errorf("%s: status %d: %v", name, st, out)
			continue
		}
		mustDenial(t, out, "OP_PARAMS_INVALID")
	}
	if len(g.ad.executions()) != 0 {
		t.Error("an invalid request reached an adapter")
	}
	// The right hash is accepted (spec reference vector).
	good := map[string]any{
		"op": "health", "op_hash": "", "target": map[string]any{"adapter": "pilot", "ref": "readiness"}, "params": map[string]any{},
	}
	delete(good, "op_hash")
	if st, out, _ := g.call("POST", "/v0/ops", runTok, good); st != 200 {
		t.Errorf("good request: %d %v", st, out)
	}
}

func TestOpHashMatchesSpec(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"pr.merge"}})
	sub := mergeOrch(sha1)
	sub["project"] = "acme-shop"
	sub["op_hash"] = "sha256:e2b37a3e74132598e3b7d86068860fb0ff3e6e627fcd732ae7252a3732833415"
	st, body, _ := g.call("POST", "/v0/ops", orchTok, sub)
	if st != 200 {
		t.Fatalf("the spec's reference hash was refused: %d %v", st, body)
	}
	if body["op_hash"] != sub["op_hash"] {
		t.Errorf("op_hash = %v", body["op_hash"])
	}
}

// ---- state machine ---------------------------------------------------------

func TestStateMachineRefusesIllegalTransitions(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"health"}})
	_, body, _ := g.call("POST", "/v0/ops", runTok, health())
	id := str(body, "id")
	for _, to := range []string{"requested", "executing", "allowed", "denied", "pending_approval"} {
		if _, err := g.db.SQL().Exec(`UPDATE ops SET state = ? WHERE id = ?`, to, id); err == nil {
			t.Errorf("succeeded -> %s must be refused by the trigger", to)
		}
	}
	if _, err := g.db.SQL().Exec(`UPDATE ops SET op_hash = 'sha256:x' WHERE id = ?`, id); err == nil {
		t.Error("op identity must be immutable")
	}
	if _, err := g.db.SQL().Exec(`DELETE FROM ops WHERE id = ?`, id); err == nil {
		t.Error("ops must not be deletable")
	}
}

func TestIdempotentSameOpHash(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"health"}})
	release := make(chan struct{})
	g.ad.execute = func(ctx context.Context, r *Request) (Outcome, error) {
		<-release
		return Outcome{ExternalRef: "ref-1"}, nil
	}
	type res struct {
		st   int
		body map[string]any
	}
	ch := make(chan res, 2)
	for range 2 {
		go func() {
			st, b, _ := g.call("POST", "/v0/ops?wait=1", runTok, health())
			ch <- res{st, b}
		}()
		time.Sleep(150 * time.Millisecond)
	}
	a, b := <-ch, <-ch
	if a.st != 202 || b.st != 202 || a.body["id"] != b.body["id"] {
		t.Fatalf("same op_hash must return the same op: %v %v", a, b)
	}
	close(release)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && opCount(t, g.db, `state = 'executing'`) > 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if n := len(g.ad.executions()); n != 1 {
		t.Errorf("adapter executed %d times, want exactly 1", n)
	}
	if n := opCount(t, g.db, `1=1`); n != 1 {
		t.Errorf("%d op rows, want 1", n)
	}
}

// TestConcurrentIdenticalRequestsRunOnce: identical requests that overlap in
// time are one op and one execution. The adapter is held until every request
// has been answered, so the op is live for all of them whatever the machine's
// load: an op that has finished is no longer live, and a request that arrives
// after that is a new op by design (TestIdenticalRequestAfterCompletionIsNew).
func TestConcurrentIdenticalRequestsRunOnce(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"health"}})
	release := make(chan struct{})
	g.ad.execute = func(ctx context.Context, r *Request) (Outcome, error) {
		select {
		case <-release:
		case <-time.After(20 * time.Second):
		}
		return Outcome{ExternalRef: "r"}, nil
	}
	var wg sync.WaitGroup
	ids := make(chan string, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// 202: the op is still executing when the wait ends.
			_, body, _ := g.call("POST", "/v0/ops?wait=1", runTok, health())
			ids <- str(body, "id")
		}()
	}
	wg.Wait()
	close(release)
	close(ids)
	seen := map[string]bool{}
	for id := range ids {
		seen[id] = true
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && opCount(t, g.db, `state = 'executing'`) > 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if len(seen) != 1 || opCount(t, g.db, `1=1`) != 1 || len(g.ad.executions()) != 1 {
		t.Errorf("8 overlapping identical requests: %d distinct ops, %d rows, %d executions; want 1 each", len(seen), opCount(t, g.db, `1=1`), len(g.ad.executions()))
	}
}

// An identical request after the first op has finished is a new op: only live
// ops are merged. (Single-use of an approval is a different guarantee, owned
// by the approvals engine.)
func TestIdenticalRequestAfterCompletionIsNew(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"health"}})
	_, a, _ := g.call("POST", "/v0/ops", runTok, health())
	g.advance(time.Second)
	_, b, _ := g.call("POST", "/v0/ops", runTok, health())
	if a["state"] != "succeeded" || b["state"] != "succeeded" || a["id"] == b["id"] || len(g.ad.executions()) != 2 {
		t.Errorf("a=%v b=%v executions=%d", a["id"], b["id"], len(g.ad.executions()))
	}
}

// ---- execution outcomes ----------------------------------------------------

func TestAdapterErrorLeavesOpUnconfirmedNotFailed(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"health"}})
	g.ad.execute = func(context.Context, *Request) (Outcome, error) {
		return Outcome{ExternalRef: "x"}, errors.New("connection reset")
	}
	st, body, _ := g.call("POST", "/v0/ops", runTok, health())
	if st != 202 && st != 200 {
		t.Fatalf("status %d", st)
	}
	if body["state"] != "unconfirmed" || body["outcome"] != "unconfirmed" {
		t.Fatalf("state = %v", body["state"])
	}
	if _, has := body["external_ref"]; has {
		t.Error("an unconfirmed op has no external_ref")
	}
	exec := str(body, "execution_id")
	if exec == "" {
		t.Fatal("no execution_id")
	}
	// Reconciliation reuses the id and writes one final result.
	if err := g.svc.Reconcile(context.Background(), str(body, "id"), Outcome{ExternalRef: "https://example.invalid/1"}); err != nil {
		t.Fatal(err)
	}
	_, body, _ = g.call("GET", "/v0/ops/"+str(body, "id"), runTok, nil)
	if body["state"] != "succeeded" || body["execution_id"] != exec {
		t.Errorf("after reconcile: %v", body)
	}
	if n := len(g.ad.executions()); n != 1 {
		t.Errorf("executions = %d, want 1 (never a second)", n)
	}
}

func TestAdapterPanicIsUnconfirmed(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"health"}})
	g.ad.execute = func(context.Context, *Request) (Outcome, error) { panic("boom") }
	_, body, _ := g.call("POST", "/v0/ops", runTok, health())
	if body["state"] != "unconfirmed" {
		t.Errorf("state = %v", body["state"])
	}
}

func TestPreconditionRefusalIsNotRequestable(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"pr.merge"}, approvals: &fakeApprovals{}})
	g.ad.check = func(*Request) (CheckResult, error) {
		return CheckResult{}, &Refusal{Code: "OP_POLICY_REFUSED", Why: "verify is not success on the exact head", CanRequest: false}
	}
	st, body, _ := g.call("POST", "/v0/ops", orchTok, mergeOrch(sha1))
	if st != 403 {
		t.Fatalf("status %d", st)
	}
	d := mustDenial(t, body, "OP_POLICY_REFUSED")
	if d["request"].(map[string]any)["possible"] != false {
		t.Errorf("red CI cannot be approved away: %v", d["request"])
	}
	// ... and the same through /v0/approvals: refused before a card exists.
	req := mergeOrch(sha1)
	req["kind"] = "op"
	req["reason"] = "please"
	st, body, _ = g.call("POST", "/v0/approvals", orchTok, req)
	if st != 403 {
		t.Fatalf("approval status %d", st)
	}
	mustDenial(t, body, "OP_POLICY_REFUSED")
}

// ---- dry run ---------------------------------------------------------------

func TestDryRunCreatesNoOp(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"pr.merge"}})
	req := mergeOrch(sha1)
	req["dry_run"] = true
	st, body, _ := g.call("POST", "/v0/ops", orchTok, req)
	if st != 200 || body["type"] != "dry_run" || body["outcome"] != "allow" || body["would_allow"] != true {
		t.Fatalf("%d %v", st, body)
	}
	if n := opCount(t, g.db, `1=1`); n != 0 || len(g.ad.executions()) != 0 {
		t.Errorf("a dry run created %d ops and ran %d executions", n, len(g.ad.executions()))
	}
	g.ad.check = func(*Request) (CheckResult, error) {
		return CheckResult{Checks: []Check{{Name: "verify", Passed: false}}}, &Refusal{Code: "OP_POLICY_REFUSED", Why: "verify missing"}
	}
	st, body, _ = g.call("POST", "/v0/ops", orchTok, req)
	if st != 200 || body["outcome"] != "refuse" || body["would_allow"] != false {
		t.Fatalf("%d %v", st, body)
	}
	d := body["denial"].(map[string]any)
	mustDenial(t, d, "OP_POLICY_REFUSED")
	if n := opCount(t, g.db, `1=1`); n != 0 {
		t.Errorf("a refused dry run created %d ops", n)
	}
	if len(g.led.rows(t, g.db, "denial")) != 1 || len(g.led.rows(t, g.db, "op.request")) != 0 {
		t.Errorf("a dry run ledgers only its denial: %v", g.led.rows(t, g.db, ""))
	}
}

// ---- ownership, cancel, expiry --------------------------------------------

func TestOwnershipAndList(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"health", "pr.merge"}})
	_, a, _ := g.call("POST", "/v0/ops", runTok, health())
	_, b, _ := g.call("POST", "/v0/ops", orchTok, mergeOrch(sha1))
	if st, body, _ := g.call("GET", "/v0/ops/"+str(b, "id"), runTok, nil); st != 404 || body["type"] != "not_found" {
		t.Errorf("run read the orchestrator's op: %d %v", st, body)
	}
	if st, _, _ := g.call("GET", "/v0/ops/"+str(a, "id"), orchTok, nil); st != 404 {
		t.Errorf("orchestrator read a run's op: %d", st)
	}
	if st, _, _ := g.call("POST", "/v0/ops/"+str(b, "id")+"/cancel", runTok, nil); st != 404 {
		t.Errorf("run cancelled the orchestrator's op: %d", st)
	}
	st, list, _ := g.call("GET", "/v0/ops", runTok, nil)
	items := list["items"].([]any)
	if st != 200 || len(items) != 1 || items[0].(map[string]any)["id"] != a["id"] {
		t.Errorf("run list: %v", list)
	}
}

func TestExpirySweep(t *testing.T) {
	ap := &fakeApprovals{}
	g := newRig(t, rigOpts{enable: []string{"deploy"}, approvals: ap})
	st, body, _ := g.call("POST", "/v0/approvals", hiTok, approvalReq("deploy", sha1))
	if st != 202 || body["state"] != "pending_approval" {
		t.Fatalf("%d %v", st, body)
	}
	g.advance(16 * time.Minute) // deploy requests live 15 minutes
	n, err := g.svc.Sweep(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	_, body, _ = g.call("GET", "/v0/ops/"+str(body, "id"), hiTok, nil)
	if body["state"] != "expired" {
		t.Errorf("state = %v", body["state"])
	}
	if len(ap.cancelled) != 1 {
		t.Errorf("the pending card was not cancelled: %v", ap.cancelled)
	}
	res := g.led.rows(t, g.db, "op.result")
	if len(res) != 1 || res[0]["attrs"].(map[string]any)["factory.outcome"] != "refused" {
		t.Errorf("expiry result event: %v", res)
	}
}

// ---- catalog --------------------------------------------------------------

func TestCatalogNarrowsToToken(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"health", "logs", "pr.open", "pr.update", "branch.push", "deploy", "mail.send"}})
	_, body, _ := g.call("GET", "/v0/catalog", runTok, nil)
	got := opNames(body)
	// token ∩ profile ceiling (code) ∩ enabled: deploy is in the token but not
	// the code ceiling; mail.send is enabled but in neither.
	want := "branch.push,health,logs,pr.open,pr.update"
	if strings.Join(got, ",") != want {
		t.Errorf("run catalog = %v, want %s", got, want)
	}
	// all=true is orchestrator-only.
	if st, body, _ := g.call("GET", "/v0/catalog?all=true", runTok, nil); st != 403 {
		t.Errorf("run asked for all: %d %v", st, body)
	}
	st, body, _ := g.call("GET", "/v0/catalog?all=true&project=acme-shop", orchTok, nil)
	if st != 200 || len(opNames(body)) != 44 {
		t.Errorf("orchestrator all: %d %v", st, opNames(body))
	}
	var disabled int
	for _, e := range body["ops"].([]any) {
		if e.(map[string]any)["enabled"] == false {
			disabled++
		}
	}
	if disabled != 21-8-4+5+3+6+1 { // the seven enabled above, plus pr.merge, which the shipped baseline turns on, and the four pr read ops, which it turns on too; plus the five Linear issue ops and keys.issue, keys.request and keys.extend, which ship off; plus the six Sentry errors.* ops, which ship off; plus mail.status of the Resend connector, which ships off
		t.Errorf("disabled = %d", disabled)
	}
	// --profile docs: only that profile's enabled ops, and a small manual.
	st, body, _ = g.call("GET", "/v0/catalog?profile=docs", runTok, nil)
	if st != 200 || body["profile"] != "docs" {
		t.Fatalf("%d %v", st, body)
	}
	size := 0
	for _, e := range body["ops"].([]any) {
		m := e.(map[string]any)
		size += len(str(m, "op")) + len(str(m, "summary")) + len(str(m, "usage"))
	}
	if strings.Join(opNames(body), ",") != "branch.push,pr.open,pr.update" || size >= 1024 {
		t.Errorf("docs manual: %v (%d bytes)", opNames(body), size)
	}
	if st, body, _ := g.call("GET", "/v0/catalog?profile=wizard", runTok, nil); st != 400 {
		t.Errorf("unknown profile: %d %v", st, body)
	}
	// Classes are in the answer, critical ones marked.
	_, body, _ = g.call("GET", "/v0/catalog?all=true", orchTok, nil)
	classes := map[string]string{}
	for _, e := range body["ops"].([]any) {
		m := e.(map[string]any)
		classes[str(m, "op")] = str(m, "class")
	}
	for op, c := range map[string]string{"repo.settings": "critical", "secrets.write": "critical", "host.scripts.refresh": "critical", "deploy": "high", "pr.merge": "gated", "health": "routine"} {
		if classes[op] != c {
			t.Errorf("class of %s = %q, want %s", op, classes[op], c)
		}
	}
}

func opNames(body map[string]any) []string {
	var out []string
	if ops, ok := body["ops"].([]any); ok {
		for _, e := range ops {
			out = append(out, str(e.(map[string]any), "op"))
		}
	}
	return out
}

// ---- atomicity: failure injection and a real crash -------------------------

func TestLedgerFailureFailsClosed(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"health"}})
	g.led.fail = func(Event) error { return errors.New("disk full") }
	st, body, _ := g.call("POST", "/v0/ops", runTok, health())
	if st != http.StatusServiceUnavailable || body["type"] != "unavailable" {
		t.Fatalf("%d %v", st, body)
	}
	if strings.Contains(strings.ToLower(string(mustJSON(body))), "disk full") {
		t.Error("the cause leaked into the response")
	}
	if n := opCount(t, g.db, `1=1`); n != 0 {
		t.Errorf("%d op rows after a failed ledger append, want 0", n)
	}
	if ledgerCount(t, g.db) != 0 || len(g.ad.executions()) != 0 || g.ad.checks == 0 {
		t.Errorf("ledger=%d executions=%d: nothing may run when the ledger is down", ledgerCount(t, g.db), len(g.ad.executions()))
	}
	// A denial that cannot be ledgered is not sent as a denial either.
	g.led.fail = func(e Event) error { return errors.New("read-only") }
	st, body, _ = g.call("POST", "/v0/ops", hiTok, map[string]any{
		"op": "deploy", "target": map[string]any{"adapter": "wsl-host", "ref": "pilot"}, "params": map[string]any{"sha": sha1},
	})
	if st != 503 || body["type"] != "unavailable" {
		t.Errorf("denial without ledger: %d %v", st, body)
	}
}

func TestResultLedgerFailureLeavesExecuting(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"health"}})
	g.led.fail = func(e Event) error {
		if e.Name == "op.result" {
			return errors.New("ledger down")
		}
		return nil
	}
	_, body, _ := g.call("POST", "/v0/ops?wait=1", runTok, health())
	if body["state"] != "executing" {
		t.Fatalf("a result that could not be ledgered must not be committed: state %v", body["state"])
	}
	if len(g.led.rows(t, g.db, "op.result")) != 0 {
		t.Error("op.result row exists")
	}
	// Restart: the dispatched op becomes unconfirmed, with its event, together.
	g.led.fail = nil
	n, err := g.svc.Recover(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("recover: %d %v", n, err)
	}
	_, body, _ = g.call("GET", "/v0/ops/"+str(body, "id"), runTok, nil)
	if body["state"] != "unconfirmed" {
		t.Errorf("after recover: %v", body["state"])
	}
	res := g.led.rows(t, g.db, "op.result")
	if len(res) != 1 || res[0]["attrs"].(map[string]any)["factory.outcome"] != "unconfirmed" {
		t.Errorf("recover event: %v", res)
	}
}

// TestCrashIsAtomic kills a real process in the middle of a transition and
// checks the database afterwards: the op row and its ledger event are both
// there or both absent, never one without the other.
func TestCrashIsAtomic(t *testing.T) {
	if os.Getenv("CHAPD_CRASH_HELPER") != "" {
		t.Skip("helper process")
	}
	run := func(path, crashAt string, nth int) {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestCrashHelper$", "-test.v")
		cmd.Env = append(os.Environ(), "CHAPD_CRASH_HELPER=1", "CHAPD_CRASH_DB="+path, "CHAPD_CRASH_AT="+crashAt, "CHAPD_CRASH_NTH="+string(rune('0'+nth)))
		out, err := cmd.CombinedOutput()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 3 {
			t.Fatalf("helper did not crash with exit 3 at %s #%d: err=%v\n%s", crashAt, nth, err, out)
		}
	}
	count := func(db *store.DB, q string) int {
		var n int
		if err := db.SQL().QueryRow(q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	t.Run("crash while recording the request", func(t *testing.T) {
		path := tempDBPath(t)
		openRigDB(t, path).Close()
		run(path, "op.request", 1)
		db := openRigDB(t, path)
		defer db.Close()
		if n := count(db, `SELECT COUNT(*) FROM ops`); n != 0 {
			t.Errorf("%d op rows survived a crash before commit", n)
		}
		if n := count(db, `SELECT COUNT(*) FROM fake_ledger`); n != 0 {
			t.Errorf("%d ledger rows survived a crash before commit", n)
		}
	})

	t.Run("crash while recording the result", func(t *testing.T) {
		path := tempDBPath(t)
		openRigDB(t, path).Close()
		run(path, "op.result", 1)
		db := openRigDB(t, path)
		defer db.Close()
		// The first transaction committed: the op is allowed->executing and
		// has its op.request. The second never did: still executing, and no
		// op.result event, not even a half-written one.
		var state string
		if err := db.SQL().QueryRow(`SELECT state FROM ops`).Scan(&state); err != nil {
			t.Fatal(err)
		}
		if state != "executing" {
			t.Errorf("state after crash = %s, want executing (the success update must have rolled back)", state)
		}
		if n := count(db, `SELECT COUNT(*) FROM fake_ledger WHERE name = 'op.result'`); n != 0 {
			t.Errorf("%d op.result rows survived", n)
		}
		if n := count(db, `SELECT COUNT(*) FROM fake_ledger WHERE name = 'op.request'`); n != 1 {
			t.Errorf("op.request rows = %d, want 1", n)
		}
		// Restart recovery resolves it atomically.
		cat, _, _ := policyDefault(t)
		ctx := context.Background()
		svc, err := NewService(Config{DB: db, Ledger: &fakeLedger{t: t}, Policy: newEngine(t, cat, "health")})
		if err != nil {
			t.Fatal(err)
		}
		if n, err := svc.Recover(ctx); err != nil || n != 1 {
			t.Fatalf("recover: %d %v", n, err)
		}
		if err := db.SQL().QueryRow(`SELECT state FROM ops`).Scan(&state); err != nil || state != "unconfirmed" {
			t.Errorf("after recover: %s %v", state, err)
		}
		if n := count(db, `SELECT COUNT(*) FROM fake_ledger WHERE name = 'op.result'`); n != 1 {
			t.Errorf("op.result rows after recover = %d, want 1", n)
		}
	})

	t.Run("crash while recording a denial", func(t *testing.T) {
		path := tempDBPath(t)
		openRigDB(t, path).Close()
		run(path, "denial", 1)
		db := openRigDB(t, path)
		defer db.Close()
		for _, q := range []string{`SELECT COUNT(*) FROM ops`, `SELECT COUNT(*) FROM denials`, `SELECT COUNT(*) FROM fake_ledger`} {
			if n := count(db, q); n != 0 {
				t.Errorf("%s = %d after a crash before commit", q, n)
			}
		}
	})
}

// TestCrashHelper is the process the crash test kills. It does nothing unless
// the parent set CHAPD_CRASH_HELPER.
func TestCrashHelper(t *testing.T) {
	if os.Getenv("CHAPD_CRASH_HELPER") == "" {
		t.Skip("only runs as a child of TestCrashIsAtomic")
	}
	crashAt := os.Getenv("CHAPD_CRASH_AT")
	seen := 0
	enable := []string{"health"}
	if crashAt == "denial" {
		enable = nil // health disabled: the request ends in a denial
	}
	g := newRig(t, rigOpts{enable: enable, dbPath: os.Getenv("CHAPD_CRASH_DB")})
	g.led.onNext = func(e Event) {
		if e.Name == crashAt {
			seen++
			if seen == int(os.Getenv("CHAPD_CRASH_NTH")[0]-'0') {
				os.Exit(3) // the process dies with the transaction open
			}
		}
	}
	g.call("POST", "/v0/ops?wait=5", runTok, health())
	// Reaching here means the crash point was never hit.
	time.Sleep(200 * time.Millisecond)
	os.Exit(0)
}

var _ sync.Mutex
var _ = spec.SpecVersion
