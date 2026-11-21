package resend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/joshua-noel/chaperone/internal/connectors/resend/resendtest"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/redact"
	"github.com/joshua-noel/chaperone/internal/spec"
)

// The values every test uses. The addresses are on example domains and nowhere
// real.
const (
	testSendKey = "re_test-sending-key-0123456789abcdef0123"
	testDomain  = "mail.example.com"
	testSender  = "alerts@mail.example.com"
	testProject = "demo"
)

// rigPolicy is the policy block every test starts from.
func rigPolicy() *policy.Resend {
	return &policy.Resend{
		Senders:         []string{testSender},
		AllowRecipients: []string{"ops@example.com", "@team.example.com"},
		MaxRecipients:   5,
	}
}

// seed puts the sending key in the fake. It can send from one domain only and do
// nothing else, as Resend's sending_access permission is.
func seed(f *resendtest.Server, sendKey string) {
	f.AddKey(sendKey, resendtest.SendingAccess, testDomain)
}

// env is the real adapters over a fake Resend, as the conformance rig builds them.
type env struct {
	t     *testing.T
	fake  *resendtest.Server
	ads   map[string]ops.Adapter
	reg   *redact.Registry
	pol   *policy.Resend
	execs atomic.Int32
}

// newEnv builds the rig of the conformance test. change adjusts the project's
// policy block before the adapters see it.
func newEnv(t *testing.T, change func(*policy.Resend)) *env {
	t.Helper()
	fake := resendtest.New(t)
	seed(fake, testSendKey)
	reg := redact.NewRegistry()
	client, err := NewClient(ClientConfig{
		SendKey:  func(context.Context) (string, error) { return testSendKey, nil },
		Registry: reg,
		HTTP:     fake.HTTPClient(),
	})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, fake: fake, reg: reg, pol: rigPolicy()}
	if change != nil {
		change(e.pol)
	}
	pol := func(project string) *policy.Resend {
		if project != testProject {
			return nil
		}
		return e.pol
	}
	e.ads, err = Adapters(Config{Client: client, Policy: pol, Redactor: reg})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func orchestrator() *ops.Caller {
	return &ops.Caller{Kind: ops.KindOrchestrator, OrchID: "main", Projects: []string{testProject}}
}

// mailParams is a message every test can start from.
func mailParams() map[string]any {
	return map[string]any{
		"to":      []any{"ops@example.com"},
		"subject": "Deploy finished",
		"body":    "The deploy of 4f2a finished.\nNo action is needed.\n",
	}
}

// request builds a request as chapd hands it to an adapter.
func request(op, ref string, params map[string]any, change func(*ops.Request)) *ops.Request {
	q := &ops.Request{
		ID: "q-abc123", Op: op, Project: testProject,
		Target: spec.Target{Adapter: AdapterName, Ref: ref},
		Params: params, Caller: orchestrator(),
	}
	if change != nil {
		change(q)
	}
	return q
}

func (e *env) sendReq(params map[string]any) *ops.Request {
	return request(OpSend, testSender, params, nil)
}

func (e *env) check(r *ops.Request) (ops.CheckResult, error) {
	e.t.Helper()
	return e.ads[r.Op].Check(context.Background(), r)
}

// run executes a request under a fresh execution id and returns the outcome. An
// error from Execute fails the test: the adapters report through the outcome.
func (e *env) run(r *ops.Request) ops.Outcome {
	e.t.Helper()
	if r.ExecutionID == "" {
		r.ExecutionID = fmt.Sprintf("x-test-%d", e.execs.Add(1))
	}
	out, err := e.ads[r.Op].Execute(context.Background(), r)
	if err != nil {
		e.t.Fatalf("%s: Execute returned an error: %v", r.Op, err)
	}
	return out
}

func mustSucceed(t *testing.T, out ops.Outcome) map[string]any {
	t.Helper()
	if out.Failed || out.Unconfirmed {
		t.Fatalf("outcome: failed=%v unconfirmed=%v %v", out.Failed, out.Unconfirmed, out.Result)
	}
	return out.Result
}

func wantRefusal(t *testing.T, err error, code string) *ops.Refusal {
	t.Helper()
	var ref *ops.Refusal
	if !errors.As(err, &ref) {
		t.Fatalf("got %v, want a refusal with code %s", err, code)
	}
	if ref.Code != code {
		t.Fatalf("refusal code %s (%s), want %s", ref.Code, ref.Why, code)
	}
	return ref
}

// errorText is the text of the result's error entry.
func errorText(out ops.Outcome) string {
	s, _ := out.Result["error"].(string)
	return s
}

// asJSON is everything a result says, as one string.
func asJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func has(s string, subs ...string) bool {
	for _, x := range subs {
		if !strings.Contains(s, x) {
			return false
		}
	}
	return true
}
