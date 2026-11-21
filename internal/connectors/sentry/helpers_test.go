package sentry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/joshua-noel/chaperone/internal/connectors/sentry/sentrytest"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/redact"
)

const testToken = "test-token-0123456789abcdef0123456789"

// env is the real adapters over a fake Sentry, seeded as the conformance rig is.
type env struct {
	t     *testing.T
	fake  *sentrytest.Server
	ads   map[string]ops.Adapter
	reg   *redact.Registry
	execs atomic.Int32
}

// newEnv builds the rig of the conformance test. change adjusts the project's
// policy block before the adapters see it.
func newEnv(t *testing.T, change func(*policy.Sentry)) *env {
	t.Helper()
	fake := sentrytest.New(t)
	fake.SetToken(testToken)
	seed(fake)
	reg := redact.NewRegistry()
	client, err := NewClient(ClientConfig{
		Credential: func(context.Context) (string, error) { return testToken, nil },
		Registry:   reg,
		HTTP:       fake.HTTPClient(),
	})
	if err != nil {
		t.Fatal(err)
	}
	pol := func(project string) *policy.Sentry {
		p := rigPolicy(sentrytest.BaseURL)(project)
		if p != nil && p.Invalid == nil && change != nil {
			change(p)
		}
		return p
	}
	ads, err := Adapters(Config{Client: client, Policy: pol, Redactor: reg})
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, fake: fake, ads: ads, reg: reg}
}

func (e *env) req(op, ref string, params map[string]any) *ops.Request {
	return request(op, ref, params, nil)(nil)
}

func (e *env) check(op, ref string, params map[string]any) (ops.CheckResult, error) {
	e.t.Helper()
	return e.ads[op].Check(context.Background(), e.req(op, ref, params))
}

// run executes a request under a fresh execution id and returns the outcome. An
// error from Execute fails the test: the adapters report through the outcome.
func (e *env) run(op, ref string, params map[string]any) ops.Outcome {
	e.t.Helper()
	q := e.req(op, ref, params)
	q.ExecutionID = fmt.Sprintf("x-test-%d", e.execs.Add(1))
	out, err := e.ads[op].Execute(context.Background(), q)
	if err != nil {
		e.t.Fatalf("%s: Execute returned an error: %v", op, err)
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

// failedWith checks an outcome is `failed` and its error text holds want.
func failedWith(t *testing.T, out ops.Outcome, want string) {
	t.Helper()
	if !out.Failed {
		t.Fatalf("outcome is not failed: %+v", out)
	}
	if msg, _ := out.Result["error"].(string); !strings.Contains(msg, want) {
		t.Fatalf("error text %q does not hold %q", msg, want)
	}
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

// writes returns the requests that the fake received and that change something.
func writes(f *sentrytest.Server) []sentrytest.Request {
	var out []sentrytest.Request
	for _, r := range f.Requests() {
		if r.Method != "GET" {
			out = append(out, r)
		}
	}
	return out
}
