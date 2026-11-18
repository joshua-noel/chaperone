package linear

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/connectors/linear/lineartest"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/redact"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/vault"
)

const testProject = "acme-shop"

// secrets is an in-memory stand-in for the vault.
type secrets struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (s *secrets) Use(_ context.Context, id string, fn func([]byte) error) error {
	s.mu.Lock()
	v, ok := s.m[id]
	s.mu.Unlock()
	if !ok {
		return vault.ErrNotFound
	}
	return fn(append([]byte(nil), v...))
}

func (s *secrets) set(id, v string) {
	s.mu.Lock()
	s.m[id] = []byte(v)
	s.mu.Unlock()
}

// clock is a settable clock shared by the connector and the fake.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type rig struct {
	t       *testing.T
	fake    *lineartest.Server
	secrets *secrets
	reg     *redact.Registry
	clock   *clock
	log     *bytes.Buffer
	ep      Endpoints
	toks    *TokenSource
	client  *Client
	board   *Board
	pol     *policy.Linear
	ads     map[string]ops.Adapter
}

type rigOpts struct {
	interval time.Duration
	budget   int
}

func newRig(t *testing.T, o ...rigOpts) *rig {
	t.Helper()
	var opt rigOpts
	if len(o) > 0 {
		opt = o[0]
	}
	r := &rig{t: t, fake: lineartest.New(t), reg: redact.NewRegistry(), log: &bytes.Buffer{}}
	r.clock = &clock{t: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)}
	r.fake.Now = r.clock.Now
	r.secrets = &secrets{m: map[string][]byte{}}
	r.secrets.set(SecretClientID, lineartest.ClientID+"\n")
	r.secrets.set(SecretClientSecret, lineartest.ClientSecret+"\n")
	r.ep = Endpoints{API: r.fake.URL + "/graphql", Token: r.fake.URL + "/oauth/token"}
	var err error
	r.toks, err = NewTokenSource(TokenConfig{Secrets: r.secrets, Registry: r.reg, Endpoints: r.ep, Now: r.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	r.client, err = NewClient(ClientConfig{Endpoints: r.ep, Tokens: r.toks, HourlyBudget: opt.budget, Now: r.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	r.board = NewBoard(BoardConfig{Client: r.client, Interval: opt.interval, Now: r.clock.Now, Log: slog.New(slog.NewTextHandler(r.log, nil))})
	r.pol = &policy.Linear{Team: "SHOP", Label: "claude", States: []string{"Handed to engineering", "In Progress", "Blocked", "Completed"}}
	r.ads, err = Adapters(Config{
		Client: r.client, Board: r.board, Redactor: r.reg, Now: r.clock.Now,
		Policy: func(p string) *policy.Linear {
			if p != testProject {
				return nil
			}
			return r.pol
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// seed adds the issues most tests use: two SHOP items with the label (one open,
// one completed), one SHOP item without it and one Engineering item with it.
func (r *rig) seed() {
	r.fake.AddIssue(lineartest.Issue{Identifier: "SHOP-1", Title: "Order market signs", Description: "Three A-frame signs.", Labels: []string{"claude", "signs"}, Assignee: "Gilliano",
		Links: []lineartest.Link{{URL: "https://github.com/example-org/storefront/issues/401", Title: "Sign order", Source: "github"}}})
	r.fake.AddIssue(lineartest.Issue{Identifier: "SHOP-2", Title: "Old finished thing", Labels: []string{"claude"}, State: "Completed"})
	r.fake.AddIssue(lineartest.Issue{Identifier: "SHOP-3", Title: "Not for the orchestrator", Labels: []string{"personal"}})
	r.fake.AddIssue(lineartest.Issue{Identifier: "ENG-1", Title: "Mirror of a GitHub issue", TeamKey: "ENG", Labels: []string{"claude"}})
}

func orchCaller() *ops.Caller {
	return &ops.Caller{Kind: ops.KindOrchestrator, OrchID: "main", Projects: []string{testProject}}
}

// req builds a request as chapd hands it to an adapter.
func req(op, ref string, params map[string]any) *ops.Request {
	if params == nil {
		params = map[string]any{}
	}
	return &ops.Request{
		ID: "q-abc123", Op: op, Project: testProject, Target: spec.Target{Adapter: AdapterName, Ref: ref},
		Params: params, ExecutionID: "x-1", Caller: orchCaller(),
	}
}

func (r *rig) ad(op string) ops.Adapter { return r.ads[op] }

// run is Check then Execute, as the op pipeline does for a routine op.
func (r *rig) run(q *ops.Request) (ops.CheckResult, error, ops.Outcome, error) {
	r.t.Helper()
	ctx := context.Background()
	cr, err := r.ad(q.Op).Check(ctx, q)
	if err != nil {
		return cr, err, ops.Outcome{}, nil
	}
	out, err2 := r.ad(q.Op).Execute(ctx, q)
	return cr, nil, out, err2
}

func wantRefusal(t *testing.T, err error, code string) *ops.Refusal {
	t.Helper()
	ref, ok := err.(*ops.Refusal)
	if !ok {
		t.Fatalf("got %v (%T), want refusal %s", err, err, code)
	}
	if ref.Code != code {
		t.Fatalf("code %s (%s), want %s", ref.Code, ref.Why, code)
	}
	return ref
}

func mustSucceed(t *testing.T, out ops.Outcome, err error) ops.Outcome {
	t.Helper()
	if err != nil || out.Failed || out.Unconfirmed {
		t.Fatalf("outcome %+v err %v, want success", out, err)
	}
	return out
}

func mustFail(t *testing.T, out ops.Outcome, err error, contains string) {
	t.Helper()
	if err != nil || !out.Failed {
		t.Fatalf("outcome %+v err %v, want failed", out, err)
	}
	msg, _ := out.Result["error"].(string)
	if !strings.Contains(msg, contains) {
		t.Fatalf("failed with %q, want %q in it", msg, contains)
	}
}

func resultItems(t *testing.T, out ops.Outcome) []map[string]any {
	t.Helper()
	list, _ := out.Result["items"].([]any)
	var items []map[string]any
	for _, e := range list {
		items = append(items, e.(map[string]any))
	}
	return items
}

func identifiers(items []map[string]any) []string {
	var ids []string
	for _, it := range items {
		ids = append(ids, it["identifier"].(string))
	}
	return ids
}
