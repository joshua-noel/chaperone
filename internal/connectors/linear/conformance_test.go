package linear

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/connectors/conformance"
	"github.com/joshua-noel/chaperone/internal/connectors/linear/linearspec"
	"github.com/joshua-noel/chaperone/internal/connectors/linear/lineartest"
	"github.com/joshua-noel/chaperone/internal/connectors/pintable"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/redact"
)

// TestConformance runs the shared connector suite (internal/connectors/conformance)
// against the real Linear adapters and the fake Linear (lineartest). The
// canary is the OAuth client secret: the fake accepts it, and the suite looks
// for it, and for every access token the fake issued, in everything the
// adapters say.

// syncBuf is a log buffer that two goroutines may write.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func conformanceRig(t testing.TB, canary string) *conformance.Rig {
	t.Helper()
	fake := lineartest.New(t)
	fake.SetClientSecret(canary)
	clk := &clock{t: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)}
	fake.Now = clk.Now
	vault := &secrets{m: map[string][]byte{}}
	vault.set(SecretClientID, lineartest.ClientID+"\n")
	vault.set(SecretClientSecret, canary+"\n")
	reg := redact.NewRegistry()
	ep := Endpoints{API: fake.URL + "/graphql", Token: fake.URL + "/oauth/token"}
	wire := &wireRecorder{next: http.DefaultTransport}
	hc := &http.Client{Transport: wire, Timeout: 30 * time.Second}
	toks, err := NewTokenSource(TokenConfig{Secrets: vault, Registry: reg, Endpoints: ep, HTTP: hc, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ClientConfig{Endpoints: ep, Tokens: toks, HTTP: hc, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuf{}
	board := NewBoard(BoardConfig{Client: client, Now: clk.Now, Log: slog.New(slog.NewTextHandler(logs, nil))})
	pol := &policy.Linear{Team: "SHOP", Label: "claude", States: []string{"Handed to engineering", "In Progress", "Blocked", "Completed"}}
	ads, err := Adapters(Config{
		Client: client, Board: board, Redactor: reg, Now: clk.Now,
		Policy: func(p string) *policy.Linear {
			if p != testProject {
				return nil
			}
			return pol
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	fake.AddIssue(lineartest.Issue{Identifier: "SHOP-1", Title: "Order market signs", Description: "Three A-frame signs.", Labels: []string{"claude", "signs"}})
	fake.AddIssue(lineartest.Issue{Identifier: "SHOP-3", Title: "Not for the orchestrator", Labels: []string{"personal"}})
	fake.AddIssue(lineartest.Issue{Identifier: "ENG-1", Title: "Mirror of a GitHub issue", TeamKey: "ENG", Labels: []string{"claude"}})

	isWrite := func(r lineartest.Request) bool { return strings.HasPrefix(strings.TrimSpace(r.Query), "mutation") }
	return &conformance.Rig{
		Adapters: ads,
		WriteCalls: func() int {
			n := 0
			for _, r := range fake.Requests() {
				if isWrite(r) {
					n++
				}
			}
			return n
		},
		WritesApplied: func() int {
			n := 0
			for _, r := range fake.Requests() {
				if isWrite(r) && !r.Errors {
					n++
				}
			}
			return n
		},
		Secrets: func() []string {
			// What the service was sent: the client secret in the token request, and
			// each access token. A rig that listed the canary itself would hide a
			// connector that ignores it.
			return append(wire.credentials(), fake.Tokens()...)
		},
		Logs:    logs.String,
		Hostile: func() { fake.Hostile("rotated-" + canary) },
		World:   fake,
	}
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// plantIssue puts the planted text in the title and description of SHOP-1.
func plantIssue(r *conformance.Rig, p conformance.Planted) {
	r.World.(*lineartest.Server).Edit("SHOP-1", func(i *lineartest.Issue) {
		i.Title = orDefault(p.Control, "Plain title")
		i.Description = strings.TrimSpace(p.Long + " " + p.Secret)
	})
}

// plantState gives SHOP-1 a workflow state named with the planted text, and
// the team the state, so the name is read back by every op that shows a state.
func plantState(r *conformance.Rig, p conformance.Planted) {
	name := strings.TrimSpace(strings.Join([]string{p.Control, p.Long, p.Secret}, " "))
	fake := r.World.(*lineartest.Server)
	fake.AddState("SHOP", lineartest.State{ID: "st-planted", Name: name, Type: "started"})
	fake.Edit("SHOP-1", func(i *lineartest.Issue) {
		i.State = name
		i.Title = orDefault(p.Control, "Plain title")
		i.Description = strings.TrimSpace(p.Long + " " + p.Secret)
	})
}

func sample(name, op, ref string, params map[string]any) conformance.Sample {
	return conformance.Sample{Name: name, Req: func(*conformance.Rig) *ops.Request { return req(op, ref, params) }}
}

func refused(name, code, op, ref string, params map[string]any, change func(*ops.Request)) conformance.Sample {
	return conformance.Sample{Name: name, Code: code, Req: func(*conformance.Rig) *ops.Request {
		q := req(op, ref, params)
		if change != nil {
			change(q)
		}
		return q
	}}
}

func asRun(q *ops.Request) {
	q.Caller = &ops.Caller{Kind: ops.KindRun, RunID: "r-1", Project: testProject}
}
func otherProject(q *ops.Request) { q.Project = "another-project" }
func notLinear(q *ops.Request)    { q.Target.Adapter = "github" }

func TestConformance(t *testing.T) {
	secretBody := "token ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
	conformance.Run(t, conformance.Connector{
		Declared: linearspec.Connector,
		Pins:     pintable.Pins,
		NewRig:   conformanceRig,
		Ops: map[string]conformance.Op{
			OpList: {
				Valid: []conformance.Sample{
					sample("the board", OpList, BoardRef, nil),
					sample("the team key, refreshed", OpList, "SHOP", map[string]any{"refresh": true}),
					sample("closed too", OpList, BoardRef, map[string]any{"closed": true}),
				},
				Invalid: []conformance.Sample{
					refused("a run asks", ops.CodePolicyRefused, OpList, BoardRef, nil, asRun),
					refused("a project with no linear block", ops.CodePolicyRefused, OpList, BoardRef, nil, otherProject),
					refused("another team", ops.CodeScopePath, OpList, "OPS", nil, nil),
					refused("not a team key", ops.CodeParamsInvalid, OpList, "shop", nil, nil),
					refused("another adapter", ops.CodeParamsInvalid, OpList, BoardRef, nil, notLinear),
					refused("refresh is not a bool", ops.CodeParamsInvalid, OpList, BoardRef, map[string]any{"refresh": "yes"}, nil),
				},
				ReadOnly: true, Text: conformance.ServiceText, Plant: plantIssue,
			},
			OpStates: {
				Valid: []conformance.Sample{sample("the board", OpStates, BoardRef, nil)},
				Invalid: []conformance.Sample{
					refused("a run asks", ops.CodePolicyRefused, OpStates, BoardRef, nil, asRun),
					refused("another team", ops.CodeScopePath, OpStates, "OPS", nil, nil),
					refused("not a team key", ops.CodeParamsInvalid, OpStates, "shop", nil, nil),
				},
				ReadOnly: true, Text: conformance.CleanedText, Plant: plantState,
			},
			OpComment: {
				Valid: []conformance.Sample{sample("comment", OpComment, "SHOP-1", map[string]any{"body": "Picked up by the orchestrator."})},
				Invalid: []conformance.Sample{
					refused("a run asks", ops.CodePolicyRefused, OpComment, "SHOP-1", map[string]any{"body": "x"}, asRun),
					refused("an item without the label", ops.CodePolicyRefused, OpComment, "SHOP-3", map[string]any{"body": "x"}, nil),
					refused("an item of another team", ops.CodeScopePath, OpComment, "ENG-1", map[string]any{"body": "x"}, nil),
					refused("an item that does not exist", ops.CodeParamsInvalid, OpComment, "SHOP-99", map[string]any{"body": "x"}, nil),
					refused("not an identifier", ops.CodeParamsInvalid, OpComment, "shop-1", map[string]any{"body": "x"}, nil),
					refused("a body that looks like a secret", ops.CodeRedactionBlocked, OpComment, "SHOP-1", map[string]any{"body": secretBody}, nil),
					refused("a body with an invisible character", ops.CodeParamsInvalid, OpComment, "SHOP-1", map[string]any{"body": "a\u202eb"}, nil),
				},
				Text: conformance.NoServiceText, Plant: plantState,
			},
			OpMove: {
				Valid: []conformance.Sample{sample("move", OpMove, "SHOP-1", map[string]any{"state": "In Progress"})},
				Invalid: []conformance.Sample{
					refused("a run asks", ops.CodePolicyRefused, OpMove, "SHOP-1", map[string]any{"state": "In Progress"}, asRun),
					refused("a state the policy does not list", ops.CodePolicyRefused, OpMove, "SHOP-1", map[string]any{"state": "Backlog"}, nil),
					refused("an item without the label", ops.CodePolicyRefused, OpMove, "SHOP-3", map[string]any{"state": "In Progress"}, nil),
					refused("an item of another team", ops.CodeScopePath, OpMove, "ENG-1", map[string]any{"state": "In Progress"}, nil),
					refused("not an identifier", ops.CodeParamsInvalid, OpMove, "shop-1", map[string]any{"state": "In Progress"}, nil),
				},
				Text: conformance.CleanedText, Plant: plantState,
			},
		},
	})
}

// wireRecorder is the HTTP transport of the client. It remembers every
// credential sent: the user and password of Basic authentication, a client
// secret in a form body, and a bearer token.
type wireRecorder struct {
	mu    sync.Mutex
	next  http.RoundTripper
	creds []string
}

func (w *wireRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	var seen []string
	if u, p, ok := req.BasicAuth(); ok {
		seen = append(seen, u, p)
	}
	if _, tok, ok := strings.Cut(req.Header.Get("Authorization"), "Bearer "); ok {
		seen = append(seen, tok)
	}
	if req.Body != nil && req.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		raw, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(strings.NewReader(string(raw)))
		for _, kv := range strings.Split(string(raw), "&") {
			if v, ok := strings.CutPrefix(kv, "client_secret="); ok {
				seen = append(seen, v)
			}
		}
	}
	w.mu.Lock()
	w.creds = append(w.creds, seen...)
	w.mu.Unlock()
	return w.next.RoundTrip(req)
}

func (w *wireRecorder) credentials() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.creds...)
}
