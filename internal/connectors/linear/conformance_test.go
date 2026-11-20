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
	// The generic issue ops work in team AGT, on issues labelled agent; the
	// operator board (team SHOP, label claude) is out of their reach.
	pol.Issues = &policy.LinearIssues{
		Team: "AGT", Label: "agent", States: []string{"In Progress", "Done"},
		Labels: []string{"bug", "triaged"}, LinkHosts: []string{"github.com"},
	}
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
	// The issue team: AGT-1 is the agent's issue, AGT-2 has no provenance label,
	// AGT-3 carries the operator-board label.
	fake.AddIssue(lineartest.Issue{Identifier: "AGT-1", Title: "Fix the cart total", Description: "Rounds wrong.", TeamKey: "AGT", State: "In Progress", Labels: []string{"agent", "bug"}})
	fake.AddIssue(lineartest.Issue{Identifier: "AGT-2", Title: "A person's issue", TeamKey: "AGT", Labels: []string{"bug"}})
	fake.AddIssue(lineartest.Issue{Identifier: "AGT-3", Title: "An operator request that landed here", TeamKey: "AGT", Labels: []string{"agent", "claude"}})
	fake.DefineLabel("triaged", "")

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
			return n - fake.NoOps() // a link the issue already had is accepted and changes nothing
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

// plantAGT puts the planted text in the title and description of AGT-1.
func plantAGT(r *conformance.Rig, p conformance.Planted) {
	r.World.(*lineartest.Server).Edit("AGT-1", func(i *lineartest.Issue) {
		i.Title = orDefault(p.Control, "Plain title")
		i.Description = strings.TrimSpace(p.Long + " " + p.Secret)
	})
}

// plantAGTState gives AGT-1 a workflow state named with the planted text, and
// the team the state, so the name is read back by every op that shows a state.
func plantAGTState(r *conformance.Rig, p conformance.Planted) {
	name := strings.TrimSpace(strings.Join([]string{p.Control, p.Long, p.Secret}, " "))
	fake := r.World.(*lineartest.Server)
	fake.AddState("AGT", lineartest.State{ID: "st-agt-planted", Name: name, Type: "started"})
	fake.Edit("AGT-1", func(i *lineartest.Issue) {
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
		Declared: linearspec.Served,
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
			OpIssueGet: {
				Valid: []conformance.Sample{sample("an issue of the issue team", OpIssueGet, "AGT-1", nil)},
				Invalid: []conformance.Sample{
					refused("an operator-board issue (the intake team)", ops.CodePolicyRefused, OpIssueGet, "SHOP-1", nil, nil),
					refused("an issue of another team", ops.CodeScopePath, OpIssueGet, "ENG-1", nil, nil),
					refused("not an identifier", ops.CodeParamsInvalid, OpIssueGet, "agt-1", nil, nil),
					refused("a project with no linear.issues block", ops.CodePolicyRefused, OpIssueGet, "AGT-1", nil, otherProject),
					refused("another adapter", ops.CodeParamsInvalid, OpIssueGet, "AGT-1", nil, notLinear),
					refused("no caller", ops.CodePolicyRefused, OpIssueGet, "AGT-1", nil, func(q *ops.Request) { q.Caller = nil }),
				},
				ReadOnly: true, Text: conformance.ServiceText, Plant: plantAGT,
			},
			OpIssueList: {
				Valid: []conformance.Sample{
					sample("the issue team by word, with every filter", OpIssueList, IssueTeamRef, map[string]any{"state": "started", "label": "bug", "cursor": "abc123"}),
					sample("the issue team by key", OpIssueList, "AGT", nil),
				},
				Invalid: []conformance.Sample{
					refused("the intake team", ops.CodePolicyRefused, OpIssueList, "SHOP", nil, nil),
					refused("another team", ops.CodeScopePath, OpIssueList, "ENG", nil, nil),
					refused("not a team key", ops.CodeParamsInvalid, OpIssueList, "agt", nil, nil),
					refused("a state type that does not exist", ops.CodeParamsInvalid, OpIssueList, IssueTeamRef, map[string]any{"state": "Todo"}, nil),
					refused("the operator-board label", ops.CodePolicyRefused, OpIssueList, IssueTeamRef, map[string]any{"label": "Claude"}, nil),
					refused("a cursor chapd never returned", ops.CodeParamsInvalid, OpIssueList, IssueTeamRef, map[string]any{"cursor": "a b"}, nil),
					refused("a project with no linear.issues block", ops.CodePolicyRefused, OpIssueList, IssueTeamRef, nil, otherProject),
					refused("another adapter", ops.CodeParamsInvalid, OpIssueList, IssueTeamRef, nil, notLinear),
				},
				ReadOnly: true, Text: conformance.ServiceText, Plant: plantAGT,
			},
			OpIssueComment: {
				Valid: []conformance.Sample{sample("comment", OpIssueComment, "AGT-1", map[string]any{"body": "Looking at it."})},
				Invalid: []conformance.Sample{
					refused("an operator-board issue (the intake team)", ops.CodePolicyRefused, OpIssueComment, "SHOP-1", map[string]any{"body": "x"}, nil),
					refused("an issue with the operator-board label", ops.CodePolicyRefused, OpIssueComment, "AGT-3", map[string]any{"body": "x"}, nil),
					refused("an issue without the provenance label", ops.CodePolicyRefused, OpIssueComment, "AGT-2", map[string]any{"body": "x"}, nil),
					refused("an issue of another team", ops.CodeScopePath, OpIssueComment, "ENG-1", map[string]any{"body": "x"}, nil),
					refused("an issue that does not exist", ops.CodeParamsInvalid, OpIssueComment, "AGT-99", map[string]any{"body": "x"}, nil),
					refused("not an identifier", ops.CodeParamsInvalid, OpIssueComment, "agt-1", map[string]any{"body": "x"}, nil),
					refused("a body that looks like a secret", ops.CodeRedactionBlocked, OpIssueComment, "AGT-1", map[string]any{"body": secretBody}, nil),
					refused("a body with an invisible character", ops.CodeParamsInvalid, OpIssueComment, "AGT-1", map[string]any{"body": "a\u202eb"}, nil),
					refused("a mention the policy does not allow", ops.CodePolicyRefused, OpIssueComment, "AGT-1", map[string]any{"body": "thanks @alice"}, nil),
					refused("a project with no linear.issues block", ops.CodePolicyRefused, OpIssueComment, "AGT-1", map[string]any{"body": "x"}, otherProject),
				},
				Text: conformance.NoServiceText, Plant: plantAGTState,
			},
			OpIssueLabel: {
				Valid: []conformance.Sample{
					sample("add a label", OpIssueLabel, "AGT-1", map[string]any{"add": "triaged"}),
					sample("remove a label", OpIssueLabel, "AGT-1", map[string]any{"remove": "bug"}),
				},
				Invalid: []conformance.Sample{
					refused("both add and remove", ops.CodeParamsInvalid, OpIssueLabel, "AGT-1", map[string]any{"add": "bug", "remove": "triaged"}, nil),
					refused("neither add nor remove", ops.CodeParamsInvalid, OpIssueLabel, "AGT-1", nil, nil),
					refused("the operator-board label", ops.CodePolicyRefused, OpIssueLabel, "AGT-1", map[string]any{"add": "Claude"}, nil),
					refused("the provenance label", ops.CodePolicyRefused, OpIssueLabel, "AGT-1", map[string]any{"remove": "agent"}, nil),
					refused("a label the policy does not list", ops.CodePolicyRefused, OpIssueLabel, "AGT-1", map[string]any{"add": "urgent"}, nil),
					refused("an operator-board issue (the intake team)", ops.CodePolicyRefused, OpIssueLabel, "SHOP-1", map[string]any{"add": "bug"}, nil),
					refused("an issue with the operator-board label", ops.CodePolicyRefused, OpIssueLabel, "AGT-3", map[string]any{"add": "bug"}, nil),
					refused("an issue without the provenance label", ops.CodePolicyRefused, OpIssueLabel, "AGT-2", map[string]any{"add": "bug"}, nil),
					refused("an issue of another team", ops.CodeScopePath, OpIssueLabel, "ENG-1", map[string]any{"add": "bug"}, nil),
				},
				Text: conformance.NoServiceText, Plant: plantAGTState,
			},
			OpIssueMove: {
				Valid: []conformance.Sample{sample("move", OpIssueMove, "AGT-1", map[string]any{"state": "Done"})},
				Invalid: []conformance.Sample{
					refused("a state the policy does not list", ops.CodePolicyRefused, OpIssueMove, "AGT-1", map[string]any{"state": "Backlog"}, nil),
					refused("an operator-board issue (the intake team)", ops.CodePolicyRefused, OpIssueMove, "SHOP-1", map[string]any{"state": "Done"}, nil),
					refused("an issue with the operator-board label", ops.CodePolicyRefused, OpIssueMove, "AGT-3", map[string]any{"state": "Done"}, nil),
					refused("an issue without the provenance label", ops.CodePolicyRefused, OpIssueMove, "AGT-2", map[string]any{"state": "Done"}, nil),
					refused("an issue of another team", ops.CodeScopePath, OpIssueMove, "ENG-1", map[string]any{"state": "Done"}, nil),
					refused("not an identifier", ops.CodeParamsInvalid, OpIssueMove, "agt-1", map[string]any{"state": "Done"}, nil),
				},
				Text: conformance.CleanedText, Plant: plantAGTState,
			},
			OpIssueLink: {
				Valid: []conformance.Sample{sample("link", OpIssueLink, "AGT-1", map[string]any{"url": "https://github.com/example-org/storefront/pull/12", "title": "The fix"})},
				Invalid: []conformance.Sample{
					refused("a host the policy does not list", ops.CodePolicyRefused, OpIssueLink, "AGT-1", map[string]any{"url": "https://example.net/x"}, nil),
					refused("not https", ops.CodeParamsInvalid, OpIssueLink, "AGT-1", map[string]any{"url": "http://github.com/x"}, nil),
					refused("a port", ops.CodeParamsInvalid, OpIssueLink, "AGT-1", map[string]any{"url": "https://github.com:8443/x"}, nil),
					refused("a user name", ops.CodeParamsInvalid, OpIssueLink, "AGT-1", map[string]any{"url": "https://alice@github.com/x"}, nil),
					refused("an operator-board issue (the intake team)", ops.CodePolicyRefused, OpIssueLink, "SHOP-1", map[string]any{"url": "https://github.com/x"}, nil),
					refused("an issue with the operator-board label", ops.CodePolicyRefused, OpIssueLink, "AGT-3", map[string]any{"url": "https://github.com/x"}, nil),
					refused("an issue without the provenance label", ops.CodePolicyRefused, OpIssueLink, "AGT-2", map[string]any{"url": "https://github.com/x"}, nil),
					refused("a title with an invisible character", ops.CodeParamsInvalid, OpIssueLink, "AGT-1", map[string]any{"url": "https://github.com/x", "title": "a\u202eb"}, nil),
					refused("a title that looks like a secret", ops.CodeRedactionBlocked, OpIssueLink, "AGT-1", map[string]any{"url": "https://github.com/x", "title": secretBody}, nil),
				},
				Text: conformance.NoServiceText, Plant: plantAGTState,
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
