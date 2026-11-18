package mcpfront

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// recorded is one request the server sent to chapd.
type recorded struct {
	Method string
	Path   string
	Query  url.Values
	Body   map[string]any
}

// fakeBackend is chapd as the server sees it: it records each request and
// answers from a handler.
type fakeBackend struct {
	mu      sync.Mutex
	calls   []recorded
	handler func(r recorded, ctx context.Context) (*Reply, error)
}

func (f *fakeBackend) Call(ctx context.Context, method, path string, q url.Values, body any) (*Reply, error) {
	r := recorded{Method: method, Path: path, Query: q}
	if body != nil {
		b, _ := json.Marshal(body)
		json.Unmarshal(b, &r.Body)
	}
	f.mu.Lock()
	f.calls = append(f.calls, r)
	f.mu.Unlock()
	return f.handler(r, ctx)
}

func (f *fakeBackend) recorded() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.calls...)
}

func jsonReply(status int, v string) *Reply { return &Reply{Status: status, Body: []byte(v)} }

// catalogJSON is a catalog with a read op, a gated op, an op with a default
// target, and a git-surface op.
const catalogJSON = `{"policy_version":"baseline-test","project":"acme-shop","ops":[
 {"op":"branch.push","class":"routine","reversibility":"reversible","surface":"git","enabled":true,"needs_approval":false,"summary":"Push the run's branch.","usage":"git push"},
 {"op":"health","class":"routine","reversibility":"reversible","surface":"op","enabled":true,"needs_approval":false,"summary":"Read the pilot's readiness status.","usage":"chap health"},
 {"op":"pr.merge","class":"gated","reversibility":"compensable","surface":"op","enabled":true,"needs_approval":false,"summary":"Merge a PR when verify is green on its exact head.","usage":"chap pr merge"},
 {"op":"pr.view","class":"routine","reversibility":"reversible","surface":"op","enabled":true,"needs_approval":false,"summary":"Read a PR's title, body, state, head, base, mergeability.","usage":"chap pr view"},
 {"op":"deploy","class":"high","reversibility":"compensable","surface":"op","enabled":true,"needs_approval":true,"summary":"Deploy a commit to the pilot.","usage":"chap deploy"}
]}`

// okBackend answers the catalog and calls the handler for everything else.
func okBackend(other func(r recorded, ctx context.Context) (*Reply, error)) *fakeBackend {
	return &fakeBackend{handler: func(r recorded, ctx context.Context) (*Reply, error) {
		if r.Path == "/v0/catalog" {
			return jsonReply(200, catalogJSON), nil
		}
		if other == nil {
			return nil, &CallError{Kind: ErrOther, Message: "unexpected call " + r.Method + " " + r.Path}
		}
		return other(r, ctx)
	}}
}

func testConfig(be Backend) Config {
	return Config{
		Backend: be,
		Project: "acme-shop",
		Version: "test",
		DefaultTargets: map[string]Target{
			"health": {Adapter: "pilot", Ref: "health"},
			"deploy": {Adapter: "wsl-host", Ref: "pilot"},
		},
		Now: func() time.Time { return time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC) },
	}
}

// exchange sends the lines to a server and returns every message it wrote, in
// order. The input ends after the last line, and the server answers what is
// in flight before it stops.
func exchange(t *testing.T, cfg Config, lines ...string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	in := strings.NewReader(strings.Join(lines, "\n") + "\n")
	if err := Serve(context.Background(), cfg, in, &lockedWriter{w: &out}); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	return parseLines(t, out.String())
}

func parseLines(t *testing.T, s string) []map[string]any {
	t.Helper()
	var msgs []map[string]any
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("the server wrote a line that is not JSON: %q", line)
		}
		msgs = append(msgs, m)
	}
	return msgs
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// byID finds the response to request id (a JSON number).
func byID(t *testing.T, msgs []map[string]any, id int) map[string]any {
	t.Helper()
	for _, m := range msgs {
		if n, ok := m["id"].(float64); ok && int(n) == id {
			return m
		}
	}
	t.Fatalf("no response with id %d in %v", id, msgs)
	return nil
}

func resultOf(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	r, ok := m["result"].(map[string]any)
	if !ok {
		t.Fatalf("not a result: %v", m)
	}
	return r
}

// modernMeta is the _meta a modern client puts on every request.
const modernMeta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"t","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}`

func call(id int, name, args string) string {
	return `{"jsonrpc":"2.0","id":` + itoa(id) + `,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + `}}`
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// text is the text of a tool result's first content block.
func text(t *testing.T, res map[string]any) string {
	t.Helper()
	c, ok := res["content"].([]any)
	if !ok || len(c) == 0 {
		t.Fatalf("no content: %v", res)
	}
	return c[0].(map[string]any)["text"].(string)
}

func isError(res map[string]any) bool { b, _ := res["isError"].(bool); return b }

// pipeW is the write end of a pipe the test feeds a server through.
type pipeW struct{ *io.PipeWriter }

func (p pipeW) WriteString(s string) { p.Write([]byte(s)) }

func ioPipe() (*io.PipeReader, pipeW) {
	r, w := io.Pipe()
	return r, pipeW{w}
}
