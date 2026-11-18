package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/joshua-noel/chaperone/internal/denialtext"
)

// mcpChapd is a chapd for `chap mcp` tests: a catalog, one allowed read, one
// op that needs a human, and the approval and status routes.
type mcpChapd struct {
	*httptest.Server
	mu    sync.Mutex
	auths []string
	paths []string
	// reject401 makes the first request with this bearer a 401.
	reject string
}

const mcpCatalog = `{"policy_version":"baseline-test","project":"acme-shop","ops":[
 {"op":"deploy","class":"high","reversibility":"compensable","surface":"op","enabled":true,"needs_approval":true,"summary":"Deploy a commit to the pilot.","usage":"chap deploy <sha>"},
 {"op":"health","class":"routine","reversibility":"reversible","surface":"op","enabled":true,"needs_approval":false,"summary":"Read the pilot's readiness status.","usage":"chap health"},
 {"op":"pr.view","class":"routine","reversibility":"reversible","surface":"op","enabled":true,"needs_approval":false,"summary":"Read a PR's title, body, state.","usage":"chap pr view <n>"}]}`

func newMcpChapd(t *testing.T) *mcpChapd {
	l := &mcpChapd{}
	l.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		l.mu.Lock()
		l.auths = append(l.auths, r.Header.Get("Authorization"))
		l.paths = append(l.paths, r.Method+" "+r.URL.RequestURI())
		reject := l.reject
		l.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if reject != "" && r.Header.Get("Authorization") == "Bearer "+reject {
			w.WriteHeader(401)
			io.WriteString(w, `{"type":"auth_error","why":"token revoked"}`)
			return
		}
		var req struct {
			Op         string `json:"op"`
			ApprovalID string `json:"approval_id"`
			Reason     string `json:"reason"`
		}
		json.Unmarshal(body, &req)
		switch {
		case r.URL.Path == "/v0/catalog":
			io.WriteString(w, mcpCatalog)
		case r.URL.Path == "/v0/ops" && req.Op == "pr.view":
			io.WriteString(w, `{"id":"q-view01","state":"succeeded","op":"pr.view","project":"acme-shop","target":{"adapter":"github","ref":"acme/shop#7"},"class":"routine","reversibility":"reversible","result":{"title":"Fix typo","body":"hello `+testRunToken+` bye"}}`)
		case r.URL.Path == "/v0/ops" && req.Op == "deploy":
			w.WriteHeader(403)
			io.WriteString(w, `{"type":"denial","denial_id":"d-1","run_id":"r-7f3a","project":"acme-shop","profile":"code","surface":"deploy","cause_code":"OP_APPROVAL_REQUIRED","why":"deploy needs one approval","action":{"verb":"deploy","target":"wsl-host:pilot"},"request":{"possible":true,"command":"chap request op deploy --reason <why>"}}`)
		case r.URL.Path == "/v0/approvals":
			w.WriteHeader(202)
			io.WriteString(w, `{"id":"q-dep001","state":"pending_approval","op":"deploy","project":"acme-shop","class":"high","requested_at":"2026-11-05T11:59:00Z","expires_at":"2026-11-05T12:30:00Z","approval":{"id":"a-card01","state":"pending","expires_at":"2026-11-05T12:15:00Z"}}`)
		case strings.HasPrefix(r.URL.Path, "/v0/ops/q-dep001"):
			io.WriteString(w, `{"id":"q-dep001","state":"succeeded","op":"deploy","class":"high","external_ref":"deploy-9"}`)
		default:
			w.WriteHeader(404)
			io.WriteString(w, `{"type":"not_found","why":"no such route"}`)
		}
	}))
	t.Cleanup(l.Close)
	return l
}

func (l *mcpChapd) seen() (auths, paths []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.auths...), append([]string(nil), l.paths...)
}

// runMcp runs `chap mcp` with the lines on stdin and returns stdout lines,
// stderr and the exit code.
func runMcp(t *testing.T, e env, lines ...string) (out []map[string]any, rawOut, stderr string, code int) {
	t.Helper()
	ta := newTestApp(t, e)
	ta.stdin = strings.NewReader(strings.Join(lines, "\n") + "\n")
	code = ta.run([]string{"mcp"})
	rawOut, stderr = ta.out.String(), ta.errb.String()
	for _, line := range strings.Split(strings.TrimRight(rawOut, "\n"), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("stdout holds a line that is not a JSON-RPC message: %q", line)
		}
		out = append(out, m)
	}
	return out, rawOut, stderr, code
}

func mcpEnv(l *mcpChapd) env {
	return env{notURL: true, extra: map[string]string{"CHAP_URL": l.URL, "CHAP_PROJECT": "acme-shop"}}
}

func mcpResult(t *testing.T, msgs []map[string]any, id int) map[string]any {
	t.Helper()
	for _, m := range msgs {
		if n, ok := m["id"].(float64); ok && int(n) == id {
			r, ok := m["result"].(map[string]any)
			if !ok {
				t.Fatalf("response %d is not a result: %v", id, m)
			}
			return r
		}
	}
	t.Fatalf("no response with id %d", id)
	return nil
}

func mcpText(r map[string]any) string {
	return r["content"].([]any)[0].(map[string]any)["text"].(string)
}

const (
	mcpModernMeta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"t","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}`
	viewArgs      = `{"target":{"adapter":"github","ref":"acme/shop#7"}}`
)

func mcpCall(id int, name, args, meta string) string {
	if meta != "" {
		meta = "," + meta
	}
	b, _ := json.Marshal(id)
	return `{"jsonrpc":"2.0","id":` + string(b) + `,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + meta + `}}`
}

// Both eras of MCP, against a fake chapd: the same tools, the same calls, the
// caller's own token on every request, and only JSON-RPC on stdout.
func TestMcpTranscriptBothEras(t *testing.T) {
	for _, era := range []struct {
		name  string
		open  []string
		meta  string
		wants string
	}{
		{"legacy", []string{
			`{"jsonrpc":"2.0","id":100,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`,
			`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		}, "", ""},
		{"modern", []string{
			`{"jsonrpc":"2.0","id":100,"method":"server/discover","params":{` + mcpModernMeta + `}}`,
		}, mcpModernMeta, "complete"},
	} {
		t.Run(era.name, func(t *testing.T) {
			l := newMcpChapd(t)
			lines := append([]string{}, era.open...)
			lines = append(lines,
				`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{`+era.meta+`}}`,
				mcpCall(2, "pr_view", viewArgs, era.meta),
				mcpCall(3, "deploy", `{"params":{"sha":"`+strings.Repeat("1", 40)+`"}}`, era.meta),
				mcpCall(4, "deploy", `{"params":{"sha":"`+strings.Repeat("1", 40)+`"},"request_approval":true,"reason":"release 5"}`, era.meta),
				mcpCall(5, "chaperone_op_status", `{"op_id":"q-dep001","wait":1}`, era.meta),
			)
			msgs, raw, stderr, code := runMcp(t, mcpEnv(l), lines...)
			if code != exitOK {
				t.Fatalf("exit %d, stderr: %s", code, stderr)
			}

			var names []string
			for _, x := range mcpResult(t, msgs, 1)["tools"].([]any) {
				names = append(names, x.(map[string]any)["name"].(string))
			}
			if strings.Join(names, ",") != "deploy,health,pr_view,chaperone_manual,chaperone_op_status" {
				t.Errorf("tools = %v", names)
			}
			if got, _ := mcpResult(t, msgs, 1)["resultType"].(string); got != era.wants {
				t.Errorf("resultType = %q, want %q", got, era.wants)
			}

			view := mcpResult(t, msgs, 2)
			if view["isError"] == true {
				t.Fatalf("pr_view: %v", view)
			}
			if !strings.Contains(raw, "[redacted]") || strings.Contains(raw, testRunToken) {
				t.Errorf("the caller's own token must be masked in a result: %s", raw)
			}

			refused := mcpResult(t, msgs, 3)
			rt := mcpText(refused)
			if refused["isError"] != true || !strings.Contains(rt, "DENIED deploy wsl-host:pilot (profile code, run r-7f3a)") ||
				!strings.Contains(rt, "cause: OP_APPROVAL_REQUIRED") || !strings.Contains(rt, "request_approval=true") {
				t.Errorf("refusal in chap's wording with the MCP next step expected:\n%s", rt)
			}

			pending := mcpResult(t, msgs, 4)
			sc := pending["structuredContent"].(map[string]any)
			if sc["status"] != "pending" || sc["approval_id"] != "a-card01" || sc["op_id"] != "q-dep001" || sc["seconds_left"] == nil {
				t.Errorf("pending = %v", sc)
			}
			if mcpResult(t, msgs, 5)["structuredContent"].(map[string]any)["status"] != "succeeded" {
				t.Errorf("op status = %v", mcpResult(t, msgs, 5))
			}

			auths, paths := l.seen()
			for _, a := range auths {
				if a != "Bearer "+testRunToken {
					t.Errorf("a request went out with %q, want the caller's own token", a)
				}
			}
			joined := strings.Join(paths, "\n")
			for _, want := range []string{"GET /v0/catalog?project=acme-shop", "POST /v0/ops", "POST /v0/approvals", "GET /v0/ops/q-dep001?wait=1"} {
				if !strings.Contains(joined, want) {
					t.Errorf("chapd never saw %q; saw:\n%s", want, joined)
				}
			}
			for _, p := range paths {
				if strings.Contains(p, "decide") || strings.Contains(p, "/approve") {
					t.Errorf("a request tried to decide an approval: %s", p)
				}
			}
			if strings.Contains(stderr, testRunToken) || !strings.Contains(stderr, "serving on stdio") {
				t.Errorf("stderr = %q", stderr)
			}
		})
	}
}

func TestMcpWithoutACredentialStartsAndSaysWhatToDo(t *testing.T) {
	l := newMcpChapd(t)
	e := mcpEnv(l)
	e.token = "none"
	msgs, _, _, code := runMcp(t, e,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		mcpCall(2, "chaperone_setup", `{}`, ""))
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	tools := mcpResult(t, msgs, 1)["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["name"] != "chaperone_setup" {
		t.Errorf("tools = %v", tools)
	}
	if tx := mcpText(mcpResult(t, msgs, 2)); !strings.Contains(tx, "no token") || !strings.Contains(tx, "CHAP_RUN_TOKEN") {
		t.Errorf("setup text = %q", tx)
	}
	if _, paths := l.seen(); len(paths) != 0 {
		t.Errorf("chapd was called without a credential: %v", paths)
	}
}

// chapd must be a loopback address: the token goes there.
func TestMcpRefusesANonLoopbackChapd(t *testing.T) {
	ta := newTestApp(t, env{notURL: true, extra: map[string]string{"CHAP_URL": "http://example.com:55398"}})
	ta.stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	if code := ta.run([]string{"mcp"}); code != exitUsage {
		t.Errorf("exit %d, want %d", code, exitUsage)
	}
	if ta.out.Len() != 0 || !strings.Contains(ta.errb.String(), "loopback") {
		t.Errorf("stdout %q, stderr %q", ta.out.String(), ta.errb.String())
	}
}

// The orchestrator's token is reissued while the server runs: a 401 makes it read the
// file again, once.
func TestMcpReadsAReissuedOrchestratorToken(t *testing.T) {
	l := newMcpChapd(t)
	const newTok = "chap_orch_cmVpc3N1ZWR0b2tlbjAxMjM0NTY3ODkwYWJjZGVmZ2hp"
	l.reject = testOrchToken
	e := mcpEnv(l)
	e.token = "orch"
	ta := newTestApp(t, e)
	var mu sync.Mutex
	file := testOrchToken + "\n"
	ta.readFile = func(p string) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		return []byte(file), nil
	}
	// The file changes when the stale token is first refused.
	inner := l.Server.Config.Handler
	l.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer "+testOrchToken {
			mu.Lock()
			file = newTok + "\n"
			mu.Unlock()
		}
		inner.ServeHTTP(w, r)
	})
	ta.stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	if code := ta.run([]string{"mcp"}); code != exitOK {
		t.Fatalf("exit %d: %s", code, ta.errb.String())
	}
	if !strings.Contains(ta.out.String(), `"pr_view"`) {
		t.Errorf("the reissued token did not get the catalog: %s", ta.out.String())
	}
	auths, _ := l.seen()
	if len(auths) != 2 || auths[0] != "Bearer "+testOrchToken || auths[1] != "Bearer "+newTok {
		t.Errorf("chapd saw %v, want the stale token once, then the new one", auths)
	}
	if strings.Contains(ta.out.String()+ta.errb.String(), newTok) || strings.Contains(ta.out.String()+ta.errb.String(), testOrchToken) {
		t.Error("a token reached the output")
	}
}

func TestMcpHelpAndUsage(t *testing.T) {
	ta := newTestApp(t, env{})
	if code := ta.run([]string{"mcp", "--help"}); code != exitOK || !strings.Contains(ta.out.String(), "usage: chap mcp") {
		t.Errorf("--help: exit %d, out %q", code, ta.out.String())
	}
	ta = newTestApp(t, env{})
	if code := ta.run([]string{"mcp", "extra"}); code != exitUsage {
		t.Errorf("extra argument: exit %d", code)
	}
	ta = newTestApp(t, env{})
	ta.run([]string{"help"})
	if !strings.Contains(ta.out.String(), "  mcp ") {
		t.Errorf("chap help does not list mcp:\n%s", ta.out.String())
	}
}

// A 401 is not free: chapd writes a ledger denial for it and counts it toward
// thrash. A CHAP_RUN_TOKEN cannot change while the process runs, so it is never
// asked again.
func TestMcpDoesNotRetryA401ForARunToken(t *testing.T) {
	l := newMcpChapd(t)
	l.reject = testRunToken
	_, raw, stderr, code := runMcp(t, mcpEnv(l), `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if auths, _ := l.seen(); len(auths) != 1 {
		t.Errorf("chapd saw %d requests, want 1 (a refused CHAP_RUN_TOKEN is not retried): %v", len(auths), auths)
	}
	if !strings.Contains(raw, "chaperone_setup") {
		t.Errorf("the refused credential should leave the setup tool: %s", raw)
	}
}

// An orchestrator token file that still holds the refused token is asked
// again once, not in a loop.
func TestMcpRetriesAFileTokenOnlyOnce(t *testing.T) {
	l := newMcpChapd(t)
	l.reject = testOrchToken
	e := mcpEnv(l)
	e.token = "orch"
	ta := newTestApp(t, e)
	ta.readFile = func(string) ([]byte, error) { return []byte(testOrchToken + "\n"), nil }
	ta.stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	if code := ta.run([]string{"mcp"}); code != exitOK {
		t.Fatalf("exit %d: %s", code, ta.errb.String())
	}
	if auths, _ := l.seen(); len(auths) != 2 {
		t.Errorf("chapd saw %d requests, want 2 (the refusal and one retry): %v", len(auths), auths)
	}
}

// Since #77 the rendered denial carries the real next step. The MCP front end
// keeps it as the only `next:` line and as the structured next; it adds its own
// line only for a denial that has none.
func TestMcpDenialKeepsTheRenderedNextStep(t *testing.T) {
	for _, c := range []struct {
		fixture string
		status  int
	}{{"denial-ci-stale", 403}, {"denial-approval-flood", 429}, {"denial-token-expired", 401}} {
		for _, via := range []string{"call", "op status"} {
			t.Run(c.fixture+"/"+via, func(t *testing.T) {
				body := loadFixture(t, c.fixture)
				var d denial
				if err := json.Unmarshal(body, &d); err != nil {
					t.Fatal(err)
				}
				want := denialtext.NextStep(d.CauseCode, d.Why, d.OrchestratorID)
				if want == "" {
					t.Fatalf("%s: denialtext has no next step; pick a fixture that has one", c.fixture)
				}
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					switch {
					case r.URL.Path == "/v0/catalog":
						io.WriteString(w, mcpCatalog)
					case r.Method == "POST" && r.URL.Path == "/v0/ops":
						w.WriteHeader(c.status)
						w.Write(body)
					case strings.HasPrefix(r.URL.Path, "/v0/ops/q-abc123"):
						io.WriteString(w, `{"id":"q-abc123","state":"denied","op":"pr.merge","class":"gated","denial":`+string(body)+`}`)
					default:
						w.WriteHeader(404)
					}
				}))
				t.Cleanup(srv.Close)
				line := mcpCall(1, "health", `{}`, "")
				if via == "op status" {
					line = mcpCall(1, "chaperone_op_status", `{"op_id":"q-abc123","wait":0}`, "")
				}
				msgs, _, stderr, code := runMcp(t, env{notURL: true, extra: map[string]string{"CHAP_URL": srv.URL, "CHAP_PROJECT": "acme-shop"}}, line)
				if code != exitOK {
					t.Fatalf("exit %d: %s", code, stderr)
				}
				res := mcpResult(t, msgs, 1)
				if res["isError"] != true {
					t.Fatalf("a denial is an error result: %v", res)
				}
				var nexts []string
				for _, l := range strings.Split(mcpText(res), "\n") {
					if strings.HasPrefix(l, "next:") {
						nexts = append(nexts, strings.TrimSpace(strings.TrimPrefix(l, "next:")))
					}
				}
				if len(nexts) != 1 {
					t.Fatalf("want exactly one next: line, got %d in:\n%s", len(nexts), mcpText(res))
				}
				if nexts[0] != want {
					t.Errorf("next: line = %q, want the rendered step %q", nexts[0], want)
				}
				if got := res["structuredContent"].(map[string]any)["next"]; got != nexts[0] {
					t.Errorf("structured next = %q, want the text's %q", got, nexts[0])
				}
				if strings.Contains(mcpText(res), "Asking is not possible") {
					t.Errorf("the generic line contradicts the real step:\n%s", mcpText(res))
				}
			})
		}
	}
}
