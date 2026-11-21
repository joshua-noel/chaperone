package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const (
	testKeyID    = "k-0123456789abcdef"
	testKeyToken = "chap_key_QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU"
)

// scripted is a chapd that answers by route and records every request with its body.
type scripted struct {
	*httptest.Server
	mu     sync.Mutex
	routes map[string]func(body string) (int, string)
	log    []string
	auth   []string
}

func newScripted(t *testing.T, routes map[string]func(body string) (int, string)) *scripted {
	s := &scripted{routes: routes}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.log = append(s.log, r.Method+" "+r.URL.Path+" "+string(b))
		s.auth = append(s.auth, r.Header.Get("Authorization"))
		h := s.routes[r.Method+" "+r.URL.Path]
		s.mu.Unlock()
		if h == nil {
			w.WriteHeader(404)
			io.WriteString(w, `{"type":"not_found","why":"no route"}`)
			return
		}
		st, body := h(string(b))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(st)
		io.WriteString(w, body)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *scripted) saw(prefix string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, l := range s.log {
		if strings.HasPrefix(l, prefix) {
			out = append(out, l)
		}
	}
	return out
}

func keyJSON(extra string) string {
	return `{"id":"` + testKeyID + `","state":"live","project":"storefront","owner":"main","holder_kind":"agent","holder":"scout",
        "ops":["pr.diff","pr.view"],"units":["example-org/storefront"],"sensitive":false,"rate_per_hour":300,
        "expires_at":"2026-11-06T16:00:00Z","fingerprint":"ab12cd34","uses":0` + extra + `}`
}

func createRoutes(final string) map[string]func(string) (int, string) {
	return map[string]func(string) (int, string){
		"POST /v0/approvals": func(string) (int, string) {
			return 202, `{"id":"q-abcdef","state":"pending_approval","approval":{"id":"a-000001"}}`
		},
		"GET /v0/ops/q-abcdef": func(string) (int, string) {
			return 200, `{"id":"q-abcdef","state":"succeeded","result":{"key_id":"` + testKeyID + `"}}`
		},
		"POST /v0/keys/" + testKeyID + "/claim": func(string) (int, string) {
			return 200, `{"token":"` + testKeyToken + `","key":` + keyJSON("") + `}`
		},
		"POST /v0/keys/" + testKeyID + "/revoke": func(string) (int, string) { return 200, keyJSON(`,"revoked_at":"2026-11-05T16:00:00Z"`) },
	}
}

func keyApp(t *testing.T, s *scripted, extra map[string]string) *testApp {
	t.Helper()
	x := map[string]string{"CHAP_URL": s.URL}
	for k, v := range extra {
		x[k] = v
	}
	return newTestApp(t, env{token: "orch", extra: x})
}

func TestKeyCreateAsksForTheCardThenClaimsIntoTheFileAndNeverPrintsTheKey(t *testing.T) {
	s := newScripted(t, createRoutes(""))
	ta := keyApp(t, s, nil)
	code := ta.run([]string{"key", "create", "--project", "storefront", "--holder", "scout", "--agent",
		"--ops", "pr.view,pr.diff,pr.view", "--repo", "Example-Org/Storefront", "--ttl", "2d", "--rate", "60",
		"--out", "/home/agent/scout.key", "--wait", "5"})
	if code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, ta.out, ta.errb)
	}
	// The card asks for exactly this, sorted and de-duplicated, in lower case, with every number written out.
	req := s.saw("POST /v0/approvals")
	if len(req) != 1 {
		t.Fatalf("approval requests: %v", req)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(req[0], "POST /v0/approvals ")), &body); err != nil {
		t.Fatal(err)
	}
	params, _ := json.Marshal(body["params"])
	if string(params) != `{"holder":"scout","holder_kind":"agent","ops":["pr.diff","pr.view"],"rate_per_hour":60,"ttl_hours":48,"units":["example-org/storefront"]}` ||
		body["op"] != "keys.issue" || body["kind"] != "op" || body["project"] != "storefront" {
		t.Errorf("request: %s", req[0])
	}
	if got := string(ta.files["/home/agent/scout.key"]); got != testKeyToken+"\n" {
		t.Errorf("the key file holds %q", got)
	}
	all := ta.out.String() + ta.errb.String()
	if strings.Contains(all, testKeyToken) || strings.Contains(all, "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU") {
		t.Errorf("a command printed the key:\n%s", all)
	}
	for _, want := range []string{"card a-000001 is waiting", "key " + testKeyID, "fingerprint ab12cd34", "It is not shown anywhere", "pr.diff, pr.view", "CHAP_KEY_FILE=/home/agent/scout.key"} {
		if !strings.Contains(all, want) {
			t.Errorf("output lacks %q:\n%s", want, all)
		}
	}
}

func TestKeyCreateRefusesBeforeAskingAnything(t *testing.T) {
	s := newScripted(t, createRoutes(""))
	base := []string{"key", "create", "--project", "storefront", "--holder", "scout", "--agent", "--ops", "pr.view", "--repo", "a/b", "--out", "/home/agent/k"}
	with := func(over ...string) []string { return append(append([]string{}, base...), over...) }
	for name, args := range map[string][]string{
		"no out":               {"key", "create", "--project", "storefront", "--holder", "scout", "--agent", "--ops", "pr.view"},
		"holder kind unsaid":   {"key", "create", "--project", "storefront", "--holder", "scout", "--ops", "pr.view", "--out", "/home/agent/k"},
		"both kinds":           with("--person"),
		"a rate of 301":        with("--rate", "301"),
		"a bad ttl":            with("--ttl", "soon"),
		"a bad repo":           with("--repo", "nope"),
		"no ops":               {"key", "create", "--project", "storefront", "--holder", "scout", "--agent", "--out", "/home/agent/k"},
		"an upper-case op":     {"key", "create", "--project", "storefront", "--holder", "scout", "--agent", "--ops", "PR.view", "--out", "/home/agent/k"},
		"a flag that is a key": with("--token", "chap_key_x"),
	} {
		ta := keyApp(t, s, nil)
		if code := ta.run(args); code != exitUsage {
			t.Errorf("%s: exit %d, want %d (%s)", name, code, exitUsage, ta.errb)
		}
	}
	// An existing --out is never overwritten: the claim hands the key over once.
	ta := keyApp(t, s, nil)
	ta.fs["/home/agent/k"] = "something"
	if code := ta.run(base); code != exitUsage || !strings.Contains(ta.errb.String(), "already exists") {
		t.Errorf("existing out: exit %d %s", code, ta.errb)
	}
	if len(s.log) != 0 {
		t.Errorf("chap called chapd before checking its arguments: %v", s.log)
	}
}

func TestKeyCreateStopsCleanlyWhenTheCardIsDenied(t *testing.T) {
	r := createRoutes("")
	r["GET /v0/ops/q-abcdef"] = func(string) (int, string) { return 200, `{"id":"q-abcdef","state":"denied"}` }
	s := newScripted(t, r)
	ta := keyApp(t, s, nil)
	code := ta.run([]string{"key", "create", "--project", "storefront", "--holder", "scout", "--person", "--ops", "health", "--out", "/home/agent/k", "--wait", "5"})
	if code != exitNotOK || len(ta.files) != 0 || len(s.saw("POST /v0/keys")) != 0 {
		t.Errorf("exit %d, files %v, claims %v\n%s", code, ta.files, s.saw("POST /v0/keys"), ta.errb)
	}
	if !strings.Contains(ta.errb.String(), "Nothing was created") {
		t.Errorf("stderr: %s", ta.errb)
	}
}

func TestKeyCreateWithNoWaitLeavesTheCardAndTheNextStep(t *testing.T) {
	s := newScripted(t, createRoutes(""))
	ta := keyApp(t, s, nil)
	code := ta.run([]string{"key", "create", "--project", "storefront", "--holder", "scout", "--agent", "--ops", "health", "--out", "/home/agent/k", "--wait", "0"})
	if code != exitPending || len(s.saw("POST /v0/keys")) != 0 {
		t.Fatalf("exit %d: %s", code, ta.out)
	}
	if !strings.Contains(ta.out.String(), "chap key claim <k-id> --out /home/agent/k") {
		t.Errorf("stdout: %s", ta.out)
	}
}

func TestKeyThatCannotBeWrittenIsRevokedNotLost(t *testing.T) {
	s := newScripted(t, createRoutes(""))
	ta := keyApp(t, s, nil)
	ta.files["/home/agent/k"] = []byte("x") // createFile refuses: the file appeared after the check
	code := ta.run([]string{"key", "claim", testKeyID, "--out", "/home/agent/k"})
	if code != exitFail {
		t.Fatalf("exit %d", code)
	}
	if len(s.saw("POST /v0/keys/"+testKeyID+"/revoke")) != 1 {
		t.Errorf("the unwritable key was not revoked: %v", s.log)
	}
	if strings.Contains(ta.out.String()+ta.errb.String(), "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU") {
		t.Error("the key was printed")
	}
}

func TestKeyClaimTwiceIsAConflictAndWritesNothing(t *testing.T) {
	r := createRoutes("")
	r["POST /v0/keys/"+testKeyID+"/claim"] = func(string) (int, string) {
		return 409, `{"type":"conflict","why":"this key was already claimed; a key is handed over once"}`
	}
	s := newScripted(t, r)
	ta := keyApp(t, s, nil)
	if code := ta.run([]string{"key", "claim", testKeyID, "--out", "/home/agent/k"}); code != exitMissing || len(ta.files) != 0 {
		t.Errorf("exit %d files %v", code, ta.files)
	}
	if !strings.Contains(ta.errb.String(), "handed over once") {
		t.Errorf("stderr: %s", ta.errb)
	}
}

func TestKeyListAndRevoke(t *testing.T) {
	r := createRoutes("")
	r["GET /v0/keys"] = func(string) (int, string) {
		return 200, `{"items":[` + keyJSON(`,"uses":7,"last_used_at":"2026-11-05T15:00:00Z"`) + `]}`
	}
	r["POST /v0/keys/"+testKeyID+"/revoke"] = func(string) (int, string) {
		return 200, keyJSON(`,"state":"revoked","stopped_by_human":true`)
	}
	s := newScripted(t, r)
	ta := keyApp(t, s, nil)
	if code := ta.run([]string{"key", "list"}); code != 0 {
		t.Fatalf("list: %d %s", code, ta.errb)
	}
	for _, want := range []string{"KEY", "agent scout", "pr.diff,pr.view", "example-org/storefront", "7"} {
		if !strings.Contains(ta.out.String(), want) {
			t.Errorf("list lacks %q:\n%s", want, ta.out)
		}
	}
	ta = keyApp(t, s, nil)
	if code := ta.run([]string{"key", "revoke", testKeyID}); code != 0 {
		t.Fatalf("revoke: %d %s", code, ta.errb)
	}
	if !strings.Contains(ta.out.String(), "stopped by a human") || !strings.Contains(ta.out.String(), "its next call is refused") {
		t.Errorf("revoke says:\n%s", ta.out)
	}
	if code := keyApp(t, s, nil).run([]string{"key", "revoke", "k-nope"}); code != exitUsage {
		t.Errorf("a bad id: %d", code)
	}
}

// The key file is a credential after CHAP_RUN_TOKEN and before the orchestrator file; an unreadable or empty key
// file is an error, never a quiet fall back to the orchestrator.
func TestKeyFileIsTheCredentialAfterTheRunToken(t *testing.T) {
	routes := map[string]func(string) (int, string){
		"GET /v0/keys/self": func(string) (int, string) { return 200, keyJSON("") },
	}
	s := newScripted(t, routes)
	files := map[string]string{"/home/agent/scout.key": testKeyToken + "\n"}
	run := func(e env) (*testApp, int) {
		e.extra = map[string]string{"CHAP_URL": s.URL, "CHAP_KEY_FILE": "/home/agent/scout.key"}
		ta := newTestApp(t, e)
		for k, v := range files {
			ta.fs[k] = v
		}
		return ta, ta.run([]string{"key", "show"})
	}
	if ta, code := run(env{token: "orch"}); code != 0 || s.auth[len(s.auth)-1] != "Bearer "+testKeyToken {
		t.Errorf("the key file lost to the orchestrator file: %d %v\n%s", code, s.auth, ta.errb)
	}
	n := len(s.auth)
	if ta, code := run(env{token: "run"}); code != 0 || s.auth[n] != "Bearer "+testRunToken {
		t.Errorf("CHAP_RUN_TOKEN did not win: %d %v\n%s", code, s.auth[n:], ta.errb)
	}
	ta, code := run(env{token: "orch"})
	if code != 0 || !strings.Contains(ta.out.String(), "key "+testKeyID) || strings.Contains(ta.out.String(), testKeyToken) {
		t.Errorf("show: %d\n%s", code, ta.out)
	}
	files["/home/agent/scout.key"] = "\n"
	before := len(s.auth)
	if ta, code := run(env{token: "orch"}); code != exitAuth || len(s.auth) != before || !strings.Contains(ta.errb.String(), "is empty") {
		t.Errorf("empty key file: %d %s", code, ta.errb)
	}
	delete(files, "/home/agent/scout.key")
	if ta, code := run(env{token: "orch"}); code != exitAuth || len(s.auth) != before || !strings.Contains(ta.errb.String(), "cannot be read") {
		t.Errorf("missing key file: %d %s", code, ta.errb)
	}
}

// A key that reaches a reply anyway is masked in what chap prints.
func TestTheScrubberMasksAKeyInAnyOutput(t *testing.T) {
	routes := map[string]func(string) (int, string){
		"GET /v0/keys/self": func(string) (int, string) {
			return 403, `{"type":"denial","spec_version":"0","denial_id":"d-1","project":"p","at":"2026-11-05T16:00:00Z","surface":"op","action":{"verb":"v","target":"t"},"cause_code":"OP_NOT_IN_TOKEN","why":"echo ` + testKeyToken + `","request":{"possible":false},"thrash":{"count":1,"window_seconds":300,"flagged":false},"policy_version":"v"}`
		},
	}
	s := newScripted(t, routes)
	ta := newTestApp(t, env{token: "orch", extra: map[string]string{"CHAP_URL": s.URL, "CHAP_KEY_FILE": "/k"}})
	ta.fs["/k"] = testKeyToken
	ta.run([]string{"key", "show"})
	if all := ta.out.String() + ta.errb.String(); strings.Contains(all, "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU") {
		t.Errorf("the key was printed:\n%s", all)
	}
	// And with no registered secret at all, the shape alone is masked.
	if got := ta.scrub("x " + "chap_key_" + strings.Repeat("A", 43) + " y"); strings.Contains(got, "chap_key_AAAA") {
		t.Errorf("scrub left a key-shaped value: %q", got)
	}
}
