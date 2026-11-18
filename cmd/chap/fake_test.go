package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/api"
)

var update = flag.Bool("update", false, "rewrite the golden files")

const (
	testRunToken  = "eyJhbGciOiJFZERTQSJ9.eyJydW4iOiJyLTdmM2EifQ.c2lnbmF0dXJlc2lnbmF0dXJl"
	testOrchToken = "chap_orch_Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZjAxMjM0"
)

// answer is what the fake chapd says to every request of one test case.
//
// fixture names:
//
//	"api:<name>"    api/examples/<name>.json, the contract's own example
//	"catalog:<p>"   a Catalog built from api/manual.yaml for profile p
//	"<name>"        testdata/chapd/<name>.json
type answer struct {
	status  int
	fixture string
	header  map[string]string
}

// fakeChapd is an httptest chapd. It records each request as text and replies
// with the case's fixture; it checks nothing about the caller beyond which
// kind of credential arrived, so the golden file shows what chap sent.
type fakeChapd struct {
	*httptest.Server
	ans  answer
	reqs []string
	// auth is the Authorization header of each request, for tests that check
	// which token was used.
	auth []string
}

func newFakeChapd(t *testing.T, ans answer) *fakeChapd {
	f := &fakeChapd{ans: ans}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		hdr := r.Header.Get("Authorization")
		f.auth = append(f.auth, hdr)
		kind := "none"
		switch {
		case strings.HasPrefix(hdr, "Bearer chap_orch_"):
			kind = "orchestrator"
		case strings.HasPrefix(hdr, "Bearer "):
			kind = "run"
		}
		line := r.Method + " " + r.URL.RequestURI() + "\nauth: " + kind
		if len(bytes.TrimSpace(body)) > 0 {
			var c bytes.Buffer
			if err := json.Compact(&c, body); err != nil {
				t.Errorf("chap sent a body that is not JSON: %s", body)
			}
			line += "\n" + c.String()
		}
		f.reqs = append(f.reqs, line)
		data := loadFixture(t, f.ans.fixture)
		data = bytes.ReplaceAll(data, []byte("@TOKEN@"), []byte(testRunToken))
		data = bytes.ReplaceAll(data, []byte("@ORCH@"), []byte(testOrchToken))
		w.Header().Set("Content-Type", "application/json")
		for k, v := range f.ans.header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(f.ans.status)
		w.Write(data)
	}))
	t.Cleanup(f.Close)
	return f
}

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	switch {
	case strings.HasPrefix(name, "api:"):
		b, err := api.Files.ReadFile("examples/" + strings.TrimPrefix(name, "api:") + ".json")
		if err != nil {
			t.Fatal(err)
		}
		return b
	case strings.HasPrefix(name, "catalog:"):
		return catalogFixture(t, strings.TrimPrefix(name, "catalog:"))
	default:
		b, err := os.ReadFile(filepath.Join("testdata", "chapd", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
}

// profileOps is which ops each profile may use in the test catalog. The
// real mapping is policy data in chapd; the text of each op is api/manual.yaml.
var profileOps = map[string][]string{
	"docs":  {"pr.open", "pr.update", "health", "logs"},
	"code":  {"pr.open", "pr.update", "pr.merge", "branch.push", "health", "logs", "deploy"},
	"worst": {"pr.open", "pr.update", "pr.merge", "health"},
}

// manualEntry is one op of api/manual.yaml.
type manualEntry map[string]string

// parseManual reads manual.yaml, which is flat enough to need no YAML parser:
// `  <op>:` opens an entry, `    key: value` fills it.
func parseManual(t *testing.T) map[string]manualEntry {
	t.Helper()
	data, err := api.Files.ReadFile("manual.yaml")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]manualEntry{}
	var cur manualEntry
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "    ") && cur != nil:
			k, v, _ := strings.Cut(strings.TrimSpace(line), ": ")
			cur[k] = v
		case strings.HasPrefix(line, "  ") && strings.HasSuffix(line, ":") && !strings.HasPrefix(line, "   "):
			cur = manualEntry{}
			out[strings.TrimSuffix(strings.TrimSpace(line), ":")] = cur
		case !strings.HasPrefix(line, " "):
			cur = nil
		}
	}
	return out
}

func catalogFixture(t *testing.T, profile string) []byte {
	t.Helper()
	manual := parseManual(t)
	ops := profileOps[profile]
	if ops == nil {
		t.Fatalf("no ops for profile %q", profile)
	}
	sort.Strings(ops)
	var entries []map[string]any
	for _, name := range ops {
		e, ok := manual[name]
		if !ok {
			t.Fatalf("manual.yaml has no op %q", name)
		}
		entries = append(entries, map[string]any{
			"op": name, "class": e["class"], "reversibility": e["reversibility"], "surface": e["surface"],
			"enabled": true, "needs_approval": e["class"] == "high" || e["class"] == "critical",
			"summary": e["summary"], "usage": e["usage"],
		})
	}
	cat := map[string]any{"policy_version": "baseline-2026.10.1", "project": "acme-shop", "ops": entries}
	if profile == "docs" || profile == "code" {
		cat["profile"] = profile
	}
	b, err := json.Marshal(cat)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const testConfigDir = "/home/agent/.config"

// testApp is chap wired to a fake chapd and in-memory everything else.
type testApp struct {
	*app
	out, errb *bytes.Buffer
	gitCalls  []string
	files     map[string][]byte // written by createFile
	fs        map[string]string // read by readFile
}

type env struct {
	chapd  *fakeChapd
	token  string            // "run" (default), "orch" (via the token file) or "none"
	git    map[string]string // "config --get remote.origin.url" -> output
	stdin  string
	fs     map[string]string
	extra  map[string]string // more environment variables
	notURL bool              // do not set CHAP_URL
	tty    bool              // stderr is a terminal
}

func newTestApp(t *testing.T, e env) *testApp {
	t.Helper()
	ta := &testApp{out: &bytes.Buffer{}, errb: &bytes.Buffer{}, files: map[string][]byte{}, fs: map[string]string{}}
	for k, v := range e.fs {
		ta.fs[k] = v
	}
	vars := map[string]string{}
	if e.chapd != nil && !e.notURL {
		vars["CHAP_URL"] = e.chapd.URL
	}
	const orchFile = "/home/agent/orchestrator.token"
	switch e.token {
	case "", "run":
		vars["CHAP_RUN_TOKEN"] = testRunToken
	case "orch":
		vars["CHAP_ORCHESTRATOR_TOKEN_FILE"] = orchFile
		ta.fs[orchFile] = testOrchToken + "\n"
	case "none":
		vars["CHAP_ORCHESTRATOR_TOKEN_FILE"] = "/home/agent/missing.token"
	}
	for k, v := range e.extra {
		vars[k] = v
	}
	ta.app = &app{
		stdout: ta.out, stderr: ta.errb, stdin: strings.NewReader(e.stdin),
		getenv: func(k string) string { return vars[k] },
		readFile: func(p string) ([]byte, error) {
			if s, ok := ta.fs[p]; ok {
				return []byte(s), nil
			}
			return nil, os.ErrNotExist
		},
		createFile: func(p string, data []byte) error {
			if _, ok := ta.files[p]; ok {
				return os.ErrExist
			}
			ta.files[p] = data
			return nil
		},
		git: func(args ...string) (string, error) {
			key := strings.Join(args, " ")
			ta.gitCalls = append(ta.gitCalls, "git "+key)
			if out, ok := e.git[key]; ok {
				return out, nil
			}
			if strings.HasPrefix(key, "config --local --") || strings.HasPrefix(key, "config --global --") {
				return "", nil
			}
			return "", fmt.Errorf("git %s: not available in the test", key)
		},
		client:    &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		stderrTTY: func() bool { return e.tty },
		configDir: func() (string, error) { return testConfigDir, nil },
		mkdirAll:  func(string) error { return nil },
	}
	return ta
}
