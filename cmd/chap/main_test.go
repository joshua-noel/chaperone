package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"version"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	if !strings.HasPrefix(out.String(), "chap ") {
		t.Fatalf("stdout %q does not start with the binary name", out.String())
	}
	if errb.Len() != 0 {
		t.Fatalf("stderr %q, want empty", errb.String())
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{nil, {"bogus"}, {"version", "extra"}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 2 {
			t.Errorf("args %q: exit %d, want 2", args, code)
		}
		if out.Len() != 0 || errb.Len() == 0 {
			t.Errorf("args %q: stdout %q, stderr %q", args, out.String(), errb.String())
		}
	}
}

// The credential is CHAP_RUN_TOKEN, else the orchestrator token file
// (ADR-007 item 6): the run token wins when both exist.
func TestTokenPrecedence(t *testing.T) {
	chapd := newFakeChapd(t, *ok200("op-health"))
	ta := newTestApp(t, env{chapd: chapd, token: "run", fs: map[string]string{"/home/agent/orchestrator.token": testOrchToken}})
	ta.getenv = func(k string) string {
		switch k {
		case "CHAP_URL":
			return chapd.URL
		case "CHAP_RUN_TOKEN":
			return testRunToken
		case "CHAP_ORCHESTRATOR_TOKEN_FILE":
			return "/home/agent/orchestrator.token"
		}
		return ""
	}
	ta.fs["/home/agent/orchestrator.token"] = testOrchToken + "\n"
	if code := ta.run([]string{"health"}); code != 0 {
		t.Fatalf("exit %d: %s", code, ta.errb)
	}
	if got := chapd.auth[0]; got != "Bearer "+testRunToken {
		t.Errorf("sent %q with both credentials present, want the run token", got)
	}

	chapd = newFakeChapd(t, *ok200("op-health"))
	ta = newTestApp(t, env{chapd: chapd, token: "orch"})
	if code := ta.run([]string{"health"}); code != 0 {
		t.Fatalf("exit %d: %s", code, ta.errb)
	}
	if got := chapd.auth[0]; got != "Bearer "+testOrchToken {
		t.Errorf("sent %q, want the orchestrator token from the file", got)
	}
}

// A missing or unusable token is a plain error that names the file and never
// a token, and nothing is sent.
func TestTokenProblems(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"missing":    nil,
		"empty":      {"/home/agent/orchestrator.token": "  \n"},
		"multi-word": {"/home/agent/orchestrator.token": "chap_orch_aaaa bbbb\n"},
	} {
		t.Run(name, func(t *testing.T) {
			chapd := newFakeChapd(t, *ok200("op-health"))
			ta := newTestApp(t, env{chapd: chapd, token: "none", fs: files})
			ta.getenv = func(k string) string {
				switch k {
				case "CHAP_URL":
					return chapd.URL
				case "CHAP_ORCHESTRATOR_TOKEN_FILE":
					return "/home/agent/orchestrator.token"
				}
				return ""
			}
			if code := ta.run([]string{"health"}); code != exitAuth {
				t.Fatalf("exit %d, want %d", code, exitAuth)
			}
			if len(chapd.reqs) != 0 {
				t.Errorf("chap called chapd without a token: %v", chapd.reqs)
			}
			msg := ta.errb.String()
			if !strings.Contains(msg, "orchestrator.token") || strings.Contains(msg, "aaaa") || strings.Contains(msg, "bbbb") {
				t.Errorf("stderr %q", msg)
			}
		})
	}
}

// No flag accepts a secret: no flag of any command is named like one, and a
// token on the command line is refused without echoing it.
func TestNoFlagAcceptsASecret(t *testing.T) {
	secretish := regexp.MustCompile(`(?i)token|secret|password|passwd|credential|key|bearer|auth`)
	flagLine := regexp.MustCompile(`(?m)^\s+-([A-Za-z][A-Za-z0-9-]*)`)
	cmds := commands()
	if len(cmds) < 20 {
		t.Fatalf("only %d commands", len(cmds))
	}
	for _, c := range cmds {
		ta := newTestApp(t, env{})
		if code := ta.run(append(strings.Fields(c.path), "--help")); code != 0 {
			t.Errorf("%s --help: exit %d, stderr %q", c.path, code, ta.errb)
			continue
		}
		flags := flagLine.FindAllStringSubmatch(ta.out.String(), -1)
		if len(flags) == 0 {
			t.Errorf("%s --help lists no flags:\n%s", c.path, ta.out)
		}
		for _, m := range flags {
			if secretish.MatchString(m[1]) {
				t.Errorf("%s has a flag named like a secret: --%s", c.path, m[1])
			}
		}
	}
	for _, args := range [][]string{
		{"health", "--token", "SECRETVALUE123"},
		{"health", "--token=SECRETVALUE123"},
		{"pr", "merge", "1", "--bearer", "SECRETVALUE123"},
	} {
		chapd := newFakeChapd(t, *ok200("op-health"))
		ta := newTestApp(t, env{chapd: chapd})
		if code := ta.run(args); code != exitUsage {
			t.Errorf("%v: exit %d, want %d", args, code, exitUsage)
		}
		if strings.Contains(ta.out.String()+ta.errb.String(), "SECRETVALUE123") || len(chapd.reqs) != 0 {
			t.Errorf("%v echoed the value or called chapd", args)
		}
	}
}

// `chap manual --profile docs` lists only that profile's ops and fits in 1 KB.
func TestManualProfileDocsUnder1KB(t *testing.T) {
	chapd := newFakeChapd(t, *ok200("catalog:docs"))
	ta := newTestApp(t, env{chapd: chapd})
	if code := ta.run([]string{"manual", "--profile", "docs"}); code != 0 {
		t.Fatalf("exit %d: %s", code, ta.errb)
	}
	out := ta.out.String()
	if n := len(out); n >= 1024 {
		t.Errorf("manual is %d bytes, want under 1024:\n%s", n, out)
	}
	if !strings.Contains(chapd.reqs[0], "profile=docs") {
		t.Errorf("request %q does not ask for profile docs", chapd.reqs[0])
	}
	manual := parseManual(t)
	for _, name := range profileOps["docs"] {
		if !strings.Contains(out, manual[name]["usage"]) || !strings.Contains(out, manual[name]["summary"]) {
			t.Errorf("manual lacks the text of %s:\n%s", name, out)
		}
	}
	for name := range manual {
		if !contains(profileOps["docs"], name) && strings.Contains(out, name+" [") {
			t.Errorf("manual lists %s, which the docs profile does not enable", name)
		}
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// The size rule of manual.yaml (summary <= 60, usage <= 100) leaves room for
// a four-op profile in 1 KB even when every text is at its limit.
func TestManualWorstCaseUnder1KB(t *testing.T) {
	var entries []string
	for _, name := range []string{"pr.update", "pr.merge", "host.scripts.refresh", "policy.activate"} {
		entries = append(entries, fmt.Sprintf(`{"op":%q,"class":"critical","reversibility":"compensable","surface":"op","enabled":true,"needs_approval":true,"summary":%q,"usage":%q}`,
			name, strings.Repeat("s", 60), strings.Repeat("u", 100)))
	}
	body := `{"policy_version":"baseline-2026.10.1","project":"acme-shop-long-name-here","profile":"docs","ops":[` + strings.Join(entries, ",") + `]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
	defer srv.Close()
	ta := newTestApp(t, env{extra: map[string]string{"CHAP_URL": srv.URL}, notURL: true})
	if code := ta.run([]string{"manual", "--profile", "docs"}); code != 0 {
		t.Fatalf("exit %d: %s", code, ta.errb)
	}
	if n := ta.out.Len(); n >= 1024 {
		t.Errorf("worst-case manual is %d bytes, want under 1024", n)
	}
}

// dev-token returns the one secret chapd hands out. It goes to the file and
// nowhere else.
func TestDevTokenWritesFileOnly(t *testing.T) {
	chapd := newFakeChapd(t, answer{status: 201, fixture: "devtoken"})
	ta := newTestApp(t, env{chapd: chapd, token: "orch"})
	args := []string{"dev-token", "--project", "acme-shop", "--repo", "acme/shop", "--branch", "agent/r-9a2b", "--path", "docs/**", "--op", "pr.open", "--out", "run.token"}
	if code := ta.run(args); code != 0 {
		t.Fatalf("exit %d: %s", code, ta.errb)
	}
	want := string(loadFixture(t, "devtoken"))
	i := strings.Index(want, `"token":"`) + len(`"token":"`)
	token := want[i : i+strings.Index(want[i:], `"`)]
	if got := string(ta.files["run.token"]); got != token+"\n" {
		t.Errorf("file holds %q, want the token and a newline", got)
	}
	if strings.Contains(ta.out.String()+ta.errb.String(), token) || strings.Contains(ta.out.String()+ta.errb.String(), token[:20]) {
		t.Errorf("the token reached the terminal:\n%s%s", ta.out, ta.errb)
	}
	// A second run must not overwrite the file: the file exists, the new
	// token is lost, and chap says how to clean up.
	ta2 := newTestApp(t, env{chapd: newFakeChapd(t, answer{status: 201, fixture: "devtoken"}), token: "orch"})
	ta2.files["run.token"] = []byte("old\n")
	if code := ta2.run(args); code != exitFail {
		t.Errorf("exit %d, want %d when the file exists", code, exitFail)
	}
	if !strings.Contains(ta2.errb.String(), "chap runs revoke r-9a2b") || strings.Contains(ta2.errb.String()+ta2.out.String(), token[:20]) {
		t.Errorf("stderr %q", ta2.errb)
	}
	if string(ta2.files["run.token"]) != "old\n" {
		t.Error("the existing file was overwritten")
	}
}

// The bearer token is only ever sent to the address it was loaded for: a
// redirect is not followed.
func TestRedirectIsNotFollowed(t *testing.T) {
	var leaked []string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = append(leaked, r.Header.Get("Authorization"))
	}))
	defer other.Close()
	chapd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/v0/ops", http.StatusTemporaryRedirect)
	}))
	defer chapd.Close()
	ta := newTestApp(t, env{extra: map[string]string{"CHAP_URL": chapd.URL}, notURL: true})
	if code := ta.run([]string{"health"}); code != exitFail {
		t.Errorf("exit %d, want %d", code, exitFail)
	}
	if len(leaked) != 0 {
		t.Errorf("the redirect target received %v", leaked)
	}
}

func TestChapdUnreachableIsUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	ta := newTestApp(t, env{extra: map[string]string{"CHAP_URL": url}, notURL: true})
	if code := ta.run([]string{"health"}); code != exitUnavailable {
		t.Errorf("exit %d, want %d; stderr %q", code, exitUnavailable, ta.errb)
	}
	if !strings.Contains(ta.errb.String(), "nothing ran") {
		t.Errorf("stderr %q", ta.errb)
	}
}

// CHAP_URL takes loopback addresses only; the default is chapd's own.
func TestBaseURL(t *testing.T) {
	for url, want := range map[string]string{
		"":                       defaultURL,
		"http://127.0.0.1:1234":  "http://127.0.0.1:1234",
		"http://localhost:55398": "http://localhost:55398",
		"http://[::1]:55398/":    "http://[::1]:55398",
	} {
		ta := newTestApp(t, env{extra: map[string]string{"CHAP_URL": url}, notURL: true})
		got, err := ta.baseURL()
		if err != nil || got != want {
			t.Errorf("CHAP_URL %q: %q, %v; want %q", url, got, err, want)
		}
	}
	for _, url := range []string{"http://example.com", "http://10.0.0.5:55398", "ftp://127.0.0.1", "http://user:pw@127.0.0.1:1", "http://127.0.0.1:1/x", "127.0.0.1:55398", "http://127.0.0.1.evil.com:1"} {
		ta := newTestApp(t, env{extra: map[string]string{"CHAP_URL": url}, notURL: true})
		if got, err := ta.baseURL(); err == nil {
			t.Errorf("CHAP_URL %q accepted as %q", url, got)
		}
	}
}

// Every exit code is reachable and distinct for its meaning (the golden
// files pin the output; this pins the numbers scripts rely on).
func TestExitCodes(t *testing.T) {
	for name, want := range map[string]int{
		"pr-merge": 0, "pr-merge-refused": exitNotOK, "pr-merge-dry-run-approval": exitPending,
		"pr-merge-denied-orchestrator": exitDenied, "denied-token-revoked": exitAuth, "auth-error": exitAuth,
		"unavailable": exitUnavailable, "op-show-not-found": exitMissing, "op-show-conflict": exitMissing,
		"deploy-executing": exitPending, "deploy-unconfirmed": exitPending, "request-op": 0,
		"ledger-verify-broken": exitNotOK, "health-rate-limited": exitDenied, "pr-open-no-title": exitUsage,
		"request-net": exitDenied, "no-token": exitAuth,
	} {
		var tc *golden
		for i := range goldenCases {
			if goldenCases[i].name == name {
				tc = &goldenCases[i]
			}
		}
		if tc == nil {
			t.Fatalf("no case %q", name)
		}
		e := tc.env
		if tc.ans != nil {
			e.chapd = newFakeChapd(t, *tc.ans)
		}
		if got := newTestApp(t, e).run(tc.args); got != want {
			t.Errorf("%s: exit %d, want %d", name, got, want)
		}
	}
}

// chap cannot know the vault's values, but it masks anything shaped like a
// credential on its way out, whatever chapd sent.
func TestScrubMasksSecretShapes(t *testing.T) {
	a := &app{}
	ghp := "ghp_" + strings.Repeat("a1B2c3D4e", 4)
	for name, in := range map[string]string{
		"a GitHub token": "why: token " + ghp + " was sent",
		"a PEM block":    "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----",
		"an Anthropic":   "key sk-ant-" + strings.Repeat("x9", 15),
	} {
		got := a.scrub(in)
		if strings.Contains(got, "a1B2c3D4e") || strings.Contains(got, "MIIEvQ") || strings.Contains(got, "x9x9") {
			t.Errorf("%s: %q", name, got)
		}
	}
	if got := a.scrub("DENIED op health (profile code)"); got != "DENIED op health (profile code)" {
		t.Errorf("ordinary text changed: %q", got)
	}
}
