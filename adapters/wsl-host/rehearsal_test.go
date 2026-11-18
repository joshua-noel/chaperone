// Package wslhost holds the rehearsal of the `deploy` op against a throwaway,
// pilot-like target (ticket L1-15 acceptance: "a rehearsal against a
// throw-away pilot-like target (named in the PR) before any live use").
//
// The throwaway target is made of three stand-ins, all local to this test:
//
//   - a fake pilot: an HTTP server on the loopback that answers
//     /api/health/ready like the real one (and refuses a request that lacks the
//     Host or X-Forwarded-Proto header);
//   - rehearsal/pilot.sh, a script that prints what the real runbook does and
//     changes nothing;
//   - a host emulator that does what chap-host does: it takes the grant from
//     chapd's event stream, verifies it under the pinned key and against the
//     script's hash, runs the script locally with bash and reports back.
//
// chapd's side is real code: the deploy adapter, the policy checks over a fake
// GitHub (ghtest), the real [ops.PilotHealth] over HTTP, and the real
// [ops.HostBus] with its HTTP routes. No WSL, Docker, Windows account or live
// pilot is touched. The first live deploy is operator-attended, later.
package wslhost

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
	"github.com/joshua-noel/chaperone/internal/grant"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/spec"
)

const (
	base      = "feat/d1-private-pilot"
	hostToken = "rehearsal-host-token-0123456789"
)

// fakePilot is the throwaway pilot: ready or not, and a record of the deploys
// the host emulator ran against it.
type fakePilot struct {
	srv *httptest.Server

	mu      sync.Mutex
	ready   bool
	badHdr  int // requests that lacked the headers the real fence needs
	deploys []string
}

func newFakePilot(t *testing.T) *fakePilot {
	t.Helper()
	p := &fakePilot{ready: true}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		if r.Method != http.MethodGet || r.URL.Path != "/api/health/ready" || r.Host != "pilot.storefront.net" || r.Header.Get("X-Forwarded-Proto") != "https" {
			p.badHdr++
			http.NotFound(w, r)
			return
		}
		if !p.ready {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"checks":{"auth":false,"database":true},"service":"web","status":"unavailable"}`))
			return
		}
		_, _ = w.Write([]byte(`{"checks":{"auth":true,"database":true},"service":"web","status":"ok"}`))
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakePilot) set(ready bool) {
	p.mu.Lock()
	p.ready = ready
	p.mu.Unlock()
}

// hostEmulator is chap-host in a test: verify, run the script, report.
type hostEmulator struct {
	t        *testing.T
	chapd    string
	script   string // the script chapd hashed into the grant
	verifier *grant.Verifier
	pilot    *fakePilot

	mu         sync.Mutex
	failScript map[string]bool // SHAs whose runbook exits 3
	badBuild   map[string]bool // SHAs whose runbook succeeds and whose pilot never comes back
}

func (h *hostEmulator) mark(set *map[string]bool, sha string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if *set == nil {
		*set = map[string]bool{}
	}
	(*set)[sha] = true
}

func (h *hostEmulator) is(set map[string]bool, sha string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return set[sha]
}

func (h *hostEmulator) run(ctx context.Context) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, h.chapd+"/v0/host/events", nil)
	req.Header.Set("Authorization", "Bearer "+hostToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	var name, data string
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			name = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			data = strings.TrimPrefix(line, "data: ")
		case line == "":
			if name == "grant" {
				h.take(ctx, data)
			}
			name, data = "", ""
		}
	}
}

func (h *hostEmulator) post(ctx context.Context, path, ctype string, body []byte) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, h.chapd+path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+hostToken)
	req.Header.Set("Content-Type", ctype)
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
	}
}

func (h *hostEmulator) take(ctx context.Context, data string) {
	var ev struct {
		Grant string `json:"grant"`
		OpID  string `json:"op_id"`
	}
	if err := json.Unmarshal([]byte(data), &ev); err != nil {
		h.t.Errorf("bad grant event: %v", err)
		return
	}
	result := func(outcome, code string, exit int) {
		b, _ := json.Marshal(map[string]any{"exit_code": exit, "outcome": outcome, "code": code})
		if code == "" {
			b, _ = json.Marshal(map[string]any{"exit_code": exit, "outcome": outcome})
		}
		h.post(ctx, "/v0/host/runs/"+ev.OpID+"/result", "application/json", b)
	}
	g, err := h.verifier.Verify(ev.Grant)
	if err != nil {
		result("refused", grant.CodeOf(err), 0)
		return
	}
	src, err := os.ReadFile(h.script)
	if err != nil || grant.HashBytes(src) != g.ScriptSHA256 {
		result("refused", grant.ErrScript.Code, 0)
		return
	}
	copyPath := filepath.Join(h.t.TempDir(), "runbook.sh")
	if err := os.WriteFile(copyPath, src, 0o700); err != nil {
		result("failed", "", 1)
		return
	}
	sha := g.Args["sha"]
	h.pilot.set(false) // the web unit restarts while the runbook deploys
	cmd := exec.CommandContext(ctx, "bash", copyPath, "deploy", sha)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	if h.is(h.failScript, sha) {
		cmd.Env = append(cmd.Env, "REHEARSAL_FAIL=1")
	}
	out, err := cmd.CombinedOutput()
	h.post(ctx, "/v0/host/runs/"+ev.OpID+"/output", "application/octet-stream", out)
	exit := 0
	if err != nil {
		exit = 1
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		}
	}
	if exit == 0 {
		h.pilot.mu.Lock()
		h.pilot.deploys = append(h.pilot.deploys, sha)
		h.pilot.mu.Unlock()
		// A bad build: the runbook says success, the pilot never comes back.
		h.pilot.set(!h.is(h.badBuild, sha))
		result("succeeded", "", 0)
		return
	}
	h.pilot.set(true) // a failed runbook leaves the old version running
	result("failed", "", exit)
}

type target struct {
	t      *testing.T
	gh     *ghtest.Server
	repo   *ghtest.Repo
	pilot  *fakePilot
	host   *hostEmulator
	d      *ops.Deploy
	dir    string
	alerts *alertSink
}

type alertSink struct {
	mu    sync.Mutex
	texts []string
}

func (a *alertSink) RaiseDeployAlert(_ context.Context, key, text string) {
	a.mu.Lock()
	a.texts = append(a.texts, key+": "+text)
	a.mu.Unlock()
}

func (a *alertSink) got() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.texts...)
}

func newTarget(t *testing.T) *target {
	t.Helper()
	bashPath, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	if strings.Contains(strings.ToLower(filepath.ToSlash(bashPath)), "/windows/system32/") {
		// On a Windows PC that bash is WSL's, and a rehearsal must not reach any distro.
		t.Skip("bash on PATH is the WSL launcher; the rehearsal never runs in a WSL distro")
	}
	x := &target{t: t, dir: t.TempDir(), alerts: &alertSink{}}

	x.gh = ghtest.New(t)
	c, err := gh.New(gh.Config{AppID: x.gh.AppID(), Keys: gh.StaticKey{Key: x.gh.Key()}, BaseURL: x.gh.URL(), Now: x.gh.Now})
	if err != nil {
		t.Fatal(err)
	}
	in := x.gh.AddInstallation(7, "example-org", map[string]string{
		"contents": "write", "pull_requests": "write", "checks": "read", "deployments": "write", "metadata": "read",
	})
	x.repo = in.AddRepo("storefront", base)

	x.pilot = newFakePilot(t)
	health, err := ops.NewPilotHealth(ops.PilotHealthConfig{URL: x.pilot.srv.URL + "/api/health/ready"})
	if err != nil {
		t.Fatal(err)
	}

	script, err := filepath.Abs(filepath.Join("rehearsal", "pilot.sh"))
	if err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(x.dir, "host.token")
	if err := os.WriteFile(tokenFile, []byte(hostToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bus, err := ops.NewHostBus(ops.HostBusConfig{
		Signer: ops.StaticGrantSigner(key), Scripts: map[string]string{ops.DeployRunbook: script}, TokenFile: tokenFile,
		KeepAlive: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	chapd := httptest.NewServer(bus.Handler())
	t.Cleanup(chapd.Close)

	verifier, err := grant.NewVerifier(pub, grant.NewMemoryNonces())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	x.host = &hostEmulator{t: t, chapd: chapd.URL, script: script, verifier: verifier, pilot: x.pilot}
	go x.host.run(ctx)

	now := time.Now()
	write := func(name, doc string) {
		if err := os.WriteFile(filepath.Join(x.dir, name), []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("load-gate.json", fmt.Sprintf(`{"mode":"normal","checkedAt":%q}`, now.Add(-time.Minute).Format(time.RFC3339Nano)))
	write("last-valid-backup.json", fmt.Sprintf(`{"validatedAt":%q,"file":"pilot-2026-10-24_0300.dump","bytes":3448020,"entries":2555}`, now.Add(-2*time.Hour).Format(time.RFC3339)))

	x.d, err = ops.NewDeploy(ops.DeployConfig{
		GitHub: c, Tokens: &ops.InstallationMinter{Client: c},
		Policy: func(string) (ops.DeployPolicy, bool) {
			return ops.DeployPolicy{PR: ops.PRPolicy{Version: "rehearsal", Repo: "example-org/storefront", Base: base}}, true
		},
		Facts:  ops.HostFacts{GatePath: filepath.Join(x.dir, "load-gate.json"), BackupPath: filepath.Join(x.dir, "last-valid-backup.json")},
		Health: health, Host: bus, Alert: x.alerts,
		PostHealthWait: 2 * time.Second, PostHealthEvery: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return x
}

// commit makes a commit on the base with a green verify.
func (x *target) commit() string {
	sha := x.repo.Commit(base)
	x.repo.SetCheck(sha, ghtest.Check{Name: "verify", AppID: gh.GitHubActionsAppID, Status: "completed", Conclusion: "success"})
	return sha
}

func (x *target) request(sha string) *ops.Request {
	return &ops.Request{
		ID: "q-000001", Op: "deploy", Project: "storefront", OpHash: "sha256:" + strings.Repeat("a", 64),
		Target: spec.Target{Adapter: "wsl-host", Ref: "pilot"}, Params: map[string]any{"sha": sha},
		Caller: &ops.Caller{Kind: ops.KindRun, RunID: "r-7f3a", Project: "storefront"},
	}
}

func TestRehearsalGoodDeploy(t *testing.T) {
	x := newTarget(t)
	sha := x.commit()
	req := x.request(sha)

	cr, err := x.d.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(cr.Checks) != 5 {
		t.Errorf("checks = %+v", cr.Checks)
	}
	out, err := x.d.Execute(context.Background(), req)
	if err != nil || out.Failed || out.Unconfirmed {
		t.Fatalf("execute: %+v %v", out, err)
	}
	if got := x.pilot.deploys; len(got) != 1 || got[0] != sha {
		t.Fatalf("the script ran for %v, want [%s]", got, sha)
	}
	tail, _ := out.Result["output_tail"].(string)
	for _, want := range []string{"changelog assembly for " + sha, "migration rehearsal ok", "deploy ok"} {
		if !strings.Contains(tail, want) {
			t.Errorf("output tail lacks %q: %q", want, tail)
		}
	}
	if out.Result["host_outcome"] != ops.HostSucceeded || out.Result["health_after"] != ops.HealthOK {
		t.Errorf("result = %v", out.Result)
	}
	deps := x.repo.Deployments()
	if len(deps) != 1 || deps[0].SHA != sha || deps[0].Statuses[len(deps[0].Statuses)-1] != gh.DeploySuccess {
		t.Errorf("deployments = %+v", deps)
	}
	if x.pilot.badHdr != 0 {
		t.Errorf("%d readiness request(s) lacked the headers the real fence needs", x.pilot.badHdr)
	}
	if len(x.alerts.got()) != 0 {
		t.Errorf("alerts = %v", x.alerts.got())
	}
	if x.gh.LiveTokens() != 0 {
		t.Errorf("%d token(s) left live", x.gh.LiveTokens())
	}
}

func TestRehearsalRunbookFailure(t *testing.T) {
	x := newTarget(t)
	sha := x.commit()
	x.host.mark(&x.host.failScript, sha)
	out, err := x.d.Execute(context.Background(), x.request(sha))
	if err != nil || !out.Failed || out.Unconfirmed {
		t.Fatalf("out = %+v err = %v", out, err)
	}
	if out.Result["host_outcome"] != ops.HostFailed || out.Result["exit_code"] != 3 || out.Result["health_after"] != ops.HealthOK {
		t.Errorf("result = %v", out.Result)
	}
	if tail, _ := out.Result["output_tail"].(string); !strings.Contains(tail, "deploy step failed") {
		t.Errorf("output tail = %q", tail)
	}
	if len(x.pilot.deploys) != 0 {
		t.Errorf("a failed runbook recorded a deploy: %v", x.pilot.deploys)
	}
	if al := x.alerts.got(); len(al) != 1 || !strings.Contains(al[0], "exit 3") {
		t.Errorf("alerts = %v", al)
	}
	deps := x.repo.Deployments()
	if len(deps) != 1 || deps[0].Statuses[len(deps[0].Statuses)-1] != gh.DeployFailure {
		t.Errorf("deployments = %+v", deps)
	}
}

// The runbook says success and the pilot does not come back: failed, with an alert.
func TestRehearsalBadBuildLeavesThePilotDown(t *testing.T) {
	x := newTarget(t)
	sha := x.commit()
	x.host.mark(&x.host.badBuild, sha)
	out, err := x.d.Execute(context.Background(), x.request(sha))
	if err != nil || !out.Failed || out.Unconfirmed {
		t.Fatalf("out = %+v err = %v: a pilot that is down after the deploy is failed", out, err)
	}
	if out.Result["host_outcome"] != ops.HostSucceeded || out.Result["health_after"] != ops.HealthUnavailable {
		t.Errorf("result = %v", out.Result)
	}
	if al := x.alerts.got(); len(al) != 1 || !strings.Contains(al[0], "unavailable after the deploy") {
		t.Errorf("alerts = %v", al)
	}
	deps := x.repo.Deployments()
	if len(deps) != 1 || deps[0].Statuses[len(deps[0].Statuses)-1] != gh.DeployFailure {
		t.Errorf("deployments = %+v", deps)
	}
}

func TestRehearsalUnhealthyPilotStopsBeforeTheHost(t *testing.T) {
	x := newTarget(t)
	sha := x.commit()
	x.pilot.set(false)
	out, err := x.d.Execute(context.Background(), x.request(sha))
	if err != nil || !out.Failed || len(x.pilot.deploys) != 0 {
		t.Fatalf("out = %+v err = %v deploys = %v", out, err, x.pilot.deploys)
	}
	if out.Result["health_before"] != ops.HealthUnavailable {
		t.Errorf("result = %v", out.Result)
	}
	if _, err := x.d.Check(context.Background(), x.request(sha)); err == nil {
		t.Error("Check must refuse a deploy while the pilot is down")
	}
}
