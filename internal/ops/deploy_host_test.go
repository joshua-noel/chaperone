package ops

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/grant"
)

const (
	hostToken  = "host-token-0123456789abcdef"
	hostScript = "#!/bin/bash\necho deploy \"$@\"\n"
)

type busFx struct {
	t      *testing.T
	bus    *HostBus
	srv    *httptest.Server
	pub    ed25519.PublicKey
	script string
}

func newBusFx(t *testing.T, mut func(*HostBusConfig)) *busFx {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "pilot.sh")
	if err := os.WriteFile(script, []byte(hostScript), 0o600); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(dir, "host.token")
	if err := os.WriteFile(tokenFile, []byte(hostToken+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := HostBusConfig{Signer: StaticGrantSigner(key), Scripts: map[string]string{DeployRunbook: script}, TokenFile: tokenFile, KeepAlive: 50 * time.Millisecond}
	if mut != nil {
		mut(&cfg)
	}
	bus, err := NewHostBus(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f := &busFx{t: t, bus: bus, pub: pub, script: script}
	f.srv = httptest.NewServer(bus.Handler())
	t.Cleanup(f.srv.Close)
	return f
}

func (f *busFx) do(method, path, token string, body io.Reader) *http.Response {
	f.t.Helper()
	req, err := http.NewRequest(method, f.srv.URL+path, body)
	if err != nil {
		f.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	return resp
}

type sseEvent struct{ name, data string }

// stream opens /v0/host/events and returns a channel of its events.
func (f *busFx) stream(ctx context.Context) <-chan sseEvent {
	f.t.Helper()
	req, _ := http.NewRequestWithContext(ctx, "GET", f.srv.URL+"/v0/host/events", nil)
	req.Header.Set("Authorization", "Bearer "+hostToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		f.t.Fatalf("events: %v %v", resp, err)
	}
	out := make(chan sseEvent, 16)
	go func() {
		defer close(out)
		defer resp.Body.Close()
		sc := bufio.NewScanner(resp.Body)
		var name, data string
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if name != "" {
					out <- sseEvent{name, data}
				}
				name, data = "", ""
			case strings.HasPrefix(line, "event: "):
				name = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				data = strings.TrimPrefix(line, "data: ")
			}
		}
	}()
	return out
}

func nextGrant(t *testing.T, ch <-chan sseEvent) (token, opID string) {
	t.Helper()
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatal("stream ended without a grant")
			}
			if ev.name != "grant" {
				continue
			}
			var p struct {
				Grant string `json:"grant"`
				OpID  string `json:"op_id"`
			}
			if err := json.Unmarshal([]byte(ev.data), &p); err != nil {
				t.Fatal(err)
			}
			return p.Grant, p.OpID
		case <-time.After(5 * time.Second):
			t.Fatal("no grant event")
		}
	}
}

func busJob(sha string) HostJob {
	return HostJob{OpID: "q-000001", OpHash: "sha256:" + strings.Repeat("a", 64), SHA: sha,
		Caller: &Caller{Kind: KindRun, RunID: "r-7f3a"}}
}

type runRes struct {
	res HostResult
	err error
}

func (f *busFx) runAsync(ctx context.Context, job HostJob) <-chan runRes {
	ch := make(chan runRes, 1)
	go func() {
		r, err := f.bus.RunDeploy(ctx, job)
		ch <- runRes{r, err}
	}()
	return ch
}

// The helper's whole life with a real verifier: a grant arrives on the stream,
// verifies under the pinned key, names this SHA, this script and this requester;
// output and the result come back.
func TestHostBusRoundTrip(t *testing.T) {
	f := newBusFx(t, func(c *HostBusConfig) {
		c.Redact = func(s string) string { return strings.ReplaceAll(s, "hunter2", "[REDACTED]") }
		c.Pending = func(context.Context) int { return 2 }
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := f.stream(ctx)

	// The first event is the pending count, then nothing until a grant exists.
	select {
	case ev := <-events:
		if ev.name != "approvals.pending" || ev.data != `{"count":2}` {
			t.Fatalf("first event = %+v", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no pending event")
	}

	sha := strings.Repeat("ab", 20)
	done := f.runAsync(ctx, busJob(sha))
	token, opID := nextGrant(t, events)
	if opID != "q-000001" {
		t.Errorf("op id = %s", opID)
	}

	v, err := grant.NewVerifier(f.pub, grant.NewMemoryNonces())
	if err != nil {
		t.Fatal(err)
	}
	g, err := v.Verify(token)
	if err != nil {
		t.Fatalf("the helper refused the grant: %v", err)
	}
	if g.Op != "deploy" || g.Runbook != "deploy" || g.Args["sha"] != sha || len(g.Args) != 1 || g.RunID != "r-7f3a" || g.OrchestratorID != "" ||
		g.OpHash != "sha256:"+strings.Repeat("a", 64) || g.ScriptSHA256 != grant.HashBytes([]byte(hostScript)) {
		t.Errorf("grant = %+v", g)
	}
	if life := time.Duration(g.ExpiresAt-g.IssuedAt) * time.Second; life > grant.MaxLifetime || life < time.Minute {
		t.Errorf("lifetime = %v", life)
	}
	// A replay at the helper is refused by its nonce store; the bus sends a grant once per stream.
	if _, err := v.Verify(token); !errors.Is(err, grant.ErrReplay) {
		t.Errorf("replay: %v", err)
	}

	r := f.do("POST", "/v0/host/runs/q-000001/output", hostToken, strings.NewReader("step 1\npassword hunter2\n"))
	if r.StatusCode != 204 {
		t.Fatalf("output: %d", r.StatusCode)
	}
	r.Body.Close()
	r = f.do("POST", "/v0/host/runs/q-000001/result", hostToken, strings.NewReader(`{"exit_code":0,"outcome":"succeeded"}`))
	if r.StatusCode != 204 {
		t.Fatalf("result: %d", r.StatusCode)
	}
	r.Body.Close()

	select {
	case got := <-done:
		if got.err != nil || got.res.Outcome != HostSucceeded || got.res.ExitCode != 0 {
			t.Fatalf("run = %+v", got)
		}
		if strings.Contains(got.res.Output, "hunter2") || !strings.Contains(got.res.Output, "[REDACTED]") {
			t.Errorf("output not redacted by chapd: %q", got.res.Output)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunDeploy did not return")
	}

	// The op is over: a second report and more output are refused.
	for _, p := range []string{"/v0/host/runs/q-000001/result", "/v0/host/runs/q-000001/output"} {
		r := f.do("POST", p, hostToken, strings.NewReader(`{"exit_code":0,"outcome":"succeeded"}`))
		if r.StatusCode != 409 {
			t.Errorf("%s after the run: %d, want 409", p, r.StatusCode)
		}
		r.Body.Close()
	}
}

func TestHostBusOrchestratorGrant(t *testing.T) {
	f := newBusFx(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := f.stream(ctx)
	job := busJob(strings.Repeat("cd", 20))
	job.Caller = &Caller{Kind: KindOrchestrator, OrchID: "main"}
	f.runAsync(ctx, job)
	token, _ := nextGrant(t, events)
	v, _ := grant.NewVerifier(f.pub, grant.NewMemoryNonces())
	g, err := v.Verify(token)
	if err != nil || g.OrchestratorID != "main" || g.RunID != "" {
		t.Fatalf("grant = %+v err = %v", g, err)
	}
}

// The helper's three routes take the host token and nothing else.
func TestHostBusRefusesOtherCredentials(t *testing.T) {
	f := newBusFx(t, nil)
	routes := [][2]string{{"GET", "/v0/host/events"}, {"POST", "/v0/host/runs/q-000001/output"}, {"POST", "/v0/host/runs/q-000001/result"}}
	for _, tok := range []string{"", "wrong", "eyJhbGciOiJFZERTQSJ9.eyJydW4iOiJyLTdmM2EifQ.c2ln", "chap_orch_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", hostToken + "x", hostToken[:10]} {
		for _, rt := range routes {
			r := f.do(rt[0], rt[1], tok, strings.NewReader(`{}`))
			body, _ := io.ReadAll(r.Body)
			r.Body.Close()
			if r.StatusCode != 401 || !strings.Contains(string(body), "TOKEN_INVALID") {
				t.Errorf("%s %s with %q: %d %s", rt[0], rt[1], tok, r.StatusCode, body)
			}
		}
	}
	// A missing or empty token file never matches an empty bearer.
	if err := os.WriteFile(f.bus.cfg.TokenFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if r := f.do("GET", "/v0/host/events", "x", nil); r.StatusCode != 401 {
		t.Errorf("empty token file: %d", r.StatusCode)
	}
	_ = os.Remove(f.bus.cfg.TokenFile)
	if r := f.do("GET", "/v0/host/events", hostToken, nil); r.StatusCode != 401 {
		t.Errorf("missing token file: %d", r.StatusCode)
	}
}

func TestHostBusRefusesResultsItDidNotAskFor(t *testing.T) {
	f := newBusFx(t, nil)
	// No op is running on the host.
	r := f.do("POST", "/v0/host/runs/q-000009/result", hostToken, strings.NewReader(`{"exit_code":0,"outcome":"succeeded"}`))
	if r.StatusCode != 409 {
		t.Errorf("result for an op that is not running: %d", r.StatusCode)
	}
	// A grant that sits in the queue and was never sent to a helper is not "running" either.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := f.runAsync(ctx, busJob(strings.Repeat("ab", 20)))
	time.Sleep(50 * time.Millisecond)
	r = f.do("POST", "/v0/host/runs/q-000001/result", hostToken, strings.NewReader(`{"exit_code":0,"outcome":"succeeded"}`))
	if r.StatusCode != 409 {
		t.Errorf("a forged result before the grant was taken: %d", r.StatusCode)
	}
	cancel()
	if got := <-done; !errors.Is(got.err, ErrHostNotTaken) {
		t.Errorf("err = %v", got.err)
	}
}

func TestHostBusResultValidation(t *testing.T) {
	f := newBusFx(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := f.stream(ctx)
	done := f.runAsync(ctx, busJob(strings.Repeat("ab", 20)))
	nextGrant(t, events)
	for _, body := range []string{
		`{"outcome":"succeeded"}`, `{"exit_code":0}`, `{"exit_code":0,"outcome":"great"}`, `{"exit_code":0,"outcome":"succeeded","extra":1}`,
		`{"exit_code":0,"outcome":"refused","code":"` + strings.Repeat("X", 49) + `"}`, `nope`, ``,
	} {
		r := f.do("POST", "/v0/host/runs/q-000001/result", hostToken, strings.NewReader(body))
		if r.StatusCode != 400 {
			t.Errorf("%q: %d, want 400", body, r.StatusCode)
		}
		r.Body.Close()
	}
	select {
	case <-done:
		t.Fatal("a malformed result ended the run")
	case <-time.After(50 * time.Millisecond):
	}
	r := f.do("POST", "/v0/host/runs/q-000001/result", hostToken, strings.NewReader(`{"exit_code":4,"outcome":"refused","code":"GRANT_EXPIRED"}`))
	r.Body.Close()
	if got := <-done; got.err != nil || got.res.Outcome != HostRefused || got.res.Code != "GRANT_EXPIRED" || got.res.ExitCode != 4 {
		t.Errorf("run = %+v", got)
	}
}

func TestHostBusGrantNeverTaken(t *testing.T) {
	var now atomic.Int64
	now.Store(time.Now().Unix())
	f := newBusFx(t, func(c *HostBusConfig) {
		c.TTL = time.Second
		c.Now = func() time.Time { return time.Unix(now.Load(), 0) }
	})
	// No stream is open: after the grant's expiry nothing ran, and the op can say so.
	done := f.runAsync(context.Background(), busJob(strings.Repeat("ab", 20)))
	time.Sleep(20 * time.Millisecond)
	now.Add(2)
	select {
	case got := <-done:
		if !errors.Is(got.err, ErrHostNotTaken) {
			t.Errorf("err = %v", got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an expired grant that was never taken must end the wait")
	}
	f.bus.mu.Lock()
	left := len(f.bus.jobs)
	f.bus.mu.Unlock()
	if left != 0 {
		t.Errorf("%d job(s) left in the queue", left)
	}
}

func TestHostBusTakenThenCancelledIsUnknown(t *testing.T) {
	f := newBusFx(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	sctx, scancel := context.WithCancel(context.Background())
	defer scancel()
	events := f.stream(sctx)
	done := f.runAsync(ctx, busJob(strings.Repeat("ab", 20)))
	nextGrant(t, events)
	cancel()
	got := <-done
	if got.err == nil || errors.Is(got.err, ErrHostNotTaken) || !errors.Is(got.err, context.Canceled) {
		t.Errorf("err = %v: once the helper has the grant, the run may have happened", got.err)
	}
}

// grantHookWriter is a ResponseWriter that runs onGrant while the grant event is
// being written: the helper has the bytes and acts on them before the bus's
// handler has a chance to run its next line.
type grantHookWriter struct {
	h       http.Header
	onGrant func()
	fired   bool
}

func (w *grantHookWriter) Header() http.Header { return w.h }
func (w *grantHookWriter) WriteHeader(int)     {}
func (w *grantHookWriter) Flush()              {}
func (w *grantHookWriter) Write(p []byte) (int, error) {
	if !w.fired && bytes.HasPrefix(p, []byte("event: grant")) {
		w.fired = true
		w.onGrant()
	}
	return len(p), nil
}

// waitQueued waits until the bus holds exactly one job.
func waitQueued(t *testing.T, f *busFx) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		f.bus.mu.Lock()
		queued := len(f.bus.jobs) == 1
		f.bus.mu.Unlock()
		if queued {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the grant was never queued")
		}
	}
}

// The grant counts as taken from the moment its bytes can reach the helper, not
// after the write returns: a helper that acts at once (output, a result) must
// be heard, and a cancelled wait must say "the run may have happened", never
// "certainly did not run". The helper's reaction is run inside the write, so no
// scheduler timing decides this test.
func TestHostBusGrantIsTakenBeforeTheHelperHasIt(t *testing.T) {
	f := newBusFx(t, nil)
	rctx, rcancel := context.WithCancel(context.Background())
	defer rcancel()
	done := f.runAsync(rctx, busJob(strings.Repeat("ab", 20)))
	waitQueued(t, f)

	// The timeout is a backstop: a regression must fail here, not hang the run.
	sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer scancel()
	req := httptest.NewRequestWithContext(sctx, "GET", "/v0/host/events", nil)
	req.Header.Set("Authorization", "Bearer "+hostToken)
	w := &grantHookWriter{h: http.Header{}}
	w.onGrant = func() {
		rec := httptest.NewRecorder()
		post := httptest.NewRequest("POST", "/v0/host/runs/q-000001/output", strings.NewReader("step 1\n"))
		post.Header.Set("Authorization", "Bearer "+hostToken)
		f.bus.Handler().ServeHTTP(rec, post)
		if rec.Code != http.StatusNoContent {
			t.Errorf("output right after the grant: %d, want 204", rec.Code)
		}
		rcancel()
		got := <-done
		if got.err == nil || errors.Is(got.err, ErrHostNotTaken) || !errors.Is(got.err, context.Canceled) {
			t.Errorf("err = %v: once the helper has the grant, the run may have happened", got.err)
		}
		scancel()
	}
	f.bus.Handler().ServeHTTP(w, req)
	if !w.fired {
		t.Fatal("no grant event was written")
	}
}

// A wait that ended "not taken" while the stream held the job in its snapshot
// must win: the stream may not write that grant afterwards, or the helper would
// run a deploy the op already recorded as not run. The cancel is placed between
// the snapshot and the mark by a seam, so no scheduler timing decides this test.
func TestHostBusWithdrawnGrantIsNeverWritten(t *testing.T) {
	f := newBusFx(t, nil)
	rctx, rcancel := context.WithCancel(context.Background())
	defer rcancel()
	done := f.runAsync(rctx, busJob(strings.Repeat("ab", 20)))
	waitQueued(t, f)

	// The timeout is a backstop: a regression must fail here, not hang the run.
	sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer scancel()
	req := httptest.NewRequestWithContext(sctx, "GET", "/v0/host/events", nil)
	req.Header.Set("Authorization", "Bearer "+hostToken)
	w := &grantHookWriter{h: http.Header{}}
	w.onGrant = func() { t.Error("a grant was written after the wait ended \"not taken\"") }
	cut := false
	f.bus.afterSnapshot = func() {
		if cut {
			return
		}
		cut = true
		rcancel()
		if got := <-done; !errors.Is(got.err, ErrHostNotTaken) {
			t.Errorf("err = %v, want ErrHostNotTaken", got.err)
		}
		scancel()
	}
	f.bus.Handler().ServeHTTP(w, req)
	if !cut {
		t.Fatal("the stream never took a snapshot with the job in it")
	}
	f.bus.mu.Lock()
	left := len(f.bus.jobs)
	f.bus.mu.Unlock()
	if left != 0 {
		t.Errorf("%d job(s) left in the queue", left)
	}
}

func TestHostBusRefusesBadJobs(t *testing.T) {
	f := newBusFx(t, nil)
	bad := []HostJob{busJob("short"), busJob(strings.Repeat("AB", 20)), busJob("main")}
	noCaller := busJob(strings.Repeat("ab", 20))
	noCaller.Caller = nil
	badID := busJob(strings.Repeat("ab", 20))
	badID.OpID = "../../x"
	badHash := busJob(strings.Repeat("ab", 20))
	badHash.OpHash = "sha256:xyz"
	bad = append(bad, noCaller, badID, badHash)
	for i, j := range bad {
		if _, err := f.bus.RunDeploy(context.Background(), j); err == nil || errors.Is(err, ErrHostNotTaken) {
			t.Errorf("job %d: err = %v, want a refusal to sign", i, err)
		}
	}
	f.bus.mu.Lock()
	n := len(f.bus.jobs)
	f.bus.mu.Unlock()
	if n != 0 {
		t.Errorf("%d job(s) queued from bad requests", n)
	}
}

func TestHostBusScriptProblems(t *testing.T) {
	f := newBusFx(t, nil)
	if err := os.WriteFile(f.script, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.bus.RunDeploy(context.Background(), busJob(strings.Repeat("ab", 20))); err == nil {
		t.Error("an empty script must not be hashed into a grant")
	}
	_ = os.Remove(f.script)
	if _, err := f.bus.RunDeploy(context.Background(), busJob(strings.Repeat("ab", 20))); err == nil {
		t.Error("a missing script must not be signed")
	}
}

func TestNewHostBusChecks(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	good := HostBusConfig{Signer: StaticGrantSigner(key), Scripts: map[string]string{DeployRunbook: "/x/pilot.sh"}, TokenFile: "/x/t"}
	if _, err := NewHostBus(good); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*HostBusConfig){
		"no signer":      func(c *HostBusConfig) { c.Signer = nil },
		"TTL over five":  func(c *HostBusConfig) { c.TTL = 6 * time.Minute },
		"no script path": func(c *HostBusConfig) { c.Scripts = nil },
	} {
		c := good
		mut(&c)
		if _, err := NewHostBus(c); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
}

// Only the newest stream gets grants: two helpers must not both run one.
func TestHostBusNewestStreamWins(t *testing.T) {
	f := newBusFx(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	old := f.stream(ctx)
	time.Sleep(30 * time.Millisecond)
	newer := f.stream(ctx)
	time.Sleep(30 * time.Millisecond)
	f.runAsync(ctx, busJob(strings.Repeat("ab", 20)))
	nextGrant(t, newer)
	for ev := range old {
		if ev.name == "grant" {
			t.Fatal("the replaced stream received a grant")
		}
	}
}

// Mounted in chapd's server the routes still take the host token only: the
// server's own run and orchestrator verifiers never see them, and the server's
// Host-header allowlist still applies.
func TestHostRoutesInTheServer(t *testing.T) {
	g := newRig(t, rigOpts{})
	f := newBusFx(t, nil)
	srv := NewServer(ServerConfig{Svc: g.svc, Auth: &Auth{Run: g.ver, Orch: g.ver, Svc: g.svc}, Version: "test", Host: f.bus.Handler()})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	srv.cfg.Hosts = []string{strings.TrimPrefix(ts.URL, "http://")}

	get := func(tok string) (*http.Response, error) {
		req, _ := http.NewRequest("GET", ts.URL+"/v0/host/events", nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		return http.DefaultClient.Do(req)
	}
	for _, tok := range []string{"", hiTok, runTok, orchTok} {
		resp, err := get(tok)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Errorf("token %.12q: %d, want 401", tok, resp.StatusCode)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL+"/v0/host/events", nil)
	req.Header.Set("Authorization", "Bearer "+hostToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("host token: %v %v", resp, err)
	}
	cancel()
	resp.Body.Close()

	req, _ = http.NewRequest("GET", ts.URL+"/v0/host/events", nil)
	req.Host = "evil.test"
	req.Header.Set("Authorization", "Bearer "+hostToken)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("a foreign Host header: %v %v", resp, err)
	}
}
