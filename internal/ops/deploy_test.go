package ops

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
	"github.com/joshua-noel/chaperone/internal/spec"
)

const dpBase = "feat/d1-private-pilot"

// The wall clock of the tests. Facts are written relative to it.
var dpNow = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

// ---- fakes -----------------------------------------------------------------

type dpHealth struct {
	mu    sync.Mutex
	seq   []string // statuses to answer in order; the last one repeats
	calls int
}

func (h *dpHealth) Check(context.Context) HealthStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := HealthOK
	if len(h.seq) > 0 {
		i := min(h.calls, len(h.seq)-1)
		st = h.seq[i]
	}
	h.calls++
	return HealthStatus{Status: st, HTTPStatus: 200, CheckedAt: dpNow}
}

func (h *dpHealth) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls
}

type dpHost struct {
	mu   sync.Mutex
	res  HostResult
	err  error
	jobs []HostJob
}

func (h *dpHost) RunDeploy(_ context.Context, j HostJob) (HostResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.jobs = append(h.jobs, j)
	if h.err != nil {
		return HostResult{}, h.err
	}
	if h.res.Outcome == "" {
		return HostResult{Outcome: HostSucceeded}, nil
	}
	return h.res, nil
}

func (h *dpHost) runs() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.jobs)
}

type dpAlerts struct {
	mu    sync.Mutex
	texts []string
}

func (a *dpAlerts) RaiseDeployAlert(_ context.Context, key, text string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.texts = append(a.texts, key+": "+text)
}

func (a *dpAlerts) got() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.texts...)
}

// ---- fixture ---------------------------------------------------------------

type dpFx struct {
	t      *testing.T
	gh     *ghtest.Server
	client *gh.Client
	repo   *ghtest.Repo
	dir    string
	health *dpHealth
	host   *dpHost
	alerts *dpAlerts
	d      *Deploy
	sha    string // a commit on the base with a green verify
}

func newDpFx(t *testing.T) *dpFx {
	t.Helper()
	s := ghtest.New(t)
	c, err := gh.New(gh.Config{AppID: s.AppID(), Keys: gh.StaticKey{Key: s.Key()}, BaseURL: s.URL(), Now: s.Now})
	if err != nil {
		t.Fatal(err)
	}
	in := s.AddInstallation(7, "example-org", map[string]string{
		"contents": "write", "pull_requests": "write", "checks": "read", "deployments": "write", "metadata": "read",
	})
	f := &dpFx{t: t, gh: s, client: c, repo: in.AddRepo("storefront", dpBase), dir: t.TempDir(),
		health: &dpHealth{}, host: &dpHost{}, alerts: &dpAlerts{}}
	f.sha = f.repo.Commit(dpBase)
	f.repo.SetCheck(f.sha, dpVerify("completed", "success"))
	f.writeGate("normal", dpNow.Add(-time.Minute))
	f.writeBackup(dpNow.Add(-3*time.Hour), 3448020, 2555)
	f.d, err = NewDeploy(DeployConfig{
		GitHub: c, Tokens: &InstallationMinter{Client: c},
		Policy: func(project string) (DeployPolicy, bool) {
			if project == "storefront" || project == "acme-shop" {
				return DeployPolicy{PR: PRPolicy{Version: "t", Repo: "example-org/storefront", Base: dpBase}}, true
			}
			return DeployPolicy{}, false
		},
		Facts:  HostFacts{GatePath: filepath.Join(f.dir, "load-gate.json"), BackupPath: filepath.Join(f.dir, "last-valid-backup.json")},
		Health: f.health, Host: f.host, Alert: f.alerts,
		Now: func() time.Time { return dpNow }, Location: time.UTC,
		PostHealthWait: 40 * time.Millisecond, PostHealthEvery: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func dpVerify(status, conclusion string) ghtest.Check {
	return ghtest.Check{Name: "verify", AppID: gh.GitHubActionsAppID, Status: status, Conclusion: conclusion}
}

func (f *dpFx) write(name, content string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, name), []byte(content), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

// writeGate writes load-gate.json in the shape load-gate.ps1 writes.
func (f *dpFx) writeGate(mode string, checkedAt time.Time) {
	f.write("load-gate.json", `{
    "mode":  "`+mode+`",
    "reasons":  [],
    "game":  null,
    "freeGB":  4.7,
    "checkedAt":  "`+checkedAt.Format("2006-01-02T15:04:05.0000000-07:00")+`",
    "awakeSince":  "2026-10-23T09:01:55.7971416-04:00"
}`)
}

// writeBackup writes last-valid-backup.json in the shape backup.ps1 writes.
func (f *dpFx) writeBackup(validatedAt time.Time, bytes, entries int64) {
	b, _ := json.Marshal(map[string]any{
		"validatedAt": validatedAt.Format("2006-01-02T15:04:05-07:00"), "file": "pilot-2026-10-24_0300.dump",
		"path": `C:\Storefront\pilot-backups\pilot-2026-10-24_0300.dump`, "bytes": bytes, "entries": entries,
	})
	f.write("last-valid-backup.json", string(b))
}

func (f *dpFx) req(sha string) *Request {
	return &Request{
		ID: "q-000001", Op: "deploy", Project: "storefront", OpHash: "sha256:" + strings.Repeat("a", 64),
		Target: spec.Target{Adapter: "wsl-host", Ref: "pilot"}, Params: map[string]any{"sha": sha},
		Caller: &Caller{Kind: KindRun, RunID: "r-7f3a", Project: "storefront"}, PolicyVer: "p1",
	}
}

func (f *dpFx) noLeak() {
	f.t.Helper()
	if n := f.gh.LiveTokens(); n != 0 {
		f.t.Fatalf("%d installation token(s) left unrevoked", n)
	}
}

func dpFailed(cr CheckResult) []string {
	var out []string
	for _, c := range cr.Checks {
		if !c.Passed {
			out = append(out, c.Name)
		}
	}
	return out
}

// ---- Check -----------------------------------------------------------------

func TestDeployCheckPasses(t *testing.T) {
	f := newDpFx(t)
	cr, err := f.d.Check(context.Background(), f.req(f.sha))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range cr.Checks {
		names = append(names, c.Name)
		if !c.Passed {
			t.Errorf("check %s failed: %s", c.Name, c.Detail)
		}
	}
	if got := strings.Join(names, ","); got != "sha_on_base,verify,load_gate,backup,pilot_health" {
		t.Errorf("checks in order = %s", got)
	}
	if len(cr.Evidence) != 1 {
		t.Fatalf("evidence: %+v", cr.Evidence)
	}
	for _, want := range []string{f.sha, dpBase, "verify: success", "Load gate: normal", "Last valid backup: validated 3h0m0s ago, 3448020 bytes", "pilot-2026-10-24_0300.dump", "2555 entries", "Pilot health before: ok"} {
		if !strings.Contains(cr.Evidence[0].Text, want) {
			t.Errorf("evidence lacks %q:\n%s", want, cr.Evidence[0].Text)
		}
	}
	if f.host.runs() != 0 {
		t.Fatal("Check must never reach the host")
	}
	f.noLeak()
}

func TestDeployCheckRefusals(t *testing.T) {
	type tc struct {
		name   string
		setup  func(f *dpFx) string // returns the sha to deploy
		failed string               // the check that fails
		stop   string
		detail string
		health int // readiness reads the run must have made
	}
	cases := []tc{
		{"sha not on base", func(f *dpFx) string {
			f.repo.Branch("agent/x", dpBase)
			sha := f.repo.Commit("agent/x")
			f.repo.SetCheck(sha, dpVerify("completed", "success"))
			return sha
		}, "sha_on_base", "", "is not on", 0},
		{"sha unknown to GitHub", func(f *dpFx) string { return strings.Repeat("9", 40) }, "sha_on_base", "", "no such commit", 0},
		{"verify red", func(f *dpFx) string {
			sha := f.repo.Commit(dpBase)
			f.repo.SetCheck(sha, dpVerify("completed", "failure"))
			return sha
		}, "verify", StopCIRed, "failure", 0},
		{"verify missing", func(f *dpFx) string { return f.repo.Commit(dpBase) }, "verify", StopCIStale, "no verify run", 0},
		{"verify still running", func(f *dpFx) string {
			sha := f.repo.Commit(dpBase)
			f.repo.SetCheck(sha, dpVerify("in_progress", ""))
			return sha
		}, "verify", "", "not completed", 0},
		{"gate rationed", func(f *dpFx) string { f.writeGate("rationed", dpNow.Add(-time.Minute)); return f.sha }, "load_gate", "", "rationed, not normal", 0},
		{"gate stopped", func(f *dpFx) string { f.writeGate("stopped", dpNow.Add(-time.Minute)); return f.sha }, "load_gate", "", "stopped, not normal", 0},
		{"gate reading older than 5 minutes", func(f *dpFx) string { f.writeGate("normal", dpNow.Add(-6*time.Minute)); return f.sha }, "load_gate", "", "6m0s old", 0},
		{"gate dated in the future", func(f *dpFx) string { f.writeGate("normal", dpNow.Add(time.Hour)); return f.sha }, "load_gate", "", "future", 0},
		{"gate file missing", func(f *dpFx) string { _ = os.Remove(filepath.Join(f.dir, "load-gate.json")); return f.sha }, "load_gate", "", "does not exist", 0},
		{"gate file garbage", func(f *dpFx) string { f.write("load-gate.json", "not json"); return f.sha }, "load_gate", "", "not valid JSON", 0},
		{"backup stale", func(f *dpFx) string { f.writeBackup(dpNow.Add(-27*time.Hour), 3448020, 2555); return f.sha }, "backup", "", "27h0m0s old", 0},
		{"backup zero bytes", func(f *dpFx) string { f.writeBackup(dpNow.Add(-time.Hour), 0, 2555); return f.sha }, "backup", "", "0 bytes", 0},
		{"backup no entries", func(f *dpFx) string { f.writeBackup(dpNow.Add(-time.Hour), 100, 0); return f.sha }, "backup", "", "no entries", 0},
		{"backup fact missing", func(f *dpFx) string { _ = os.Remove(filepath.Join(f.dir, "last-valid-backup.json")); return f.sha }, "backup", "", "does not exist", 0},
		{"backup dated in the future", func(f *dpFx) string { f.writeBackup(dpNow.Add(2*time.Hour), 100, 5); return f.sha }, "backup", "", "future", 0},
		{"pilot unavailable", func(f *dpFx) string { f.health.seq = []string{HealthUnavailable}; return f.sha }, "pilot_health", "", "unavailable, not ok", 1},
		{"pilot unreachable", func(f *dpFx) string { f.health.seq = []string{HealthUnreachable}; return f.sha }, "pilot_health", "", "unreachable, not ok", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newDpFx(t)
			sha := c.setup(f)
			cr, err := f.d.Check(context.Background(), f.req(sha))
			var ref *Refusal
			if !errors.As(err, &ref) {
				t.Fatalf("err = %v, want a refusal", err)
			}
			if ref.Code != CodePolicyRefused || !strings.Contains(ref.Why, c.detail) {
				t.Errorf("refusal = %s: %s (want detail %q)", ref.Code, ref.Why, c.detail)
			}
			if c.stop != "" && !strings.HasPrefix(ref.Why, c.stop+": ") {
				t.Errorf("refusal %q does not lead with %s", ref.Why, c.stop)
			}
			if got := dpFailed(cr); len(got) != 1 || got[0] != c.failed {
				t.Errorf("failed checks = %v, want [%s]", got, c.failed)
			}
			if last := cr.Checks[len(cr.Checks)-1]; last.Name != c.failed {
				t.Errorf("checks stop at the first failure: last = %s", last.Name)
			}
			if f.health.count() != c.health {
				t.Errorf("readiness reads = %d, want %d (a later check ran past a failed one)", f.health.count(), c.health)
			}
			if len(cr.Evidence) != 0 || f.host.runs() != 0 {
				t.Error("a refused deploy has no card text and never reaches the host")
			}
			f.noLeak()
		})
	}
}

func TestDeployBackupDumpFile(t *testing.T) {
	f := newDpFx(t)
	dump := filepath.Join(f.dir, "dump")
	f.d.cfg.Facts.DumpSize = func(p string) (int64, error) {
		if !strings.HasSuffix(p, ".dump") {
			t.Errorf("DumpSize got %q", p)
		}
		fi, err := os.Stat(dump)
		if err != nil {
			return 0, err
		}
		return fi.Size(), nil
	}
	check := func() error { _, err := f.d.Check(context.Background(), f.req(f.sha)); return err }

	if err := check(); err == nil || !strings.Contains(err.Error(), "is gone") {
		t.Errorf("a dump that is gone: %v", err)
	}
	if err := os.WriteFile(dump, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil || !strings.Contains(err.Error(), "is empty (0 bytes)") {
		t.Errorf("a zero-byte dump: %v", err)
	}
	if err := os.WriteFile(dump, []byte("PGDMP"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := check(); err != nil {
		t.Errorf("a real dump: %v", err)
	}
	// An access error is not a refusal: the fact file's byte count is the witness.
	f.d.cfg.Facts.DumpSize = func(string) (int64, error) { return 0, os.ErrPermission }
	if err := check(); err != nil {
		t.Errorf("an unreadable dump folder: %v", err)
	}
}

func TestDeployCheckRequestShape(t *testing.T) {
	f := newDpFx(t)
	bad := map[string]func(r *Request){
		"wrong target adapter": func(r *Request) { r.Target.Adapter = "ssh-host" },
		"wrong target ref":     func(r *Request) { r.Target.Ref = "staging" },
		"extra param":          func(r *Request) { r.Params["force"] = true },
		"no sha":               func(r *Request) { delete(r.Params, "sha") },
		"short sha":            func(r *Request) { r.Params["sha"] = f.sha[:12] },
		"upper-case sha":       func(r *Request) { r.Params["sha"] = strings.ToUpper(f.sha) },
		"a branch name":        func(r *Request) { r.Params["sha"] = dpBase },
	}
	for name, mut := range bad {
		r := f.req(f.sha)
		mut(r)
		_, err := f.d.Check(context.Background(), r)
		var ref *Refusal
		if !errors.As(err, &ref) || ref.Code != CodeParamsInvalid {
			t.Errorf("%s: err = %v, want OP_PARAMS_INVALID", name, err)
		}
	}
	r := f.req(f.sha)
	r.Project = "chaperone-sandbox"
	if _, err := f.d.Check(context.Background(), r); err == nil || !strings.Contains(err.Error(), "no deploy settings") {
		t.Errorf("a project without deploy settings: %v", err)
	}
	if f.gh.Count("GET", "") != 0 || f.health.count() != 0 {
		t.Error("a malformed request must be refused before any read")
	}
}

// ---- Execute ---------------------------------------------------------------

func TestDeployExecuteSuccess(t *testing.T) {
	f := newDpFx(t)
	out, err := f.d.Execute(context.Background(), f.req(f.sha))
	if err != nil || out.Failed || out.Unconfirmed {
		t.Fatalf("out = %+v, err = %v", out, err)
	}
	if len(f.host.jobs) != 1 {
		t.Fatalf("host runs = %d", len(f.host.jobs))
	}
	j := f.host.jobs[0]
	if j.SHA != f.sha || j.OpID != "q-000001" || j.Caller.RunID != "r-7f3a" || j.OpHash != "sha256:"+strings.Repeat("a", 64) {
		t.Errorf("job = %+v", j)
	}
	if out.Result["health_after"] != "ok" || out.Result["blast_radius"] != "12:00-12:00" || out.Result["started_at"] != "12:00" {
		t.Errorf("result = %v", out.Result)
	}
	deps := f.repo.Deployments()
	if len(deps) != 1 || deps[0].SHA != f.sha || deps[0].Environment != DeployEnvironment || len(deps[0].Statuses) == 0 || deps[0].Statuses[len(deps[0].Statuses)-1] != gh.DeploySuccess {
		t.Errorf("deployments = %+v", deps)
	}
	if !strings.HasPrefix(out.ExternalRef, "https://api.github.com/repos/example-org/storefront/deployments/") {
		t.Errorf("external ref = %q", out.ExternalRef)
	}
	if len(f.alerts.got()) != 0 {
		t.Errorf("alerts on a good deploy: %v", f.alerts.got())
	}
	f.noLeak()
}

func TestDeployExecutePostHealthFailureIsFailed(t *testing.T) {
	f := newDpFx(t)
	f.health.seq = []string{HealthOK, HealthUnavailable} // healthy before, down after
	out, err := f.d.Execute(context.Background(), f.req(f.sha))
	if err != nil || !out.Failed || out.Unconfirmed {
		t.Fatalf("out = %+v, err = %v: a pilot that is not ok afterwards is failed", out, err)
	}
	if out.Result["health_after"] != HealthUnavailable || !strings.Contains(out.Result["error"].(string), "not healthy afterwards") {
		t.Errorf("result = %v", out.Result)
	}
	al := f.alerts.got()
	if len(al) != 1 || !strings.HasPrefix(al[0], AlertDeployFailed+": Deploy of "+f.sha[:12]) || !strings.Contains(al[0], "unavailable") {
		t.Errorf("alerts = %v", al)
	}
	deps := f.repo.Deployments()
	if len(deps) != 1 || deps[0].Statuses[len(deps[0].Statuses)-1] != gh.DeployFailure {
		t.Errorf("deployments = %+v: a bad deploy is recorded as a failure", deps)
	}
	f.noLeak()
}

func TestDeployExecutePilotRecoversInTheWindow(t *testing.T) {
	f := newDpFx(t)
	f.health.seq = []string{HealthOK, HealthUnavailable, HealthUnavailable, HealthOK} // the web unit is restarting
	out, err := f.d.Execute(context.Background(), f.req(f.sha))
	if err != nil || out.Failed || out.Result["health_after"] != "ok" {
		t.Fatalf("out = %+v, err = %v", out, err)
	}
}

func TestDeployExecuteHostOutcomes(t *testing.T) {
	cases := []struct {
		name        string
		res         HostResult
		err         error
		failed      bool
		unconfirmed bool
		alert       bool
		status      string // the recorded deployment's last status, "" for no record
	}{
		{"script failed", HostResult{Outcome: HostFailed, ExitCode: 3, Output: "migration 0042 failed"}, nil, true, false, true, gh.DeployFailure},
		{"script timed out", HostResult{Outcome: HostTimeout, ExitCode: -1}, nil, false, true, true, gh.DeployError},
		{"host refused the grant", HostResult{Outcome: HostRefused, Code: "GRANT_EXPIRED"}, nil, true, false, true, ""},
		{"grant never taken", HostResult{}, ErrHostNotTaken, true, false, false, ""},
		{"host lost", HostResult{}, errors.New("stream closed"), false, true, true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newDpFx(t)
			f.host.res, f.host.err = c.res, c.err
			out, err := f.d.Execute(context.Background(), f.req(f.sha))
			if err != nil {
				t.Fatal(err)
			}
			if out.Failed != c.failed || out.Unconfirmed != c.unconfirmed {
				t.Errorf("failed=%v unconfirmed=%v, want %v %v (%v)", out.Failed, out.Unconfirmed, c.failed, c.unconfirmed, out.Result)
			}
			if (len(f.alerts.got()) > 0) != c.alert {
				t.Errorf("alerts = %v, want alert=%v", f.alerts.got(), c.alert)
			}
			deps := f.repo.Deployments()
			switch {
			case c.status == "" && len(deps) != 0:
				t.Errorf("deployments = %+v, want none", deps)
			case c.status != "" && (len(deps) != 1 || deps[0].Statuses[len(deps[0].Statuses)-1] != c.status):
				t.Errorf("deployments = %+v, want status %s", deps, c.status)
			}
			if out.ExternalRef != "" && !out.Failed && !out.Unconfirmed {
				t.Errorf("external ref on a bad op: %q", out.ExternalRef)
			}
			if c.res.Output != "" && out.Result["output_tail"] != c.res.Output {
				t.Errorf("output tail missing: %v", out.Result)
			}
			f.noLeak()
		})
	}
}

func TestDeployExecuteRefusesAnUnhealthyPilotWithoutStarting(t *testing.T) {
	f := newDpFx(t)
	f.health.seq = []string{HealthUnreachable}
	out, err := f.d.Execute(context.Background(), f.req(f.sha))
	if err != nil || !out.Failed || f.host.runs() != 0 {
		t.Fatalf("out = %+v err = %v host runs = %d", out, err, f.host.runs())
	}
}

func TestDeployRecordFailureIsAWarning(t *testing.T) {
	f := newDpFx(t)
	f.gh.Inject("POST", "/deployments", ghtest.Unavailable())
	out, err := f.d.Execute(context.Background(), f.req(f.sha))
	if err != nil || out.Failed || out.Unconfirmed {
		t.Fatalf("out = %+v err = %v: the pilot runs the commit, so the op succeeded", out, err)
	}
	if !strings.Contains(out.Result["record_warning"].(string), "could not be recorded") || out.ExternalRef != "" {
		t.Errorf("result = %v ref %q", out.Result, out.ExternalRef)
	}
	f.noLeak()
}

func TestNewDeployNeedsItsParts(t *testing.T) {
	if _, err := NewDeploy(DeployConfig{}); err == nil {
		t.Error("an empty config must be refused")
	}
	f := newDpFx(t)
	cfg := f.d.cfg
	cfg.Facts = HostFacts{}
	if _, err := NewDeploy(cfg); err == nil {
		t.Error("a config without fact paths must be refused")
	}
}
