package redteam

// RT-23: deploy preconditions and approval binding (ticket L1-15). A deploy
// changes the pilot the operator's testers use, so nothing may start it unless
// the commit is on the base branch with a green `verify`, the host is idle
// (load gate `normal`, read under 5 minutes ago), a verified non-empty backup
// younger than the limit exists and the pilot answers `ok`, and a human has
// approved that exact SHA. Threat model: TB4-T2 (high-class op without a human)
// and the deploy rows of the 17 to 19 Oct incidents. Red-team list:
// docs/manual-crosswalk.md, RT-23.
//
// Setup: the real deploy adapter (the one cmd/chapd installs) over a fake GitHub
// (ghtest), fact files in a scratch folder, a fake pilot and a fake `chap-host`.
// Nothing here runs a script or touches WSL, Docker or a live pilot.
//
// Attack: ask for a deploy with, one at a time, a commit that is not on the
// base, a red `verify`, a gate that is not `normal` or is 6 minutes old, a
// backup that is 27 hours old, empty, or has no entries, and a pilot that is not
// ok. Then approve deploy A and request deploy B.
//
// Expected block: each is OP_POLICY_REFUSED with the reason, asked outright or
// as an approval request, and **no approval card exists** for any of them; the
// host is never reached. A control with everything in order gets a card; the
// approval for A is APPROVAL_HASH_MISMATCH for B; A runs once with A's SHA. A
// deploy after which the pilot is not ok is `failed`, with `op.result`
// outcome=failed in the ledger and an alert.
//
// To see this fail, remove a check in internal/ops/deploy.go or
// internal/ops/deploy_facts.go; mutation_test.go does exactly that.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/ops"
)

type rt23Pilot struct {
	mu    sync.Mutex
	seq   []string
	calls int
}

func (p *rt23Pilot) Check(context.Context) ops.HealthStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := ops.HealthOK
	if len(p.seq) > 0 {
		st = p.seq[min(p.calls, len(p.seq)-1)]
	}
	p.calls++
	return ops.HealthStatus{Status: st, HTTPStatus: 200, CheckedAt: time.Now()}
}

type rt23Host struct {
	mu   sync.Mutex
	jobs []ops.HostJob
}

func (h *rt23Host) RunDeploy(_ context.Context, j ops.HostJob) (ops.HostResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.jobs = append(h.jobs, j)
	return ops.HostResult{Outcome: ops.HostSucceeded}, nil
}

func (h *rt23Host) runs() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.jobs)
}

type rt23Alerts struct {
	mu sync.Mutex
	n  int
}

func (a *rt23Alerts) RaiseDeployAlert(context.Context, string, string) {
	a.mu.Lock()
	a.n++
	a.mu.Unlock()
}

type rt23 struct {
	x      *rt01
	dir    string
	pilot  *rt23Pilot
	host   *rt23Host
	alerts *rt23Alerts
	d      *ops.Deploy
	sha    string
}

// Fact files carry real wall-clock times: the adapter reads the real clock.
func (d *rt23) gate(t *testing.T, mode string, age time.Duration) {
	t.Helper()
	at := time.Now().Add(-age).Format("2006-01-02T15:04:05.0000000-07:00")
	if err := os.WriteFile(filepath.Join(d.dir, "load-gate.json"), []byte(`{"mode":"`+mode+`","checkedAt":"`+at+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (d *rt23) backup(t *testing.T, age time.Duration, bytes, entries string) {
	t.Helper()
	at := time.Now().Add(-age).Format("2006-01-02T15:04:05-07:00")
	doc := `{"validatedAt":"` + at + `","file":"pilot-2026-10-24_0300.dump","bytes":` + bytes + `,"entries":` + entries + `}`
	if err := os.WriteFile(filepath.Join(d.dir, "last-valid-backup.json"), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newRT23(t *testing.T) *rt23 {
	t.Helper()
	x := newRT01For(t, "acme", "shop")
	d := &rt23{x: x, dir: t.TempDir(), pilot: &rt23Pilot{}, host: &rt23Host{}, alerts: &rt23Alerts{}}
	d.sha = x.r.Commit(rt01Base)
	x.r.SetCheck(d.sha, *rt01Verify("completed", "success"))
	d.gate(t, "normal", time.Minute)
	d.backup(t, 3*time.Hour, "3448020", "2555")
	var err error
	d.d, err = ops.NewDeploy(ops.DeployConfig{
		GitHub: x.c, Tokens: &ops.InstallationMinter{Client: x.c},
		Policy: func(project string) (ops.DeployPolicy, bool) {
			if project != rigProject {
				return ops.DeployPolicy{}, false
			}
			return ops.DeployPolicy{PR: ops.PRPolicy{Version: "rt-1", Repo: "acme/shop", Base: rt01Base}}, true
		},
		Facts:  ops.HostFacts{GatePath: filepath.Join(d.dir, "load-gate.json"), BackupPath: filepath.Join(d.dir, "last-valid-backup.json")},
		Health: d.pilot, Host: d.host, Alert: d.alerts,
		PostHealthWait: 40 * time.Millisecond, PostHealthEvery: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func rt23Body(sha string) map[string]any {
	b := opBody("deploy", "pilot", map[string]any{"sha": sha})
	b["target"] = map[string]any{"adapter": "wsl-host", "ref": "pilot"}
	return b
}

func rt23Approval(sha string) map[string]any {
	b := rt23Body(sha)
	b["kind"] = "op"
	b["reason"] = "red-team"
	return b
}

func TestRT23DeployPreconditions(t *testing.T) {
	cases := []struct {
		name   string
		break_ func(t *testing.T, d *rt23) string // returns the SHA to deploy
		why    string
	}{
		{"commit not on the base branch", func(t *testing.T, d *rt23) string {
			d.x.r.Branch("agent/off-base", rt01Base)
			sha := d.x.r.Commit("agent/off-base")
			d.x.r.SetCheck(sha, *rt01Verify("completed", "success"))
			return sha
		}, "is not on"},
		{"verify red (22 Oct)", func(t *testing.T, d *rt23) string {
			sha := d.x.r.Commit(rt01Base)
			d.x.r.SetCheck(sha, *rt01Verify("completed", "failure"))
			return sha
		}, "CI_RED"},
		{"verify never ran on this commit", func(t *testing.T, d *rt23) string { return d.x.r.Commit(rt01Base) }, "CI_STALE"},
		{"load gate rationed", func(t *testing.T, d *rt23) string { d.gate(t, "rationed", time.Minute); return d.sha }, "rationed, not normal"},
		{"load gate reading 6 minutes old", func(t *testing.T, d *rt23) string { d.gate(t, "normal", 6*time.Minute); return d.sha }, "old (limit 5m0s)"},
		{"backup 27 hours old", func(t *testing.T, d *rt23) string { d.backup(t, 27*time.Hour, "3448020", "2555"); return d.sha }, "old (limit 26h0m0s)"},
		{"backup of zero bytes (20 Oct)", func(t *testing.T, d *rt23) string { d.backup(t, time.Hour, "0", "2555"); return d.sha }, "0 bytes"},
		{"backup listing no entries", func(t *testing.T, d *rt23) string { d.backup(t, time.Hour, "3448020", "0"); return d.sha }, "no entries"},
		{"pilot not ok before", func(t *testing.T, d *rt23) string { d.pilot.seq = []string{ops.HealthUnavailable}; return d.sha }, "unavailable, not ok"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ap := &fakeApprovals{}
			d := newRT23(t)
			g := newRig(t, rigOpts{enable: []string{"deploy"}, approvals: ap, deploy: d.d})
			run, _ := g.mint("deploy")
			sha := c.break_(t, d)

			for range 3 {
				for path, body := range map[string]map[string]any{"/v0/ops": rt23Body(sha), "/v0/approvals": rt23Approval(sha)} {
					st, got := g.call("POST", path, run, body)
					if st < 400 {
						t.Fatalf("%s: %d %v", path, st, got)
					}
					dn := mustDenial(t, got, "OP_POLICY_REFUSED")
					if !strings.Contains(str(dn, "why"), c.why) {
						t.Fatalf("%s: the denial does not say %q: %v", path, c.why, dn["why"])
					}
				}
			}
			if ap.cards() != 0 {
				t.Fatalf("%d approval card(s) exist for a deploy that policy refuses", ap.cards())
			}
			if d.host.runs() != 0 {
				t.Fatal("the host was reached")
			}
			g.mustLedgerOK()
		})
	}

	// Control: with everything in order the deploy gets a card and nothing else.
	t.Run("control: all in order, a card and no run", func(t *testing.T) {
		ap := &fakeApprovals{}
		d := newRT23(t)
		g := newRig(t, rigOpts{enable: []string{"deploy"}, approvals: ap, deploy: d.d})
		run, _ := g.mint("deploy")
		st, got := g.call("POST", "/v0/ops", run, rt23Body(d.sha))
		if st != 403 {
			t.Fatalf("%d %v", st, got)
		}
		mustDenial(t, got, "OP_APPROVAL_REQUIRED")
		if st, got := g.call("POST", "/v0/approvals", run, rt23Approval(d.sha)); st != 202 || ap.cards() != 1 {
			t.Fatalf("%d %v cards %d", st, got, ap.cards())
		}
		if d.host.runs() != 0 {
			t.Fatal("the host was reached before a human decided")
		}
	})
}

// Approve deploy A, request deploy B: APPROVAL_HASH_MISMATCH; A runs once.
func TestRT23DeployApprovalIsBoundToTheSHA(t *testing.T) {
	ap := &fakeApprovals{}
	d := newRT23(t)
	g := newRig(t, rigOpts{enable: []string{"deploy"}, approvals: ap, deploy: d.d})
	run, _ := g.mint("deploy")
	shaB := d.x.r.Commit(rt01Base)
	d.x.r.SetCheck(shaB, *rt01Verify("completed", "success"))

	st, op := g.call("POST", "/v0/approvals", run, rt23Approval(d.sha))
	if st != 202 {
		t.Fatalf("%d %v", st, op)
	}
	aid := str(op["approval"].(map[string]any), "id")
	// The operator approves A. Before the engine releases it, B asks for A's approval.
	ap.set(aid, "approved")
	b := rt23Body(shaB)
	b["approval_id"] = aid
	st, body := g.call("POST", "/v0/ops", run, b)
	if st != 409 {
		t.Fatalf("%d %v", st, body)
	}
	mustDenial(t, body, "APPROVAL_HASH_MISMATCH")
	if d.host.runs() != 0 {
		t.Fatal("deploy B reached the host on A's approval")
	}

	g.decide(t, ap, str(op, "id"), aid, true)
	waitOpState(t, g, run, str(op, "id"), "succeeded")
	if d.host.runs() != 1 || d.host.jobs[0].SHA != d.sha {
		t.Fatalf("host jobs = %+v, want one run of %s", d.host.jobs, d.sha)
	}
	// Using the approval again does not run anything a second time.
	again := rt23Body(d.sha)
	again["approval_id"] = aid
	g.call("POST", "/v0/ops", run, again)
	if d.host.runs() != 1 {
		t.Fatalf("%d runs from one approval", d.host.runs())
	}
	if d.x.s.LiveTokens() != 0 {
		t.Errorf("%d installation token(s) left live", d.x.s.LiveTokens())
	}
	g.mustLedgerOK()
}

// A deploy after which the pilot is not ok is failed, in the ledger, with an alert.
func TestRT23DeployFailedPostHealth(t *testing.T) {
	ap := &fakeApprovals{}
	d := newRT23(t)
	// Reads: submit check, release check, "before" in Execute; then the pilot stays down.
	d.pilot.seq = []string{ops.HealthOK, ops.HealthOK, ops.HealthOK, ops.HealthUnavailable}
	g := newRig(t, rigOpts{enable: []string{"deploy"}, approvals: ap, deploy: d.d})
	run, _ := g.mint("deploy")

	st, op := g.call("POST", "/v0/approvals", run, rt23Approval(d.sha))
	if st != 202 {
		t.Fatalf("%d %v", st, op)
	}
	g.decide(t, ap, str(op, "id"), str(op["approval"].(map[string]any), "id"), true)
	waitOpState(t, g, run, str(op, "id"), "failed")

	if d.host.runs() != 1 {
		t.Fatalf("host runs = %d", d.host.runs())
	}
	if d.alerts.n != 1 {
		t.Errorf("alerts = %d, want 1", d.alerts.n)
	}
	if n := g.count(`SELECT COUNT(*) FROM ledger_events WHERE event_name = 'op.result' AND event LIKE '%"factory.outcome":"failed"%'`); n != 1 {
		t.Errorf("op.result events with outcome failed = %d, want 1", n)
	}
	// The deployment is recorded as a failure, not a success.
	deps := d.x.r.Deployments()
	if len(deps) != 1 || deps[0].Statuses[len(deps[0].Statuses)-1] != gh.DeployFailure {
		t.Errorf("deployments = %+v", deps)
	}
	g.mustLedgerOK()
}
