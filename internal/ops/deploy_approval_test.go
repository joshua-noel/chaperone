package ops

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/store"
)

// deployRig is the whole op pipeline with the real deploy adapter, the real
// policy checks against a fake GitHub, fake host files, a fake pilot and a fake
// helper. Only the approvals engine is the harness's fake: the console decides
// through Service.Decided exactly as in TestApprovalFlow.
func deployRig(t *testing.T) (*rig, *dpFx, *fakeApprovals) {
	t.Helper()
	ap := &fakeApprovals{}
	g := newRig(t, rigOpts{enable: []string{"deploy"}, approvals: ap})
	f := newDpFx(t)
	g.svc.adapters["deploy"] = f.d
	return g, f, ap
}

func decide(t *testing.T, g *rig, ap *fakeApprovals, opID, approvalID string) {
	t.Helper()
	ap.set(approvalID, "approved")
	if err := g.db.Immediate(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		return g.svc.Decided(ctx, tx, opID, approvalID, Decision{Approved: true})
	}); err != nil {
		t.Fatal(err)
	}
}

// Acceptance: approve deploy A, request deploy B: APPROVAL_HASH_MISMATCH.
func TestDeployApprovalIsBoundToTheSHA(t *testing.T) {
	g, f, ap := deployRig(t)
	shaA := f.sha
	shaB := f.repo.Commit(dpBase)
	f.repo.SetCheck(shaB, dpVerify("completed", "success"))

	st, op, _ := g.call("POST", "/v0/approvals", hiTok, approvalReq("deploy", shaA))
	if st != 202 || op["state"] != "pending_approval" || ap.n != 1 {
		t.Fatalf("card for A: %d %v (cards %d)", st, op, ap.n)
	}
	aid := str(op["approval"].(map[string]any), "id")
	decide(t, g, ap, str(op, "id"), aid)

	st, body, _ := g.call("POST", "/v0/ops", hiTok, withApproval(opReq("deploy", shaB), aid))
	if st != 409 {
		t.Fatalf("deploy B under A's approval: %d %v", st, body)
	}
	mustDenial(t, body, "APPROVAL_HASH_MISMATCH")
	if f.host.runs() != 0 {
		t.Fatal("nothing may reach the host for B")
	}

	// A itself still runs, once, with A's SHA.
	if err := g.svc.Release(context.Background(), str(op, "id")); err != nil {
		t.Fatal(err)
	}
	waitState(t, g, hiTok, str(op, "id"), "succeeded")
	if f.host.runs() != 1 || f.host.jobs[0].SHA != shaA {
		t.Fatalf("host jobs = %+v", f.host.jobs)
	}
	if f.host.jobs[0].OpID != str(op, "id") || f.host.jobs[0].Caller.RunID != "r-9b2c" {
		t.Errorf("job = %+v", f.host.jobs[0])
	}
}

// Acceptance: a stale or zero-byte backup, and a gate that is not `normal`, are
// refused, and no approval card is created for any of them.
func TestDeployRefusedBeforeAnyCard(t *testing.T) {
	cases := map[string]struct {
		breakIt func(f *dpFx)
		why     string
	}{
		"stale backup":     {func(f *dpFx) { f.writeBackup(dpNow.Add(-27*time.Hour), 3448020, 2555) }, "27h0m0s old"},
		"zero-byte backup": {func(f *dpFx) { f.writeBackup(dpNow.Add(-time.Minute), 0, 2555) }, "0 bytes"},
		"gate rationed":    {func(f *dpFx) { f.writeGate("rationed", dpNow.Add(-time.Minute)) }, "rationed, not normal"},
		"gate stale":       {func(f *dpFx) { f.writeGate("normal", dpNow.Add(-6*time.Minute)) }, "6m0s old"},
		"pilot not ok":     {func(f *dpFx) { f.health.seq = []string{HealthUnavailable} }, "unavailable, not ok"},
		"verify red":       {func(f *dpFx) { f.repo.SetCheck(f.sha, dpVerify("completed", "failure")) }, "failure"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			g, f, ap := deployRig(t)
			c.breakIt(f)
			for _, path := range []string{"/v0/approvals", "/v0/ops"} {
				body := approvalReq("deploy", f.sha)
				if path == "/v0/ops" {
					body = opReq("deploy", f.sha)
				}
				st, got, _ := g.call("POST", path, hiTok, body)
				if st < 400 {
					t.Fatalf("%s: status %d %v", path, st, got)
				}
				mustDenial(t, got, "OP_POLICY_REFUSED")
				if !strings.Contains(str(got, "why"), c.why) {
					t.Errorf("%s: why = %q, want %q", path, got["why"], c.why)
				}
			}
			if ap.n != 0 {
				t.Errorf("%d approval card(s) created for a refused deploy", ap.n)
			}
			if f.host.runs() != 0 {
				t.Error("the host must not be reached")
			}
		})
	}
}

// Acceptance: a failed post-health writes op.result outcome=failed and raises an alert.
func TestDeployFailedPostHealthWritesOutcomeFailed(t *testing.T) {
	g, f, ap := deployRig(t)
	// Reads: submit check, release check, "before" in Execute, then the wait after the runbook.
	f.health.seq = []string{HealthOK, HealthOK, HealthOK, HealthUnavailable}

	_, op, _ := g.call("POST", "/v0/approvals", hiTok, approvalReq("deploy", f.sha))
	id := str(op, "id")
	decide(t, g, ap, id, str(op["approval"].(map[string]any), "id"))
	if err := g.svc.Release(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	waitState(t, g, hiTok, id, "failed")

	var found map[string]any
	for _, row := range g.led.rows(t, g.db, "op.result") {
		attrs := row["attrs"].(map[string]any)
		if attrs["factory.request_id"] == id {
			found = attrs
		}
	}
	if found == nil || found["factory.outcome"] != "failed" || found["factory.execution_id"] == "" {
		t.Fatalf("op.result = %v", found)
	}
	_, got, _ := g.call("GET", "/v0/ops/"+id, hiTok, nil)
	res, _ := got["result"].(map[string]any)
	if res["health_after"] != HealthUnavailable || res["host_outcome"] != HostSucceeded {
		t.Errorf("op result = %v", got["result"])
	}
	if al := f.alerts.got(); len(al) != 1 || !strings.HasPrefix(al[0], AlertDeployFailed+": ") {
		t.Errorf("alerts = %v", al)
	}
}
