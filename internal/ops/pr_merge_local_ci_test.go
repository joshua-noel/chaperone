package ops_test

import (
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
	"github.com/joshua-noel/chaperone/internal/ops"
)

// ADR-002 amendment 10: pr.merge step 3 with a `pr.local_ci` policy. The local check is a check run of Chaperone's
// own App on exactly the head; a check of that name from any other App, and a commit status, never count.

func localCheck(app int64, status, conclusion string) ghtest.Check {
	return ghtest.Check{Name: "local-ci", AppID: app, Status: status, Conclusion: conclusion}
}

func (f *fx) withLocalCI(instead bool) {
	f.pol.LocalCI = &ops.PRLocalCI{Check: "local-ci", Instead: instead}
}

func checkNamed(v ops.PRVerdict, name string) (ops.PRCheck, bool) {
	for _, c := range v.Checks {
		if c.Name == name {
			return c, true
		}
	}
	return ops.PRCheck{}, false
}

func TestLocalCIAlsoNeedsBoth(t *testing.T) {
	f := newFx(t)
	f.withLocalCI(false)

	// Both green: merges, and both checks are in the verdict.
	n, head := f.green(t, "agent/both")
	f.r.SetCheck(head, localCheck(ghtest.OwnAppID, "completed", "success"))
	res, err := f.m.Merge(ctx, f.req(n, head))
	if err != nil || !res.Merged {
		t.Fatalf("both green: %v %+v", err, res)
	}
	for _, name := range []string{"verify", "local-ci"} {
		if c, ok := checkNamed(res.Verdict, name); !ok || !c.Passed {
			t.Errorf("check %s: %+v %v", name, c, ok)
		}
	}
	f.noLeak(t)

	// verify green, no local check: stale, nothing merged.
	n2, head2 := f.green(t, "agent/no-local")
	res, err = f.m.Merge(ctx, f.req(n2, head2))
	f.refused(t, n2, res, err)
	wantFailed(t, res.Verdict, "local-ci")
	if res.Verdict.Stop != ops.StopCIStale {
		t.Errorf("stop = %q, want %s", res.Verdict.Stop, ops.StopCIStale)
	}

	// local check green, verify red: the hosted check still counts.
	n3, head3 := f.open(t, "agent/red-verify", "docs: update notes")
	f.r.SetCheck(head3, verify("completed", "failure"))
	f.r.SetCheck(head3, localCheck(ghtest.OwnAppID, "completed", "success"))
	res, err = f.m.Merge(ctx, f.req(n3, head3))
	f.refused(t, n3, res, err)
	wantFailed(t, res.Verdict, "verify")
}

func TestLocalCIInsteadReplacesVerify(t *testing.T) {
	f := newFx(t)
	f.withLocalCI(true)

	// No verify at all, local check green: merges.
	n, head := f.open(t, "agent/local-only", "docs: update notes")
	f.r.SetCheck(head, localCheck(ghtest.OwnAppID, "completed", "success"))
	res, err := f.m.Merge(ctx, f.req(n, head))
	if err != nil || !res.Merged {
		t.Fatalf("local only: %v %+v", err, res)
	}
	if _, ok := checkNamed(res.Verdict, "verify"); ok {
		t.Error("verify is not read when a local check stands in for it")
	}
	f.noLeak(t)

	// A red verify does not block, a red local check does.
	n2, head2 := f.open(t, "agent/red-local", "docs: update notes")
	f.r.SetCheck(head2, verify("completed", "success"))
	f.r.SetCheck(head2, localCheck(ghtest.OwnAppID, "completed", "failure"))
	res, err = f.m.Merge(ctx, f.req(n2, head2))
	f.refused(t, n2, res, err)
	wantFailed(t, res.Verdict, "local-ci")
	if res.Verdict.Stop != ops.StopCIRed {
		t.Errorf("stop = %q, want %s", res.Verdict.Stop, ops.StopCIRed)
	}

	// The extra checks stay required from GitHub Actions.
	f.pol.ExtraChecks = []string{"lint"}
	n3, head3 := f.open(t, "agent/extra", "docs: update notes")
	f.r.SetCheck(head3, localCheck(ghtest.OwnAppID, "completed", "success"))
	res, err = f.m.Merge(ctx, f.req(n3, head3))
	f.refused(t, n3, res, err)
	wantFailed(t, res.Verdict, "lint")
}

func TestLocalCIIgnoresEveryOtherSource(t *testing.T) {
	for name, plant := range map[string]func(f *fx, head string){
		"GitHub Actions posts a check named local-ci": func(f *fx, head string) {
			f.r.SetCheck(head, localCheck(gh.GitHubActionsAppID, "completed", "success"))
		},
		"another App posts it": func(f *fx, head string) {
			f.r.SetCheck(head, localCheck(999001, "completed", "success"))
		},
		"the App's check is not completed": func(f *fx, head string) {
			f.r.SetCheck(head, localCheck(ghtest.OwnAppID, "in_progress", ""))
		},
		"the App's check is neutral": func(f *fx, head string) {
			f.r.SetCheck(head, localCheck(ghtest.OwnAppID, "completed", "neutral"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFx(t)
			f.withLocalCI(true)
			n, head := f.green(t, "agent/x")
			plant(f, head)
			res, err := f.m.Merge(ctx, f.req(n, head))
			f.refused(t, n, res, err)
			wantFailed(t, res.Verdict, "local-ci")
			if f.writes() != 0 {
				t.Fatal("a merge was sent")
			}
		})
	}
}

func TestLocalCIForAnotherHeadDoesNotCount(t *testing.T) {
	f := newFx(t)
	f.withLocalCI(true)
	n, head := f.open(t, "agent/moved", "docs: update notes")
	// The report was for the head before the last push.
	f.r.SetCheck(head, localCheck(ghtest.OwnAppID, "completed", "success"))
	newHead := f.r.Commit("agent/moved") // the PR's head follows its branch
	res, err := f.m.Merge(ctx, f.req(n, newHead))
	f.refused(t, n, res, err)
	wantFailed(t, res.Verdict, "local-ci")
	if res.Verdict.Stop != ops.StopCIStale {
		t.Errorf("stop = %q, want %s", res.Verdict.Stop, ops.StopCIStale)
	}
}

func TestLocalCILatestReportWins(t *testing.T) {
	f := newFx(t)
	f.withLocalCI(true)

	// A later green report replaces an earlier red one.
	n, head := f.open(t, "agent/rerun", "docs: update notes")
	f.r.SetCheck(head, localCheck(ghtest.OwnAppID, "completed", "failure"))
	f.r.SetCheck(head, localCheck(ghtest.OwnAppID, "completed", "success"))
	res, err := f.m.Merge(ctx, f.req(n, head))
	if err != nil || !res.Merged {
		t.Fatalf("red then green: %v %+v", err, res)
	}

	// A later red report is not hidden by an earlier green one.
	n2, head2 := f.open(t, "agent/regress", "docs: update notes")
	f.r.SetCheck(head2, localCheck(ghtest.OwnAppID, "completed", "success"))
	f.r.SetCheck(head2, localCheck(ghtest.OwnAppID, "completed", "failure"))
	res, err = f.m.Merge(ctx, f.req(n2, head2))
	f.refused(t, n2, res, err)
	wantFailed(t, res.Verdict, "local-ci")
}

func TestNoLocalCIPolicyIgnoresTheAppsCheck(t *testing.T) {
	f := newFx(t)
	// Without a local_ci block a green local-ci check is worth nothing: verify from GitHub Actions is still required.
	n, head := f.open(t, "agent/no-verify", "docs: update notes")
	f.r.SetCheck(head, localCheck(ghtest.OwnAppID, "completed", "success"))
	res, err := f.m.Merge(ctx, f.req(n, head))
	f.refused(t, n, res, err)
	wantFailed(t, res.Verdict, "verify")
	if _, ok := checkNamed(res.Verdict, "local-ci"); ok {
		t.Error("local-ci is read only when policy asks for it")
	}
}

func TestLocalCIPolicyValidation(t *testing.T) {
	f := newFx(t)
	for name, l := range map[string]*ops.PRLocalCI{
		"empty name":   {Check: ""},
		"newline":      {Check: "a\nb"},
		"long name":    {Check: strings.Repeat("x", 65)},
		"nul in name":  {Check: "a\x00b"},
		"all is well?": nil,
	} {
		f.pol.LocalCI = l
		n, head := f.green(t, "agent/v-"+strings.ReplaceAll(name, " ", "-"))
		if l != nil {
			if _, err := f.m.Merge(ctx, f.req(n, head)); err == nil {
				t.Errorf("%s: want an error for an unusable check name", name)
			}
		}
	}
}
