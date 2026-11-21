package ops_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
)

// A bad tier glob in the project file turns off pr.merge and pr.update for that project only. The refusal carries
// the cause the code base uses for a policy problem (OP_POLICY_REFUSED: the operator's fault, not a wrong request)
// and names the project, the policy file, the tier and the glob. pr.open still works for the project.
func TestMergeOpsRefuseAProjectWithABadTierGlobAndPROpenStillWorks(t *testing.T) {
	cat, pack, err := policy.Default()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	file := "project: storefront\npr:\n  repo: example-org/storefront\n  base: " + base + "\n  tiers:\n    low: [\"docs/caf\u00e9/**\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "storefront.yaml"), []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(cat, pack, dir)
	pol := ops.PRPolicyFromEngine(eng)

	f := newFx(t)
	n, head := f.green(t, "agent/ok")
	for name, a := range map[string]ops.Adapter{"pr.merge": ops.NewPRMergeAdapter(f.m, pol), "pr.update": ops.NewPRUpdateAdapter(f.m, pol)} {
		req := f.mergeReq("storefront", n, head)
		req.Op = name
		if name == "pr.update" {
			req.Params = map[string]any{"expected_head_sha": head}
		}
		_, err := a.Check(context.Background(), req)
		wantRefusal(t, err, ops.CodePolicyRefused, "storefront.yaml")
		for _, want := range []string{"project storefront", "tiers.low", "docs/caf\u00e9/**", name + " is refused"} {
			if !strings.Contains(err.(*ops.Refusal).Why, want) {
				t.Errorf("%s: the refusal does not hold %q: %s", name, want, err.(*ops.Refusal).Why)
			}
		}
		if out, err := a.Execute(context.Background(), req); err != nil || !out.Failed || !strings.Contains(out.Result["error"].(string), "storefront.yaml") {
			t.Errorf("%s: Execute = %+v, %v", name, out, err)
		}
	}
	if f.writes() != 0 {
		t.Error("a merge reached GitHub")
	}
	if ok, _ := f.r.Merged(n); ok {
		t.Error("the PR was merged under a policy whose tier globs cannot be used")
	}

	// pr.open for the same project, with the project function chapd builds from the same engine.
	project := func(name string) (ops.PRProject, bool) {
		eff := eng.For(name)
		if eff.Invalid != nil || eff.PR == nil {
			return ops.PRProject{}, false
		}
		return ops.PRProject{Repo: eff.PR.Repo, Base: eff.PR.Base}, true
	}
	f.r.Branch(openBranch, base)
	f.r.Commit(openBranch)
	opener := f.opener(t, project)
	req := f.openReq(f.runCaller(), okParams())
	if _, err := opener.Check(context.Background(), req); err != nil {
		t.Fatalf("pr.open Check: %v", err)
	}
	if out, err := opener.Execute(context.Background(), req); err != nil || out.Failed {
		t.Fatalf("pr.open Execute: %+v, %v", out, err)
	}
}

// A policy built by hand (no engine) with a bad glob gets the same refusal at request time.
func TestMergeRefusesAHandBuiltPolicyWithABadTierGlob(t *testing.T) {
	f := newFx(t)
	n, head := f.green(t, "agent/ok")
	f.pol.Tiers = ops.PRTierGlobs{High: []string{"docs/\u65e5\u672c\u8a9e/**"}}
	_, err := f.mergeAdapter().Check(context.Background(), f.mergeReq("storefront", n, head))
	wantRefusal(t, err, ops.CodePolicyRefused, "storefront.yaml")
	if !strings.Contains(err.(*ops.Refusal).Why, "\u65e5\u672c\u8a9e") {
		t.Errorf("the refusal does not name the glob: %s", err.(*ops.Refusal).Why)
	}
}
