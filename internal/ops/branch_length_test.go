package ops_test

import (
	"context"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/connectors/github/githubspec"
	"github.com/joshua-noel/chaperone/internal/ops"
)

// head and base are branch names: the schema says at most githubspec.BranchMax, and the adapters refuse more with
// OP_PARAMS_INVALID, in Check and in Execute.
func TestBranchNameParamsAreBounded(t *testing.T) {
	long := strings.Repeat("b", githubspec.BranchMax+1)
	exact := strings.Repeat("b", githubspec.BranchMax)

	f := newFx(t)
	a := f.opener(t, nil)
	for _, key := range []string{"head", "base"} {
		req := f.openReq(f.runCaller(), with(okParams(), key, long))
		if _, err := a.Check(context.Background(), req); err == nil || refusalCode(t, err) != ops.CodeParamsInvalid {
			t.Errorf("pr.open %s of %d bytes: Check = %v, want OP_PARAMS_INVALID", key, len(long), err)
		}
		if out, err := a.Execute(context.Background(), req); err != nil || !out.Failed {
			t.Errorf("pr.open %s of %d bytes: Execute = %+v, %v, want a failed outcome", key, len(long), out, err)
		}
	}
	// The limit itself passes the length check (the branch is then refused for another reason, not for its length).
	req := f.openReq(f.runCaller(), with(okParams(), "base", exact))
	if _, err := a.Check(context.Background(), req); err != nil && strings.Contains(err.Error(), "required") {
		t.Errorf("a base of %d bytes was refused for its length: %v", len(exact), err)
	}

	n, head := f.green(t, "agent/ok")
	m := f.mergeAdapter()
	r := f.mergeReq("storefront", n, head)
	r.Params["base"] = long
	_, err := m.Check(context.Background(), r)
	wantRefusal(t, err, ops.CodeParamsInvalid, "at most 255 bytes")
	out, err := m.Execute(context.Background(), r)
	if err != nil || !out.Failed || !strings.Contains(out.Result["error"].(string), "at most 255 bytes") {
		t.Errorf("pr.merge base of %d bytes: Execute = %+v, %v", len(long), out, err)
	}
	if f.writes() != 0 {
		t.Error("an over-long base reached the merge")
	}
}
