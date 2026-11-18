package ops_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/ops"
)

// The permission set each op asks GitHub for, pinned. First the runner runs, 25 Oct:
// pr.open asked for pull_requests:write and metadata:read only, and GitHub then
// refused every pull request (422 "not all refs are readable") because the token
// could not read the head ref. Each set is the least that its calls need:
// anything that reads a ref has contents:read (contents:write includes it).

// minted returns the permission request of every installation token minted so
// far, each as a map.
func (f *fx) minted() []map[string]string {
	var out []map[string]string
	for _, r := range f.s.Requests() {
		if r.Method == "POST" && strings.HasSuffix(r.Path, "/access_tokens") {
			var b struct{ Permissions map[string]string }
			_ = json.Unmarshal([]byte(r.Body), &b)
			out = append(out, b.Permissions)
		}
	}
	return out
}

func wantSets(t *testing.T, op string, got []map[string]string, want ...map[string]string) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("%s minted %v, want %v", op, got, want)
	}
}

func TestPROpenTokenPermissions(t *testing.T) {
	f := newFx(t)
	f.r.Branch(openBranch, base)
	f.r.Commit(openBranch)
	a := f.opener(t, nil)
	out, err := a.Execute(ctx, f.openReq(f.runCaller(), okParams()))
	if err != nil || out.Failed {
		t.Fatalf("%+v %v", out, err)
	}
	wantSets(t, "pr.open", f.minted(), map[string]string{"pull_requests": "write", "contents": "read", "metadata": "read"})
}

// GitHub's own answer, reason included, reaches the agent's denial text.
func TestPROpenFailureTextCarriesGitHubsReason(t *testing.T) {
	f := newFx(t)
	f.r.Branch(openBranch, base) // no commit: "No commits between"
	a := f.opener(t, nil)
	out, err := a.Execute(ctx, f.openReq(f.runCaller(), okParams()))
	if err != nil || !out.Failed {
		t.Fatalf("%+v %v", out, err)
	}
	got, _ := out.Result["error"].(string)
	if want := "GitHub refused the pull request (422): Validation Failed (PullRequest custom: No commits between " + base + " and " + openBranch + ")"; got != want {
		t.Errorf("error text %q, want %q", got, want)
	}
}

func TestPRMergeTokenPermissions(t *testing.T) {
	f := newFx(t)
	n, head := f.green(t, "agent/ok")
	if _, err := f.m.Merge(ctx, f.req(n, head)); err != nil {
		t.Fatal(err)
	}
	wantSets(t, "pr.merge", f.minted(),
		map[string]string{"pull_requests": "read", "checks": "read", "contents": "read", "metadata": "read"},
		map[string]string{"contents": "write", "pull_requests": "write", "metadata": "read"})
}

func TestPRUpdateTokenPermissions(t *testing.T) {
	f := newFx(t)
	n, head := f.green(t, "agent/x")
	f.r.Commit(base) // behind
	res, err := f.m.UpdateBranch(ctx, f.ureq(n, head))
	if err != nil || !res.Updated {
		t.Fatalf("%+v %v", res, err)
	}
	wantSets(t, "pr.update", f.minted(),
		map[string]string{"pull_requests": "read", "checks": "read", "contents": "read", "metadata": "read"},
		map[string]string{"contents": "write", "pull_requests": "write", "metadata": "read"})
}

var _ = ops.OpPROpen
