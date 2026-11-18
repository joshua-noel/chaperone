package ops

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// deploy reads the commit and its checks, then records the deployment: two
// sets, and the write one holds deployments:write only (checked live on
// the sandbox repository: creating a deployment for a ref needs nothing more).
func TestDeployTokenPermissions(t *testing.T) {
	f := newDpFx(t)
	if out, err := f.d.Execute(context.Background(), f.req(f.sha)); err != nil || out.Failed {
		t.Fatalf("%+v %v", out, err)
	}
	read := fmt.Sprint(map[string]string{"contents": "read", "checks": "read", "metadata": "read"})
	write := fmt.Sprint(map[string]string{"deployments": "write"})
	wrote := false
	for _, r := range f.gh.Requests() {
		if r.Method != "POST" || !strings.HasSuffix(r.Path, "/access_tokens") {
			continue
		}
		var b struct{ Permissions map[string]string }
		_ = json.Unmarshal([]byte(r.Body), &b)
		switch got := fmt.Sprint(b.Permissions); got {
		case read:
		case write:
			wrote = true
		default:
			t.Errorf("deploy minted %s, want %s or %s", got, read, write)
		}
	}
	if !wrote {
		t.Error("deploy minted no deployments:write token")
	}
}
