//go:build live

// Live test for pr.merge against the real GitHub API (ticket L1-10 acceptance:
// "live test on chaperone-sandbox for the success path and the 409"). It needs the
// operator's GitHub App (H1), never runs in CI, and fails (not skips) when its
// environment is missing.
//
// The sandbox repository must run a workflow with a job named `verify` on
// pull_request (it may do nothing but succeed), and must allow squash merges.
//
// Command, PowerShell, repository root:
//
//	$env:CHAP_GH_LIVE_APP_ID = '<App ID or client ID>'
//	$env:CHAP_GH_LIVE_VAULT  = '<path of state.db; the key was stored with chapd vault import --name github-app-key>'
//	$env:CHAP_GH_LIVE_REPO   = 'example-org/storefront-sandbox'
//	$env:CHAP_GH_LIVE_BRANCH = 'main'      # the sandbox repo's merge base
//	$env:GOFLAGS = '-mod=vendor'; $env:CGO_ENABLED = '0'
//	go test -tags live -run TestLivePRMerge -count=1 -v -timeout 20m ./internal/ops/
//
// Writes, all in CHAP_GH_LIVE_REPO: two throwaway branches `live-test/ops-<unix
// time>-{ok,race}`, one docs file each, two pull requests, and one squash merge
// of the first into CHAP_GH_LIVE_BRANCH (the sandbox repo's history grows by one
// commit per run). Both branches are deleted and the second PR closed at the end.
package ops_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/store"
	"github.com/joshua-noel/chaperone/internal/vault"
)

func liveEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("live test needs %s (see the header of pr_merge_live_test.go)", name)
	}
	return v
}

type liveRepo struct {
	c      *gh.Client
	repo   gh.Repo
	branch string
	inst   int64
	push   *gh.Token // contents:write + pull_requests:write, for setup and cleanup only
}

func newLiveRepo(t *testing.T) *liveRepo {
	t.Helper()
	ctx := context.Background()
	dbPath := liveEnv(t, "CHAP_GH_LIVE_VAULT")
	db, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open state.db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	v, err := vault.Open(ctx, vault.Config{
		Dir:     filepath.Join(filepath.Dir(dbPath), "vault"),
		KeyDir:  filepath.Join(filepath.Dir(dbPath), "vault-keys"),
		DB:      db,
		Wrapper: vault.NewDPAPI(),
	})
	if err != nil {
		t.Fatalf("open the vault (run as the account that imported the key): %v", err)
	}
	t.Cleanup(v.Close)
	keys, err := gh.NewVaultKey(v, "")
	if err != nil {
		t.Fatal(err)
	}
	c, err := gh.New(gh.Config{AppID: liveEnv(t, "CHAP_GH_LIVE_APP_ID"), Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	repo, err := gh.ParseRepo(liveEnv(t, "CHAP_GH_LIVE_REPO"))
	if err != nil {
		t.Fatal(err)
	}
	inst, err := c.FindInstallation(ctx, repo)
	if err != nil {
		t.Fatalf("the App is not installed on %s: %v", repo, err)
	}
	br := os.Getenv("CHAP_GH_LIVE_BRANCH")
	if br == "" {
		br = "main"
	}
	l := &liveRepo{c: c, repo: repo, branch: br, inst: inst.ID}
	l.push, err = c.MintToken(ctx, inst.ID, gh.TokenRequest{Repositories: []string{repo.Name}, Permissions: gh.PermsPush()})
	if err != nil {
		t.Fatalf("mint setup token: %v", err)
	}
	t.Cleanup(func() {
		if err := c.RevokeToken(context.Background(), l.push); err != nil {
			t.Errorf("revoke setup token: %v", err)
		}
		l.push.Wipe()
	})
	return l
}

// raw is a request the typed client does not offer; live test only.
func (l *liveRepo) raw(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, gh.DefaultBaseURL+"/repos/"+l.repo.String()+path, rd)
	req.Header.Set("Authorization", "Bearer "+l.push.Reveal())
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", gh.APIVersion)
	req.Header.Set("User-Agent", "chaperone-ops-live-test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// branchWithFile creates branch from the base, adds one docs file, and returns
// the new head SHA. The branch is deleted at the end of the test.
func (l *liveRepo) branchWithFile(t *testing.T, name string) string {
	t.Helper()
	status, body := l.raw(t, "GET", "/git/ref/heads/"+l.branch, nil)
	var ref struct{ Object struct{ SHA string } }
	if status != 200 || json.Unmarshal(body, &ref) != nil || ref.Object.SHA == "" {
		t.Fatalf("read %s: %d %s", l.branch, status, body)
	}
	if s, b := l.raw(t, "POST", "/git/refs", map[string]string{"ref": "refs/heads/" + name, "sha": ref.Object.SHA}); s != 201 {
		t.Fatalf("create branch: %d %s", s, b)
	}
	t.Cleanup(func() {
		if s, b := l.raw(t, "DELETE", "/git/refs/heads/"+name, nil); s != 204 && s != 422 {
			t.Errorf("delete %s: %d %s (delete it by hand)", name, s, b)
		}
	})
	return l.commitFile(t, name, "docs/"+strings.ReplaceAll(name, "/", "-")+".md")
}

func (l *liveRepo) commitFile(t *testing.T, branch, path string) string {
	t.Helper()
	s, b := l.raw(t, "PUT", "/contents/"+path, map[string]string{
		"message": "docs: live test", "branch": branch,
		"content": base64.StdEncoding.EncodeToString([]byte("chaperone ops live test " + time.Now().String() + "\n")),
	})
	var out struct{ Commit struct{ SHA string } }
	if s != 201 || json.Unmarshal(b, &out) != nil || out.Commit.SHA == "" {
		t.Fatalf("write %s: %d %s", path, s, b)
	}
	return out.Commit.SHA
}

// waitForVerify polls a dry run until `verify` has finished on head, so the
// verdict is a real one (allow) and not "not yet".
func waitForVerify(t *testing.T, m *ops.PRMerger, req ops.PRMergeRequest) {
	t.Helper()
	req.DryRun = true
	deadline := time.Now().Add(8 * time.Minute)
	for {
		res, err := m.Merge(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if res.Verdict.WouldAllow() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("verify never went green on %s: %s", req.HeadSHA, res.Verdict.Why)
		}
		time.Sleep(15 * time.Second)
	}
}

// pushThenMerge moves the PR branch just before the real merge call, which is
// the race step 8's `sha` precondition exists for. It counts merge requests.
type pushThenMerge struct {
	*gh.Client
	push   func()
	merges int
}

func (p *pushThenMerge) MergePull(ctx context.Context, tok *gh.Token, repo gh.Repo, n int, req gh.MergeRequest) (*gh.MergeResult, error) {
	p.merges++
	p.push()
	return p.Client.MergePull(ctx, tok, repo, n, req)
}

func TestLivePRMerge(t *testing.T) {
	l := newLiveRepo(t)
	ctx := context.Background()
	m, err := ops.NewPRMerger(ops.PRMergerConfig{GitHub: l.c, Tokens: &ops.InstallationMinter{Client: l.c}})
	if err != nil {
		t.Fatal(err)
	}
	pol := ops.PRPolicy{Version: "live", Base: l.branch}
	stamp := time.Now().Unix()

	open := func(branch, head string) (int, ops.PRMergeRequest) {
		p, err := l.c.CreatePull(ctx, l.push, l.repo, gh.NewPull{Title: fmt.Sprintf("docs: live test %d", stamp), Head: branch, Base: l.branch})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if s, b := l.raw(t, "PATCH", fmt.Sprintf("/pulls/%d", p.Number), map[string]string{"state": "closed"}); s != 200 {
				t.Logf("close PR #%d: %d %s", p.Number, s, b)
			}
		})
		return p.Number, ops.PRMergeRequest{Repo: l.repo, Number: p.Number, Base: l.branch, HeadSHA: head, Policy: pol}
	}

	t.Run("success: verify green on the exact head, low tier, merged, token revoked", func(t *testing.T) {
		branch := fmt.Sprintf("live-test/ops-%d-ok", stamp)
		head := l.branchWithFile(t, branch)
		_, req := open(branch, head)
		waitForVerify(t, m, req)
		res, err := m.Merge(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if !res.Merged || res.MergeCommitSHA == "" || res.ExternalRef == "" || !res.WriteTokenRevoked {
			t.Fatalf("%+v", res)
		}
		t.Logf("merged: external_ref=%s merge_commit=%s", res.ExternalRef, res.MergeCommitSHA)
	})

	t.Run("409: the head moves between the check and the write", func(t *testing.T) {
		branch := fmt.Sprintf("live-test/ops-%d-race", stamp)
		head := l.branchWithFile(t, branch)
		_, req := open(branch, head)
		waitForVerify(t, m, req)
		spy := &pushThenMerge{Client: l.c, push: func() { l.commitFile(t, branch, fmt.Sprintf("docs/live-race-%d.md", stamp)) }}
		race, err := ops.NewPRMerger(ops.PRMergerConfig{GitHub: spy, Tokens: &ops.InstallationMinter{Client: l.c}})
		if err != nil {
			t.Fatal(err)
		}
		res, err := race.Merge(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if res.Merged || res.Verdict.Outcome != ops.PRRefuse || !strings.Contains(res.Verdict.Why, "409") {
			t.Fatalf("%+v", res.Verdict)
		}
		if spy.merges != 1 || !res.WriteTokenRevoked {
			t.Fatalf("merge requests=%d revoked=%v: a 409 is refused once and the write token revoked", spy.merges, res.WriteTokenRevoked)
		}
		t.Logf("refused: %s", res.Verdict.Why)
	})
}
