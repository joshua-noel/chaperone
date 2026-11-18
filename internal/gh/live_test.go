//go:build live

// Live test against the real GitHub API (ticket L1-05 acceptance; needs the
// operator's GitHub App, H1). It never runs in CI: it needs `-tags live` and the
// environment below, and it fails (not skips) when the environment is missing.
//
// Command, PowerShell, repository root:
//
//	$env:CHAP_GH_LIVE_APP_ID = '<App ID or client ID>'
//	$env:CHAP_GH_LIVE_VAULT  = '<path of state.db; the key was stored with chapd vault import --name github-app-key>'
//	$env:CHAP_GH_LIVE_REPO   = 'joshua-noel/chaperone-sandbox'
//	$env:CHAP_GH_LIVE_OTHER  = 'example-org/storefront'
//	$env:CHAP_GH_LIVE_BRANCH = 'main'      # default branch of the sandbox repo
//	$env:GOFLAGS = '-mod=vendor'; $env:CGO_ENABLED = '0'
//	go test -tags live -run TestLive -count=1 -v ./internal/gh/
//
// Writes: one throwaway branch `live-test/<unix time>` with one file in
// CHAP_GH_LIVE_REPO, deleted again at the end. Nothing is written to CHAP_GH_LIVE_OTHER.
package gh_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/store"
	"github.com/joshua-noel/chaperone/internal/vault"
)

func liveEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("live test needs %s (see the header of live_test.go)", name)
	}
	return v
}

type live struct {
	c      *gh.Client
	repo   gh.Repo
	other  gh.Repo
	branch string
	inst   int64
}

func newLive(t *testing.T) *live {
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
	other, err := gh.ParseRepo(liveEnv(t, "CHAP_GH_LIVE_OTHER"))
	if err != nil {
		t.Fatal(err)
	}
	if repo == other {
		t.Fatal("CHAP_GH_LIVE_REPO and CHAP_GH_LIVE_OTHER must differ")
	}
	inst, err := c.FindInstallation(context.Background(), repo)
	if err != nil {
		t.Fatalf("the App is not installed on %s: %v", repo, err)
	}
	br := os.Getenv("CHAP_GH_LIVE_BRANCH")
	if br == "" {
		br = "main"
	}
	return &live{c: c, repo: repo, other: other, branch: br, inst: inst.ID}
}

func (l *live) mint(t *testing.T, perms map[string]string) *gh.Token {
	t.Helper()
	tok, err := l.c.MintToken(context.Background(), l.inst, gh.TokenRequest{Repositories: []string{l.repo.Name}, Permissions: perms})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	t.Cleanup(tok.Wipe)
	return tok
}

// raw is a request the typed client does not offer; live test only.
func raw(t *testing.T, tok *gh.Token, method, path string, body any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, gh.DefaultBaseURL+path, rd)
	req.Header.Set("Authorization", "Bearer "+tok.Reveal())
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", gh.APIVersion)
	req.Header.Set("User-Agent", "chaperone-gh-live-test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func TestLive(t *testing.T) {
	l := newLive(t)
	ctx := context.Background()

	t.Run("narrowed token cannot touch another repository", func(t *testing.T) {
		tok := l.mint(t, map[string]string{"contents": gh.Read, "pull_requests": gh.Read, "checks": gh.Read})
		if len(tok.Repositories) != 1 || tok.Repositories[0] != l.repo.Name {
			t.Fatalf("token repositories = %v", tok.Repositories)
		}
		if _, err := l.c.Compare(ctx, tok, l.repo, l.branch, l.branch); err != nil {
			t.Fatalf("positive control on %s: %v", l.repo, err)
		}
		_, err := l.c.Compare(ctx, tok, l.other, l.branch, l.branch)
		if !errors.Is(err, gh.ErrNotFound) {
			t.Fatalf("other repo %s with a token narrowed to %s: got %v, want 404", l.other, l.repo, err)
		}
		t.Logf("other repo answered: %v", err)
	})

	t.Run("token without workflows cannot write a workflow file", func(t *testing.T) {
		tok := l.mint(t, gh.PermsPush())
		if _, ok := tok.Permissions["workflows"]; ok {
			t.Fatalf("token has workflows: %v", tok.Permissions)
		}
		repoPath := "/repos/" + l.repo.String()
		status, body := raw(t, tok, "GET", repoPath+"/git/ref/heads/"+l.branch, nil)
		if status != 200 {
			t.Fatalf("read %s ref: %d %s", l.branch, status, body)
		}
		var ref struct {
			Object struct{ SHA string } `json:"object"`
		}
		if err := json.Unmarshal(body, &ref); err != nil || ref.Object.SHA == "" {
			t.Fatalf("ref answer: %s", body)
		}
		work := fmt.Sprintf("live-test/%d", time.Now().Unix())
		if status, body = raw(t, tok, "POST", repoPath+"/git/refs", map[string]string{"ref": "refs/heads/" + work, "sha": ref.Object.SHA}); status != 201 {
			t.Fatalf("create branch: %d %s", status, body)
		}
		t.Cleanup(func() {
			if s, b := raw(t, tok, "DELETE", repoPath+"/git/refs/heads/"+work, nil); s != 204 {
				t.Errorf("delete %s: %d %s (delete it by hand)", work, s, b)
			}
		})
		put := func(path string) (int, []byte) {
			return raw(t, tok, "PUT", repoPath+"/contents/"+path, map[string]string{
				"message": "chore: live test", "branch": work,
				"content": base64.StdEncoding.EncodeToString([]byte("chaperone live test\n")),
			})
		}
		// Positive control: the same token can write an ordinary file.
		if s, b := put("chaperone-live-test.txt"); s != 201 {
			t.Fatalf("positive control (ordinary file): %d %s", s, b)
		}
		s, b := put(".github/workflows/chaperone-live-test.yml")
		if s >= 200 && s < 300 {
			t.Fatalf("a token without workflows wrote a workflow file: %d %s", s, b)
		}
		t.Logf("workflow write refused: %d %s", s, b)
	})

	t.Run("DELETE /installation/token makes the token return 401", func(t *testing.T) {
		tok := l.mint(t, map[string]string{"contents": gh.Read})
		if _, err := l.c.Compare(ctx, tok, l.repo, l.branch, l.branch); err != nil {
			t.Fatalf("before revoke: %v", err)
		}
		if err := l.c.RevokeToken(ctx, tok); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		// GitHub takes a moment to apply the revoke (a first run that asked at
		// once still got 200; a retry 3 s later got 401). Ask again every 3 s for
		// up to 15 s. A token that still works after that is logged, not failed:
		// a token is good for 1 h at most whatever this call does.
		var err error
		for waited := time.Duration(0); ; waited += 3 * time.Second {
			_, err = l.c.Compare(ctx, tok, l.repo, l.branch, l.branch)
			if errors.Is(err, gh.ErrUnauthorized) {
				t.Logf("token returned 401 %v after the revoke", waited)
				return
			}
			if err != nil {
				t.Fatalf("after revoke the token fails differently: %v", err)
			}
			if waited >= 15*time.Second {
				break
			}
			time.Sleep(3 * time.Second)
		}
		t.Logf("RESIDUAL RISK: the token still worked 15 s after DELETE /installation/token; it is good until it expires (1 h)")
	})
}
