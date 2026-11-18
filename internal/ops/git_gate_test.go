package ops

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/policy"
)

const zeroSHA = "0000000000000000000000000000000000000000"

// gateHandler is a GitHandler that only asks the gate, as the proxy does.
type gateHandler struct{ svc *Service }

func (h *gateHandler) ServeGit(w http.ResponseWriter, r *http.Request, c *Caller) error {
	if strings.HasSuffix(r.URL.Path, "/info/refs") && r.URL.Query().Get("service") == "git-receive-pack" {
		if err := h.svc.GitPushDiscovery(r.Context(), c, "acme/shop"); err != nil {
			return err
		}
	} else if err := h.svc.GitRead(r.Context(), c, "other/repo"); err != nil {
		return err
	}
	_, _ = io.WriteString(w, "ok")
	return nil
}

func gitCaller(g *rig) *Caller { c := *g.ver.runs[runTok]; return &c }

func okPush() GitPush {
	return GitPush{Repo: "acme/shop", Updates: []GitUpdate{{Old: zeroSHA, New: sha1, Ref: "refs/heads/agent/r-7f3a"}}}
}

func denialCode(t *testing.T, err error) string {
	t.Helper()
	var de *DeniedError
	if !errors.As(err, &de) {
		t.Fatalf("want a denial, got %v", err)
	}
	return de.Denial.CauseCode
}

func TestGitPushAdmittedAndFinished(t *testing.T) {
	for _, tc := range []struct {
		res   GitPushResult
		state string
	}{
		{GitPushResult{Outcome: "succeeded"}, "succeeded"},
		{GitPushResult{Outcome: "failed", Detail: "ref refused: hook declined"}, "failed"},
		{GitPushResult{Outcome: "unconfirmed"}, "unconfirmed"},
	} {
		g := newRig(t, rigOpts{enable: []string{"branch.push"}})
		op, err := g.svc.BeginGitPush(context.Background(), gitCaller(g), okPush())
		if err != nil {
			t.Fatal(err)
		}
		if n := opCount(t, g.db, `op = 'branch.push' AND state = 'executing'`); n != 1 {
			t.Fatalf("%s: %d executing rows after Begin, want 1", tc.state, n)
		}
		if n := len(g.led.rows(t, g.db, "op.request")); n != 1 {
			t.Fatalf("%s: %d op.request events, want 1", tc.state, n)
		}
		if err := op.Finish(context.Background(), tc.res); err != nil {
			t.Fatal(err)
		}
		if n := opCount(t, g.db, `state = ?`, tc.state); n != 1 {
			t.Errorf("%s: no row in state %s", tc.state, tc.state)
		}
		if n := len(g.led.rows(t, g.db, "op.result")); n != 1 {
			t.Errorf("%s: %d op.result events, want 1", tc.state, n)
		}
	}
}

func TestGitPushRefusals(t *testing.T) {
	two := okPush()
	two.Updates = append(two.Updates, GitUpdate{Old: zeroSHA, New: sha2, Ref: "refs/heads/agent/other"})
	two.More = true
	mod := func(f func(p *GitPush)) GitPush { p := okPush(); f(&p); return p }
	for name, tc := range map[string]struct {
		push GitPush
		code string
	}{
		"base branch":   {mod(func(p *GitPush) { p.Updates[0].Ref = "refs/heads/main" }), CodeScopeBranch},
		"other branch":  {mod(func(p *GitPush) { p.Updates[0].Ref = "refs/heads/agent/r-9b2c" }), CodeScopeBranch},
		"prefix branch": {mod(func(p *GitPush) { p.Updates[0].Ref = "refs/heads/agent/r-7f3a-evil" }), CodeScopeBranch},
		"tag":           {mod(func(p *GitPush) { p.Updates[0].Ref = "refs/tags/v1" }), CodeScopeBranch},
		"delete":        {mod(func(p *GitPush) { p.Updates[0].New = zeroSHA }), CodeScopeBranch},
		"two refs":      {two, CodeScopeBranch},
		"push cert":     {mod(func(p *GitPush) { p.PushCert = true }), CodeScopeBranch},
		"other repo":    {mod(func(p *GitPush) { p.Repo = "acme/other" }), CodeScopePath},
		"malformed":     {GitPush{Repo: "acme/shop", Malformed: "bad packet length"}, CodeParamsInvalid},
		"no command":    {GitPush{Repo: "acme/shop"}, CodeParamsInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			g := newRig(t, rigOpts{enable: []string{"branch.push"}})
			_, err := g.svc.BeginGitPush(context.Background(), gitCaller(g), tc.push)
			if got := denialCode(t, err); got != tc.code {
				t.Errorf("cause %s, want %s", got, tc.code)
			}
			if n := opCount(t, g.db, `state = 'executing'`); n != 0 {
				t.Errorf("%d rows executing after a refusal", n)
			}
			if n := opCount(t, g.db, `state = 'denied'`); name != "other repo" && n != 1 {
				t.Errorf("%d denied rows, want 1", n)
			}
		})
	}
}

// turnOff switches an op the shipped baseline enables back off.
func (g *rig) turnOff(op string) {
	g.t.Helper()
	cat, _, err := policy.Default()
	if err != nil {
		g.t.Fatal(err)
	}
	src := string(policy.BaselineBytes())
	i := strings.Index(src, "  "+op+":")
	if i < 0 {
		g.t.Fatalf("op %s not in baseline", op)
	}
	eol := strings.Index(src[i:], "\n")
	line := strings.Replace(src[i:i+eol], "enabled: true", "enabled: false", 1)
	pack, err := policy.LoadBaseline([]byte(src[:i]+line+src[i+eol:]), cat)
	if err != nil {
		g.t.Fatal(err)
	}
	g.svc.policy = policy.NewEngine(cat, pack, "")
}

func TestGitPushDisabledAndNotInToken(t *testing.T) {
	g := newRig(t, rigOpts{})
	g.turnOff(OpBranchPush)
	_, err := g.svc.BeginGitPush(context.Background(), gitCaller(g), okPush())
	if got := denialCode(t, err); got != CodeOpDisabled {
		t.Errorf("disabled: %s", got)
	}
	if got := denialCode(t, g.svc.GitPushDiscovery(context.Background(), gitCaller(g), "acme/shop")); got != CodeOpDisabled {
		t.Errorf("discovery, disabled: %s", got)
	}

	g = newRig(t, rigOpts{enable: []string{"branch.push"}})
	c := gitCaller(g)
	c.TokenOps = []string{"health"}
	if got := denialCode(t, g.svc.GitPushDiscovery(context.Background(), c, "acme/shop")); got != CodeOpNotInToken {
		t.Errorf("discovery, not in token: %s", got)
	}
	if _, err := g.svc.BeginGitPush(context.Background(), c, okPush()); denialCode(t, err) != CodeOpNotInToken {
		t.Errorf("push, not in token: %v", err)
	}
}

func TestGitFetchIsHeldToTheRunsRepo(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"branch.push"}})
	ctx := context.Background()
	if err := g.svc.GitRead(ctx, gitCaller(g), "acme/shop"); err != nil {
		t.Fatalf("own repo: %v", err)
	}
	if err := g.svc.GitRead(ctx, gitCaller(g), "ACME/Shop"); err != nil {
		t.Fatalf("own repo, other case: %v", err)
	}
	if got := denialCode(t, g.svc.GitRead(ctx, gitCaller(g), "acme/secret")); got != CodeScopePath {
		t.Errorf("other repo: %s", got)
	}
	orch := &Caller{Kind: KindOrchestrator, OrchID: "main", Projects: []string{"acme-shop"}}
	if got := denialCode(t, g.svc.GitRead(ctx, orch, "acme/shop")); got != CodeScopePath {
		t.Errorf("orchestrator: %s", got)
	}
}

// A push the proxy could not confirm must not hold the retry back.
func TestGitPushRetryAfterUnconfirmed(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"branch.push"}})
	ctx := context.Background()
	op, err := g.svc.BeginGitPush(ctx, gitCaller(g), okPush())
	if err != nil {
		t.Fatal(err)
	}
	if err := op.Finish(ctx, GitPushResult{Outcome: "unconfirmed"}); err != nil {
		t.Fatal(err)
	}
	op2, err := g.svc.BeginGitPush(ctx, gitCaller(g), okPush())
	if err != nil {
		t.Fatalf("retry of an unconfirmed push: %v", err)
	}
	if op2.ID() == op.ID() {
		t.Error("the retry reused the op")
	}
}

func TestGitHandlerDenialsAndChallenge(t *testing.T) {
	h := &gateHandler{}
	g := newRig(t, rigOpts{enable: []string{"branch.push"}, git: h})
	h.svc = g.svc

	get := func(path, user string) (*http.Response, string) {
		req, _ := http.NewRequest("GET", g.http.URL+path, nil)
		if user != "" {
			req.SetBasicAuth("x", user)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}

	resp, _ := get("/git/acme/shop.git/info/refs?service=git-upload-pack", "")
	if resp.StatusCode != 401 || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Basic ") {
		t.Errorf("no credentials: %d %q, want 401 with a Basic challenge", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	resp, _ = get("/v0/status", "")
	if !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Bearer ") {
		t.Errorf("API challenge: %q, want Bearer", resp.Header.Get("WWW-Authenticate"))
	}
	resp, body := get("/git/acme/shop.git/info/refs?service=git-upload-pack", runTok)
	if resp.StatusCode != 403 || !strings.Contains(body, "DENIED git.fetch") || resp.Header.Get("X-Chaperone-Denial-Id") == "" {
		t.Errorf("fetch of another repo: %d %q", resp.StatusCode, body)
	}
	if strings.Contains(body, runTok) {
		t.Error("the denial text echoes the token")
	}
}
