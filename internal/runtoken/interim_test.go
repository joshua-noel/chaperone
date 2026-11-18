package runtoken

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

type fakeVault struct {
	secrets map[string][]byte
	used    []string
}

func (v *fakeVault) Use(_ context.Context, id string, fn func([]byte) error) error {
	s, ok := v.secrets[id]
	if !ok {
		return errors.New("no such secret")
	}
	v.used = append(v.used, id)
	return fn(append([]byte(nil), s...))
}

// interimEnv is an env whose interim issuer signs through a (fake) vault with
// the key the key set pins.
func interimEnv(t *testing.T) (*env, *Interim) {
	t.Helper()
	e := newEnv(t)
	return e, e.mkInterim()
}

func (e *env) mkInterim() *Interim {
	e.t.Helper()
	v := &fakeVault{secrets: map[string][]byte{
		"interim-key": []byte(base64.RawURLEncoding.EncodeToString(e.intr.priv.Seed())),
	}}
	i, err := NewInterim(InterimConfig{Runs: e.runs, Orch: e.orch, Signer: NewVaultSigner(v, "interim-key", e.intr.kid)})
	if err != nil {
		e.t.Fatal(err)
	}
	return i
}

func mintReq() MintRequest {
	return MintRequest{Project: "acme-shop", Profile: "host-interim", Repo: "acme/shop", Branch: "agent/fix-1",
		Ops: []string{"pr.open", "branch.push"}, Minutes: 60}
}

func TestMintVerifiesAndEnds(t *testing.T) {
	ctx := context.Background()
	e, in := interimEnv(t)
	orch := e.issueOrch("main", mainScope, 0)
	res, err := in.Mint(ctx, orch.Token, MintRequest{Project: "acme-shop", Repo: "acme/shop", Branch: "agent/fix-1",
		Ops: []string{"pr.open", "pr.merge"}, Minutes: 60})
	mustNil(t, err)
	c := res.Claims
	if c.Iss != "chaperone.interim" || c.Isolation != "host" || c.Profile.Name != InterimProfile || c.Profile.Version != "0.0.0" ||
		c.Profile.Digest != "" || c.Exp-c.Iat != 3600 || c.Budget.Minutes != 60 || c.Budget.Tokens != DefaultInterimTokens ||
		c.TaskScope.Base != "main" || c.Sub != "run:"+c.RunID {
		t.Fatalf("claims %+v", c)
	}
	// It verifies as a registered interim run, through the same verifier.
	rt, err := e.verify(res.Token)
	mustNil(t, err)
	if !rt.Interim || rt.Profile != nil || rt.KID != "interim-1" {
		t.Fatalf("verified %+v", rt)
	}
	if got := rt.EffectiveOps([]string{"pr.open", "pr.merge", "deploy"}); len(got) != 2 {
		t.Fatalf("effective %v", got)
	}
	if want := []string{"grant", "run.start"}; strings.Join(e.led.names(), ",") != "op.request,op.result,"+strings.Join(want, ",") {
		t.Fatalf("events %v", e.led.names())
	}
	g := e.led.find("grant")[0]
	if g.Attributes["factory.isolation"] != "host" || g.RunID != c.RunID {
		t.Fatalf("grant %+v", g)
	}
	if _, ok := g.Attributes["factory.profile.digest"]; ok {
		t.Fatal("an interim grant carries a profile digest")
	}
	// Run end revokes on the very next request.
	mustNil(t, e.runs.Revoke(ctx, c.RunID, StopOperatorStopRun))
	_, err = e.verify(res.Token)
	wantCode(t, err, CauseTokenRevoked)
}

func TestMintNeedsAnOrchestratorToken(t *testing.T) {
	ctx := context.Background()
	e, in := interimEnv(t)
	orch := e.issueOrch("main", mainScope, 0)
	runTok := e.register(e.claims())
	for name, bearer := range map[string]string{
		"no token":                "",
		"a run token":             runTok,
		"a made-up orchestrator":  OrchPrefix + strings.Repeat("B", 43),
		"a prefix with no secret": OrchPrefix,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := in.Mint(ctx, bearer, mintReq())
			wantCode(t, err, CauseTokenInvalid)
		})
	}
	// A revoked orchestrator token mints nothing; the very next request.
	_, err := in.Mint(ctx, orch.Token, mintReq())
	mustNil(t, err)
	mustNil(t, e.orch.Revoke(ctx, "main", "console"))
	_, err = in.Mint(ctx, orch.Token, mintReq())
	wantCode(t, err, CauseTokenRevoked)
	// An expired one too.
	o2 := e.issueOrch("main", mainScope, 1)
	e.clock = o2.ExpiresAt
	_, err = in.Mint(ctx, o2.Token, mintReq())
	wantCode(t, err, CauseTokenExpired)
	var n int
	_ = e.db.SQL().QueryRow(`SELECT COUNT(*) FROM runs WHERE interim = 1`).Scan(&n)
	if n != 1 {
		t.Fatalf("%d interim runs, only the one minted with a live token should exist", n)
	}
}

func TestMintRefusals(t *testing.T) {
	ctx := context.Background()
	e, in := interimEnv(t)
	narrow := e.issueOrch("narrow", OrchScope{Projects: []string{"acme-shop"}, Ops: []string{"pr.open"}, MintInterim: true}, 0)
	noMint := e.issueOrch("nomint", OrchScope{Projects: []string{"acme-shop"}, Ops: []string{"pr.open", "branch.push"}}, 0)
	full := e.issueOrch("main", OrchScope{Projects: []string{"acme-shop"}, Ops: []string{"pr.open", "branch.push", "approvers.enroll", "secrets.read", "deploy"}, MintInterim: true}, 0)
	mod := func(f func(r *MintRequest)) MintRequest { r := mintReq(); f(&r); return r }
	for _, c := range []struct {
		name  string
		token string
		req   MintRequest
		code  string
	}{
		{"two hours and a minute", full.Token, mod(func(r *MintRequest) { r.Minutes = 121 }), CauseTokenInvalid},
		{"zero minutes", full.Token, mod(func(r *MintRequest) { r.Minutes = 0 }), CauseTokenInvalid},
		{"negative minutes", full.Token, mod(func(r *MintRequest) { r.Minutes = -5 }), CauseTokenInvalid},
		{"op outside the ceiling: approvers.enroll", full.Token, mod(func(r *MintRequest) { r.Ops = []string{"approvers.enroll"} }), CauseOpNotInToken},
		{"op outside the ceiling: secrets.read", full.Token, mod(func(r *MintRequest) { r.Ops = []string{"secrets.read"} }), CauseOpNotInToken},
		{"one op over the ceiling among good ones", full.Token, mod(func(r *MintRequest) { r.Ops = []string{"pr.open", "approvers.enroll"} }), CauseOpNotInToken},
		{"no ops", full.Token, mod(func(r *MintRequest) { r.Ops = nil }), CauseOpNotInToken},
		{"wildcard op", full.Token, mod(func(r *MintRequest) { r.Ops = []string{"pr.*"} }), CauseOpNotInToken},
		{"op the orchestrator may not ask for", narrow.Token, mod(func(r *MintRequest) {}), CauseOpNotInToken},
		{"project outside the orchestrator's scope", full.Token, mod(func(r *MintRequest) { r.Project = "other-project" }), CauseOpNotInToken},
		{"orchestrator without mint_interim", noMint.Token, mintReq(), CauseOpNotInToken},
		{"a real profile", full.Token, mod(func(r *MintRequest) { r.Profile = "code" }), CauseTokenInvalid},
		{"branch outside agent/", full.Token, mod(func(r *MintRequest) { r.Branch = "feature/x" }), CauseScopeBranch},
		{"the base branch", full.Token, mod(func(r *MintRequest) { r.Branch = "agent/x"; r.Base = "agent/x" }), CauseScopeBranch},
		{"placeholder branch", full.Token, mod(func(r *MintRequest) { r.Branch = "agent/{run}" }), CauseTokenInvalid},
		{"repo with option injection", full.Token, mod(func(r *MintRequest) { r.Repo = "-x/shop" }), CauseTokenInvalid},
		{"path with a leading dash", full.Token, mod(func(r *MintRequest) { r.Paths = []string{"-rf"} }), CauseTokenInvalid},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := in.Mint(ctx, c.token, c.req)
			wantCode(t, err, c.code)
		})
	}
	var n int
	_ = e.db.SQL().QueryRow(`SELECT COUNT(*) FROM runs`).Scan(&n)
	if n != 0 {
		t.Fatalf("refused mints registered %d runs", n)
	}
	// The ceiling accepts the high class (always approval-gated) and the routine ones.
	_, err := in.Mint(ctx, full.Token, mod(func(r *MintRequest) { r.Ops = []string{"deploy", "pr.open"}; r.Minutes = 120 }))
	mustNil(t, err)
}

func TestAllowInterimFalse(t *testing.T) {
	ctx := context.Background()
	e, in := interimEnv(t)
	orch := e.issueOrch("main", mainScope, 0)
	res, err := in.Mint(ctx, orch.Token, mintReq())
	mustNil(t, err)

	// The cut-over: allow_interim=false, chapd restarts.
	e.rebuild(false)
	in = e.mkInterim()
	_, err = in.Mint(ctx, orch.Token, mintReq())
	wantCode(t, err, CauseOpDisabled)
	// Every interim token is rejected, including one minted before the flip.
	_, err = e.verify(res.Token)
	wantCode(t, err, CauseTokenInvalid)
	// An orchestrator token still verifies; only the interim path is shut.
	if _, err := e.orch.Verify(ctx, orch.Token); err != nil {
		t.Fatal(err)
	}
}

func TestMintTokenLeavesNoSeed(t *testing.T) {
	ctx := context.Background()
	e, in := interimEnv(t)
	orch := e.issueOrch("main", mainScope, 0)
	res, err := in.Mint(ctx, orch.Token, mintReq())
	mustNil(t, err)
	seed := base64.RawURLEncoding.EncodeToString(e.intr.priv.Seed())
	for _, ev := range e.led.events {
		if strings.Contains(sprint(ev), seed) {
			t.Fatalf("event %s holds the key", ev.Name)
		}
	}
	if strings.Contains(res.Token, seed) {
		t.Fatal("token holds the seed")
	}
}

func TestNewInterimNeedsAnInterimKey(t *testing.T) {
	e := newEnv(t)
	v := &fakeVault{secrets: map[string][]byte{"k": []byte("x")}}
	for _, kid := range []string{"runner-1", "unknown"} {
		if _, err := NewInterim(InterimConfig{Runs: e.runs, Orch: e.orch, Signer: NewVaultSigner(v, "k", kid)}); err == nil {
			t.Fatalf("kid %q accepted as the interim signer", kid)
		}
	}
}

func TestVaultSigner(t *testing.T) {
	seed, pub, err := GenerateKeyPair()
	mustNil(t, err)
	v := &fakeVault{secrets: map[string][]byte{"k": []byte(seed), "bad": []byte("not a seed"), "short": []byte(seed[:20]),
		"long": []byte(seed + seed), "newline": []byte(seed + "\n"), "empty": {}}}
	s := NewVaultSigner(v, "k", "interim-1")
	sig, err := s.Sign(context.Background(), []byte("msg"))
	mustNil(t, err)
	raw, _ := base64.RawURLEncoding.DecodeString(pub)
	if !ed25519.Verify(ed25519.PublicKey(raw), []byte("msg"), sig) {
		t.Fatal("signature does not verify under the generated public key")
	}
	for _, id := range []string{"bad", "short", "long", "newline", "empty", "missing"} {
		if _, err := NewVaultSigner(v, id, "interim-1").Sign(context.Background(), []byte("m")); err == nil {
			t.Fatalf("secret %q signed", id)
		}
	}
}
