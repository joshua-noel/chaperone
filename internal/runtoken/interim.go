package runtoken

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

const (
	// InterimProfile is the profile name of every interim token.
	InterimProfile = "host-interim"
	// InterimBranchPrefix is where an interim token's pushable branch lives:
	// threat model TB3-S4 keeps low-impact ops of a host run inside agent/*.
	InterimBranchPrefix = "agent/"
	// DefaultInterimTokens is budget.tokens when the mint request names none
	// (the value the spec's own example token uses).
	DefaultInterimTokens int64 = 2_000_000
)

// Signer signs with the interim issuer's Ed25519 key.
type Signer interface {
	// KID is the kid under which the public half is pinned in the key set.
	KID() string
	Sign(ctx context.Context, msg []byte) ([]byte, error)
}

// SecretUser is the vault's Use method (internal/vault.Vault satisfies it):
// the secret is handed to fn and never returned.
type SecretUser interface {
	Use(ctx context.Context, id string, fn func(secret []byte) error) error
}

type vaultSigner struct {
	vault SecretUser
	id    string
	kid   string
}

// NewVaultSigner returns a Signer whose key is the vault secret id: the
// base64url (unpadded) text of a 32-byte Ed25519 seed, as [GenerateKeyPair]
// prints it. The seed exists only inside the Use closure for one signature.
func NewVaultSigner(v SecretUser, secretID, kid string) Signer {
	return &vaultSigner{vault: v, id: secretID, kid: kid}
}

func (s *vaultSigner) KID() string { return s.kid }

func (s *vaultSigner) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	var sig []byte
	err := s.vault.Use(ctx, s.id, func(secret []byte) error {
		// Check the length before decoding: Decode writes up to DecodedLen(len(secret))
		// bytes, so a longer secret would run past the 32-byte seed buffer and panic.
		if len(secret) != base64.RawURLEncoding.EncodedLen(ed25519.SeedSize) {
			return errors.New("the interim key secret is not a base64url Ed25519 seed")
		}
		seed := make([]byte, ed25519.SeedSize)
		defer clear(seed)
		if n, err := base64.RawURLEncoding.Strict().Decode(seed, secret); err != nil || n != ed25519.SeedSize {
			return errors.New("the interim key secret is not a base64url Ed25519 seed")
		}
		key := ed25519.NewKeyFromSeed(seed)
		defer clear(key)
		sig = ed25519.Sign(key, msg)
		return nil
	})
	return sig, err
}

// GenerateKeyPair makes an Ed25519 key for the interim issuer: seed is what to
// import into the vault, public is the key-set `public_key`.
func GenerateKeyPair() (seed, public string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	defer clear(priv)
	enc := base64.RawURLEncoding
	return enc.EncodeToString(priv.Seed()), enc.EncodeToString(pub), nil
}

// randomLower returns n random characters of [0-9a-z] without modulo bias
// (256 mod 36 would bias; reject the top bytes).
func randomLower(n int) (string, error) {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	out := make([]byte, 0, n)
	buf := make([]byte, n*2)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("runtoken: random: %w", err)
		}
		for _, b := range buf {
			if b < 252 { // 252 = 7 * 36
				out = append(out, alphabet[int(b)%36])
				if len(out) == n {
					break
				}
			}
		}
	}
	return string(out), nil
}

// InterimConfig configures Interim.
type InterimConfig struct {
	Runs   *Runs
	Orch   *Orchestrators
	Signer Signer
}

// Interim is the Phase 1 interim issuer, the backend of `chap dev-token`.
type Interim struct {
	cfg InterimConfig
}

// NewInterim returns an Interim. The Signer's kid must name an interim key in
// the key set Runs holds.
func NewInterim(cfg InterimConfig) (*Interim, error) {
	if cfg.Runs == nil || cfg.Orch == nil || cfg.Signer == nil {
		return nil, errors.New("runtoken: Interim needs Runs, Orch and Signer")
	}
	k, ok := cfg.Runs.cfg.Keys.Lookup(cfg.Signer.KID())
	if !ok || k.Interim == nil {
		return nil, fmt.Errorf("runtoken: kid %q is not an interim key in the key set", cfg.Signer.KID())
	}
	return &Interim{cfg: cfg}, nil
}

// MintRequest is what `chap dev-token --profile --repo --branch --ops
// --minutes` sends, plus the project.
type MintRequest struct {
	Project string
	Profile string // empty or "host-interim"
	Repo    string
	Base    string   // empty means main
	Branch  string   // must start with agent/
	Paths   []string // empty means ["**"]
	Ops     []string // concrete op kinds inside the host-interim ceiling
	Minutes int      // 1 to 120
	Tokens  int64    // budget.tokens; 0 means DefaultInterimTokens
}

// MintResult is a new interim token. Token is shown once to the caller.
type MintResult struct {
	Token  string
	Claims spec.RunTokenClaims
}

// Mint issues an interim run token, and registers its run in the same
// transaction, for a caller that presents a valid orchestrator token whose
// scope lets it mint (ADR-005 amendment 2, ADR-007). It refuses, in this order:
//
//   - no valid orchestrator token (TOKEN_INVALID, TOKEN_REVOKED,
//     TOKEN_EXPIRED): no orchestrator token, no interim token;
//   - allow_interim false (OP_DISABLED);
//   - a scope without mint_interim, a project or op outside the orchestrator's
//     scope, or an op outside the host-interim ceiling (OP_NOT_IN_TOKEN);
//   - a profile other than host-interim, more minutes than the key's limit
//     (2 hours at most), a branch outside agent/ or equal to the base, or
//     claims the run-token schema rejects (TOKEN_INVALID).
func (i *Interim) Mint(ctx context.Context, orchBearer string, req MintRequest) (*MintResult, error) {
	keys := i.cfg.Runs.cfg.Keys
	key, _ := keys.Lookup(i.cfg.Signer.KID())
	pr, err := i.cfg.Orch.Verify(ctx, orchBearer)
	if err != nil {
		return nil, err
	}
	if !keys.AllowInterim() {
		return nil, refuse(CauseOpDisabled, "the interim issuer is disabled (allow_interim is false)")
	}
	if !pr.Scope.MintInterim {
		return nil, refuse(CauseOpNotInToken, "orchestrator token %s may not mint interim tokens", pr.ID)
	}
	_, canonical, err := i.buildClaims(pr, key, req)
	if err != nil {
		return nil, err
	}
	jwt, err := signJWS(typRun, key.KID, canonical, func(msg []byte) ([]byte, error) {
		return i.cfg.Signer.Sign(ctx, msg)
	})
	if err != nil {
		return nil, err
	}
	// Register what was signed, from the signed text: the same parse the
	// verifier will do, so the grant hash matches.
	rt, e := parseRunToken(jwt, keys, nil)
	if e != nil {
		return nil, fmt.Errorf("runtoken: interim issuer made a token it cannot verify: %w", e)
	}
	if e := checkClaims(rt, i.cfg.Runs.now(), false); e != nil {
		return nil, e
	}
	err = i.cfg.Runs.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := i.cfg.Runs.insertRun(ctx, tx, rt)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &MintResult{Token: jwt, Claims: rt.Claims}, nil
}

func (i *Interim) buildClaims(pr *Principal, key *Key, req MintRequest) (spec.RunTokenClaims, []byte, error) {
	var zero spec.RunTokenClaims
	if req.Profile != "" && req.Profile != InterimProfile {
		return zero, nil, refuse(CauseTokenInvalid, "the interim issuer signs profile %s only", InterimProfile)
	}
	if req.Minutes < 1 || int64(req.Minutes)*60 > key.Interim.MaxSeconds {
		return zero, nil, refuse(CauseTokenInvalid, "minutes must be 1 to %d for the interim issuer", key.Interim.MaxSeconds/60)
	}
	if len(req.Ops) == 0 {
		return zero, nil, refuse(CauseOpNotInToken, "an interim token needs at least one op")
	}
	for _, op := range req.Ops {
		if !slices.Contains(key.Interim.Ops, op) {
			return zero, nil, refuse(CauseOpNotInToken, "op %q is outside the host-interim ceiling", op)
		}
		if err := pr.CheckOp(req.Project, op); err != nil {
			return zero, nil, err
		}
	}
	if !slices.Contains(pr.Scope.Projects, req.Project) {
		return zero, nil, refuse(CauseOpNotInToken, "project %q is outside the orchestrator token's scope", req.Project)
	}
	base := req.Base
	if base == "" {
		base = "main"
	}
	paths := req.Paths
	if len(paths) == 0 {
		paths = []string{"**"}
	}
	if !strings.HasPrefix(req.Branch, InterimBranchPrefix) {
		return zero, nil, refuse(CauseScopeBranch, "an interim token's branch must start with %s", InterimBranchPrefix)
	}
	tokens := req.Tokens
	if tokens == 0 {
		tokens = DefaultInterimTokens
	}
	runSuffix, err := randomLower(8)
	if err != nil {
		return zero, nil, err
	}
	var jtiRaw [16]byte
	if _, err := rand.Read(jtiRaw[:]); err != nil {
		return zero, nil, fmt.Errorf("runtoken: random: %w", err)
	}
	briefTree, err := spec.Tree(map[string]any{
		"orchestrator": pr.ID, "project": req.Project, "repo": req.Repo, "base": base, "branch": req.Branch,
		"paths": paths, "ops": req.Ops, "minutes": req.Minutes,
	})
	if err != nil {
		return zero, nil, fmt.Errorf("runtoken: brief hash: %w", err)
	}
	brief, err := spec.JCS(briefTree)
	if err != nil {
		return zero, nil, fmt.Errorf("runtoken: brief hash: %w", err)
	}
	now := i.cfg.Runs.now().Unix()
	runID := "r-" + runSuffix
	claims := spec.RunTokenClaims{
		Iss: key.Issuer, Sub: "run:" + runID, Aud: "chaperone",
		Iat: now, Exp: now + int64(req.Minutes)*60,
		JTI:       base64.RawURLEncoding.EncodeToString(jtiRaw[:]),
		RunID:     runID,
		Project:   req.Project,
		Profile:   spec.TokenProfile{Name: InterimProfile, Version: "0.0.0"},
		BriefSHA:  spec.SHA256Tagged(brief),
		Isolation: "host",
		TaskScope: spec.TaskScope{Repo: req.Repo, Base: base, Branch: req.Branch, Paths: paths, Ops: slices.Clone(req.Ops)},
		Budget:    spec.Budget{Minutes: req.Minutes, Tokens: tokens},
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return zero, nil, err
	}
	if _, err := spec.LoadTree(spec.SchemaRunToken, payload); err != nil {
		return zero, nil, refuse(CauseTokenInvalid, "claims do not match the run-token schema: %v", err)
	}
	return claims, payload, nil
}
