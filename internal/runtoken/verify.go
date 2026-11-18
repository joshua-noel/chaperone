package runtoken

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// ProfileFunc resolves the signed generic profile a token's profile.digest
// names. It reports false for a digest Chaperone has not admitted.
type ProfileFunc func(digest string) (*spec.GenericProfile, bool)

// RunToken is a run token that passed verification.
type RunToken struct {
	Claims spec.RunTokenClaims
	KID    string
	// Interim reports a token signed by the interim issuer: isolation host,
	// no profile; its high-impact requests always need an approval.
	Interim bool
	// Profile is the generic profile the digest named; nil for an interim token.
	Profile *spec.GenericProfile

	grantSHA string   // SHA-256 of the JCS form of the claims
	ceiling  []string // interim: the key's op ceiling
}

// CheckOp is step 8 for one op: it must be in task_scope.ops (OP_NOT_IN_TOKEN).
func (t *RunToken) CheckOp(op string) error {
	if !slices.Contains(t.Claims.TaskScope.Ops, op) {
		return forRun(refuse(CauseOpNotInToken, "op %q is not in the token", op), t.Claims)
	}
	return nil
}

// CheckBranch is step 8 for a push target: it must be task_scope.branch
// (SCOPE_BRANCH).
func (t *RunToken) CheckBranch(branch string) error {
	if branch != t.Claims.TaskScope.Branch {
		return forRun(refuse(CauseScopeBranch, "branch %q is not the run's branch", branch), t.Claims)
	}
	return nil
}

// CheckRepo requires the request's repo to be task_scope.repo (SCOPE_BRANCH,
// the code ADR-005 step 8 gives repo and branch checks).
func (t *RunToken) CheckRepo(repo string) error {
	if repo != t.Claims.TaskScope.Repo {
		return forRun(refuse(CauseScopeBranch, "repo %q is not the run's repo", repo), t.Claims)
	}
	return nil
}

// EffectiveOps is ADR-005 step 8: task_scope.ops intersected with the ops the
// profile allows (the interim key's ceiling for an interim token) and with
// catalogEnabled, the ops enabled by the catalog and project policy. A nil
// catalogEnabled enables nothing: every op is disabled by default.
func (t *RunToken) EffectiveOps(catalogEnabled []string) []string {
	var out []string
	for _, op := range t.Claims.TaskScope.Ops {
		var allowed bool
		if t.Profile != nil {
			allowed = spec.OpAllowed(op, t.Profile.Ops.Allow)
		} else {
			allowed = slices.Contains(t.ceiling, op)
		}
		if allowed && slices.Contains(catalogEnabled, op) {
			out = append(out, op)
		}
	}
	return out
}

// parseRunToken is ADR-005 steps 1 to 5 plus the issuer restrictions and the
// profile lookup: no clock and no database. Interim reports whether the key
// is the interim issuer's.
func parseRunToken(token string, keys *KeySet, profiles ProfileFunc) (*RunToken, *Error) {
	jws, e := verifyJWS(token, typRun, keys)
	if e != nil {
		return nil, e
	}
	tree, err := spec.ParseStrict(jws.Payload)
	if err != nil {
		return nil, refuse(CauseTokenInvalid, "claims are not strict JSON: %v", err)
	}
	// Step 4, second half: iss is the issuer pinned for this kid.
	if m, ok := tree.(map[string]any); !ok {
		return nil, refuse(CauseTokenInvalid, "claims are not a JSON object")
	} else if iss, _ := m["iss"].(string); iss != jws.Key.Issuer {
		return nil, refuse(CauseTokenInvalid, "iss is not the issuer pinned for kid %q", jws.Key.KID)
	}
	// Step 5: the JSON Schema (aud, sub shape, no unknown claim, host tokens
	// only from chaperone.* with host-interim, runner.* only with a digest).
	if err := spec.Validate(spec.SchemaRunToken, tree); err != nil {
		return nil, refuse(CauseTokenInvalid, "claims do not match the run-token schema: %v", err)
	}
	var c spec.RunTokenClaims
	dec := json.NewDecoder(bytes.NewReader(jws.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, refuse(CauseTokenInvalid, "claims do not decode: %v", err)
	}
	canon, err := spec.JCS(tree)
	if err != nil {
		return nil, refuse(CauseTokenInvalid, "claims have no canonical form: %v", err)
	}
	rt := &RunToken{Claims: c, KID: jws.Key.KID, grantSHA: spec.SHA256Tagged(canon)}
	if e := rt.restrict(jws.Key, keys, profiles); e != nil {
		return nil, forRun(e, c)
	}
	return rt, nil
}

// restrict applies what the key and the profile source add to the schema:
// the interim restrictions for the interim key, the profile lookup for every
// other key.
func (rt *RunToken) restrict(key *Key, keys *KeySet, profiles ProfileFunc) *Error {
	c := rt.Claims
	if chap := key.Interim; chap != nil {
		if !keys.AllowInterim() {
			return refuse(CauseTokenInvalid, "interim tokens are disabled (allow_interim is false)")
		}
		if c.Isolation != "host" || c.Profile.Name != InterimProfile {
			return refuse(CauseTokenInvalid, "the interim key signs only host-interim tokens with isolation host")
		}
		if c.Exp-c.Iat > chap.MaxSeconds {
			return refuse(CauseTokenInvalid, "interim token lives %d s, the interim limit is %d s", c.Exp-c.Iat, chap.MaxSeconds)
		}
		for _, op := range c.TaskScope.Ops {
			if !slices.Contains(chap.Ops, op) {
				return refuse(CauseOpNotInToken, "op %q is outside the host-interim ceiling", op)
			}
		}
		if !strings.HasPrefix(c.TaskScope.Branch, InterimBranchPrefix) {
			return refuse(CauseScopeBranch, "an interim token's branch must start with %s", InterimBranchPrefix)
		}
		rt.Interim, rt.ceiling = true, chap.Ops
		return nil
	}
	if c.Isolation == "host" {
		return refuse(CauseTokenInvalid, "isolation host is for the interim issuer only")
	}
	if profiles == nil {
		return refuse(CauseTokenInvalid, "no profile source is configured: start chapd with -profiles-dir (or a profiles folder next to state.db)")
	}
	p, ok := profiles(c.Profile.Digest)
	if !ok || p == nil {
		return refuse(CauseTokenInvalid, "profile digest %s is not admitted", c.Profile.Digest)
	}
	rt.Profile = p
	return nil
}

// classify maps one problem string of spec.CheckRunTokenClaims to a cause
// code and the rank of the step that raises it: shape (0), revocation (1),
// time (2), scope (3). Revocation ranks above time so that a run the operator
// stopped, or one that has ended, always answers TOKEN_REVOKED, even after its
// token has also passed exp: TOKEN_EXPIRED would hand the caller a restart step.
func classify(problem string) (code string, rank int) {
	switch {
	case strings.HasPrefix(problem, "TOKEN_EXPIRED"),
		strings.HasPrefix(problem, "exp is not after iat"),
		strings.HasPrefix(problem, "token lifetime exceeds"):
		return CauseTokenExpired, 2
	case strings.HasPrefix(problem, "TOKEN_REVOKED"):
		return CauseTokenRevoked, 1
	case strings.HasPrefix(problem, "SCOPE_BRANCH"):
		return CauseScopeBranch, 3
	case strings.HasPrefix(problem, "OP_NOT_IN_TOKEN"):
		return CauseOpNotInToken, 3
	}
	// TOKEN_INVALID, "sub is not ...", "token profile name differs ...",
	// "branch still has ...", "a token without a profile ...".
	return CauseTokenInvalid, 0
}

// checkClaims is step 6 to 8 through spec.CheckRunTokenClaims (grace 300 s,
// skew 30 s): the spec's function owns those numbers, this one maps its
// problems onto cause codes and returns the one ranked first (see classify).
func checkClaims(rt *RunToken, now time.Time, revoked bool) *Error {
	var rev map[string]bool
	if revoked {
		rev = map[string]bool{rt.Claims.JTI: true}
	}
	problems := spec.CheckRunTokenClaims(rt.Claims, rt.Profile, spec.TokenCheck{Now: now, Revoked: rev})
	if len(problems) == 0 {
		return nil
	}
	best, bestRank, detail := "", 99, ""
	for _, p := range problems {
		if code, rank := classify(p); rank < bestRank {
			best, bestRank, detail = code, rank, p
		}
	}
	e := forRun(refuse(best, "%s", detail), rt.Claims)
	if best == CauseTokenExpired || best == CauseTokenRevoked {
		misuse(e)
	}
	return e
}

// VerifierConfig configures a Verifier.
type VerifierConfig struct {
	DB       *store.DB
	Keys     *KeySet
	Profiles ProfileFunc // resolves profile.digest; required for runner.* tokens
	Now      func() time.Time
}

// Verifier is the run-token verification path of ADR-005. It is safe for
// concurrent use and reads SQLite on every call, so a revocation holds on the
// next request.
type Verifier struct {
	db       *store.DB
	keys     *KeySet
	profiles ProfileFunc
	now      func() time.Time
}

// NewVerifier returns a Verifier.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if cfg.DB == nil || cfg.Keys == nil {
		return nil, errors.New("runtoken: Verifier needs DB and Keys")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Verifier{db: cfg.DB, keys: cfg.Keys, profiles: cfg.Profiles, now: now}, nil
}

// Verify runs the eight steps of ADR-005 on a bearer token. It returns an
// *Error (use errors.As) carrying the denial cause code for every refusal,
// and a plain error when the database cannot be read (fail closed: the
// caller refuses the request).
func (v *Verifier) Verify(ctx context.Context, bearer string) (*RunToken, error) {
	rt, e := parseRunToken(bearer, v.keys, v.profiles)
	if e != nil {
		return nil, e
	}
	var (
		jti, grant, state string
		revoked           bool
	)
	err := v.db.SQL().QueryRowContext(ctx,
		`SELECT jti, claims_sha256, state, EXISTS(SELECT 1 FROM revoked_jti WHERE jti = ?)
		   FROM runs WHERE run_id = ?`, rt.Claims.JTI, rt.Claims.RunID).Scan(&jti, &grant, &state, &revoked)
	registered := true
	switch {
	case errors.Is(err, sql.ErrNoRows):
		registered = false
		var r bool
		// A revoked jti with no run row cannot happen; ask anyway so a lost row fails closed.
		if err := v.db.SQL().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM revoked_jti WHERE jti = ?)`, rt.Claims.JTI).Scan(&r); err != nil {
			return nil, fmt.Errorf("runtoken: read revocations: %w", err)
		}
		revoked = r
	case err != nil:
		return nil, fmt.Errorf("runtoken: read run: %w", err)
	}
	if e := checkClaims(rt, v.now(), revoked || state == "ended"); e != nil {
		return nil, e
	}
	switch {
	case !registered:
		return nil, forRun(refuse(CauseTokenInvalid, "run %s is not registered", rt.Claims.RunID), rt.Claims)
	case jti != rt.Claims.JTI:
		return nil, forRun(refuse(CauseTokenInvalid, "token jti is not the one registered for run %s", rt.Claims.RunID), rt.Claims)
	case grant != rt.grantSHA:
		return nil, forRun(refuse(CauseTokenInvalid, "token claims differ from the grant recorded for run %s", rt.Claims.RunID), rt.Claims)
	}
	return rt, nil
}
