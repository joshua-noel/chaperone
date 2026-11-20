package ops

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

// OrchPrefix routes a bearer token to the orchestrator verifier (ADR-007).
const OrchPrefix = "chap_orch_"

// KeyPrefix routes a bearer token to the key verifier (ADR-008).
const KeyPrefix = "chap_key_"

// VerifyError is a token verifier's refusal. Code is a denial cause code
// (TOKEN_INVALID, TOKEN_EXPIRED, TOKEN_REVOKED, OP_NOT_IN_TOKEN, SCOPE_BRANCH).
// When the verifier knew who the token was (a valid signature on an expired
// token, a revoked orchestrator row) it sets Run or OrchID, and chapd answers
// with a full structured denial. Without either the caller is unidentified.
type VerifyError struct {
	Code    string
	Surface string // "token" (default), "op" or "scope"
	Detail  string

	// Identity, when the token was recognised.
	Run     *Caller // kind run: RunID, Project, Profile set
	Key     *Caller // kind key: KeyID, Project, KeyOwner set
	OrchID  string
	Project string // for an orchestrator denial: the project to name, if known
}

func (e *VerifyError) Error() string { return e.Code + ": " + e.Detail }

// RunVerifier verifies a run token (internal/runtoken, ADR-005).
type RunVerifier interface {
	VerifyRun(ctx context.Context, bearer string) (*Caller, error)
}

// OrchVerifier verifies an orchestrator token (internal/runtoken, ADR-007).
type OrchVerifier interface {
	VerifyOrch(ctx context.Context, bearer string) (*Caller, error)
}

// KeyVerifier verifies a key (internal/keys, ADR-008).
type KeyVerifier interface {
	VerifyKey(ctx context.Context, bearer string) (*Caller, error)
}

type ctxKey int

const callerKey ctxKey = 1

// CallerFrom returns the authenticated caller of a request.
func CallerFrom(ctx context.Context) *Caller {
	c, _ := ctx.Value(callerKey).(*Caller)
	return c
}

// Auth is the authentication middleware: it routes one bearer token by prefix
// to one of two verifiers, so a request is a run or the orchestrator and never
// both. It refuses, with TOKEN_INVALID and nothing executed:
//
//   - no Authorization header, or more than one;
//   - a value that is not exactly "Bearer <token>" (a comma-joined pair is two
//     credentials in one header);
//   - a credential also given in the query string.
//
// Under /git/ only, a run token may be sent as the HTTP Basic password, because
// git cannot send a bearer header from a URL. The orchestrator token is
// refused there.
type Auth struct {
	Run  RunVerifier
	Orch OrchVerifier
	Key  KeyVerifier
	Svc  *Service
	Now  func() time.Time
}

// authFailure is what the middleware writes for an unauthenticated caller.
type authFailure struct {
	err error // *DeniedError, *UnavailableError or *authError
}

type authError struct{ Why string }

func (e *authError) Error() string { return e.Why }

// Authenticate extracts and verifies the caller of r. It returns *authError for
// an unidentified caller, *DeniedError when the token was recognised but
// refused, *UnavailableError when the denial could not be ledgered.
func (a *Auth) Authenticate(r *http.Request) (*Caller, error) {
	if err := rejectQueryCredential(r); err != nil {
		return nil, err
	}
	vals := r.Header.Values("Authorization")
	if len(vals) != 1 {
		if len(vals) == 0 {
			return nil, &authError{"no Authorization header"}
		}
		return nil, &authError{"exactly one Authorization header is allowed"}
	}
	token, ok := bearerToken(vals[0])
	if !ok && strings.HasPrefix(r.URL.Path, "/git/") {
		token, ok = basicPassword(r)
	}
	if !ok || token == "" {
		return nil, &authError{"the Authorization header must be exactly \"Bearer <token>\""}
	}
	kind := tokenKind(token)
	if (kind == KindOrchestrator || kind == KindKey) && strings.HasPrefix(r.URL.Path, "/git/") {
		return nil, &authError{"the " + kind + " token is not accepted on the git proxy"}
	}

	var c *Caller
	var err error
	switch {
	case kind == KindOrchestrator && a.Orch != nil:
		c, err = a.Orch.VerifyOrch(r.Context(), token)
	case kind == KindKey && a.Key != nil:
		c, err = a.Key.VerifyKey(r.Context(), token)
	case kind == KindRun && a.Run != nil:
		c, err = a.Run.VerifyRun(r.Context(), token)
	default:
		return nil, &authError{"no verifier for this kind of token"}
	}
	if err != nil {
		return nil, a.refused(r.Context(), err, r)
	}
	if c == nil || c.Kind != kind {
		return nil, &authError{"the token verifier returned the wrong kind of caller"}
	}
	return c, nil
}

// tokenKind routes a bearer value by its prefix: one token, one verifier, one
// caller kind. Anything that is not an orchestrator or a key is a run token.
func tokenKind(token string) string {
	switch {
	case strings.HasPrefix(token, OrchPrefix):
		return KindOrchestrator
	case strings.HasPrefix(token, KeyPrefix):
		return KindKey
	}
	return KindRun
}

func bearerToken(h string) (string, bool) {
	scheme, rest, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	if rest == "" || strings.ContainsAny(rest, " ,\t") {
		return "", false
	}
	return rest, true
}

func basicPassword(r *http.Request) (string, bool) {
	_, pw, ok := r.BasicAuth()
	return pw, ok && pw != ""
}

// rejectQueryCredential refuses a credential given in the query string.
func rejectQueryCredential(r *http.Request) error {
	for _, q := range []string{"token", "access_token", "authorization", "bearer", "orch_token", "run_token"} {
		if r.URL.Query().Has(q) {
			return &authError{"a credential in the query string is refused; send one Authorization header"}
		}
	}
	return nil
}

// requestBearer returns the token of a request that carries exactly one
// "Authorization: Bearer <token>" header and no credential in the query. It
// is for routes that read the token themselves instead of going through
// [Auth] (the control routes).
func requestBearer(r *http.Request) (string, error) {
	if err := rejectQueryCredential(r); err != nil {
		return "", err
	}
	vals := r.Header.Values("Authorization")
	switch len(vals) {
	case 0:
		return "", &authError{"no Authorization header"}
	case 1:
	default:
		return "", &authError{"exactly one Authorization header is allowed"}
	}
	token, ok := bearerToken(vals[0])
	if !ok {
		return "", &authError{"the Authorization header must be exactly \"Bearer <token>\""}
	}
	return token, nil
}

// refused turns a verifier error into the right body: a structured denial when
// the token was recognised, else an unidentified-caller error.
func (a *Auth) refused(ctx context.Context, err error, r *http.Request) error {
	var ve *VerifyError
	if !errors.As(err, &ve) {
		// A verifier fault is not the caller's doing and not an identity.
		return &UnavailableError{Why: "the token verifier failed", Retryable: true, Err: err}
	}
	var c *Caller
	project := ve.Project
	switch {
	case ve.Run != nil:
		c = ve.Run
		c.Kind = KindRun
		project = c.Project
	case ve.Key != nil:
		c = ve.Key
		c.Kind = KindKey
		project = c.Project
	case ve.OrchID != "":
		c = &Caller{Kind: KindOrchestrator, OrchID: ve.OrchID}
	default:
		return &authError{ve.Detail}
	}
	if project == "" {
		project = "unknown"
	}
	surface := ve.Surface
	if surface == "" {
		surface = "token"
	}
	verb := "request"
	target := r.URL.Path
	return a.Svc.deny(ctx, c, denial{Project: project, Surface: surface, Verb: verb, Target: target, Code: ve.Code, Why: ve.Detail})
}
