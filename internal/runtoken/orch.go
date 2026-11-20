package runtoken

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// OrchPrefix starts every orchestrator token (ADR-007 item 1). The auth
// middleware routes on it: a bearer with this prefix goes to
// [Orchestrators.Verify], anything else to [Verifier.Verify].
const OrchPrefix = "chap_orch_"

// MaxOrchDays is the cap on an orchestrator token's lifetime (ADR-007 item 4).
const MaxOrchDays = 30

const orchSecretChars = 43 // base64url of 32 bytes, unpadded

var (
	orchIDRe   = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,62}$`)
	projectRe  = regexp.MustCompile(`^[a-z][a-z0-9-]{1,38}$`)
	opPatternR = regexp.MustCompile(`^[a-z][a-z0-9]*(\.([a-z][a-z0-9]*|\*))*$`)
)

// IsOrchToken reports whether a bearer value is routed to the orchestrator
// verifier.
func IsOrchToken(bearer string) bool { return strings.HasPrefix(bearer, OrchPrefix) }

// OrchScope is what an orchestrator token may ask for (ADR-007 item 3). It is
// data in the row; the caller cannot change it.
type OrchScope struct {
	Projects []string `json:"projects"`
	// Ops are op kinds, or "prefix.*" patterns.
	Ops []string `json:"ops"`
	// MintInterim lets the holder mint interim run tokens while allow_interim
	// is true.
	MintInterim bool `json:"mint_interim"`
}

func (s OrchScope) check() error {
	if len(s.Projects) == 0 || len(s.Projects) > 64 || len(s.Ops) == 0 || len(s.Ops) > 64 {
		return invalid("scope needs 1 to 64 projects and 1 to 64 ops")
	}
	for _, p := range s.Projects {
		if !projectRe.MatchString(p) {
			return invalid("project %q is not a project id", p)
		}
	}
	for _, op := range s.Ops {
		if !opPatternR.MatchString(op) || len(op) > 64 {
			return invalid("op %q is not an op kind or a prefix.* pattern", op)
		}
	}
	if hasDup(s.Projects) || hasDup(s.Ops) {
		return invalid("scope lists a project or op twice")
	}
	return nil
}

func hasDup(s []string) bool {
	c := slices.Clone(s)
	slices.Sort(c)
	return len(slices.Compact(c)) != len(c)
}

// Principal is a verified orchestrator token.
type Principal struct {
	ID          string // the orchestrators.id, "main" for example
	Fingerprint string // first 8 hex of SHA-256(token): what the ledger records
	ExpiresAt   time.Time
	Scope       OrchScope
}

// CheckOp is the scope check of ADR-007 item 3: a project or op outside the
// token's scope is OP_NOT_IN_TOKEN.
func (p *Principal) CheckOp(project, op string) error {
	if !slices.Contains(p.Scope.Projects, project) {
		return forOrch(refuse(CauseOpNotInToken, "project %q is outside the orchestrator token's scope", project), p.ID, p.Scope.Projects[0])
	}
	if !spec.OpAllowed(op, p.Scope.Ops) {
		return forOrch(refuse(CauseOpNotInToken, "op %q is outside the orchestrator token's scope", op), p.ID, p.Scope.Projects[0])
	}
	return nil
}

// EffectiveOps is scope.ops intersected with catalogEnabled, the ops enabled
// for the orchestrator in the catalog and project policy. A project outside
// the scope, or a nil catalogEnabled, gives none.
func (p *Principal) EffectiveOps(project string, catalogEnabled []string) []string {
	if !slices.Contains(p.Scope.Projects, project) {
		return nil
	}
	var out []string
	for _, op := range catalogEnabled {
		if spec.OpAllowed(op, p.Scope.Ops) {
			out = append(out, op)
		}
	}
	return out
}

// SecretSink receives a plaintext token so no log or response can print it:
// *redact.Registry satisfies it.
type SecretSink interface {
	Set(id string, value []byte) error
}

// OrchConfig configures Orchestrators.
type OrchConfig struct {
	DB       *store.DB
	Appender Appender
	// Redact receives each issued token (id "orchestrator-<id>"). Optional.
	Redact SecretSink
	// PolicyVersion names the active policy version for the op.result events
	// of issue and revoke.
	PolicyVersion func() string
	// TxRevoke runs inside the revoke transaction: cancel the orchestrator's
	// pending approvals here (ADR-007 item 7). An error rolls the revoke back.
	TxRevoke func(ctx context.Context, tx *store.Tx, id string) error
	// AfterRevoke runs after the revoke committed.
	AfterRevoke func(ctx context.Context, id string)
	Now         func() time.Time
}

// Orchestrators issues, verifies, rotates and revokes orchestrator tokens
// (ADR-007).
type Orchestrators struct {
	cfg OrchConfig
	now func() time.Time
}

// NewOrchestrators returns an Orchestrators.
func NewOrchestrators(cfg OrchConfig) (*Orchestrators, error) {
	if cfg.DB == nil || cfg.Appender == nil || cfg.PolicyVersion == nil {
		return nil, errors.New("runtoken: Orchestrators needs DB, Appender and PolicyVersion")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Orchestrators{cfg: cfg, now: now}, nil
}

func tokenHash(token string) (sum [32]byte, hexSum string) {
	sum = sha256.Sum256([]byte(token))
	return sum, hex.EncodeToString(sum[:])
}

// Verify checks an orchestrator token: shape, SHA-256 lookup, constant-time
// compare of the stored hash, revoked, expired (30-day cap re-checked), scope
// well-formed. Refusals are TOKEN_INVALID, TOKEN_REVOKED and TOKEN_EXPIRED
// *Errors; a database error is returned as is (fail closed). Scope is
// checked per request with [Principal.CheckOp].
func (o *Orchestrators) Verify(ctx context.Context, bearer string) (*Principal, error) {
	secret, ok := strings.CutPrefix(bearer, OrchPrefix)
	if !ok || len(secret) != orchSecretChars || !isB64URL(secret) {
		return nil, refuse(CauseTokenInvalid, "not an orchestrator token")
	}
	if raw, err := base64.RawURLEncoding.Strict().DecodeString(secret); err != nil || len(raw) != 32 {
		return nil, refuse(CauseTokenInvalid, "not an orchestrator token")
	}
	_, want := tokenHash(bearer)
	var (
		stored, id, scopeJSON string
		issued, expires       int64
		revoked               sql.NullInt64
	)
	err := o.cfg.DB.SQL().QueryRowContext(ctx,
		`SELECT token_sha256, id, scope, issued_at, expires_at, revoked_at FROM orchestrators WHERE token_sha256 = ?`,
		want).Scan(&stored, &id, &scopeJSON, &issued, &expires, &revoked)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, refuse(CauseTokenInvalid, "unknown orchestrator token")
	case err != nil:
		return nil, fmt.Errorf("runtoken: read orchestrator: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(stored), []byte(want)) != 1 {
		return nil, refuse(CauseTokenInvalid, "unknown orchestrator token")
	}
	// The scope is read first only so a refusal can name the project the
	// denial body needs (the first one); its validity is judged below.
	var scope OrchScope
	dec := json.NewDecoder(strings.NewReader(scopeJSON))
	dec.DisallowUnknownFields()
	scopeErr := dec.Decode(&scope)
	project := ""
	if scopeErr == nil && len(scope.Projects) > 0 {
		project = scope.Projects[0]
	}
	if revoked.Valid {
		return nil, forOrch(misuse(refuse(CauseTokenRevoked, "orchestrator token %s was revoked", id)), id, project)
	}
	now := o.now().Unix()
	if now >= expires {
		return nil, forOrch(misuse(refuse(CauseTokenExpired, "orchestrator token %s expired", id)), id, project)
	}
	if expires-issued > MaxOrchDays*24*60*60 {
		return nil, forOrch(refuse(CauseTokenInvalid, "orchestrator token %s lives longer than %d days", id, MaxOrchDays), id, project)
	}
	if scopeErr != nil || scope.check() != nil {
		return nil, forOrch(refuse(CauseTokenInvalid, "orchestrator token %s has an unreadable scope", id), id, project)
	}
	return &Principal{ID: id, Fingerprint: want[:8], ExpiresAt: time.Unix(expires, 0).UTC(), Scope: scope}, nil
}

// IssueParams are the arguments of `chapd orch issue`.
type IssueParams struct {
	ID    string
	Scope OrchScope
	Days  int // 1 to 30; 0 means 30
}

// IssueResult carries the plaintext token, which exists only here. The caller
// writes it to the operator's token file and prints only the Fingerprint and
// ExpiresAt.
type IssueResult struct {
	Token       string
	Fingerprint string
	ExpiresAt   time.Time
}

// Issue creates a token and stores only its SHA-256. A live token for the same
// id is revoked in the same transaction (rotation: revoked_by "rotated"). The
// token is added to the redaction sink before the row commits. The events are
// the operator-only ops orchestrator.issue (op.request, op.result).
func (o *Orchestrators) Issue(ctx context.Context, p IssueParams) (IssueResult, error) {
	if !orchIDRe.MatchString(p.ID) || strings.HasPrefix(p.ID, spec.KeyRequesterPrefix) {
		return IssueResult{}, invalid("orchestrator id %q must match %s and must not start with %q (reserved for keys)", p.ID, orchIDRe, spec.KeyRequesterPrefix)
	}
	if err := p.Scope.check(); err != nil {
		return IssueResult{}, err
	}
	days := p.Days
	if days == 0 {
		days = MaxOrchDays
	}
	if days < 1 || days > MaxOrchDays {
		return IssueResult{}, invalid("days must be 1 to %d", MaxOrchDays)
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return IssueResult{}, fmt.Errorf("runtoken: random: %w", err)
	}
	token := OrchPrefix + base64.RawURLEncoding.EncodeToString(raw[:])
	_, hexSum := tokenHash(token)
	now := o.now()
	expires := now.Add(time.Duration(days) * 24 * time.Hour)
	scopeJSON, err := json.Marshal(p.Scope)
	if err != nil {
		return IssueResult{}, err
	}
	if o.cfg.Redact != nil {
		if err := o.cfg.Redact.Set("orchestrator-"+p.ID, []byte(token)); err != nil {
			return IssueResult{}, fmt.Errorf("runtoken: redaction registry: %w", err)
		}
	}
	res := IssueResult{Token: token, Fingerprint: hexSum[:8], ExpiresAt: time.Unix(expires.Unix(), 0).UTC()}
	err = o.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`UPDATE orchestrators SET revoked_at = ?, revoked_by = 'rotated' WHERE id = ? AND revoked_at IS NULL`,
			now.Unix(), p.ID); err != nil {
			return fmt.Errorf("runtoken: rotate orchestrator: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO orchestrators (token_sha256, id, scope, issued_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
			hexSum, p.ID, string(scopeJSON), now.Unix(), expires.Unix()); err != nil {
			return fmt.Errorf("runtoken: store orchestrator token: %w", err)
		}
		params := map[string]any{
			"id": p.ID, "projects": p.Scope.Projects, "ops": p.Scope.Ops, "mint_interim": p.Scope.MintInterim,
			"days": days, "fingerprint": res.Fingerprint,
		}
		body := fmt.Sprintf("operator issued orchestrator token %s (fingerprint %s, expires %s)", p.ID, res.Fingerprint, res.ExpiresAt.Format(time.RFC3339))
		return o.appendOp(ctx, tx, "orchestrator.issue", p.Scope.Projects[0], p.ID, params, body)
	})
	if err != nil {
		return IssueResult{}, err
	}
	return res, nil
}

func (o *Orchestrators) appendOp(ctx context.Context, tx *store.Tx, op, project, id string, params map[string]any, body string) error {
	evs, err := orchOpEvents(op, project, id, params, o.cfg.PolicyVersion(), body)
	if err != nil {
		return err
	}
	for _, ev := range evs {
		if err := o.cfg.Appender.Append(ctx, tx, ev); err != nil {
			return fmt.Errorf("runtoken: ledger %s: %w", ev.Name, err)
		}
	}
	return nil
}

// Revoke revokes the live token of id (ADR-007 item 7): the next Verify is
// TOKEN_REVOKED. by names who did it ("console", "chapd orch revoke"). The
// TxRevoke hook runs in the same transaction. No live token is ErrNotFound.
func (o *Orchestrators) Revoke(ctx context.Context, id, by string) error {
	if !orchIDRe.MatchString(id) {
		return invalid("orchestrator id %q must match %s", id, orchIDRe)
	}
	if strings.TrimSpace(by) == "" {
		return invalid("revoke needs a revoked_by")
	}
	err := o.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		var scopeJSON, hexSum string
		err := tx.QueryRowContext(ctx, `SELECT scope, token_sha256 FROM orchestrators WHERE id = ? AND revoked_at IS NULL`, id).Scan(&scopeJSON, &hexSum)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: no live orchestrator token for %q", ErrNotFound, id)
		} else if err != nil {
			return fmt.Errorf("runtoken: read orchestrator: %w", err)
		}
		var scope OrchScope
		if err := json.NewDecoder(bytes.NewReader([]byte(scopeJSON))).Decode(&scope); err != nil || len(scope.Projects) == 0 {
			return fmt.Errorf("runtoken: stored scope of %q is unreadable", id)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE orchestrators SET revoked_at = ?, revoked_by = ? WHERE id = ? AND revoked_at IS NULL`,
			o.now().Unix(), by, id); err != nil {
			return fmt.Errorf("runtoken: revoke orchestrator: %w", err)
		}
		if o.cfg.TxRevoke != nil {
			if err := o.cfg.TxRevoke(ctx, tx, id); err != nil {
				return fmt.Errorf("runtoken: revoke hook: %w", err)
			}
		}
		params := map[string]any{"id": id, "fingerprint": hexSum[:8], "revoked_by": by}
		body := fmt.Sprintf("operator revoked orchestrator token %s (fingerprint %s) by %s", id, hexSum[:8], by)
		return o.appendOp(ctx, tx, "orchestrator.revoke", scope.Projects[0], id, params, body)
	})
	if err != nil {
		return err
	}
	if o.cfg.AfterRevoke != nil {
		o.cfg.AfterRevoke(ctx, id)
	}
	return nil
}

// OrchInfo is one row for `chapd orch list` and the console. It holds no token.
type OrchInfo struct {
	ID          string
	Fingerprint string
	Scope       OrchScope
	IssuedAt    time.Time
	ExpiresAt   time.Time
	RevokedAt   time.Time // zero while not revoked
	RevokedBy   string
}

// Live reports a token that is neither revoked nor expired at now.
func (i OrchInfo) Live(now time.Time) bool {
	return i.RevokedAt.IsZero() && now.Before(i.ExpiresAt)
}

// List returns every orchestrator token row, newest first.
func (o *Orchestrators) List(ctx context.Context) ([]OrchInfo, error) {
	rows, err := o.cfg.DB.SQL().QueryContext(ctx,
		`SELECT token_sha256, id, scope, issued_at, expires_at, revoked_at, revoked_by FROM orchestrators ORDER BY issued_at DESC, id`)
	if err != nil {
		return nil, fmt.Errorf("runtoken: list orchestrators: %w", err)
	}
	defer rows.Close()
	var out []OrchInfo
	for rows.Next() {
		var (
			hexSum, id, scopeJSON string
			issued, expires       int64
			revoked               sql.NullInt64
			by                    sql.NullString
		)
		if err := rows.Scan(&hexSum, &id, &scopeJSON, &issued, &expires, &revoked, &by); err != nil {
			return nil, fmt.Errorf("runtoken: list orchestrators: %w", err)
		}
		info := OrchInfo{ID: id, Fingerprint: hexSum[:8], IssuedAt: time.Unix(issued, 0).UTC(), ExpiresAt: time.Unix(expires, 0).UTC(), RevokedBy: by.String}
		if err := json.Unmarshal([]byte(scopeJSON), &info.Scope); err != nil {
			return nil, fmt.Errorf("runtoken: scope of %s: %w", id, err)
		}
		if revoked.Valid {
			info.RevokedAt = time.Unix(revoked.Int64, 0).UTC()
		}
		out = append(out, info)
	}
	return out, rows.Err()
}
