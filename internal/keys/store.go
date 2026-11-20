package keys

import (
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
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// SecretSink receives each claimed token the moment it exists. *redact.Registry
// satisfies it.
type SecretSink interface {
	Set(id string, value []byte) error
}

// Config configures Store.
type Config struct {
	DB     *store.DB
	Ledger ops.Ledger
	// Redact receives each token (id "key-<id>") before the row that holds its
	// hash commits. Optional in tests only.
	Redact SecretSink
	// PolicyVersion names the active policy for the op.result events.
	PolicyVersion func() string
	// TxRevoke runs inside the revoke transaction: cancel the key's pending
	// approvals and waiting ops there (ops.Service.CancelKeyOps). An error rolls
	// the revoke back.
	TxRevoke func(ctx context.Context, tx *store.Tx, keyID string) error
	Now      func() time.Time
}

// Store issues, claims, verifies and revokes keys.
type Store struct {
	cfg Config
	now func() time.Time
}

var (
	_ ops.KeyVerifier = (*Store)(nil)
)

// New returns a Store.
func New(cfg Config) (*Store, error) {
	if cfg.DB == nil || cfg.Ledger == nil || cfg.PolicyVersion == nil {
		return nil, errors.New("keys: Store needs DB, Ledger and PolicyVersion")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Store{cfg: cfg, now: now}, nil
}

// KeyIDFor is the id of the key a keys.issue op makes: derived from the op's
// request id, so a retried execution finds its key instead of making a second.
func KeyIDFor(requestID string) string {
	sum := sha256.Sum256([]byte("key:" + requestID))
	return "k-" + hex.EncodeToString(sum[:8])
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Issue writes the key row of an approved keys.issue (state granted: no token
// yet). It is idempotent per request id. An agent that a human stopped is
// refused; granting an agent more replaces its live key in the same
// transaction (one live key per agent).
func (s *Store) Issue(ctx context.Context, g Grant) (ops.KeyInfo, error) {
	if err := g.Shape(); err != nil {
		return ops.KeyInfo{}, err
	}
	if g.ApprovalID == "" || g.RequestID == "" || g.GrantedBy == "" || g.Claimant == "" || g.Owner == "" {
		return ops.KeyInfo{}, errors.New("keys: a grant needs its approval, request, approver, claimant and owner")
	}
	id := KeyIDFor(g.RequestID)
	opsJSON, _ := json.Marshal(g.Ops)
	unitsJSON, _ := json.Marshal(nonNil(g.Units))
	now := s.now()
	expires := now.Add(time.Duration(g.TTLHours) * time.Hour)
	var info ops.KeyInfo
	err := s.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		if k, err := s.get(ctx, tx, id); err == nil {
			info = k // already issued by an earlier attempt of this op
			return nil
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		if g.HolderKind == HolderAgent {
			var stopped int
			err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM key_agents WHERE owner_id = ? AND label = ?`, g.Owner, g.Holder).Scan(&stopped)
			if err != nil {
				return err
			}
			if stopped > 0 {
				return rule("%s is %s", g.Holder, StoppedWhy)
			}
			if err := s.revokeReplaced(ctx, tx, g, id); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO keys (id, project, owner_id, holder_kind, holder, ops_json, units_json, sensitive,
                rate_per_hour, issued_at, expires_at, claim_deadline, claimant, granted_by, grant_kind, approval_id, request_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,'approved',?,?)`,
			id, g.Project, g.Owner, g.HolderKind, g.Holder, string(opsJSON), string(unitsJSON), b2i(g.Sensitive),
			g.Rate, now.Unix(), expires.Unix(), now.Add(ClaimWindow).Unix(), g.Claimant, g.GrantedBy, g.ApprovalID, g.RequestID)
		if err != nil {
			return fmt.Errorf("keys: store key: %w", err)
		}
		info, err = s.get(ctx, tx, id)
		return err
	})
	return info, err
}

// revokeReplaced revokes the agent's earlier keys that are still granted or
// live (a new grant replaces them). It is not a human stop.
func (s *Store) revokeReplaced(ctx context.Context, tx *store.Tx, g Grant, newID string) error {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM keys WHERE owner_id = ? AND holder_kind = 'agent' AND holder = ? AND revoked_at IS NULL`, g.Owner, g.Holder)
	if err != nil {
		return err
	}
	var old []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		old = append(old, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range old {
		if err := s.revokeTx(ctx, tx, id, "key."+newID, "replaced by "+newID, false); err != nil {
			return err
		}
	}
	return nil
}

// Claim hands the claimant of a granted key its token, once. The token is made
// here and only its hash is kept; it is registered with the redaction sink
// before the row commits, so no response, log line or event can carry it.
func (s *Store) Claim(ctx context.Context, id, claimant string) (token string, info ops.KeyInfo, err error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", ops.KeyInfo{}, fmt.Errorf("keys: random: %w", err)
	}
	token = Prefix + base64.RawURLEncoding.EncodeToString(raw[:])
	hash := tokenHash(token)
	now := s.now()
	err = s.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		k, err := s.get(ctx, tx, id)
		if err != nil {
			return err
		}
		var who string
		if err := tx.QueryRowContext(ctx, `SELECT claimant FROM keys WHERE id = ?`, id).Scan(&who); err != nil {
			return err
		}
		if subtle.ConstantTimeCompare([]byte(who), []byte(claimant)) != 1 {
			return ErrNotFound // another caller's key looks like no key
		}
		switch {
		case k.RevokedAt != "":
			return ErrRevoked
		case k.ClaimedAt != "":
			return ErrAlreadyClaimed
		}
		deadline, _ := time.Parse(time.RFC3339, k.ClaimDeadline)
		if !now.Before(deadline) {
			return errExpiredCommit
		}
		if s.cfg.Redact != nil {
			if err := s.cfg.Redact.Set("key-"+id, []byte(token)); err != nil {
				return fmt.Errorf("keys: redaction registry: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE keys SET token_sha256 = ?, fingerprint = ?, claimed_at = ? WHERE id = ? AND token_sha256 IS NULL AND revoked_at IS NULL`,
			hash, hash[:8], now.Unix(), id); err != nil {
			return fmt.Errorf("keys: store claim: %w", err)
		}
		params := map[string]any{"id": id, "fingerprint": hash[:8]}
		body := fmt.Sprintf("key %s claimed by %s (fingerprint %s)", id, claimant, hash[:8])
		if err := s.appendOp(ctx, tx, "keys.claim", k.Project, claimerID(claimant), id, params, body); err != nil {
			return err
		}
		info, err = s.get(ctx, tx, id)
		return err
	})
	if errors.Is(err, errExpiredCommit) {
		// The transaction wrote nothing; the sweeper writes the revoke down, in its own.
		if _, serr := s.Sweep(ctx); serr != nil {
			return "", ops.KeyInfo{}, serr
		}
		return "", ops.KeyInfo{}, ErrClaimExpired
	}
	if err != nil {
		return "", ops.KeyInfo{}, err
	}
	return token, info, nil
}

// errExpiredCommit ends the claim transaction when the window has passed.
var errExpiredCommit = errors.New("keys: claim window passed")

// claimerID turns a Caller.Key() into the id the ledger names as the requester.
func claimerID(callerKey string) string {
	if id, ok := strings.CutPrefix(callerKey, "orchestrator:"); ok {
		return id
	}
	if id, ok := strings.CutPrefix(callerKey, "key:"); ok {
		return spec.KeyRequesterPrefix + id
	}
	return "operator"
}

// Revoke revokes a key. A human revoke (by an orchestrator, standing for the
// owner or an approver) of an agent's key also stops the agent: the owner must
// resume it before it can be given a key again. A key revoking itself does not.
// Revoking a revoked key is ErrRevoked.
func (s *Store) Revoke(ctx context.Context, id, by string, human bool) (ops.KeyInfo, error) {
	var info ops.KeyInfo
	err := s.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		if err := s.revokeTx(ctx, tx, id, claimerID(by), "revoked by "+by, human); err != nil {
			return err
		}
		var err error
		info, err = s.get(ctx, tx, id)
		return err
	})
	return info, err
}

// revokeTx revokes one key inside tx: the row, the stop of its agent for a
// human revoke, the cancel of its pending approvals and waiting ops, and the
// ledger events, all or nothing.
func (s *Store) revokeTx(ctx context.Context, tx *store.Tx, id, byID, reason string, human bool) error {
	var project, holderKind, holder, owner, fp string
	var revoked sql.NullInt64
	var fpn sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT project, holder_kind, holder, owner_id, fingerprint, revoked_at FROM keys WHERE id = ?`, id).
		Scan(&project, &holderKind, &holder, &owner, &fpn, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if revoked.Valid {
		return ErrRevoked
	}
	fp = fpn.String
	stop := human && holderKind == HolderAgent
	now := s.now().Unix()
	if _, err := tx.ExecContext(ctx, `UPDATE keys SET revoked_at = ?, revoked_by = ?, revoke_reason = ?, human_stopped = ? WHERE id = ? AND revoked_at IS NULL`,
		now, byID, clipText(reason, 200), b2i(stop), id); err != nil {
		return fmt.Errorf("keys: revoke: %w", err)
	}
	if stop {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO key_agents (owner_id, label, stopped_at, stopped_by, key_id) VALUES (?,?,?,?,?)`,
			owner, holder, now, byID, id); err != nil {
			return fmt.Errorf("keys: stop agent: %w", err)
		}
	}
	if s.cfg.TxRevoke != nil {
		if err := s.cfg.TxRevoke(ctx, tx, id); err != nil {
			return fmt.Errorf("keys: revoke hook: %w", err)
		}
	}
	params := map[string]any{"id": id, "fingerprint": fp, "human": human, "agent_stopped": stop}
	body := fmt.Sprintf("key %s revoked: %s", id, clipText(reason, 200))
	return s.appendOp(ctx, tx, "keys.revoke", project, byID, id, params, body)
}

// AgentStopped reports whether a human stopped this owner's agent.
func (s *Store) AgentStopped(ctx context.Context, owner, label string) (bool, error) {
	var n int
	err := s.cfg.DB.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM key_agents WHERE owner_id = ? AND label = ?`, owner, label).Scan(&n)
	return n > 0, err
}

// Sweep revokes every key that was not claimed by its deadline (and so holds no
// token), one ledger event each. It returns how many it revoked.
func (s *Store) Sweep(ctx context.Context) (int, error) {
	rows, err := s.cfg.DB.SQL().QueryContext(ctx, `SELECT id FROM keys WHERE token_sha256 IS NULL AND revoked_at IS NULL AND claim_deadline <= ?`, s.now().Unix())
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		err := s.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
			return s.revokeTx(ctx, tx, id, "chapd", "not claimed within the claim window", false)
		})
		if errors.Is(err, ErrRevoked) {
			continue
		}
		if err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// VerifyKey implements [ops.KeyVerifier]: shape, SHA-256 lookup, constant-time
// compare, revoked (a human-stopped agent is told so), expired. A key is
// recognised (and its refusal named) as soon as its hash is found; an unknown
// token is an unidentified caller. The scope is cut down to what a key may
// ever hold, so a hand-edited row cannot add a critical op.
func (s *Store) VerifyKey(ctx context.Context, bearer string) (*ops.Caller, error) {
	secret, ok := strings.CutPrefix(bearer, Prefix)
	if !ok || len(secret) != secretChars {
		return nil, &ops.VerifyError{Code: ops.CodeTokenInvalid, Detail: "not a key"}
	}
	if raw, err := base64.RawURLEncoding.Strict().DecodeString(secret); err != nil || len(raw) != 32 {
		return nil, &ops.VerifyError{Code: ops.CodeTokenInvalid, Detail: "not a key"}
	}
	want := tokenHash(bearer)
	var (
		id, project, owner, holderKind, holder, opsJSON, unitsJSON, stored, fp string
		rate                                                                   int
		issued, expires                                                        int64
		revoked, lastUsed                                                      sql.NullInt64
		revokeReason                                                           sql.NullString
		stopped                                                                int
	)
	err := s.cfg.DB.SQL().QueryRowContext(ctx, `SELECT id, project, owner_id, holder_kind, holder, ops_json, units_json, rate_per_hour,
            issued_at, expires_at, token_sha256, fingerprint, revoked_at, revoke_reason, human_stopped, last_used_at
        FROM keys WHERE token_sha256 = ?`, want).
		Scan(&id, &project, &owner, &holderKind, &holder, &opsJSON, &unitsJSON, &rate, &issued, &expires, &stored, &fp, &revoked, &revokeReason, &stopped, &lastUsed)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, &ops.VerifyError{Code: ops.CodeTokenInvalid, Detail: "unknown key"}
	case err != nil:
		return nil, fmt.Errorf("keys: read key: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(stored), []byte(want)) != 1 {
		return nil, &ops.VerifyError{Code: ops.CodeTokenInvalid, Detail: "unknown key"}
	}
	who := &ops.Caller{Kind: ops.KindKey, KeyID: id, Project: project, KeyOwner: owner, KeyHolder: holder, Fingerprint: fp}
	if revoked.Valid {
		why := "key " + id + " was revoked"
		if stopped == 1 {
			why = "key " + id + " was revoked and its agent " + StoppedWhy
		}
		return nil, &ops.VerifyError{Code: ops.CodeTokenRevoked, Detail: why, Key: who}
	}
	now := s.now()
	if !now.Before(time.Unix(expires, 0)) {
		return nil, &ops.VerifyError{Code: ops.CodeTokenExpired, Detail: "key " + id + " expired", Key: who}
	}
	if time.Duration(expires-issued)*time.Second > MaxDays*24*time.Hour {
		return nil, &ops.VerifyError{Code: ops.CodeTokenInvalid, Detail: "key " + id + " lives longer than the maximum", Key: who}
	}
	var granted, units []string
	if json.Unmarshal([]byte(opsJSON), &granted) != nil || json.Unmarshal([]byte(unitsJSON), &units) != nil {
		return nil, &ops.VerifyError{Code: ops.CodeTokenInvalid, Detail: "key " + id + " has an unreadable scope", Key: who}
	}
	for _, op := range granted {
		if _, ok := ops.KeyUnitKind(op); ok && !ops.NeverInKey(op) {
			who.KeyOps = append(who.KeyOps, op)
		}
	}
	who.KeyUnits, who.KeyRate, who.Expires = units, rate, time.Unix(expires, 0).UTC()
	// The last use is written at most once a minute: a busy key is not a write per call.
	if !lastUsed.Valid || now.Unix()-lastUsed.Int64 >= 60 {
		if _, err := s.cfg.DB.SQL().ExecContext(ctx, `UPDATE keys SET last_used_at = ? WHERE id = ?`, now.Unix(), id); err != nil {
			return nil, fmt.Errorf("keys: record use: %w", err)
		}
	}
	return who, nil
}

// get reads one key row as the API shows it.
type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

const infoColumns = `id, project, owner_id, holder_kind, holder, ops_json, units_json, sensitive, rate_per_hour, issued_at, expires_at,
    claim_deadline, COALESCE(claimed_at,0), COALESCE(fingerprint,''), granted_by, approval_id, request_id, COALESCE(revoked_at,0),
    COALESCE(revoked_by,''), COALESCE(revoke_reason,''), human_stopped, COALESCE(last_used_at,0),
    (SELECT COUNT(*) FROM ops WHERE ops.requester_key = 'key:' || keys.id)`

type rowScanner interface{ Scan(dest ...any) error }

func (s *Store) scan(r rowScanner) (ops.KeyInfo, error) {
	var k ops.KeyInfo
	var opsJSON, unitsJSON string
	var sens, stopped int
	var issued, expires, deadline, claimed, revoked, used int64
	if err := r.Scan(&k.ID, &k.Project, &k.Owner, &k.HolderKind, &k.Holder, &opsJSON, &unitsJSON, &sens, &k.RatePerHour, &issued, &expires,
		&deadline, &claimed, &k.Fingerprint, &k.GrantedBy, &k.ApprovalID, &k.RequestID, &revoked,
		&k.RevokedBy, &k.RevokeReason, &stopped, &used, &k.Uses); err != nil {
		return ops.KeyInfo{}, err
	}
	_ = json.Unmarshal([]byte(opsJSON), &k.Ops)
	_ = json.Unmarshal([]byte(unitsJSON), &k.Units)
	k.Ops, k.Units = nonNil(k.Ops), nonNil(k.Units)
	k.Sensitive, k.StoppedByHuman = sens == 1, stopped == 1
	at := func(u int64) string {
		if u == 0 {
			return ""
		}
		return ops.KeyTime(time.Unix(u, 0))
	}
	k.IssuedAt, k.ExpiresAt, k.ClaimDeadline, k.ClaimedAt = at(issued), at(expires), at(deadline), at(claimed)
	k.RevokedAt, k.LastUsedAt = at(revoked), at(used)
	switch now := s.now().Unix(); {
	case revoked != 0:
		k.State = "revoked"
	case claimed == 0 && now >= deadline:
		k.State = "revoked" // unclaimed past its deadline: the sweeper has not written it down yet, but no token exists
	case claimed == 0:
		k.State = "granted"
	case now >= expires:
		k.State = "expired"
	default:
		k.State = "live"
	}
	return k, nil
}

func (s *Store) get(ctx context.Context, q queryer, id string) (ops.KeyInfo, error) {
	if !keyIDRE.MatchString(id) {
		return ops.KeyInfo{}, ErrNotFound
	}
	k, err := s.scan(q.QueryRowContext(ctx, `SELECT `+infoColumns+` FROM keys WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return ops.KeyInfo{}, ErrNotFound
	}
	return k, err
}

// Get returns one key.
func (s *Store) Get(ctx context.Context, id string) (ops.KeyInfo, error) {
	return s.get(ctx, s.cfg.DB.SQL(), id)
}

// List returns the keys newest first; owner "" lists them all.
func (s *Store) List(ctx context.Context, owner string) ([]ops.KeyInfo, error) {
	q, args := `SELECT `+infoColumns+` FROM keys ORDER BY issued_at DESC, id`, []any(nil)
	if owner != "" {
		q, args = `SELECT `+infoColumns+` FROM keys WHERE owner_id = ? ORDER BY issued_at DESC, id`, []any{owner}
	}
	rows, err := s.cfg.DB.SQL().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ops.KeyInfo
	for rows.Next() {
		k, err := s.scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
