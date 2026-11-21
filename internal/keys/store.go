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
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
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
	// Access bounds what an owner may be granted; nil means [PersonAccess].
	Access Access
	// Limits are the caps on key requests (a cap on requests); the zero value means [DefaultRequestLimits].
	Limits RequestLimits
	// OnLooping is called, after the request was refused, when an agent has been refused three times in five
	// minutes: the looping-agent alert hook (the alert itself is not built yet). Optional.
	OnLooping func(ctx context.Context, l Looping)
	// EnrolProject reports whether agents may be enrolled for a project (the policy turns keys.request on for
	// it). Nil allows any project name; chapd always sets it.
	EnrolProject func(project string) bool
	// Catalog gives the class of each op, so that a key's sensitivity is worked out again whenever it is used and
	// is never taken from the row alone. Optional in tests only: without it the row's own flag stands.
	Catalog interface {
		Lookup(op string) (policy.Entry, bool)
	}
	// Log receives the warning about an enrolment that was refused for lack of room. Nil means slog.Default().
	Log *slog.Logger
}

// Store issues, claims, verifies and revokes keys.
type Store struct {
	cfg Config
	now func() time.Time

	mu       sync.Mutex
	refused  map[string]time.Time // when a refused enrolment start of project/label was last written down
	noteFrom time.Time            // the minute in which noteN refusals were written down, for all labels
	noteN    int
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
	if cfg.Access == nil {
		cfg.Access = PersonAccess{}
	}
	if cfg.Limits == (RequestLimits{}) {
		cfg.Limits = DefaultRequestLimits
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
// refused. A grant that answers a key request marks that request granted, and
// a bootstrap grant completes its enrolment, in the same transaction, so a key
// and the answer to the ask are never apart. The agent's older keys are not
// touched here: the claim of the new key replaces them.
func (s *Store) Issue(ctx context.Context, g Grant) (ops.KeyInfo, error) {
	if err := g.Shape(); err != nil {
		return ops.KeyInfo{}, err
	}
	if g.ApprovalID == "" || g.RequestID == "" || g.GrantedBy == "" || g.Claimant == "" || g.Owner == "" {
		return ops.KeyInfo{}, errors.New("keys: a grant needs its approval, request, approver, claimant and owner")
	}
	kind := g.Kind
	if kind == "" {
		kind = GrantApproved
	}
	id := KeyIDFor(g.RequestID)
	opsJSON, _ := json.Marshal(nonNil(g.Ops))
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
		}
		if kind == GrantBootstrap {
			var live int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM keys WHERE owner_id = ? AND holder_kind = 'agent' AND holder = ? AND revoked_at IS NULL
                AND (claimed_at IS NULL AND claim_deadline > ? OR claimed_at IS NOT NULL AND expires_at > ?)`,
				g.Owner, g.Holder, now.Unix(), now.Unix()).Scan(&live); err != nil {
				return err
			}
			if live > 0 {
				return rule("the agent %s already has a key: revoke it first, or ask it to request what it needs", g.Holder)
			}
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO keys (id, project, owner_id, holder_kind, holder, ops_json, units_json, sensitive,
                rate_per_hour, issued_at, expires_at, claim_deadline, claimant, granted_by, grant_kind, approval_id, request_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			id, g.Project, g.Owner, g.HolderKind, g.Holder, string(opsJSON), string(unitsJSON), b2i(g.Sensitive),
			g.Rate, now.Unix(), expires.Unix(), now.Add(ClaimWindow).Unix(), g.Claimant, g.GrantedBy, kind, g.ApprovalID, g.RequestID)
		if err != nil {
			return fmt.Errorf("keys: store key: %w", err)
		}
		if g.KeyRequest != "" {
			res, err := tx.ExecContext(ctx, `UPDATE key_requests SET state = 'granted', decided_at = ?, decided_by = ?, granted_key_id = ?,
                    grant_ops_json = ?, grant_units_json = ?, grant_ttl_hours = ?, grant_rate = ?
                WHERE id = ? AND state = 'pending' AND expires_at > ?`,
				now.Unix(), g.GrantedBy, id, string(opsJSON), string(unitsJSON), g.TTLHours, g.Rate, g.KeyRequest, now.Unix())
			if err != nil {
				return fmt.Errorf("keys: answer the request: %w", err)
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return rule("request %s is no longer waiting: it was withdrawn, answered, cancelled or it expired", g.KeyRequest)
			}
		}
		if g.Enrolment != "" {
			res, err := tx.ExecContext(ctx, `UPDATE key_enrolments SET state = 'issued', key_id = ?, owner_id = ?
                WHERE id = ? AND state = 'pending' AND expires_at > ?`, id, g.Owner, g.Enrolment, now.Unix())
			if err != nil {
				return fmt.Errorf("keys: complete the enrolment: %w", err)
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return rule("enrolment %s is no longer waiting: it expired or was already answered", g.Enrolment)
			}
		}
		info, err = s.get(ctx, tx, id)
		return err
	})
	return info, err
}

// replaceOthers revokes the agent's other keys that are still granted or live:
// a newly claimed key replaces them (one live key per agent). It is not a
// human stop.
func (s *Store) replaceOthers(ctx context.Context, tx *store.Tx, owner, holder, newID string) error {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM keys WHERE owner_id = ? AND holder_kind = 'agent' AND holder = ? AND revoked_at IS NULL AND id <> ?`, owner, holder, newID)
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
// before the row commits, so no response, log line or event can carry it. The
// claim of an agent's key revokes the agent's other keys, the one it asked
// with included, in the same transaction.
func (s *Store) Claim(ctx context.Context, id, claimant string) (token string, info ops.KeyInfo, err error) {
	return s.claim(ctx, id, claimant, nil)
}

// claim is Claim with a step that runs in the claim's own transaction (the enrolment is marked claimed there).
func (s *Store) claim(ctx context.Context, id, claimant string, after func(ctx context.Context, tx *store.Tx, k ops.KeyInfo) error) (token string, info ops.KeyInfo, err error) {
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
		if k.HolderKind == HolderAgent {
			if err := s.replaceOthers(ctx, tx, k.Owner, k.Holder, id); err != nil {
				return err
			}
		}
		params := map[string]any{"id": id, "fingerprint": hash[:8]}
		body := fmt.Sprintf("key %s claimed by %s (fingerprint %s)", id, claimant, hash[:8])
		if err := s.appendOp(ctx, tx, "keys.claim", k.Project, claimerID(claimant), id, params, body); err != nil {
			return err
		}
		info, err = s.get(ctx, tx, id)
		if err != nil {
			return err
		}
		if after != nil {
			return after(ctx, tx, info)
		}
		return nil
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
	if rest, ok := strings.CutPrefix(callerKey, "agent:"); ok {
		// "agent:person:operator/scout": the agent, named the way the ledger can hold it
		return fitID(strings.ToLower(strings.NewReplacer("person:", "", "/", ".", ":", ".").Replace("agent." + rest)))
	}
	if name, ok := strings.CutPrefix(callerKey, "person:"); ok {
		return fitID("person." + strings.ToLower(name)) // the owner at the console
	}
	if id, ok := strings.CutPrefix(callerKey, "enrol:"); ok {
		return "enrol." + id
	}
	return "operator"
}

// maxLedgerID is the longest id the ledger holds for a requester (^[a-z][a-z0-9._-]{0,62}$).
const maxLedgerID = 63

// fitID makes an id fit the ledger. A longer one keeps its head and ends with 8 hex digits of its own hash, so
// the id never fails the ledger's pattern and two long ids stay apart.
func fitID(id string) string {
	if len(id) <= maxLedgerID {
		return id
	}
	sum := sha256.Sum256([]byte(id))
	return id[:maxLedgerID-9] + "." + hex.EncodeToString(sum[:4])
}

// Revoke revokes a key. A human revoke (by the owner at the console, Decider.Revoke) of an agent's key also stops
// the agent: the owner must resume it before it can be given a key again. A revoke by a token (an orchestrator
// that owns the key, or the key itself) is never human. Revoking a revoked key is ErrRevoked.
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
		// The agent's waiting asks go with it: nobody may be asked about an agent a human stopped.
		if _, err := tx.ExecContext(ctx, `UPDATE key_requests SET state = 'cancelled' WHERE owner_id = ? AND holder = ? AND state = 'pending'`, owner, holder); err != nil {
			return fmt.Errorf("keys: cancel the agent's requests: %w", err)
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

// RevokeOwnedTx revokes, inside the caller's transaction, every key that owner holds and that is not revoked yet:
// all of them (projects nil), or only those in the given projects. It is what happens to what an orchestrator built
// when the orchestrator is revoked, or is re-issued without a project (ADR-008): such a key could otherwise not be
// read or revoked by its owner, which has no access to it any more. It is never a human stop, and it is ledgered
// as chapd's own act, one keys.revoke per key. The pending approvals and waiting ops of each key are cancelled with it.
func (s *Store) RevokeOwnedTx(ctx context.Context, tx *store.Tx, owner string, projects []string, why string) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, project FROM keys WHERE owner_id = ? AND revoked_at IS NULL ORDER BY id`, owner)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id, project string
		if err := rows.Scan(&id, &project); err != nil {
			rows.Close()
			return err
		}
		if projects == nil || slices.Contains(projects, project) {
			ids = append(ids, id)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		if err := s.revokeTx(ctx, tx, id, "chapd", why, false); err != nil {
			return err
		}
	}
	return nil
}

// RevokeOwnedBeyondTx revokes, inside the caller's transaction, the keys owner holds that its new token no longer
// reaches: a key in a project the token does not cover, or holding an op the token's ops (patterns, as in the token)
// do not allow. It is what happens when an orchestrator's token is re-issued narrower (ADR-008). Like
// [Store.RevokeOwnedTx] it is chapd's own act, never a human stop, with one keys.revoke event for each key whose
// reason says what was lost. A key that is still inside the new scope is left alone.
func (s *Store) RevokeOwnedBeyondTx(ctx context.Context, tx *store.Tx, owner string, projects, opPatterns []string) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, project, ops_json FROM keys WHERE owner_id = ? AND revoked_at IS NULL ORDER BY id`, owner)
	if err != nil {
		return err
	}
	type lost struct{ id, why string }
	var out []lost
	for rows.Next() {
		var id, project, opsJSON string
		if err := rows.Scan(&id, &project, &opsJSON); err != nil {
			rows.Close()
			return err
		}
		if !slices.Contains(projects, project) {
			out = append(out, lost{id, "its orchestrator " + owner + " no longer covers the project"})
			continue
		}
		var granted []string
		_ = json.Unmarshal([]byte(opsJSON), &granted) // an unreadable list holds nothing, and is revoked below
		if len(granted) == 0 && opsJSON != "[]" {
			out = append(out, lost{id, "its list of ops is unreadable"})
			continue
		}
		for _, op := range granted {
			if !spec.OpAllowed(op, opPatterns) {
				out = append(out, lost{id, "its orchestrator " + owner + " no longer holds " + clipText(op, 60)})
				break
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, l := range out {
		if err := s.revokeTx(ctx, tx, l.id, "chapd", l.why, false); err != nil {
			return err
		}
	}
	return nil
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
	// Asks and enrolments that waited past their deadline are written down as expired.
	if err := s.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error { return s.expireTx(ctx, tx, s.now()) }); err != nil {
		return 0, err
	}
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
// ever hold, so a row that lists a critical or never-in-key op does not give the key that op. The sensitivity of the
// key is worked out again from the ops (the catalog), and a life longer than the limit for it is refused, so the
// row's own flag and dates cannot widen a key either. A row can still name another project or other repositories:
// whoever can write the database is the trusted administrator.
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
		stopped, sensitiveRow                                                  int
	)
	err := s.cfg.DB.SQL().QueryRowContext(ctx, `SELECT id, project, owner_id, holder_kind, holder, ops_json, units_json, rate_per_hour,
            issued_at, expires_at, token_sha256, fingerprint, revoked_at, revoke_reason, human_stopped, last_used_at, sensitive
        FROM keys WHERE token_sha256 = ?`, want).
		Scan(&id, &project, &owner, &holderKind, &holder, &opsJSON, &unitsJSON, &rate, &issued, &expires, &stored, &fp, &revoked, &revokeReason, &stopped, &lastUsed, &sensitiveRow)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, &ops.VerifyError{Code: ops.CodeTokenInvalid, Detail: "unknown key"}
	case err != nil:
		return nil, fmt.Errorf("keys: read key: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(stored), []byte(want)) != 1 {
		return nil, &ops.VerifyError{Code: ops.CodeTokenInvalid, Detail: "unknown key"}
	}
	who := &ops.Caller{Kind: ops.KindKey, KeyID: id, Project: project, KeyOwner: owner, KeyHolder: holder, KeyHolderKind: holderKind, Fingerprint: fp}
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
	sensitive := sensitiveRow == 1
	for _, op := range granted {
		if _, ok := ops.KeyUnitKind(op); ok && !ops.NeverInKey(op) {
			who.KeyOps = append(who.KeyOps, op)
			if s.cfg.Catalog != nil {
				if entry, known := s.cfg.Catalog.Lookup(op); !known || entry.Class != policy.ClassRoutine {
					sensitive = true // worked out again: the row's own flag can only add to it
				}
			}
		}
	}
	if sensitive && time.Duration(expires-issued)*time.Second > SensitiveMaxDays*24*time.Hour {
		return nil, &ops.VerifyError{Code: ops.CodeTokenInvalid, Detail: "key " + id + " holds an op that asks for a card each time and lives longer than " + fmt.Sprint(SensitiveMaxDays) + " days", Key: who}
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

// Live is the ops.Config.KeyLive hook: it says, inside the transaction that releases an approved op, whether the
// key that asked still lives. It returns nil when it does, and a refusal (TOKEN_REVOKED or TOKEN_EXPIRED) when
// the key was revoked or has expired, so a call in flight when the key was revoked, or an op whose card was signed
// after the key ran out, does not run and its approval is not spent.
func (s *Store) Live(ctx context.Context, q queryer, id string) error {
	var claimed, revoked sql.NullInt64
	var expires int64
	err := q.QueryRowContext(ctx, `SELECT claimed_at, revoked_at, expires_at FROM keys WHERE id = ?`, id).Scan(&claimed, &revoked, &expires)
	switch {
	case errors.Is(err, sql.ErrNoRows), err == nil && !claimed.Valid:
		return &ops.Refusal{Code: ops.CodeTokenRevoked, Why: "key " + clipText(id, 40) + " is not a live key, so the op it asked for does not run"}
	case err != nil:
		return err
	case revoked.Valid:
		return &ops.Refusal{Code: ops.CodeTokenRevoked, Why: "key " + id + " was revoked, so the op it asked for does not run"}
	case !s.now().Before(time.Unix(expires, 0)):
		return &ops.Refusal{Code: ops.CodeTokenExpired, Why: "key " + id + " has expired, so the op it asked for does not run"}
	}
	return nil
}

// get reads one key row as the API shows it.
type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

const infoColumns = `id, project, owner_id, holder_kind, holder, ops_json, units_json, sensitive, rate_per_hour, issued_at, expires_at,
    claim_deadline, COALESCE(claimed_at,0), COALESCE(fingerprint,''), granted_by, approval_id, request_id, COALESCE(revoked_at,0),
    COALESCE(revoked_by,''), COALESCE(revoke_reason,''), human_stopped, COALESCE(last_used_at,0),
    (SELECT COUNT(*) FROM ops WHERE ops.requester_key = 'key:' || keys.id), grant_kind`

type rowScanner interface{ Scan(dest ...any) error }

func (s *Store) scan(r rowScanner) (ops.KeyInfo, error) {
	var k ops.KeyInfo
	var opsJSON, unitsJSON string
	var sens, stopped int
	var issued, expires, deadline, claimed, revoked, used int64
	if err := r.Scan(&k.ID, &k.Project, &k.Owner, &k.HolderKind, &k.Holder, &opsJSON, &unitsJSON, &sens, &k.RatePerHour, &issued, &expires,
		&deadline, &claimed, &k.Fingerprint, &k.GrantedBy, &k.ApprovalID, &k.RequestID, &revoked,
		&k.RevokedBy, &k.RevokeReason, &stopped, &used, &k.Uses, &k.GrantKind); err != nil {
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
