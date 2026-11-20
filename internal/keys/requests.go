package keys

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/localtime"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/store"
)

// Key requests (ADR-008): "the agent asks, you tap". An agent that holds a key of its own
// (a request-only key at first) writes down what it needs, for how long and why; its owner answers at the console:
// Grant as asked, Narrow, or Deny. A request is a row, not an op: the op `keys.request` only writes it.

// Kinds and states of a request.
const (
	reqNew    = "new"
	reqExtend = "extend"

	reqPending   = "pending"
	reqGranted   = "granted"
	reqDenied    = "denied"
	reqWithdrawn = "withdrawn"
	reqExpired   = "expired"
	reqCancelled = "cancelled"
)

// RequestLife is how long a request waits for its owner (the spec's 24 hours).
const RequestLife = 24 * time.Hour

// DenySticky is how long an exact request an owner denied is refused when asked again (ADR-004 item 5).
const DenySticky = 60 * time.Minute

// Looping-agent alert: this many refusals of keys.request inside this window.
const (
	LoopWindow    = 5 * time.Minute
	LoopThreshold = 3
)

// RequestLimits are the caps that keep a looping agent from filling its owner's queue (a cap on requests). They are
// policy data in spirit: tune them after a week of use.
type RequestLimits struct {
	PerAgentPending int // requests of one agent waiting at once
	PerAgentPerHour int // new requests of one agent in an hour
	PerOwnerPending int // requests waiting for one owner
	TotalPending    int // requests waiting in all
}

// DefaultRequestLimits are the spec's: 3 waiting per agent, 6 new an hour, 10 per owner, 20 in all.
var DefaultRequestLimits = RequestLimits{PerAgentPending: 3, PerAgentPerHour: 6, PerOwnerPending: 10, TotalPending: 20}

// Looping is what the looping-agent alert hook is told.
type Looping struct {
	Owner, Holder, KeyID string
	Refusals             int
}

// requestRow is a row of key_requests.
type requestRow struct {
	ID, Kind, Project, Owner, Holder, RequesterKey string
	Ops, Units                                     []string
	TTLHours, Rate                                 int
	Reason                                         string
	NeededToday                                    bool
	ScopeHash, ExtendsKey, RequestOp, State        string
	Created, Expires, Decided                      int64
	DecidedBy, DenyReason                          string
	GrantOps, GrantUnits                           []string
	GrantTTL, GrantRate                            int
	IssueOp, GrantedKey                            string
}

const reqColumns = `id, kind, project, owner_id, holder, requester_key_id, ops_json, units_json, ttl_hours, rate_per_hour, reason, needed_today,
    scope_hash, COALESCE(extends_key_id,''), request_op_id, state, created_at, expires_at, COALESCE(decided_at,0), COALESCE(decided_by,''),
    COALESCE(deny_reason,''), COALESCE(grant_ops_json,''), COALESCE(grant_units_json,''), COALESCE(grant_ttl_hours,0), COALESCE(grant_rate,0),
    COALESCE(issue_op_id,''), COALESCE(granted_key_id,'')`

func scanRequest(r rowScanner) (*requestRow, error) {
	var q requestRow
	var opsJSON, unitsJSON, gOps, gUnits string
	var needed int
	if err := r.Scan(&q.ID, &q.Kind, &q.Project, &q.Owner, &q.Holder, &q.RequesterKey, &opsJSON, &unitsJSON, &q.TTLHours, &q.Rate, &q.Reason, &needed,
		&q.ScopeHash, &q.ExtendsKey, &q.RequestOp, &q.State, &q.Created, &q.Expires, &q.Decided, &q.DecidedBy,
		&q.DenyReason, &gOps, &gUnits, &q.GrantTTL, &q.GrantRate, &q.IssueOp, &q.GrantedKey); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(opsJSON), &q.Ops)
	_ = json.Unmarshal([]byte(unitsJSON), &q.Units)
	if gOps != "" {
		_ = json.Unmarshal([]byte(gOps), &q.GrantOps)
		_ = json.Unmarshal([]byte(gUnits), &q.GrantUnits)
	}
	q.Ops, q.Units = nonNil(q.Ops), nonNil(q.Units)
	q.NeededToday = needed == 1
	return &q, nil
}

type dbx interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func unixTime(u int64) time.Time { return time.Unix(u, 0) }

func (s *Store) requestRow(ctx context.Context, q dbx, id string) (*requestRow, error) {
	if !requestIDRE.MatchString(id) {
		return nil, ErrNotFound
	}
	r, err := scanRequest(q.QueryRowContext(ctx, `SELECT `+reqColumns+` FROM key_requests WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

// view is the request as the API shows it. A request that waited past its deadline reads as expired even before
// the sweeper writes it down.
func (s *Store) view(q *requestRow) ops.KeyRequestInfo {
	state := q.State
	if state == reqPending && !s.now().Before(unixTime(q.Expires)) {
		state = reqExpired
	}
	v := ops.KeyRequestInfo{
		ID: q.ID, Kind: q.Kind, State: state, Project: q.Project, Owner: q.Owner, Holder: q.Holder,
		Ops: q.Ops, Units: q.Units, TTLHours: q.TTLHours, RatePerHour: q.Rate, Reason: q.Reason, NeededToday: q.NeededToday,
		CreatedAt: ops.KeyTime(unixTime(q.Created)), ExpiresAt: ops.KeyTime(unixTime(q.Expires)),
		ExtendsKey: q.ExtendsKey, IssueOp: q.IssueOp,
	}
	if q.Decided != 0 {
		v.DecidedAt, v.DecidedBy = ops.KeyTime(unixTime(q.Decided)), q.DecidedBy
	}
	if q.State == reqDenied {
		v.DenyReason = q.DenyReason
	}
	if q.State == reqGranted {
		v.KeyID = q.GrantedKey
		g := &ops.KeyRequestGrant{Ops: nonNil(q.GrantOps), Units: nonNil(q.GrantUnits), TTLHours: q.GrantTTL, RatePerHour: q.GrantRate}
		v.Granted = g
		v.Removed = &ops.KeyRequestGrant{
			Ops: nonNil(missing(q.Ops, q.GrantOps)), Units: nonNil(missing(q.Units, q.GrantUnits)),
			TTLHours: max(q.TTLHours-q.GrantTTL, 0), RatePerHour: max(q.Rate-q.GrantRate, 0),
		}
	}
	return v
}

// NewRequest is what keys.request writes down.
type NewRequest struct {
	Kind           string
	Project        string
	Owner, Holder  string
	RequesterKeyID string
	Ops, Units     []string
	TTLHours, Rate int
	Reason         string
	NeededToday    bool
	ExtendsKey     string
	RequestOp      string
}

// scopeHash identifies an ask by what it asks for, never by the words around it: the same agent asking for the
// same thing twice is one request, whatever reason it gives the second time.
func (n NewRequest) scopeHash() string {
	h := sha256.Sum256([]byte(strings.Join([]string{
		n.Kind, n.Project, n.Owner, n.Holder, strings.Join(n.Ops, ","), strings.Join(n.Units, ","),
		strconv.Itoa(n.TTLHours), strconv.Itoa(n.Rate), n.ExtendsKey,
	}, "\x00")))
	return hex.EncodeToString(h[:])
}

func rateRefusal(why string, retry int) error {
	if retry < 1 {
		retry = 1
	}
	return &ops.Refusal{Code: ops.CodePolicyRefused, Why: "rate limit: " + why, Status: 429, RetryAfter: retry}
}

// admit decides whether an ask may be written down. It returns the id of the identical ask that already waits
// (the ask is then answered with that one and nothing is written), or a refusal: an agent a human stopped,
// an exact ask the owner just denied, or a cap (a cap on requests). It writes nothing.
func (s *Store) admit(ctx context.Context, q dbx, n NewRequest, hash string, now time.Time) (existing string, err error) {
	var stopped int
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM key_agents WHERE owner_id = ? AND label = ?`, n.Owner, n.Holder).Scan(&stopped); err != nil {
		return "", err
	}
	if stopped > 0 {
		return "", &ops.Refusal{Code: ops.CodeTokenRevoked, Why: n.Holder + " is " + StoppedWhy, Surface: "token"}
	}
	err = q.QueryRowContext(ctx, `SELECT id FROM key_requests WHERE owner_id = ? AND holder = ? AND scope_hash = ? AND state = 'pending' AND expires_at > ?`,
		n.Owner, n.Holder, hash, now.Unix()).Scan(&existing)
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	var denied int64
	var why string
	err = q.QueryRowContext(ctx, `SELECT decided_at, COALESCE(deny_reason,'') FROM key_requests
        WHERE owner_id = ? AND holder = ? AND scope_hash = ? AND state = 'denied' AND decided_at > ? ORDER BY decided_at DESC LIMIT 1`,
		n.Owner, n.Holder, hash, now.Add(-DenySticky).Unix()).Scan(&denied, &why)
	switch {
	case err == nil:
		text := fmt.Sprintf("%s denied this exact request at %s; it is refused until %s", ownerName(n.Owner), localtime.Clock(unixTime(denied)), localtime.Clock(unixTime(denied).Add(DenySticky)))
		if why != "" {
			text += ". They said: " + plainText(why, 200)
		}
		return "", &ops.Refusal{Code: ops.CodePolicyRefused, Why: text + ". Ask for something different, or ask your owner", Surface: "op"}
	case !errors.Is(err, sql.ErrNoRows):
		return "", err
	}
	chap := s.cfg.Limits
	count := func(where string, args ...any) (int, error) {
		var c int
		err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM key_requests WHERE `+where, args...).Scan(&c)
		return c, err
	}
	if c, err := count(`owner_id = ? AND holder = ? AND state = 'pending' AND expires_at > ?`, n.Owner, n.Holder, now.Unix()); err != nil {
		return "", err
	} else if c >= chap.PerAgentPending {
		return "", rateRefusal(fmt.Sprintf("%s already has %d requests waiting for its owner; wait for an answer, or withdraw one (chap key request --withdraw <id>)", n.Holder, c), 60)
	}
	since := now.Add(-time.Hour).Unix()
	if c, err := count(`owner_id = ? AND holder = ? AND created_at > ?`, n.Owner, n.Holder, since); err != nil {
		return "", err
	} else if c >= chap.PerAgentPerHour {
		var oldest int64
		if err := q.QueryRowContext(ctx, `SELECT MIN(created_at) FROM (SELECT created_at FROM key_requests WHERE owner_id = ? AND holder = ? AND created_at > ? ORDER BY created_at DESC LIMIT ?)`,
			n.Owner, n.Holder, since, chap.PerAgentPerHour).Scan(&oldest); err != nil {
			return "", err
		}
		return "", rateRefusal(fmt.Sprintf("an agent may ask for %d keys an hour; %s has", chap.PerAgentPerHour, n.Holder), int(oldest+3600-now.Unix()))
	}
	if c, err := count(`owner_id = ? AND state = 'pending' AND expires_at > ?`, n.Owner, now.Unix()); err != nil {
		return "", err
	} else if c >= chap.PerOwnerPending {
		return "", rateRefusal(fmt.Sprintf("%d requests already wait for %s; ask them to answer some first", c, ownerName(n.Owner)), 60)
	}
	if c, err := count(`state = 'pending' AND expires_at > ?`, now.Unix()); err != nil {
		return "", err
	} else if c >= chap.TotalPending {
		return "", rateRefusal(fmt.Sprintf("%d requests already wait in all; try again later", c), 60)
	}
	return "", nil
}

// refusalsRecently counts the keys.request ops this key had refused in the looping window.
func (s *Store) refusalsRecently(ctx context.Context, keyID string) (int, error) {
	var n int
	err := s.cfg.DB.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM ops WHERE op = 'keys.request' AND requester_key = ? AND state = 'denied' AND requested_at > ?`,
		"key:"+keyID, s.now().Add(-LoopWindow).Unix()).Scan(&n)
	return n, err
}

// Precheck is the read-only half of CreateRequest: the refusal the ask would get, if any. The refusal that
// makes the third in five minutes also calls the looping-agent hook.
func (s *Store) Precheck(ctx context.Context, n NewRequest) (existing string, err error) {
	existing, err = s.admit(ctx, s.cfg.DB.SQL(), n, n.scopeHash(), s.now())
	var ref *ops.Refusal
	if errors.As(err, &ref) && s.cfg.OnLooping != nil && ref.Code == ops.CodePolicyRefused {
		if c, cerr := s.refusalsRecently(ctx, n.RequesterKeyID); cerr == nil && c+1 >= LoopThreshold {
			s.cfg.OnLooping(ctx, Looping{Owner: n.Owner, Holder: n.Holder, KeyID: n.RequesterKeyID, Refusals: c + 1})
		}
	}
	return existing, err
}

// CreateRequest writes an ask down, or returns the identical one that already waits. The caps are checked again
// inside the transaction, so a burst of concurrent asks cannot get past them.
func (s *Store) CreateRequest(ctx context.Context, n NewRequest) (v ops.KeyRequestInfo, deduplicated bool, err error) {
	hash := n.scopeHash()
	now := s.now()
	opsJSON, _ := json.Marshal(nonNil(n.Ops))
	unitsJSON, _ := json.Marshal(nonNil(n.Units))
	err = s.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		if err := s.expireTx(ctx, tx, now); err != nil {
			return err
		}
		existing, err := s.admit(ctx, tx, n, hash, now)
		if err != nil {
			return err
		}
		if existing != "" {
			q, err := s.requestRow(ctx, tx, existing)
			if err != nil {
				return err
			}
			v, deduplicated = s.view(q), true
			return nil
		}
		id, err := randomHex("kr-", 8)
		if err != nil {
			return err
		}
		var ext any
		if n.ExtendsKey != "" {
			ext = n.ExtendsKey
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO key_requests (id, kind, project, owner_id, holder, requester_key_id, ops_json, units_json, ttl_hours,
                rate_per_hour, reason, needed_today, scope_hash, extends_key_id, request_op_id, state, created_at, expires_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending',?,?)`,
			id, n.Kind, n.Project, n.Owner, n.Holder, n.RequesterKeyID, string(opsJSON), string(unitsJSON), n.TTLHours,
			n.Rate, n.Reason, b2i(n.NeededToday), hash, ext, n.RequestOp, now.Unix(), now.Add(RequestLife).Unix()); err != nil {
			return fmt.Errorf("keys: write the request: %w", err)
		}
		q, err := s.requestRow(ctx, tx, id)
		if err != nil {
			return err
		}
		v = s.view(q)
		return nil
	})
	return v, deduplicated, err
}

func randomHex(prefix string, n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("keys: random: %w", err)
	}
	return prefix + hex.EncodeToString(b), nil
}

// expireTx writes down the requests and enrolments that waited past their deadline.
func (s *Store) expireTx(ctx context.Context, tx dbx, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `UPDATE key_requests SET state = 'expired' WHERE state = 'pending' AND expires_at <= ?`, now.Unix()); err != nil {
		return fmt.Errorf("keys: expire requests: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE key_enrolments SET state = 'expired' WHERE state = 'pending' AND expires_at <= ?`, now.Unix()); err != nil {
		return fmt.Errorf("keys: expire enrolments: %w", err)
	}
	return nil
}

// GetRequest returns one request.
func (s *Store) GetRequest(ctx context.Context, id string) (ops.KeyRequestInfo, error) {
	q, err := s.requestRow(ctx, s.cfg.DB.SQL(), id)
	if err != nil {
		return ops.KeyRequestInfo{}, err
	}
	return s.view(q), nil
}

// ListRequests lists requests, newest first. owner and holder narrow it (empty means all); pendingOnly keeps only
// the requests still waiting for an answer.
func (s *Store) ListRequests(ctx context.Context, owner, holder string, pendingOnly bool) ([]ops.KeyRequestInfo, error) {
	where, args := []string{"1=1"}, []any(nil)
	if owner != "" {
		where, args = append(where, "owner_id = ?"), append(args, owner)
	}
	if holder != "" {
		where, args = append(where, "holder = ?"), append(args, holder)
	}
	if pendingOnly {
		where, args = append(where, "state = 'pending' AND expires_at > ?"), append(args, s.now().Unix())
	}
	rows, err := s.cfg.DB.SQL().QueryContext(ctx, `SELECT `+reqColumns+` FROM key_requests WHERE `+strings.Join(where, " AND ")+` ORDER BY created_at DESC, id LIMIT 200`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ops.KeyRequestInfo{}
	for rows.Next() {
		q, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s.view(q))
	}
	return out, rows.Err()
}

// ErrRequestState is a request that is not in a state that allows what was asked.
var ErrRequestState = errors.New("keys: the request is not waiting")

// closeRequest moves a waiting request to withdrawn, denied or cancelled, once.
func (s *Store) closeRequest(ctx context.Context, id, state, decidedBy, actor, reason string) (ops.KeyRequestInfo, error) {
	var v ops.KeyRequestInfo
	now := s.now()
	err := s.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE key_requests SET state = ?, decided_at = ?, decided_by = ?, deny_reason = ?
            WHERE id = ? AND state = 'pending' AND expires_at > ?`, state, now.Unix(), clipText(decidedBy, 80), nullIfEmpty(plainText(reason, 200)), id, now.Unix())
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			if _, err := s.requestRow(ctx, tx, id); err != nil {
				return err
			}
			return ErrRequestState
		}
		q, err := s.requestRow(ctx, tx, id)
		if err != nil {
			return err
		}
		v = s.view(q)
		return s.appendOp(ctx, tx, "keys.request."+state, q.Project, actor, q.RequesterKey,
			map[string]any{"request": id, "holder": q.Holder}, fmt.Sprintf("request %s of agent %s is %s", id, q.Holder, state))
	})
	return v, err
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Withdraw lets an agent take back a request that still waits; by is the agent's key id.
func (s *Store) Withdraw(ctx context.Context, id, byKeyID string) (ops.KeyRequestInfo, error) {
	return s.closeRequest(ctx, id, reqWithdrawn, "key:"+byKeyID, claimerID("key:"+byKeyID), "")
}

// Deny answers a waiting request with a no, by the person (their approver id) who owns the agent. The same exact
// ask is then refused for DenySticky.
func (s *Store) Deny(ctx context.Context, id, approver, reason string) (ops.KeyRequestInfo, error) {
	return s.closeRequest(ctx, id, reqDenied, approver, "person."+approver, reason)
}

// BindIssue remembers the card the owner started for a request, with what the owner chose to grant, so the page
// can say "a card is waiting" and the agent can see what is coming. It never changes the ask.
func (s *Store) BindIssue(ctx context.Context, id, opID string, grantOps, grantUnits []string, ttl, rate int) error {
	opsJSON, _ := json.Marshal(nonNil(grantOps))
	unitsJSON, _ := json.Marshal(nonNil(grantUnits))
	res, err := s.cfg.DB.SQL().ExecContext(ctx, `UPDATE key_requests SET issue_op_id = ?, grant_ops_json = ?, grant_units_json = ?, grant_ttl_hours = ?, grant_rate = ?
        WHERE id = ? AND state = 'pending'`, opID, string(opsJSON), string(unitsJSON), ttl, rate, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrRequestState
	}
	return nil
}
