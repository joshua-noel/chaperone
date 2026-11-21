package keys

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/localtime"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/store"
)

// Extending a key (ADR-008): the agent's work runs long, so its owner makes the key last longer
// with one tap and a Hello. Extending changes the expiry and nothing else: it never adds scope, and it never
// takes a key past its cap, which counts from the day the key was made (30 days in all, 7 when it holds an op
// that asks for a card each time). Past that, the agent asks for a new key.

// OpExtend is the extension op. It is class high, and never in a key's list (ops.NeverInKey).
const OpExtend = ops.OpKeysExtend

// MaxExtendHours is the most one extension adds.
const MaxExtendHours = MaxDays * 24

var extendKeys = paramSet("key", "extend_hours", "owner", "holder", "request")

// keyFacts are the columns of a key that an extension is judged on.
type keyFacts struct {
	ID, Project, Owner, HolderKind, Holder, Kind string
	Sensitive                                    bool
	Issued, Expires                              int64
	Claimed, Revoked                             bool
	Ops, Units                                   []string
	Rate                                         int
}

func (s *Store) keyFacts(ctx context.Context, q dbx, id string) (*keyFacts, error) {
	if !keyIDRE.MatchString(id) {
		return nil, ErrNotFound
	}
	var k keyFacts
	var opsJSON, unitsJSON string
	var sens int
	var claimed, revoked sql.NullInt64
	err := q.QueryRowContext(ctx, `SELECT id, project, owner_id, holder_kind, holder, grant_kind, sensitive, issued_at, expires_at, claimed_at, revoked_at,
        ops_json, units_json, rate_per_hour FROM keys WHERE id = ?`, id).
		Scan(&k.ID, &k.Project, &k.Owner, &k.HolderKind, &k.Holder, &k.Kind, &sens, &k.Issued, &k.Expires, &claimed, &revoked, &opsJSON, &unitsJSON, &k.Rate)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	k.Sensitive, k.Claimed, k.Revoked = sens == 1, claimed.Valid, revoked.Valid
	k.Ops, k.Units = decodeList(opsJSON), decodeList(unitsJSON)
	return &k, nil
}

// extendCheck judges adding hours to the key: it must be a live key of an agent whose owner granted it with their
// own Hello, and the new expiry must stay inside the cap that counts from the day it was made.
func (s *Store) extendCheck(ctx context.Context, q dbx, id string, hours int) (*keyFacts, time.Time, error) {
	k, err := s.keyFacts(ctx, q, id)
	if err != nil {
		return nil, time.Time{}, err
	}
	now := s.now()
	switch {
	case k.HolderKind != HolderAgent || k.Kind != GrantSelf:
		return nil, time.Time{}, rule("only the key an owner granted their own agent is extended here; a request-only key is renewed by enrolling again, and any other key by a new one")
	case k.Revoked:
		return nil, time.Time{}, rule("the key %s is revoked: ask for a new one", k.ID)
	case !k.Claimed:
		return nil, time.Time{}, rule("the key %s has not been claimed yet, so there is nothing to extend", k.ID)
	case !now.Before(unixTime(k.Expires)):
		return nil, time.Time{}, rule("the key %s has expired: ask for a new one", k.ID)
	case hours < 1 || hours > MaxExtendHours:
		return nil, time.Time{}, rule("an extension adds 1 to %d hours", MaxExtendHours)
	}
	newExpires := unixTime(k.Expires).Add(time.Duration(hours) * time.Hour)
	limit := MaxDays
	if k.Sensitive {
		limit = SensitiveMaxDays
	}
	if newExpires.Sub(unixTime(k.Issued)) > time.Duration(limit)*24*time.Hour {
		left := unixTime(k.Issued).Add(time.Duration(limit) * 24 * time.Hour).Sub(unixTime(k.Expires))
		return nil, time.Time{}, rule("a key lives at most %d days from the day it was made%s: this one can be extended by at most %s more; after that the agent asks for a new key",
			limit, sensitiveWhy(k.Sensitive), hours2(left))
	}
	return k, newExpires, nil
}

func sensitiveWhy(sensitive bool) string {
	if sensitive {
		return " (it holds an op that asks for a card each time)"
	}
	return ""
}

func hours2(d time.Duration) string {
	if d < time.Hour {
		return "no time"
	}
	return hours(int(d / time.Hour))
}

func decodeList(s string) []string {
	var out []string
	_ = jsonUnmarshal(s, &out)
	return nonNil(out)
}

// ExtendGrant is an approved keys.extend.
type ExtendGrant struct {
	KeyID      string
	Hours      int
	Owner      string
	KeyRequest string // the extend request this answers; "" for an extension the owner started
	ApprovalID string
	RequestID  string // the keys.extend op: one op, one extension
	GrantedBy  string
}

// Extend moves a live key's expiry later, once per op, and answers the request it came from. The scope columns
// are untouched (the database refuses to change them).
func (s *Store) Extend(ctx context.Context, g ExtendGrant) (ops.KeyInfo, error) {
	var info ops.KeyInfo
	now := s.now()
	err := s.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		var prior int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM key_extensions WHERE request_id = ?`, g.RequestID).Scan(&prior); err != nil {
			return err
		}
		if prior > 0 {
			var err error
			info, err = s.get(ctx, tx, g.KeyID)
			return err // an earlier attempt of this op already did it
		}
		k, newExpires, err := s.extendCheck(ctx, tx, g.KeyID, g.Hours)
		if err != nil {
			return err
		}
		if k.Owner != g.Owner {
			return rule("the key %s belongs to another owner", k.ID)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE keys SET expires_at = ? WHERE id = ? AND revoked_at IS NULL AND claimed_at IS NOT NULL`, newExpires.Unix(), k.ID); err != nil {
			return fmt.Errorf("keys: extend: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO key_extensions (request_id, key_id, approval_id, extended_by, hours, old_expires_at, new_expires_at, created_at)
            VALUES (?,?,?,?,?,?,?,?)`, g.RequestID, k.ID, g.ApprovalID, g.GrantedBy, g.Hours, k.Expires, newExpires.Unix(), now.Unix()); err != nil {
			return fmt.Errorf("keys: record the extension: %w", err)
		}
		if g.KeyRequest != "" {
			opsJSON, unitsJSON := encodeList(k.Ops), encodeList(k.Units)
			res, err := tx.ExecContext(ctx, `UPDATE key_requests SET state = 'granted', decided_at = ?, decided_by = ?, granted_key_id = ?,
                    grant_ops_json = ?, grant_units_json = ?, grant_ttl_hours = ?, grant_rate = ?
                WHERE id = ? AND state = 'pending' AND kind = 'extend' AND extends_key_id = ?`,
				now.Unix(), g.GrantedBy, k.ID, opsJSON, unitsJSON, g.Hours, k.Rate, g.KeyRequest, k.ID)
			if err != nil {
				return fmt.Errorf("keys: answer the request: %w", err)
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return rule("request %s is no longer waiting", g.KeyRequest)
			}
		}
		params := map[string]any{"id": k.ID, "hours": g.Hours, "expires_at": ops.KeyTime(newExpires)}
		body := fmt.Sprintf("key %s extended by %d hours, now until %s", k.ID, g.Hours, ops.KeyTime(newExpires))
		if err := s.appendOp(ctx, tx, "keys.extend", k.Project, "person."+g.GrantedBy, k.ID, params, body); err != nil {
			return err
		}
		info, err = s.get(ctx, tx, k.ID)
		return err
	})
	return info, err
}

// ExtendAdapter is the keys.extend adapter.
type ExtendAdapter struct {
	store    *Store
	approval ApprovalOf
}

var _ ops.Adapter = (*ExtendAdapter)(nil)

// NewExtendAdapter returns the keys.extend adapter.
func NewExtendAdapter(s *Store, approval ApprovalOf) (*ExtendAdapter, error) {
	if s == nil || approval == nil {
		return nil, errors.New("keys: the keys.extend adapter needs a Store and Approval")
	}
	return &ExtendAdapter{store: s, approval: approval}, nil
}

type extension struct {
	ExtendGrant
	facts   *keyFacts
	expires time.Time
	asked   *requestRow
	holder  string
}

func (a *ExtendAdapter) parse(ctx context.Context, req *ops.Request) (extension, error) {
	c := req.Caller
	if c == nil || c.Kind != ops.KindOrchestrator || c.OrchID != ops.OperatorID {
		return extension{}, refuse("a key is extended at the console, by its owner: a key never extends a key")
	}
	if err := unknownParam(req.Params, extendKeys, "key, extend_hours, owner, holder, request"); err != nil {
		return extension{}, err
	}
	var e extension
	id, _ := req.Params["key"].(string)
	hours, err := intParam(req.Params, "extend_hours")
	if err != nil {
		return extension{}, err
	}
	owner, _ := req.Params["owner"].(string)
	holder, _ := req.Params["holder"].(string)
	if !keyIDRE.MatchString(id) || hours == 0 || !personRE.MatchString(owner) || !labelRE.MatchString(holder) {
		return extension{}, invalid("keys.extend takes key (k-...), extend_hours, owner and holder")
	}
	facts, newExpires, err := a.store.extendCheck(ctx, a.store.cfg.DB.SQL(), id, hours)
	if err != nil {
		var re *RuleError
		if errors.As(err, &re) {
			return extension{}, refuse("%s", re.Why)
		}
		if errors.Is(err, ErrNotFound) {
			return extension{}, invalid("there is no key %s", id)
		}
		return extension{}, err
	}
	switch {
	case facts.Owner != owner || facts.Holder != holder:
		return extension{}, refuse("the key %s is not %s's agent %s", id, ownerName(owner), clipText(holder, 60))
	case facts.Project != req.Project:
		return extension{}, refuse("the key %s is for project %s", id, facts.Project)
	}
	e.ExtendGrant = ExtendGrant{KeyID: id, Hours: hours, Owner: owner}
	e.facts, e.expires, e.holder = facts, newExpires, holder
	if rid, ok := req.Params["request"].(string); ok {
		rq, err := a.store.requestRow(ctx, a.store.cfg.DB.SQL(), rid)
		switch {
		case errors.Is(err, ErrNotFound):
			return extension{}, invalid("there is no key request %s", clipText(rid, 40))
		case err != nil:
			return extension{}, err
		case rq.Kind != reqExtend || rq.ExtendsKey != id || rq.State != reqPending || !a.store.now().Before(unixTime(rq.Expires)):
			return extension{}, refuse("request %s is not a waiting request to extend key %s", rid, id)
		case hours > rq.TTLHours:
			return extension{}, refuse("an extension can only narrow what was asked: %d hours is more than the %d asked for", hours, rq.TTLHours)
		}
		e.KeyRequest, e.asked = rid, rq
	}
	return e, nil
}

// Check implements [ops.Adapter]: the card shows the old and the new expiry, in local time and UTC, and says
// the scope is unchanged.
func (a *ExtendAdapter) Check(ctx context.Context, req *ops.Request) (ops.CheckResult, error) {
	e, err := a.parse(ctx, req)
	if err != nil {
		return ops.CheckResult{}, err
	}
	old := unixTime(e.facts.Expires)
	lines := []string{
		fmt.Sprintf("Extend the key %s of agent %q (acting for %s) in project %s by %s.", e.KeyID, e.holder, ownerName(e.Owner), req.Project, hours(e.Hours)),
		fmt.Sprintf("It now ends:     %s %s time (%s)", localtime.Clock(old), localtime.Label(), ops.KeyTime(old)),
		fmt.Sprintf("It will end:     %s %s time (%s)", localtime.Clock(e.expires), localtime.Label(), ops.KeyTime(e.expires)),
		"What the key can do does not change: " + strings.Join(e.facts.Ops, ", ") + units(e.facts.Units) + ".",
	}
	if e.asked != nil {
		lines = append(lines, fmt.Sprintf("The agent asked for %s (request %s) and wrote: %q", hours(e.asked.TTLHours), e.asked.ID, plainText(e.asked.Reason, 300)))
	}
	lines = append(lines, "This is your own agent: you alone decide, with your own Windows Hello. Nobody else is asked.")
	detail := fmt.Sprintf("key %s +%dh, %s to %s", e.KeyID, e.Hours, ops.KeyTime(old), ops.KeyTime(e.expires))
	return ops.CheckResult{
		Checks:   []ops.Check{{Name: "key.extend", Passed: true, Detail: detail}},
		Evidence: []ops.Evidence{{Name: "How long the key will last", Text: strings.Join(lines, "\n")}},
	}, nil
}

func units(u []string) string {
	if len(u) == 0 {
		return ""
	}
	return " on " + strings.Join(u, ", ")
}

// Execute implements [ops.Adapter].
func (a *ExtendAdapter) Execute(ctx context.Context, req *ops.Request) (ops.Outcome, error) {
	e, err := a.parse(ctx, req)
	if err != nil {
		var ref *ops.Refusal
		if errors.As(err, &ref) {
			return ops.Outcome{Failed: true, Result: map[string]any{"error": ref.Why}}, nil
		}
		return ops.Outcome{}, err
	}
	g := e.ExtendGrant
	g.RequestID = req.ID
	if g.ApprovalID, g.GrantedBy, err = a.approval(ctx, req.ID); err != nil {
		return ops.Outcome{}, err
	}
	if ownerName(g.Owner) != g.GrantedBy {
		return ops.Outcome{Failed: true, Result: map[string]any{
			"error": fmt.Sprintf("this key is for %s's agent, so only %s signs its extension; the card was signed by %s", ownerName(g.Owner), ownerName(g.Owner), clipText(g.GrantedBy, 60)),
		}}, nil
	}
	info, err := a.store.Extend(ctx, g)
	if err != nil {
		var re *RuleError
		if errors.As(err, &re) {
			return ops.Outcome{Failed: true, Result: map[string]any{"error": re.Why}}, nil
		}
		return ops.Outcome{}, err
	}
	return ops.Outcome{ExternalRef: info.ID, Result: map[string]any{"key_id": info.ID, "expires_at": info.ExpiresAt}}, nil
}

func jsonUnmarshal(s string, v any) error { return json.Unmarshal([]byte(s), v) }

func encodeList(l []string) string {
	b, _ := json.Marshal(nonNil(l))
	return string(b)
}
