package keys

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
)

// OpRequest is the op an agent calls to ask for a key (chap key request). It is routine: it writes the ask down and
// nothing more, so it raises no card. The card comes when the agent's owner answers.
const OpRequest = ops.OpKeysRequest

var requestParamKeys = paramSet("kind", "ops", "units", "ttl_hours", "rate_per_hour", "needed_today", "preset", "key")

// PresetReadOnly is "same as me, read-only": every routine op the owner may grant, bound to the project's own
// repository. The server expands it, so the stored ask names the ops and the owner reads them.
const PresetReadOnly = "same-as-me-read"

// RequestConfig configures the keys.request adapter.
type RequestConfig struct {
	Store   *Store
	Catalog interface {
		Lookup(op string) (policy.Entry, bool)
	}
	Enabled func(project, op string) bool
	Project func(project string) (ops.PRProject, bool)
}

// RequestAdapter is the keys.request adapter.
type RequestAdapter struct {
	s     *Store
	rules ScopeRules
}

var _ ops.Adapter = (*RequestAdapter)(nil)

// NewRequestAdapter returns the keys.request adapter.
func NewRequestAdapter(cfg RequestConfig) (*RequestAdapter, error) {
	if cfg.Store == nil || cfg.Catalog == nil || cfg.Enabled == nil || cfg.Project == nil {
		return nil, errors.New("keys: the keys.request adapter needs Store, Catalog, Enabled and Project")
	}
	return &RequestAdapter{s: cfg.Store, rules: ScopeRules{Catalog: cfg.Catalog, Enabled: cfg.Enabled, Project: cfg.Project}}, nil
}

func boolParam(p map[string]any, key string) (bool, error) {
	v, ok := p[key]
	if !ok {
		return false, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, invalid("param %s must be true or false", key)
	}
	return b, nil
}

// parse turns the call into an ask. The owner, the holder and the project are the key's own: nothing in the
// body can name another.
func (a *RequestAdapter) parse(ctx context.Context, req *ops.Request) (NewRequest, error) {
	c := req.Caller
	if c == nil || c.Kind != ops.KindKey || c.KeyHolderKind != HolderAgent {
		return NewRequest{}, refuse("only an agent's key asks for a key this way; a person asks at the console")
	}
	if err := unknownParam(req.Params, requestParamKeys, "kind, ops, units, ttl_hours, rate_per_hour, needed_today, preset, key"); err != nil {
		return NewRequest{}, err
	}
	reason := plainText(req.Reason, 500)
	if reason == "" {
		return NewRequest{}, invalid("a reason is required: say what the access is for, in a sentence (--reason)")
	}
	n := NewRequest{Kind: reqNew, Project: req.Project, Owner: c.KeyOwner, Holder: c.KeyHolder, RequesterKeyID: c.KeyID, Reason: reason, RequestOp: req.ID}
	if k, ok := req.Params["kind"]; ok {
		if k != reqNew && k != reqExtend {
			return NewRequest{}, invalid("param kind is new or extend")
		}
		n.Kind = k.(string)
	}
	var err error
	if n.NeededToday, err = boolParam(req.Params, "needed_today"); err != nil {
		return NewRequest{}, err
	}
	if n.Kind == reqExtend {
		return a.parseExtend(ctx, req, n)
	}
	if has(req.Params, "key") {
		return NewRequest{}, invalid("param key is for kind extend")
	}
	// What is asked for: named ops, or the shortcut.
	if preset, ok := req.Params["preset"]; ok {
		if preset != PresetReadOnly {
			return NewRequest{}, invalid("param preset is %q", PresetReadOnly)
		}
		if has(req.Params, "ops") || has(req.Params, "units") {
			return NewRequest{}, invalid("a preset stands for the ops and units: name either the preset or the ops, not both")
		}
		n.Ops, n.Units = a.rules.ReadOps(req.Project)
		if len(n.Ops) == 0 {
			return NewRequest{}, refuse("no read access can be asked for in project %s: the policy turns on no op a key may hold", req.Project)
		}
	} else {
		if n.Ops, err = stringList(req.Params["ops"], "ops"); err != nil {
			return NewRequest{}, err
		}
		if v, has := req.Params["units"]; has && v != nil {
			if n.Units, err = stringList(req.Params["units"], "units"); err != nil {
				return NewRequest{}, err
			}
		}
	}
	n.Ops, n.Units = sortedUnique(n.Ops), sortedUnique(lowerAll(n.Units))
	if n.TTLHours, err = intParam(req.Params, "ttl_hours"); err != nil {
		return NewRequest{}, err
	}
	if n.TTLHours == 0 {
		n.TTLHours = DefaultTTLHours
	}
	if n.Rate, err = intParam(req.Params, "rate_per_hour"); err != nil {
		return NewRequest{}, err
	}
	if n.Rate == 0 {
		n.Rate = ops.DefaultKeyRatePerHour
	}
	if n.Rate > ops.DefaultKeyRatePerHour {
		return NewRequest{}, refuse("the rate is 1 to %d calls an hour", ops.DefaultKeyRatePerHour)
	}
	g := Grant{Project: n.Project, HolderKind: HolderAgent, Holder: n.Holder, Ops: n.Ops, Units: n.Units, TTLHours: n.TTLHours, Rate: n.Rate, Kind: GrantSelf}
	if len(n.Ops) > 16 || len(n.Units) > 8 {
		return NewRequest{}, refuse("ask for at most 16 ops and 8 repositories")
	}
	if g.Sensitive, err = a.rules.Check(n.Project, n.Ops, n.Units); err != nil {
		return NewRequest{}, err
	}
	if err := g.Shape(); err != nil {
		return NewRequest{}, refuse("%s", err)
	}
	// Nothing past the owner's own access.
	if err := a.s.cfg.Access.Within(ctx, n.Owner, n.Project, n.Ops, n.Units); err != nil {
		return NewRequest{}, accessRefusal(err)
	}
	return n, nil
}

// parseExtend reads an ask to make the agent's own key last longer.
func (a *RequestAdapter) parseExtend(ctx context.Context, req *ops.Request, n NewRequest) (NewRequest, error) {
	c := req.Caller
	for _, k := range []string{"ops", "units", "rate_per_hour", "preset"} {
		if has(req.Params, k) {
			return NewRequest{}, invalid("an extension changes nothing but the time: param %s does not belong to it", k)
		}
	}
	if req.Params["key"] != "self" && req.Params["key"] != c.KeyID {
		return NewRequest{}, invalid("param key is \"self\": an agent asks to extend its own key")
	}
	hours, err := intParam(req.Params, "ttl_hours")
	if err != nil {
		return NewRequest{}, err
	}
	if hours == 0 {
		return NewRequest{}, invalid("param ttl_hours is required: how many hours to add")
	}
	k, _, err := a.s.extendCheck(ctx, a.s.cfg.DB.SQL(), c.KeyID, hours)
	if err != nil {
		var re *RuleError
		if errors.As(err, &re) {
			return NewRequest{}, refuse("%s", re.Why)
		}
		return NewRequest{}, err
	}
	n.ExtendsKey, n.Ops, n.Units, n.TTLHours, n.Rate = k.ID, k.Ops, k.Units, hours, k.Rate
	return n, nil
}

// Check implements [ops.Adapter]. It is read-only; the refusals it gives are the ones the owner's queue is
// protected by.
func (a *RequestAdapter) Check(ctx context.Context, req *ops.Request) (ops.CheckResult, error) {
	n, err := a.parse(ctx, req)
	if err != nil {
		return ops.CheckResult{}, err
	}
	if _, err := a.s.Precheck(ctx, n); err != nil {
		return ops.CheckResult{}, err
	}
	detail := fmt.Sprintf("%s ask by %s for %s: ops %s; units %s; %dh; %d/h", n.Kind, n.Holder, ownerName(n.Owner), strings.Join(n.Ops, ","), strings.Join(n.Units, ","), n.TTLHours, n.Rate)
	return ops.CheckResult{Checks: []ops.Check{{Name: "key.request", Passed: true, Detail: clipText(detail, 400)}}}, nil
}

// Execute implements [ops.Adapter]: it writes the ask down, or returns the identical one that already waits.
func (a *RequestAdapter) Execute(ctx context.Context, req *ops.Request) (ops.Outcome, error) {
	n, err := a.parse(ctx, req)
	if err != nil {
		var ref *ops.Refusal
		if errors.As(err, &ref) {
			return ops.Outcome{Failed: true, Result: map[string]any{"error": ref.Why}}, nil
		}
		return ops.Outcome{}, err
	}
	v, dup, err := a.s.CreateRequest(ctx, n)
	if err != nil {
		var ref *ops.Refusal
		if errors.As(err, &ref) {
			return ops.Outcome{Failed: true, Result: map[string]any{"error": ref.Why}}, nil
		}
		return ops.Outcome{}, err
	}
	next := "your owner decides; wait with `chap key request --wait` or look with `chap key request --status " + v.ID + "`"
	return ops.Outcome{ExternalRef: v.ID, Result: map[string]any{
		"request_id": v.ID, "state": v.State, "deduplicated": dup,
		"expires_at": v.ExpiresAt, "next": next,
	}}, nil
}
