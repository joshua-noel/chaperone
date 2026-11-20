package keys

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
)

// OpIssue is the grant op. It is class high: every key is a card the operator
// signs with Windows Hello, and the card says what the key can do, for whom, in
// which project and repositories, until when and how fast. The op is never in a
// key (ops.NeverInKey): a key cannot issue a key.
const OpIssue = "keys.issue"

// issueKeys are the params of keys.issue. The owner, the claimant and the
// project are never params: they are the caller's.
var issueKeys = map[string]bool{
	"holder": true, "holder_kind": true, "ops": true, "units": true, "ttl_hours": true, "rate_per_hour": true,
}

// ApprovalOf finds the approval that released a keys.issue op: its id and the
// spec id of the approver who signed it.
type ApprovalOf func(ctx context.Context, requestID string) (approvalID, approver string, err error)

// IssueConfig configures the keys.issue adapter.
type IssueConfig struct {
	Store   *Store
	Catalog interface {
		Lookup(op string) (policy.Entry, bool)
	}
	// Enabled reports whether the policy turns op on for project.
	Enabled func(project, op string) bool
	// Project returns the project's pull-request repository (its `pr:` block).
	Project  func(project string) (ops.PRProject, bool)
	Approval ApprovalOf
}

// IssueAdapter is the keys.issue adapter.
type IssueAdapter struct{ cfg IssueConfig }

var _ ops.Adapter = (*IssueAdapter)(nil)

// NewIssueAdapter returns the keys.issue adapter.
func NewIssueAdapter(cfg IssueConfig) (*IssueAdapter, error) {
	if cfg.Store == nil || cfg.Catalog == nil || cfg.Enabled == nil || cfg.Project == nil || cfg.Approval == nil {
		return nil, errors.New("keys: the keys.issue adapter needs Store, Catalog, Enabled, Project and Approval")
	}
	return &IssueAdapter{cfg: cfg}, nil
}

func refuse(why string, a ...any) error {
	return &ops.Refusal{Code: ops.CodePolicyRefused, Surface: "scope", Why: fmt.Sprintf(why, a...)}
}

func invalid(why string, a ...any) error {
	return &ops.Refusal{Code: ops.CodeParamsInvalid, Why: fmt.Sprintf(why, a...)}
}

// parse turns the request into a Grant (not yet approved). A failure is a
// *ops.Refusal and nothing is written.
func (a *IssueAdapter) parse(ctx context.Context, req *ops.Request) (Grant, error) {
	c := req.Caller
	if c == nil || c.Kind != ops.KindOrchestrator {
		return Grant{}, refuse("keys.issue is for the orchestrator token only: a key never issues a key, and a run never does")
	}
	for k := range req.Params {
		if !issueKeys[k] {
			return Grant{}, invalid("unknown param %q; keys.issue takes holder, holder_kind, ops, units, ttl_hours, rate_per_hour", clipText(k, 40))
		}
	}
	g := Grant{Project: req.Project, Owner: c.OrchID, Claimant: c.Key()}
	var ok bool
	if g.Holder, ok = req.Params["holder"].(string); !ok {
		return Grant{}, invalid("param holder is required: the name of the script, person or agent that will hold the key")
	}
	if g.HolderKind, ok = req.Params["holder_kind"].(string); !ok {
		return Grant{}, invalid("param holder_kind is required: person or agent")
	}
	var err error
	if g.Ops, err = stringList(req.Params["ops"], "ops"); err != nil {
		return Grant{}, err
	}
	if v, has := req.Params["units"]; has && v != nil {
		if g.Units, err = stringList(req.Params["units"], "units"); err != nil {
			return Grant{}, err
		}
	}
	if g.TTLHours, err = intParam(req.Params, "ttl_hours"); err != nil {
		return Grant{}, err
	}
	if g.Rate, err = intParam(req.Params, "rate_per_hour"); err != nil {
		return Grant{}, err
	}
	// What is signed is what is granted: every number is written on the card, and the lists are in the one
	// order the key will hold, so no default and no re-ordering hides between the card and the key.
	if g.TTLHours == 0 || g.Rate == 0 {
		return Grant{}, invalid("params ttl_hours and rate_per_hour are required: the card states both")
	}
	if !sameList(g.Ops, sortedUnique(g.Ops)) || !sameList(g.Units, sortedUnique(lowerAll(g.Units))) {
		return Grant{}, invalid("ops and units are listed in sorted order, in lower case, without repeats, so the card shows exactly what the key holds")
	}

	// R1: what a key may ever hold. The ceiling, the never list, critical ops, and
	// only ops the policy turns on for this project.
	for _, op := range sortedUnique(g.Ops) {
		if ops.NeverInKey(op) {
			return Grant{}, refuse("%s can never be in a key: a key cannot decide, issue or administer anything", clipText(op, 60))
		}
		entry, known := a.cfg.Catalog.Lookup(op)
		if !known {
			return Grant{}, invalid("unknown op %q", clipText(op, 60))
		}
		if entry.Class == policy.ClassCritical {
			return Grant{}, refuse("%s is critical, and a critical op is never in a key", op)
		}
		if _, has := ops.KeyUnitKind(op); !has {
			return Grant{}, refuse("%s names no unit a key can be bound to (a repository or the project), so it cannot be in a key yet", op)
		}
		if !a.cfg.Enabled(req.Project, op) {
			return Grant{}, refuse("%s is disabled by policy for %s, so a key cannot hold it", op, req.Project)
		}
		if entry.Class != policy.ClassRoutine {
			g.Sensitive = true // it asks for a card every time: the key is sensitive, and capped at 7 days
		}
	}
	if err := g.Shape(); err != nil {
		return Grant{}, refuse("%s", err)
	}

	// Q14: a key is tied to a unit. A repository op needs the repositories; a
	// repository named for no op is a mistake.
	needsRepo := false
	for _, op := range g.Ops {
		if k, _ := ops.KeyUnitKind(op); k == ops.UnitRepo {
			needsRepo = true
		}
	}
	switch {
	case needsRepo && len(g.Units) == 0:
		return Grant{}, refuse("a key with pull-request ops names the repository it covers (units)")
	case !needsRepo && len(g.Units) > 0:
		return Grant{}, refuse("units name repositories, and none of the ops in this key is bound to one")
	}
	if needsRepo {
		pr, ok := a.cfg.Project(req.Project)
		if !ok || pr.Repo == "" {
			return Grant{}, refuse("project %s has no pull request settings (a pr: block), so no repository can be named", req.Project)
		}
		for _, u := range g.Units {
			if !strings.EqualFold(u, pr.Repo) {
				return Grant{}, refuse("project %s is %s, so a key for it cannot cover %s", req.Project, pr.Repo, clipText(u, 80))
			}
		}
	}

	if g.HolderKind == HolderAgent {
		stopped, err := a.cfg.Store.AgentStopped(ctx, g.Owner, g.Holder)
		if err != nil {
			return Grant{}, err
		}
		if stopped {
			return Grant{}, refuse("%s is %s", g.Holder, StoppedWhy)
		}
	}
	return g, nil
}

func sameList(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func stringList(v any, name string) ([]string, error) {
	list, ok := v.([]any)
	if !ok || len(list) == 0 {
		return nil, invalid("param %s is required: a list of names", name)
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		s, ok := e.(string)
		if !ok || s == "" {
			return nil, invalid("param %s holds only names", name)
		}
		out = append(out, s)
	}
	return out, nil
}

func intParam(p map[string]any, key string) (int, error) {
	v, ok := p[key]
	if !ok {
		return 0, nil
	}
	if n, ok := v.(float64); ok && n >= 1 && n <= 1<<20 && n == float64(int(n)) {
		return int(n), nil
	}
	return 0, invalid("param %s must be a positive whole number", key)
}

// Check implements [ops.Adapter]. It writes nothing: the card is made from what
// it returns, and what it returns is what the operator reads and signs.
func (a *IssueAdapter) Check(ctx context.Context, req *ops.Request) (ops.CheckResult, error) {
	g, err := a.parse(ctx, req)
	if err != nil {
		return ops.CheckResult{}, err
	}
	var lines []string
	lines = append(lines, fmt.Sprintf("This key lets %s %q, acting for %s, work in project %s:", g.HolderKind, g.Holder, g.Owner, g.Project))
	for _, op := range g.Ops {
		entry, _ := a.cfg.Catalog.Lookup(op)
		line := "  - " + op + ": " + entry.Summary
		if entry.Class != policy.ClassRoutine {
			line += " (a risky op: every use of the key still raises its own card)"
		}
		lines = append(lines, line)
	}
	if len(g.Units) > 0 {
		lines = append(lines, "Repositories: "+strings.Join(g.Units, ", "))
	}
	lines = append(lines,
		fmt.Sprintf("It lasts %s from the moment this card is approved, and makes at most %d calls an hour.", hours(g.TTLHours), g.Rate),
		"It cannot approve anything, issue or revoke other keys, or do a critical action. A risky action still asks for a card each time. The key is handed only to the caller that asked for it, once, and is never shown.")
	detail := fmt.Sprintf("%s %s of %s; ops %s; units %s; %dh; %d/h; sensitive=%t",
		g.HolderKind, g.Holder, g.Owner, strings.Join(g.Ops, ","), strings.Join(g.Units, ","), g.TTLHours, g.Rate, g.Sensitive)
	return ops.CheckResult{
		Checks:   []ops.Check{{Name: "key.scope", Passed: true, Detail: clipText(detail, 400)}},
		Evidence: []ops.Evidence{{Name: "What this key can do", Text: strings.Join(lines, "\n")}},
	}, nil
}

func hours(h int) string {
	if h%24 == 0 {
		d := h / 24
		if d == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", d)
	}
	if h == 1 {
		return "1 hour"
	}
	return fmt.Sprintf("%d hours", h)
}

// Execute implements [ops.Adapter]: it writes the key's row. No token is made
// here; the claim makes it. The result names the key and says how to claim it,
// and holds no secret.
func (a *IssueAdapter) Execute(ctx context.Context, req *ops.Request) (ops.Outcome, error) {
	g, err := a.parse(ctx, req)
	if err != nil {
		var ref *ops.Refusal
		if errors.As(err, &ref) {
			return ops.Outcome{Failed: true, Result: map[string]any{"error": ref.Why}}, nil
		}
		return ops.Outcome{}, err
	}
	g.RequestID = req.ID
	if g.ApprovalID, g.GrantedBy, err = a.cfg.Approval(ctx, req.ID); err != nil {
		return ops.Outcome{}, err
	}
	info, err := a.cfg.Store.Issue(ctx, g)
	if err != nil {
		var re *RuleError
		if errors.As(err, &re) {
			return ops.Outcome{Failed: true, Result: map[string]any{"error": re.Why}}, nil
		}
		return ops.Outcome{}, err
	}
	return ops.Outcome{ExternalRef: info.ID, Result: map[string]any{
		"key_id":         info.ID,
		"expires_at":     info.ExpiresAt,
		"claim_deadline": info.ClaimDeadline,
		"next":           "claim it once, before the deadline, with `chap key claim " + info.ID + "`",
	}}, nil
}
