package keys

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/joshua-noel/chaperone/internal/connectors/untrusted"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/spec"
)

// OpIssue is the grant op. It is class high: every key is a card a person signs with Windows Hello, and the
// card says what the key can do, for whom, in which project and repositories, until when and how fast. The op
// is never in a key (ops.NeverInKey): a key cannot issue a key.
//
// It has three modes, told apart by their params:
//
//   - direct : an orchestrator (a script's owner) asks for a key for a holder. The orchestrator is the
//     key's owner and claims it.
//   - request : the owner of an agent answers the agent's key request, as asked or narrowed. Only the
//     console starts this one (the operator), the owner's own Hello signs it, and the agent claims the key.
//   - enrolment : the owner enrols an agent: a request-only key that holds no op and can only ask.
const OpIssue = "keys.issue"

// The params of keys.issue, by mode. The owner, the claimant and the project are never taken from a caller's
// say-so: in direct mode they are the caller's, in the other two the stored request or enrolment names them.
var (
	issueKeys   = paramSet("holder", "holder_kind", "ops", "units", "ttl_hours", "rate_per_hour")
	requestKeys = paramSet("request", "owner", "holder", "holder_kind", "ops", "units", "ttl_hours", "rate_per_hour")
	enrolKeys   = paramSet("enrolment", "owner", "holder", "holder_kind", "ops", "units", "ttl_hours", "rate_per_hour")
)

func paramSet(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
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
type IssueAdapter struct {
	cfg   IssueConfig
	rules ScopeRules
}

var _ ops.Adapter = (*IssueAdapter)(nil)

// NewIssueAdapter returns the keys.issue adapter.
func NewIssueAdapter(cfg IssueConfig) (*IssueAdapter, error) {
	if cfg.Store == nil || cfg.Catalog == nil || cfg.Enabled == nil || cfg.Project == nil || cfg.Approval == nil {
		return nil, errors.New("keys: the keys.issue adapter needs Store, Catalog, Enabled, Project and Approval")
	}
	return &IssueAdapter{cfg: cfg, rules: ScopeRules{Catalog: cfg.Catalog, Enabled: cfg.Enabled, Project: cfg.Project}}, nil
}

func refuse(why string, a ...any) error {
	return &ops.Refusal{Code: ops.CodePolicyRefused, Surface: "scope", Why: fmt.Sprintf(why, a...)}
}

func invalid(why string, a ...any) error {
	return &ops.Refusal{Code: ops.CodeParamsInvalid, Why: fmt.Sprintf(why, a...)}
}

// parsed is a Grant and what the card needs besides it.
type parsed struct {
	Grant
	asked *requestRow // request mode: what the agent asked for
	enrol *enrolRow   // enrolment mode
}

func has(p map[string]any, k string) bool { _, ok := p[k]; return ok }

// parse turns the request into a Grant (not yet approved). A failure is a *ops.Refusal and nothing is written.
func (a *IssueAdapter) parse(ctx context.Context, req *ops.Request) (parsed, error) {
	c := req.Caller
	if c == nil || c.Kind != ops.KindOrchestrator {
		return parsed{}, refuse("keys.issue is for the orchestrator token only: a key never issues a key, and a run never does")
	}
	switch {
	case has(req.Params, "enrolment"):
		return a.parseEnrol(ctx, req)
	case has(req.Params, "request"):
		return a.parseRequest(ctx, req)
	}
	if c.OrchID == ops.OperatorID {
		return parsed{}, invalid("at the console a key is made to answer an agent's request or an enrolment, and says which")
	}
	return a.parseDirect(ctx, req)
}

func unknownParam(p map[string]any, allowed map[string]bool, names string) error {
	for k := range p {
		if !allowed[k] {
			return invalid("unknown param %q; keys.issue takes %s", clipText(k, 40), names)
		}
	}
	return nil
}

// scopeParams reads the holder, lists, hours and rate every mode carries, and puts the lists in the one order
// the card, the hash and the row all use.
func scopeParams(req *ops.Request, g *Grant, emptyOps bool) error {
	var ok bool
	if g.Holder, ok = req.Params["holder"].(string); !ok {
		return invalid("param holder is required: the name of the script, person or agent that will hold the key")
	}
	if g.HolderKind, ok = req.Params["holder_kind"].(string); !ok {
		return invalid("param holder_kind is required: person or agent")
	}
	var err error
	if emptyOps {
		if l, isList := req.Params["ops"].([]any); !isList || len(l) != 0 {
			return invalid("param ops is an empty list: a request-only key holds no op")
		}
		if l, isList := req.Params["units"].([]any); !isList || len(l) != 0 {
			return invalid("param units is an empty list: a request-only key holds no op")
		}
	} else {
		if g.Ops, err = stringList(req.Params["ops"], "ops"); err != nil {
			return err
		}
		if v, has := req.Params["units"]; has && v != nil {
			if l, isList := v.([]any); !isList || len(l) > 0 { // an empty list is "no repository", as an absent one
				if g.Units, err = stringList(v, "units"); err != nil {
					return err
				}
			}
		}
	}
	if g.TTLHours, err = intParam(req.Params, "ttl_hours"); err != nil {
		return err
	}
	if g.Rate, err = intParam(req.Params, "rate_per_hour"); err != nil {
		return err
	}
	// What is signed is what is granted: every number is written on the card, and the lists are in the one
	// order the key will hold, so no default and no re-ordering hides between the card and the key.
	if g.TTLHours == 0 || g.Rate == 0 {
		return invalid("params ttl_hours and rate_per_hour are required: the card states both")
	}
	if !sameList(g.Ops, sortedUnique(g.Ops)) || !sameList(g.Units, sortedUnique(lowerAll(g.Units))) {
		return invalid("ops and units are listed in sorted order, in lower case, without repeats, so the card shows exactly what the key holds")
	}
	return nil
}

func (a *IssueAdapter) parseDirect(ctx context.Context, req *ops.Request) (parsed, error) {
	c := req.Caller
	if err := unknownParam(req.Params, issueKeys, "holder, holder_kind, ops, units, ttl_hours, rate_per_hour"); err != nil {
		return parsed{}, err
	}
	g := Grant{Project: req.Project, Owner: c.OrchID, Claimant: c.Key()}
	if err := scopeParams(req, &g, false); err != nil {
		return parsed{}, err
	}
	sensitive, err := a.rules.Check(req.Project, sortedUnique(g.Ops), g.Units)
	if err != nil {
		return parsed{}, err
	}
	g.Sensitive = sensitive
	if err := g.Shape(); err != nil {
		return parsed{}, refuse("%s", err)
	}
	// A key never reaches past its owner's own access: the orchestrator may hand out only what its own token holds.
	for _, op := range g.Ops {
		if !spec.OpAllowed(op, c.ScopeOps) {
			return parsed{}, refuse("%s is not an op your own token holds, so a key you build cannot hold it (a key never reaches past its owner)", clipText(op, 60))
		}
	}
	if g.HolderKind == HolderAgent {
		stopped, err := a.cfg.Store.AgentStopped(ctx, g.Owner, g.Holder)
		if err != nil {
			return parsed{}, err
		}
		if stopped {
			return parsed{}, refuse("%s is %s", g.Holder, StoppedWhy)
		}
	}
	return parsed{Grant: g}, nil
}

// parseRequest checks an owner's answer to an agent's request: the grant may only narrow what was asked.
func (a *IssueAdapter) parseRequest(ctx context.Context, req *ops.Request) (parsed, error) {
	c := req.Caller
	if c.OrchID != ops.OperatorID {
		return parsed{}, refuse("a key that answers an agent's request is made at the console, by the agent's owner")
	}
	if err := unknownParam(req.Params, requestKeys, "request, owner, holder, holder_kind, ops, units, ttl_hours, rate_per_hour"); err != nil {
		return parsed{}, err
	}
	id, _ := req.Params["request"].(string)
	if !requestIDRE.MatchString(id) {
		return parsed{}, invalid("param request is a key request id (kr-...)")
	}
	rq, err := a.cfg.Store.requestRow(ctx, a.cfg.Store.cfg.DB.SQL(), id)
	if errors.Is(err, ErrNotFound) {
		return parsed{}, invalid("there is no key request %s", id)
	}
	if err != nil {
		return parsed{}, err
	}
	if rq.Kind != reqNew {
		return parsed{}, refuse("%s asks to extend a key, which is answered with keys.extend", id)
	}
	if rq.State != reqPending || !a.cfg.Store.now().Before(unixTime(rq.Expires)) {
		return parsed{}, refuse("request %s is no longer waiting: it was withdrawn, answered, cancelled or it expired", id)
	}
	g := Grant{Project: req.Project, Owner: rq.Owner, Claimant: agentClaimant(rq.Owner, rq.Holder), KeyRequest: id}
	if err := scopeParams(req, &g, false); err != nil {
		return parsed{}, err
	}
	if owner, _ := req.Params["owner"].(string); owner != rq.Owner {
		return parsed{}, refuse("the request is from an agent of %s, not %s", ownerName(rq.Owner), clipText(ownerName(owner), 60))
	}
	switch {
	case g.Holder != rq.Holder || g.HolderKind != HolderAgent:
		return parsed{}, refuse("request %s is from agent %s", id, rq.Holder)
	case req.Project != rq.Project:
		return parsed{}, refuse("request %s is for project %s", id, rq.Project)
	}
	// The owner can only narrow, never widen.
	switch {
	case !subset(g.Ops, rq.Ops):
		return parsed{}, refuse("a grant can only narrow what was asked: %s was not asked for", strings.Join(missing(g.Ops, rq.Ops), ", "))
	case !subset(g.Units, rq.Units):
		return parsed{}, refuse("a grant can only narrow what was asked: %s was not asked for", strings.Join(missing(g.Units, rq.Units), ", "))
	case g.TTLHours > rq.TTLHours:
		return parsed{}, refuse("a grant can only narrow what was asked: %d hours is more than the %d asked for", g.TTLHours, rq.TTLHours)
	case g.Rate > rq.Rate:
		return parsed{}, refuse("a grant can only narrow what was asked: %d calls an hour is more than the %d asked for", g.Rate, rq.Rate)
	}
	sensitive, err := a.rules.Check(req.Project, sortedUnique(g.Ops), g.Units)
	if err != nil {
		return parsed{}, err
	}
	g.Sensitive = sensitive
	g.Kind = GrantSelf
	if err := g.Shape(); err != nil {
		return parsed{}, refuse("%s", err)
	}
	if err := a.cfg.Store.cfg.Access.Within(ctx, g.Owner, g.Project, g.Ops, g.Units); err != nil {
		return parsed{}, accessRefusal(err)
	}
	if stopped, err := a.cfg.Store.AgentStopped(ctx, g.Owner, g.Holder); err != nil {
		return parsed{}, err
	} else if stopped {
		return parsed{}, refuse("%s is %s", g.Holder, StoppedWhy)
	}
	return parsed{Grant: g, asked: rq}, nil
}

// accessRefusal turns the Access rule's answer into a refusal; a fault stays a fault.
func accessRefusal(err error) error {
	var re *RuleError
	if errors.As(err, &re) {
		return refuse("%s", re.Why)
	}
	return err
}

func agentClaimant(owner, holder string) string { return "agent:" + owner + "/" + holder }

// parseEnrol checks the enrolment of an agent: a request-only key, no op, 30 days, a low rate.
func (a *IssueAdapter) parseEnrol(ctx context.Context, req *ops.Request) (parsed, error) {
	c := req.Caller
	if c.OrchID != ops.OperatorID {
		return parsed{}, refuse("an agent is enrolled at the console, by its owner")
	}
	if err := unknownParam(req.Params, enrolKeys, "enrolment, owner, holder, holder_kind, ops, units, ttl_hours, rate_per_hour"); err != nil {
		return parsed{}, err
	}
	id, _ := req.Params["enrolment"].(string)
	if !enrolIDRE.MatchString(id) {
		return parsed{}, invalid("param enrolment is an enrolment id (en-...)")
	}
	en, err := a.cfg.Store.enrolRow(ctx, a.cfg.Store.cfg.DB.SQL(), id)
	if errors.Is(err, ErrNotFound) {
		return parsed{}, invalid("there is no enrolment %s", id)
	}
	if err != nil {
		return parsed{}, err
	}
	if en.State != enrolPending || !a.cfg.Store.now().Before(unixTime(en.Expires)) {
		return parsed{}, refuse("enrolment %s is no longer waiting: it expired or was already answered", id)
	}
	owner, _ := req.Params["owner"].(string)
	if !personRE.MatchString(owner) {
		return parsed{}, invalid("param owner is the person who owns the agent")
	}
	g := Grant{Project: req.Project, Owner: owner, Claimant: "enrol:" + id, Enrolment: id, Kind: GrantBootstrap, Sensitive: false}
	if err := scopeParams(req, &g, true); err != nil {
		return parsed{}, err
	}
	switch {
	case g.Holder != en.Label || g.HolderKind != HolderAgent:
		return parsed{}, refuse("enrolment %s is for the agent %s", id, en.Label)
	case req.Project != en.Project:
		return parsed{}, refuse("enrolment %s is for project %s", id, en.Project)
	case g.TTLHours != BootstrapHours || g.Rate != BootstrapRate:
		return parsed{}, refuse("a request-only key lasts %d hours and makes at most %d calls an hour", BootstrapHours, BootstrapRate)
	}
	if err := g.Shape(); err != nil {
		return parsed{}, refuse("%s", err)
	}
	if stopped, err := a.cfg.Store.AgentStopped(ctx, g.Owner, g.Holder); err != nil {
		return parsed{}, err
	} else if stopped {
		return parsed{}, refuse("%s is %s", g.Holder, StoppedWhy)
	}
	return parsed{Grant: g, enrol: en}, nil
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

// Check implements [ops.Adapter]. It writes nothing: the card is made from what it returns, and what it returns
// is what the person reads and signs.
func (a *IssueAdapter) Check(ctx context.Context, req *ops.Request) (ops.CheckResult, error) {
	p, err := a.parse(ctx, req)
	if err != nil {
		return ops.CheckResult{}, err
	}
	g := p.Grant
	var lines []string
	switch {
	case p.enrol != nil:
		lines = append(lines,
			fmt.Sprintf("Enrol the agent %q for %s in project %s.", g.Holder, ownerName(g.Owner), g.Project),
			"It gets a request-only key: no access at all. All it can do is ask its owner for a key; every ask is a card you answer.",
			fmt.Sprintf("The key lasts %s and makes at most %d calls an hour. It is handed to the agent once, by the code it holds, and is never shown.", hours(g.TTLHours), g.Rate),
			"This is your own agent: you alone decide, with your own Windows Hello. Nobody else is asked.")
	default:
		who := "acting for " + g.Owner
		if p.asked != nil {
			who = "acting for " + ownerName(g.Owner)
		}
		lines = append(lines, fmt.Sprintf("This key lets %s %q, %s, work in project %s:", g.HolderKind, g.Holder, who, g.Project))
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
			fmt.Sprintf("It lasts %s from the moment this card is approved, and makes at most %d calls an hour.", hours(g.TTLHours), g.Rate))
		if p.asked != nil {
			lines = append(lines, "", fmt.Sprintf("The agent %s asked for (request %s):", g.Holder, p.asked.ID))
			lines = append(lines, askedLines(p.asked)...)
			lines = append(lines, removedLines(p.asked, g.Ops, g.Units, g.TTLHours, g.Rate)...)
			lines = append(lines, "", "This is your own agent: you alone decide, with your own Windows Hello. Nobody else is asked.")
		}
		lines = append(lines,
			"It cannot approve anything, issue or revoke other keys, or do a critical action. A risky action still asks for a card each time. The key is handed only to the caller that asked for it, once, and is never shown.")
	}
	detail := fmt.Sprintf("%s %s of %s; ops %s; units %s; %dh; %d/h; sensitive=%t; kind=%s",
		g.HolderKind, g.Holder, g.Owner, strings.Join(g.Ops, ","), strings.Join(g.Units, ","), g.TTLHours, g.Rate, g.Sensitive, g.Kind)
	return ops.CheckResult{
		Checks:   []ops.Check{{Name: "key.scope", Passed: true, Detail: clipText(detail, 400)}},
		Evidence: []ops.Evidence{{Name: "What this key can do", Text: strings.Join(lines, "\n")}},
	}, nil
}

// askedLines is what the agent asked for, with the reason it wrote. The reason is the agent's text (it may be
// anything), so it is quoted and clipped, and the card marks the whole evidence as untrusted text.
func askedLines(rq *requestRow) []string {
	out := []string{
		"  ops: " + strings.Join(rq.Ops, ", "),
		fmt.Sprintf("  for %s, at most %d calls an hour", hours(rq.TTLHours), rq.Rate),
	}
	if len(rq.Units) > 0 {
		out = append(out, "  repositories: "+strings.Join(rq.Units, ", "))
	}
	if rq.NeededToday {
		out = append(out, "  the agent marked it needed today")
	}
	return append(out, fmt.Sprintf("  the agent wrote: %q", plainText(rq.Reason, 300)))
}

// removedLines says what the grant takes away from the ask, so the card shows both side by side.
func removedLines(rq *requestRow, ops, units []string, ttl, rate int) []string {
	var out []string
	if m := missing(rq.Ops, ops); len(m) > 0 {
		out = append(out, "  ops removed: "+strings.Join(m, ", "))
	}
	if m := missing(rq.Units, units); len(m) > 0 {
		out = append(out, "  repositories removed: "+strings.Join(m, ", "))
	}
	if ttl < rq.TTLHours {
		out = append(out, fmt.Sprintf("  shortened from %s to %s", hours(rq.TTLHours), hours(ttl)))
	}
	if rate < rq.Rate {
		out = append(out, fmt.Sprintf("  rate lowered from %d to %d calls an hour", rq.Rate, rate))
	}
	if len(out) == 0 {
		return []string{"Nothing was removed: it is granted as asked."}
	}
	return append([]string{"Removed from what was asked:"}, out...)
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

// plainText makes agent-written text one safe line, with the shared cleaner every connector uses (untrusted.Line):
// control characters, bidirectional controls and zero-width characters become spaces, and a cut stays on a rune.
func plainText(s string, n int) string {
	s = strings.TrimSpace(untrusted.Line(s))
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "..."
}

// Execute implements [ops.Adapter]: it writes the key's row. No token is made here; the claim makes it. The
// result names the key and says how to claim it, and holds no secret.
func (a *IssueAdapter) Execute(ctx context.Context, req *ops.Request) (ops.Outcome, error) {
	p, err := a.parse(ctx, req)
	if err != nil {
		var ref *ops.Refusal
		if errors.As(err, &ref) {
			return ops.Outcome{Failed: true, Result: map[string]any{"error": ref.Why}}, nil
		}
		return ops.Outcome{}, err
	}
	g := p.Grant
	g.RequestID = req.ID
	if g.ApprovalID, g.GrantedBy, err = a.cfg.Approval(ctx, req.ID); err != nil {
		return ops.Outcome{}, err
	}
	if g.Kind == GrantSelf || g.Kind == GrantBootstrap {
		// Self-delegation : the owner's own Hello, and nobody else's. A card signed by another person is
		// refused here, after the fact: the card is spent and the owner answers again.
		if ownerName(g.Owner) != g.GrantedBy {
			return ops.Outcome{Failed: true, Result: map[string]any{
				"error": fmt.Sprintf("this key is for %s's agent, so only %s signs it; the card was signed by %s", ownerName(g.Owner), ownerName(g.Owner), clipText(g.GrantedBy, 60)),
			}}, nil
		}
	}
	info, err := a.cfg.Store.Issue(ctx, g)
	if err != nil {
		var re *RuleError
		if errors.As(err, &re) {
			return ops.Outcome{Failed: true, Result: map[string]any{"error": re.Why}}, nil
		}
		return ops.Outcome{}, err
	}
	next := "claim it once, before the deadline, with `chap key claim " + info.ID + "`"
	if g.Kind == GrantSelf || g.Kind == GrantBootstrap {
		next = "the agent claims it once, before the deadline; nobody else can"
	}
	return ops.Outcome{ExternalRef: info.ID, Result: map[string]any{
		"key_id":         info.ID,
		"expires_at":     info.ExpiresAt,
		"claim_deadline": info.ClaimDeadline,
		"next":           next,
	}}, nil
}
