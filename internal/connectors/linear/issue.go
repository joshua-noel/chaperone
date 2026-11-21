package linear

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/connectors/linear/linearspec"
	"github.com/joshua-noel/chaperone/internal/connectors/untrusted"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
)

// The generic issue ops: `issue.get`, `issue.list`, `issue.comment`,
// `issue.label`, `issue.move` and `issue.link` on Linear, for the orchestrator
// token (a custom key cannot hold an `issue.*` op: internal/ops/keyceiling.go). They sit beside the operator-board
// intake ops and are fenced away from it:
//
//   - They work only in the project's `linear.issues.team` and, for a write,
//     only on an issue that carries `linear.issues.label` now.
//   - `intake_label_excluded`: an issue in the intake team (`linear.team`) or
//     carrying the intake label (`linear.label`) is never read, listed,
//     commented on, labelled, moved or linked by these ops. The check is in
//     code, runs on every read and write (Check and again in Execute), fails
//     closed when an issue's labels do not fit one page, and no field of the
//     `linear.issues` block can lift it; the policy loader refuses a block
//     that names the intake team or label.
//   - The ops are off unless the project's policy file has a `linear.issues`
//     block. `issue.comment` shares its name with the GitHub op that the error
//     watcher uses and so is on in the baseline; the block is what keeps it off
//     for Linear.
//   - Opening and editing an issue (`issue.open`, `issue.update`) are not
//     built.
//
// The facts of each op (name, class, params and their bounds) are declared in
// [linearspec]. Who may ask is the op pipeline's business (the token's ops, the
// profile ceiling); no run profile lists these ops today.

// The generic issue op kinds.
const (
	OpIssueGet     = linearspec.NameIssueGet
	OpIssueList    = linearspec.NameIssueList
	OpIssueComment = linearspec.NameIssueComment
	OpIssueLabel   = linearspec.NameIssueLabel
	OpIssueMove    = linearspec.NameIssueMove
	OpIssueLink    = linearspec.NameIssueLink
)

// IssueOps lists the generic issue op kinds of the connector.
var IssueOps = []string{OpIssueGet, OpIssueList, OpIssueComment, OpIssueLabel, OpIssueMove, OpIssueLink}

// IssueTeamRef is the target ref of issue.list that means "the team of the
// project's linear.issues block", for a caller that does not know the key.
const IssueTeamRef = linearspec.IssueTeamRef

var (
	stateTypeRE = regexp.MustCompile(linearspec.StateTypePattern)
	cursorRE    = regexp.MustCompile(linearspec.CursorPattern)
	// A mention in Linear's markdown: "@name" at a word start, or a link to a
	// person's profile page.
	mentionRE = regexp.MustCompile(`(?:^|[\s(\[])@[A-Za-z0-9_][A-Za-z0-9_.-]*|https://linear\.app/[^/\s)]+/profiles/`)
)

// issueAdapters builds the generic issue adapters.
func issueAdapters(b base) map[string]ops.Adapter {
	return map[string]ops.Adapter{
		OpIssueGet:     &issueGetAdapter{base: b},
		OpIssueList:    &issueListAdapter{base: b},
		OpIssueComment: &issueCommentAdapter{base: b},
		OpIssueLabel:   &issueLabelAdapter{base: b},
		OpIssueMove:    &issueMoveAdapter{base: b},
		OpIssueLink:    &issueLinkAdapter{base: b},
	}
}

// issuePolicy checks the request's target adapter and returns the project's
// `linear:` block and its `issues` block.
func (b base) issuePolicy(r *ops.Request) (*policy.Linear, *policy.LinearIssues, error) {
	if r.Caller == nil {
		return nil, nil, policyRefused("%s has no verified caller", r.Op)
	}
	if r.Target.Adapter != AdapterName {
		return nil, nil, paramsInvalid("target.adapter must be %s", AdapterName)
	}
	pol := b.cfg.Policy(r.Project)
	if pol == nil {
		return nil, nil, policyRefused("%s is refused for project %s: its policy file has no valid linear: block", r.Op, clip(r.Project, 60))
	}
	if pol.IssuesInvalid != nil {
		return nil, nil, policyRefused("%s is refused for project %s: %s", r.Op, clip(r.Project, 60), clip(pol.IssuesInvalid.Error(), 900))
	}
	if pol.Issues == nil {
		return nil, nil, policyRefused("%s is refused for project %s: its policy file has no linear.issues block", r.Op, clip(r.Project, 60))
	}
	return pol, pol.Issues, nil
}

// intakeRefused is the refusal of the `intake_label_excluded` condition.
func intakeRefused(format string, a ...any) error {
	return policyRefused("intake_label_excluded: "+format, a...)
}

// issueIdent checks a target that names an issue and returns its identifier.
func issueIdent(r *ops.Request, pol *policy.Linear, iss *policy.LinearIssues) (string, error) {
	m := identRefRE.FindStringSubmatch(r.Target.Ref)
	if m == nil {
		return "", paramsInvalid("target.ref must be an issue identifier such as %s-12", iss.Team)
	}
	switch m[1] {
	case pol.Team:
		return "", intakeRefused("issue %s is in team %s, the operator board; the issue ops never work there", r.Target.Ref, m[1])
	case iss.Team:
		return r.Target.Ref, nil
	}
	return "", scopeRefused("issue %s is in team %s; project %s allows team %s only", r.Target.Ref, m[1], clip(r.Project, 60), iss.Team)
}

func hasFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// issueFence applies the policy to an issue as Linear describes it: the
// operator-board exclusion first, then the team, then (for a write) the
// provenance label. A *ops.Refusal is a "no".
func issueFence(pol *policy.Linear, iss *policy.LinearIssues, ident, teamKey, teamName string, labels []string, labelsMore, write bool) error {
	switch {
	case pol.IntakeItem(teamKey, labels):
		return intakeRefused("issue %s is an operator-board item (the intake team or label); the issue ops never read or write it", ident)
	case labelsMore:
		return intakeRefused("issue %s has more labels than one page shows, so it cannot be shown free of the operator-board label", ident)
	case teamKey != iss.Team:
		return scopeRefused("issue %s is not in team %s: the identifier is an old one; nothing was done", ident, iss.Team)
	case strings.EqualFold(strings.TrimSpace(teamName), "engineering"):
		return scopeRefused("issue %s is in the Engineering team, which the issue ops never use", ident)
	case write && !hasFold(labels, iss.Label):
		return policyRefused("label_present_now: issue %s does not carry the label %q now: the issue ops write only to items labelled so", ident, iss.Label)
	}
	return nil
}

// guard reads the issue and applies the fence. It is the one function every
// issue write goes through, in Check and again in Execute.
func (b base) issueGuard(ctx context.Context, pol *policy.Linear, iss *policy.LinearIssues, ident string) (*IssueGuardRead, error) {
	g, err := b.cfg.Client.ReadIssueGuard(ctx, ident)
	if errors.Is(err, ErrNotFound) {
		return nil, paramsInvalid("Linear has no issue %s that the app can see", ident)
	}
	if err != nil {
		return nil, credentialRefusal(err)
	}
	if err := issueFence(pol, iss, ident, g.TeamKey, g.TeamName, g.LabelNames(), g.LabelsMore, true); err != nil {
		return nil, err
	}
	return g, nil
}

func issueChecks(g *IssueGuardRead, iss *policy.LinearIssues) []ops.Check {
	return []ops.Check{
		{Name: "team_in_scope", Passed: true, Detail: g.TeamKey},
		{Name: "intake_label_excluded", Passed: true, Detail: "not an operator-board item"},
		{Name: "label_present_now", Passed: true, Detail: iss.Label},
		{Name: "issue", Passed: true, Detail: g.Identifier + " is " + untrusted.Clean(g.State.Name, maxName)},
	}
}

// ---- issue.get -------------------------------------------------------------

type issueGetAdapter struct{ base }

var _ ops.Adapter = (*issueGetAdapter)(nil)

func (a *issueGetAdapter) parse(r *ops.Request) (*policy.Linear, *policy.LinearIssues, string, error) {
	pol, iss, err := a.issuePolicy(r)
	if err != nil {
		return nil, nil, "", err
	}
	ident, err := issueIdent(r, pol, iss)
	if err != nil {
		return nil, nil, "", err
	}
	return pol, iss, ident, onlyParams(r.Params, linearspec.IssueGet.ParamNames()...)
}

// Check validates the request; it reads nothing.
func (a *issueGetAdapter) Check(_ context.Context, r *ops.Request) (ops.CheckResult, error) {
	_, iss, _, err := a.parse(r)
	if err != nil {
		return ops.CheckResult{}, err
	}
	return ops.CheckResult{Checks: []ops.Check{{Name: "team_in_scope", Passed: true, Detail: iss.Team}}}, nil
}

// Execute reads the issue and applies the fence before any of its text is
// returned. A read has no effect, so every failure of it is `failed`.
func (a *issueGetAdapter) Execute(ctx context.Context, r *ops.Request) (ops.Outcome, error) {
	pol, iss, ident, err := a.parse(r)
	if err != nil {
		return failed(err, nil), nil
	}
	v, err := a.cfg.Client.GetIssue(ctx, ident)
	if errors.Is(err, ErrNotFound) {
		return failed(paramsInvalid("Linear has no issue %s that the app can see", ident), nil), nil
	}
	if err != nil {
		return failed(credentialRefusal(err), nil), nil
	}
	if err := issueFence(pol, iss, ident, v.TeamKey, v.TeamName, v.Labels, v.LabelsMore, false); err != nil {
		return failed(err, nil), nil
	}
	return ops.Outcome{ExternalRef: refOr(v.URL, ""), Result: map[string]any{
		"team": iss.Team, "untrusted_text": true, "issue": a.itemResult(v.Item),
	}}, nil
}

// ---- issue.list ------------------------------------------------------------

type issueListAdapter struct{ base }

var _ ops.Adapter = (*issueListAdapter)(nil)

type issueListParams struct {
	state, label, cursor string
}

func (a *issueListAdapter) parse(r *ops.Request) (*policy.Linear, *policy.LinearIssues, issueListParams, error) {
	var p issueListParams
	pol, iss, err := a.issuePolicy(r)
	if err != nil {
		return nil, nil, p, err
	}
	switch ref := r.Target.Ref; {
	case ref == pol.Team:
		return nil, nil, p, intakeRefused("team %s is the operator board; the issue ops never work there", ref)
	case ref == IssueTeamRef || ref == iss.Team:
	case teamRefRE.MatchString(ref):
		return nil, nil, p, scopeRefused("team %s is not the issue team of project %s (%s)", ref, clip(r.Project, 60), iss.Team)
	default:
		return nil, nil, p, paramsInvalid("target.ref must be the team key, for example %s, or %s", iss.Team, IssueTeamRef)
	}
	if err := onlyParams(r.Params, linearspec.IssueList.ParamNames()...); err != nil {
		return nil, nil, p, err
	}
	for _, f := range []struct {
		key string
		dst *string
	}{{"state", &p.state}, {"label", &p.label}, {"cursor", &p.cursor}} {
		if _, ok := r.Params[f.key]; !ok {
			continue
		}
		if *f.dst, err = paramString(r.Params, f.key); err != nil {
			return nil, nil, p, err
		}
	}
	if p.state != "" && !stateTypeRE.MatchString(p.state) {
		return nil, nil, p, paramsInvalid("state must be one of triage, backlog, unstarted, started, completed, canceled")
	}
	if p.label != "" {
		if err := checkText("label", p.label, policy.LinearMaxLabel); err != nil {
			return nil, nil, p, err
		}
		if strings.EqualFold(p.label, pol.Label) {
			return nil, nil, p, intakeRefused("label %q is the operator-board label; the issue ops never list it", clip(p.label, 60))
		}
	}
	if p.cursor != "" && !cursorRE.MatchString(p.cursor) {
		return nil, nil, p, paramsInvalid("cursor is not a cursor chapd returned")
	}
	return pol, iss, p, nil
}

// Check validates the request; it reads nothing.
func (a *issueListAdapter) Check(_ context.Context, r *ops.Request) (ops.CheckResult, error) {
	_, iss, _, err := a.parse(r)
	if err != nil {
		return ops.CheckResult{}, err
	}
	return ops.CheckResult{Checks: []ops.Check{{Name: "team_in_scope", Passed: true, Detail: iss.Team}}}, nil
}

// Execute reads one page. An item that is on the operator board, in another
// team or has too many labels to judge is left out of the page, whatever Linear
// was asked: a filter Linear applied wrongly must not put such an item in a
// result.
func (a *issueListAdapter) Execute(ctx context.Context, r *ops.Request) (ops.Outcome, error) {
	pol, iss, p, err := a.parse(r)
	if err != nil {
		return failed(err, nil), nil
	}
	page, err := a.cfg.Client.ListIssues(ctx, iss.Team, p.state, p.label, p.cursor)
	if err != nil {
		return failed(credentialRefusal(err), nil), nil
	}
	items := make([]any, 0, len(page.Issues))
	for _, v := range page.Issues {
		if issueFence(pol, iss, v.Identifier, v.TeamKey, v.TeamName, v.Labels, v.LabelsMore, false) != nil {
			continue
		}
		items = append(items, a.itemResult(v.Item))
	}
	res := map[string]any{
		"team": iss.Team, "untrusted_text": true, "count": len(items), "items": items,
		"fetched_at": a.cfg.now().UTC().Format(time.RFC3339),
	}
	// The cursor is Linear's text. It is returned only in the shape this adapter
	// accepts back, so it is the same text a caller must send again; any other
	// cursor is withheld, and the result says so.
	if page.Next != "" {
		if cursorRE.MatchString(page.Next) {
			res["next_cursor"] = page.Next
		} else {
			res["cursor_withheld"] = true
		}
	}
	return ops.Outcome{Result: res}, nil
}

// ---- issue.comment ---------------------------------------------------------

type issueCommentAdapter struct{ base }

var _ ops.Adapter = (*issueCommentAdapter)(nil)

type issueCommentParams struct {
	pol   *policy.Linear
	iss   *policy.LinearIssues
	ident string
	body  string
}

func (a *issueCommentAdapter) parse(r *ops.Request) (issueCommentParams, error) {
	var p issueCommentParams
	pol, iss, err := a.issuePolicy(r)
	if err != nil {
		return p, err
	}
	if !iss.Comment {
		return p, policyRefused("comment_enabled: issue.comment on Linear is refused for project %s: its linear.issues block does not set comment: true", clip(r.Project, 60))
	}
	if p.ident, err = issueIdent(r, pol, iss); err != nil {
		return p, err
	}
	if err := onlyParams(r.Params, linearspec.IssueComment.ParamNames()...); err != nil {
		return p, err
	}
	if p.body, err = paramString(r.Params, "body"); err != nil {
		return p, err
	}
	if err := checkText("body", p.body, MaxCommentBytes); err != nil {
		return p, err
	}
	if err := guardBoard(pol, "a comment", p.body); err != nil {
		return p, err
	}
	if n := len(mentionRE.FindAllString(p.body, -1)); n > iss.MaxMentions {
		return p, policyRefused("no_broadcast_mentions: the comment mentions %d people; the policy allows %d", n, iss.MaxMentions)
	}
	if err := a.scan("body", p.body); err != nil {
		return p, err
	}
	p.pol, p.iss = pol, iss
	return p, nil
}

// Check validates the request and reads the issue; it changes nothing.
func (a *issueCommentAdapter) Check(ctx context.Context, r *ops.Request) (ops.CheckResult, error) {
	p, err := a.parse(r)
	if err != nil {
		return ops.CheckResult{}, err
	}
	g, err := a.issueGuard(ctx, p.pol, p.iss, p.ident)
	if err != nil {
		return ops.CheckResult{}, err
	}
	return ops.CheckResult{Checks: issueChecks(g, p.iss)}, nil
}

// Execute reads the issue again, with the whole fence, and posts the comment once.
func (a *issueCommentAdapter) Execute(ctx context.Context, r *ops.Request) (ops.Outcome, error) {
	p, err := a.parse(r)
	if err != nil {
		return failed(err, nil), nil
	}
	res := map[string]any{"identifier": p.ident}
	g, err := a.issueGuard(ctx, p.pol, p.iss, p.ident)
	if err != nil {
		return failed(err, res), nil // nothing was written
	}
	id := CommentID(r.ExecutionID)
	res["comment_id"] = id
	c, err := a.cfg.Client.AddComment(ctx, id, g.ID, p.body)
	if err != nil {
		return writeErr(err, res)
	}
	url := untrusted.Clean(c.URL, maxURL)
	res["url"] = url
	return ops.Outcome{ExternalRef: refOr(url, g.URL), Result: res}, nil
}

// ---- issue.label -----------------------------------------------------------

type issueLabelAdapter struct{ base }

var _ ops.Adapter = (*issueLabelAdapter)(nil)

type issueLabelParams struct {
	pol    *policy.Linear
	iss    *policy.LinearIssues
	ident  string
	label  string // the policy's spelling
	remove bool
}

func (a *issueLabelAdapter) parse(r *ops.Request) (issueLabelParams, error) {
	var p issueLabelParams
	pol, iss, err := a.issuePolicy(r)
	if err != nil {
		return p, err
	}
	if p.ident, err = issueIdent(r, pol, iss); err != nil {
		return p, err
	}
	if err := onlyParams(r.Params, linearspec.IssueLabel.ParamNames()...); err != nil {
		return p, err
	}
	_, hasAdd := r.Params["add"]
	_, hasRemove := r.Params["remove"]
	if hasAdd == hasRemove {
		return p, paramsInvalid("give exactly one of add and remove")
	}
	key := "add"
	if hasRemove {
		key, p.remove = "remove", true
	}
	name, err := paramString(r.Params, key)
	if err != nil {
		return p, err
	}
	if err := checkText(key, name, policy.LinearMaxLabel); err != nil {
		return p, err
	}
	name = strings.TrimSpace(name)
	switch {
	case strings.EqualFold(name, pol.Label):
		return p, intakeRefused("label %q is the operator-board label; the issue ops never add or remove it", clip(name, 60))
	case strings.EqualFold(name, iss.Label):
		return p, policyRefused("provenance_label_immutable: the label %q marks the issues these ops may write to; issue.label never adds or removes it", clip(name, 60))
	}
	canon, ok := iss.LabelAllowed(name)
	if !ok {
		if len(iss.Labels) == 0 {
			return p, policyRefused("label_in_policy_list: issue.label is refused for project %s: its policy file lists no linear.issues.labels", clip(r.Project, 60))
		}
		return p, policyRefused("label_in_policy_list: label %q is not one issue.label may use for project %s; allowed: %s", clip(name, 60), clip(r.Project, 60), clip(strings.Join(iss.Labels, ", "), 250))
	}
	p.pol, p.iss, p.label = pol, iss, canon
	return p, nil
}

// Check validates the request and reads the issue; it changes nothing.
func (a *issueLabelAdapter) Check(ctx context.Context, r *ops.Request) (ops.CheckResult, error) {
	p, err := a.parse(r)
	if err != nil {
		return ops.CheckResult{}, err
	}
	g, err := a.issueGuard(ctx, p.pol, p.iss, p.ident)
	if err != nil {
		return ops.CheckResult{}, err
	}
	return ops.CheckResult{Checks: append(issueChecks(g, p.iss),
		ops.Check{Name: "label_in_policy_list", Passed: true, Detail: p.label},
		ops.Check{Name: "provenance_label_immutable", Passed: true, Detail: "the provenance label is not touched"},
	)}, nil
}

// Execute reads the issue again and adds or removes the one label. Adding a
// label the issue has, or removing one it lacks, sends nothing.
func (a *issueLabelAdapter) Execute(ctx context.Context, r *ops.Request) (ops.Outcome, error) {
	p, err := a.parse(r)
	if err != nil {
		return failed(err, nil), nil
	}
	res := map[string]any{"identifier": p.ident, "label": p.label}
	g, err := a.issueGuard(ctx, p.pol, p.iss, p.ident)
	if err != nil {
		return failed(err, res), nil // nothing was written
	}
	have, ok := g.HasLabel(p.label)
	if p.remove {
		res["action"] = "remove"
		if !ok {
			res["changed"] = false
			return ops.Outcome{ExternalRef: refOr(g.URL, ""), Result: res}, nil
		}
		if err := a.cfg.Client.ChangeLabel(ctx, g.ID, have.ID, false); err != nil {
			return writeErr(err, res)
		}
		res["changed"] = true
		return ops.Outcome{ExternalRef: refOr(g.URL, ""), Result: res}, nil
	}
	res["action"] = "add"
	if ok {
		res["changed"] = false
		return ops.Outcome{ExternalRef: refOr(g.URL, ""), Result: res}, nil
	}
	l, err := a.cfg.Client.FindLabel(ctx, p.label, g.TeamKey)
	if errors.Is(err, ErrNotFound) {
		return failed(paramsInvalid("Linear has no label %q for team %s although the policy lists it", clip(p.label, 60), g.TeamKey), res), nil
	}
	if err != nil {
		return failed(credentialRefusal(err), res), nil // a read: nothing was written
	}
	if err := a.cfg.Client.ChangeLabel(ctx, g.ID, l.ID, true); err != nil {
		return writeErr(err, res)
	}
	res["changed"] = true
	return ops.Outcome{ExternalRef: refOr(g.URL, ""), Result: res}, nil
}

// ---- issue.move ------------------------------------------------------------

type issueMoveAdapter struct{ base }

var _ ops.Adapter = (*issueMoveAdapter)(nil)

type issueMoveParams struct {
	pol   *policy.Linear
	iss   *policy.LinearIssues
	ident string
	state string // the policy's spelling of the state name
}

func (a *issueMoveAdapter) parse(r *ops.Request) (issueMoveParams, error) {
	var p issueMoveParams
	pol, iss, err := a.issuePolicy(r)
	if err != nil {
		return p, err
	}
	if p.ident, err = issueIdent(r, pol, iss); err != nil {
		return p, err
	}
	if err := onlyParams(r.Params, linearspec.IssueMove.ParamNames()...); err != nil {
		return p, err
	}
	name, err := paramString(r.Params, "state")
	if err != nil {
		return p, err
	}
	if len(name) > policy.LinearMaxState {
		return p, paramsInvalid("state is longer than %d bytes", policy.LinearMaxState)
	}
	canon, ok := iss.StateAllowed(strings.TrimSpace(name))
	if !ok {
		if len(iss.States) == 0 {
			return p, policyRefused("state_in_policy: issue.move is refused for project %s: its policy file lists no linear.issues.states", clip(r.Project, 60))
		}
		return p, policyRefused("state_in_policy: state %q is not one issue.move may set for project %s; allowed: %s", clip(name, 60), clip(r.Project, 60), clip(strings.Join(iss.States, ", "), 250))
	}
	p.pol, p.iss, p.state = pol, iss, canon
	return p, nil
}

func (p issueMoveParams) target(g *IssueGuardRead) (State, error) {
	for _, s := range g.States {
		if strings.EqualFold(s.Name, p.state) {
			return s, nil
		}
	}
	return State{}, paramsInvalid("the team has no state named %q although the policy lists it; fix linear.issues.states", clip(p.state, 60))
}

// Check validates the request and reads the issue; it changes nothing.
func (a *issueMoveAdapter) Check(ctx context.Context, r *ops.Request) (ops.CheckResult, error) {
	p, err := a.parse(r)
	if err != nil {
		return ops.CheckResult{}, err
	}
	g, err := a.issueGuard(ctx, p.pol, p.iss, p.ident)
	if err != nil {
		return ops.CheckResult{}, err
	}
	if _, err := p.target(g); err != nil {
		return ops.CheckResult{}, err
	}
	return ops.CheckResult{Checks: append(issueChecks(g, p.iss),
		ops.Check{Name: "state_in_policy", Passed: true, Detail: untrusted.Clean(g.State.Name, maxName) + " -> " + p.state})}, nil
}

// Execute reads the issue again and moves it. A move to the state it is in
// sends nothing.
func (a *issueMoveAdapter) Execute(ctx context.Context, r *ops.Request) (ops.Outcome, error) {
	p, err := a.parse(r)
	if err != nil {
		return failed(err, nil), nil
	}
	res := map[string]any{"identifier": p.ident, "to": p.state}
	g, err := a.issueGuard(ctx, p.pol, p.iss, p.ident)
	if err != nil {
		return failed(err, res), nil // nothing was written
	}
	to, err := p.target(g)
	if err != nil {
		return failed(err, res), nil // nothing was written
	}
	res["from"] = untrusted.Clean(g.State.Name, maxName)
	if strings.EqualFold(g.State.Name, to.Name) {
		res["moved"] = false
		return ops.Outcome{ExternalRef: refOr(g.URL, ""), Result: res}, nil
	}
	got, err := a.cfg.Client.SetState(ctx, g.ID, to.ID)
	if err != nil {
		return writeErr(err, res)
	}
	res["moved"] = true
	if !strings.EqualFold(got, to.Name) {
		res["error"] = "Linear reports the state " + untrusted.Clean(got, maxName) + " after the move"
		res["now"] = untrusted.Clean(got, maxName)
		return ops.Outcome{Unconfirmed: true, Result: res}, nil
	}
	return ops.Outcome{ExternalRef: refOr(g.URL, ""), Result: res}, nil
}

// ---- issue.link ------------------------------------------------------------

type issueLinkAdapter struct{ base }

var _ ops.Adapter = (*issueLinkAdapter)(nil)

type issueLinkParams struct {
	pol   *policy.Linear
	iss   *policy.LinearIssues
	ident string
	url   string
	title string
}

func (a *issueLinkAdapter) parse(r *ops.Request) (issueLinkParams, error) {
	var p issueLinkParams
	pol, iss, err := a.issuePolicy(r)
	if err != nil {
		return p, err
	}
	if p.ident, err = issueIdent(r, pol, iss); err != nil {
		return p, err
	}
	if err := onlyParams(r.Params, linearspec.IssueLink.ParamNames()...); err != nil {
		return p, err
	}
	if p.url, err = paramString(r.Params, "url"); err != nil {
		return p, err
	}
	if err := checkText("url", p.url, maxURL); err != nil {
		return p, err
	}
	if err := guardBoard(pol, "a link", p.url); err != nil {
		return p, err
	}
	u, err := url.ParseRequestURI(p.url)
	switch {
	case err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Port() != "" || strings.ContainsAny(p.url, " \t\n"):
		return p, paramsInvalid("url must be an https URL with a host name, no user name and no port")
	case !iss.HostAllowed(u.Hostname()):
		if len(iss.LinkHosts) == 0 {
			return p, policyRefused("link_host_allowlist: issue.link is refused for project %s: its policy file lists no linear.issues.link_hosts", clip(r.Project, 60))
		}
		return p, policyRefused("link_host_allowlist: the host %q is not one issue.link may use for project %s; allowed: %s", clip(u.Hostname(), 60), clip(r.Project, 60), clip(strings.Join(iss.LinkHosts, ", "), 250))
	}
	if _, ok := r.Params["title"]; ok {
		if p.title, err = paramString(r.Params, "title"); err != nil {
			return p, err
		}
		if err := checkText("title", p.title, maxLinkTitle); err != nil {
			return p, err
		}
		if err := guardBoard(pol, "the link title", p.title); err != nil {
			return p, err
		}
	}
	for _, s := range []struct{ where, text string }{{"url", p.url}, {"title", p.title}} {
		if err := a.scan(s.where, s.text); err != nil {
			return p, err
		}
	}
	p.pol, p.iss = pol, iss
	return p, nil
}

// Check validates the request and reads the issue; it changes nothing.
func (a *issueLinkAdapter) Check(ctx context.Context, r *ops.Request) (ops.CheckResult, error) {
	p, err := a.parse(r)
	if err != nil {
		return ops.CheckResult{}, err
	}
	g, err := a.issueGuard(ctx, p.pol, p.iss, p.ident)
	if err != nil {
		return ops.CheckResult{}, err
	}
	return ops.CheckResult{Checks: append(issueChecks(g, p.iss),
		ops.Check{Name: "link_host_allowlist", Passed: true, Detail: clip(p.url, 120)})}, nil
}

// Execute reads the issue again and attaches the link. Linear keeps one
// attachment per issue and URL, so a repeat does not duplicate.
func (a *issueLinkAdapter) Execute(ctx context.Context, r *ops.Request) (ops.Outcome, error) {
	p, err := a.parse(r)
	if err != nil {
		return failed(err, nil), nil
	}
	res := map[string]any{"identifier": p.ident, "url": untrusted.Clean(p.url, maxURL)}
	g, err := a.issueGuard(ctx, p.pol, p.iss, p.ident)
	if err != nil {
		return failed(err, res), nil // nothing was written
	}
	if err := a.cfg.Client.AddLink(ctx, g.ID, p.url, p.title); err != nil {
		return writeErr(err, res)
	}
	return ops.Outcome{ExternalRef: refOr(g.URL, ""), Result: res}, nil
}
