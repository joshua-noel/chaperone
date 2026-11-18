package linear

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
)

// Caps of the text a list puts in its result.
const (
	maxTitle       = 200
	maxDescription = 2000
	maxCommentText = 600
	maxLinkTitle   = 120
	maxURL         = 300
	maxName        = 80

	withheld = "[withheld: the text looks like a secret]"
)

// ---- intake.list -----------------------------------------------------------

type listAdapter struct{ base }

var _ ops.Adapter = (*listAdapter)(nil)

type listParams struct {
	refresh, closed bool
}

func (a *listAdapter) parse(r *ops.Request) (*policy.Linear, listParams, error) {
	var p listParams
	pol, err := a.policy(r)
	if err != nil {
		return nil, p, err
	}
	if err := a.teamTarget(r, pol); err != nil {
		return nil, p, err
	}
	if err := onlyParams(r.Params, "refresh", "closed"); err != nil {
		return nil, p, err
	}
	if p.refresh, err = paramBool(r.Params, "refresh"); err != nil {
		return nil, p, err
	}
	if p.closed, err = paramBool(r.Params, "closed"); err != nil {
		return nil, p, err
	}
	return pol, p, nil
}

// Check validates the request; it reads nothing.
func (a *listAdapter) Check(_ context.Context, r *ops.Request) (ops.CheckResult, error) {
	pol, _, err := a.parse(r)
	if err != nil {
		return ops.CheckResult{}, err
	}
	return ops.CheckResult{Checks: []ops.Check{
		{Name: "team", Passed: true, Detail: pol.Team},
		{Name: "label", Passed: true, Detail: pol.Label},
	}}, nil
}

// Execute answers from the board cache or reads Linear. A read has no effect,
// so every failure of it is `failed`, never `unconfirmed`.
func (a *listAdapter) Execute(ctx context.Context, r *ops.Request) (ops.Outcome, error) {
	pol, p, err := a.parse(r)
	if err != nil {
		return failed(err, nil), nil
	}
	snap, err := a.cfg.Board.Get(ctx, pol.Team, pol.Label, p.refresh, p.closed)
	if err != nil {
		return failed(err, nil), nil
	}
	items := make([]any, 0, len(snap.Items))
	for _, it := range snap.Items {
		items = append(items, a.itemResult(it))
	}
	res := map[string]any{
		"team":           pol.Team,
		"label":          pol.Label,
		"untrusted_text": true,
		"source":         snap.Source,
		"fetched_at":     snap.FetchedAt.UTC().Format(time.RFC3339),
		"age_seconds":    max(0, int(a.cfg.now().Sub(snap.FetchedAt).Seconds())),
		"count":          len(items),
		"truncated":      snap.Truncated,
		"closed_too":     p.closed,
		"items":          items,
	}
	if snap.Note != "" {
		res["note"] = snap.Note
	}
	return ops.Outcome{Result: res}, nil
}

// itemResult is one item as the caller gets it. The text is Linear's: it is
// cleaned and capped, and withheld whole when it looks like a secret.
func (a *listAdapter) itemResult(it Item) map[string]any {
	m := map[string]any{
		"identifier": clean(it.Identifier, maxName),
		"url":        clean(it.URL, maxURL),
		"state":      map[string]any{"name": clean(it.State.Name, maxName), "type": clean(it.State.Type, maxName)},
		"created_at": clean(it.CreatedAt, 40),
		"updated_at": clean(it.UpdatedAt, 40),
	}
	if it.Assignee != "" {
		m["assignee"] = clean(it.Assignee, maxName)
	}
	labels := make([]any, 0, len(it.Labels))
	for _, l := range it.Labels {
		labels = append(labels, clean(l, maxName))
	}
	m["labels"] = labels

	title, desc := clean(it.Title, maxTitle), clean(it.Description, maxDescription)
	comments := make([]any, 0, len(it.Comments))
	for _, c := range it.Comments {
		comments = append(comments, map[string]any{
			"author": clean(c.Author, maxName), "created_at": clean(c.CreatedAt, 40), "body": clean(c.Body, maxCommentText),
		})
	}
	links := make([]any, 0, len(it.Links))
	for _, l := range it.Links {
		links = append(links, map[string]any{
			"url": clean(l.URL, maxURL), "title": clean(l.Title, maxLinkTitle), "source": clean(l.Source, maxName),
		})
	}
	if a.looksSecret(title, desc, it) {
		m["title"], m["description"], m["withheld"] = withheld, "", true
		comments, links = []any{}, []any{}
	} else {
		m["title"], m["description"] = title, desc
	}
	m["comments"], m["links"] = comments, links
	m["more_comments"], m["more_links"] = it.MoreComments, it.MoreLinks
	return m
}

// looksSecret reports whether any of the item's text would trip the redaction
// check. The op result is scanned again as a whole; one item with a secret
// would otherwise block the whole board.
func (a *listAdapter) looksSecret(title, desc string, it Item) bool {
	if a.cfg.Redactor == nil {
		return false
	}
	var b strings.Builder
	b.WriteString(title + "\n" + desc + "\n")
	for _, c := range it.Comments {
		b.WriteString(c.Body + "\n")
	}
	for _, l := range it.Links {
		b.WriteString(l.URL + "\n" + l.Title + "\n")
	}
	_, res := a.cfg.Redactor.Redact(b.String())
	return res.Blocked()
}

// ---- intake.states ---------------------------------------------------------

type statesAdapter struct{ base }

var _ ops.Adapter = (*statesAdapter)(nil)

func (a *statesAdapter) parse(r *ops.Request) (*policy.Linear, error) {
	pol, err := a.policy(r)
	if err != nil {
		return nil, err
	}
	if err := a.teamTarget(r, pol); err != nil {
		return nil, err
	}
	return pol, onlyParams(r.Params)
}

// Check validates the request; it reads nothing.
func (a *statesAdapter) Check(_ context.Context, r *ops.Request) (ops.CheckResult, error) {
	pol, err := a.parse(r)
	if err != nil {
		return ops.CheckResult{}, err
	}
	return ops.CheckResult{Checks: []ops.Check{{Name: "team", Passed: true, Detail: pol.Team}}}, nil
}

// Execute lists the team's real workflow states and marks those the policy
// lets `intake.move` use, so the operator can confirm the names.
func (a *statesAdapter) Execute(ctx context.Context, r *ops.Request) (ops.Outcome, error) {
	pol, err := a.parse(r)
	if err != nil {
		return failed(err, nil), nil
	}
	team, err := a.cfg.Client.TeamStates(ctx, pol.Team)
	if errors.Is(err, ErrNotFound) {
		return failed(errors.New("Linear has no team "+pol.Team+" that the app can see: check the team key in the policy and the app's team access"), nil), nil
	}
	if err != nil {
		return failed(err, nil), nil
	}
	if strings.EqualFold(strings.TrimSpace(team.Name), "engineering") {
		return failed(errors.New("team "+pol.Team+" is the Engineering team, which the intake never uses"), nil), nil
	}
	have := map[string]bool{}
	states := make([]any, 0, len(team.States))
	for _, s := range team.States {
		_, ok := pol.StateAllowed(s.Name)
		have[strings.ToLower(s.Name)] = true
		states = append(states, map[string]any{"name": clean(s.Name, maxName), "type": clean(s.Type, maxName), "in_policy": ok})
	}
	var missing []any
	allowed := make([]any, 0, len(pol.States))
	for _, s := range pol.States {
		allowed = append(allowed, s)
		if !have[strings.ToLower(s)] {
			missing = append(missing, s)
		}
	}
	if missing == nil {
		missing = []any{}
	}
	return ops.Outcome{Result: map[string]any{
		"team":               pol.Team,
		"team_name":          clean(team.Name, maxName),
		"label":              pol.Label,
		"states":             states,
		"policy_states":      allowed,
		"policy_not_in_team": missing,
	}}, nil
}

// ---- intake.comment --------------------------------------------------------

type commentAdapter struct{ base }

var _ ops.Adapter = (*commentAdapter)(nil)

type commentParams struct {
	pol   *policy.Linear
	ident string
	body  string
}

func (a *commentAdapter) parse(r *ops.Request) (commentParams, error) {
	var p commentParams
	pol, err := a.policy(r)
	if err != nil {
		return p, err
	}
	if p.ident, err = a.issueTarget(r, pol); err != nil {
		return p, err
	}
	if err := onlyParams(r.Params, "body"); err != nil {
		return p, err
	}
	if p.body, err = paramString(r.Params, "body"); err != nil {
		return p, err
	}
	if err := checkText("body", p.body, MaxCommentBytes); err != nil {
		return p, err
	}
	if err := a.scan("body", p.body); err != nil {
		return p, err
	}
	p.pol = pol
	return p, nil
}

// Check validates the request and reads the issue; it changes nothing.
func (a *commentAdapter) Check(ctx context.Context, r *ops.Request) (ops.CheckResult, error) {
	p, err := a.parse(r)
	if err != nil {
		return ops.CheckResult{}, err
	}
	g, err := a.guard(ctx, p.pol, p.ident)
	if err != nil {
		return ops.CheckResult{}, err
	}
	return ops.CheckResult{Checks: []ops.Check{
		{Name: "team", Passed: true, Detail: g.TeamKey},
		{Name: "label", Passed: true, Detail: p.pol.Label},
		{Name: "issue", Passed: true, Detail: g.Identifier + " is " + clean(g.State.Name, maxName)},
	}}, nil
}

// Execute reads the issue again, with the label and team rules, and then posts
// the comment once.
func (a *commentAdapter) Execute(ctx context.Context, r *ops.Request) (ops.Outcome, error) {
	p, err := a.parse(r)
	if err != nil {
		return failed(err, nil), nil
	}
	res := map[string]any{"identifier": p.ident}
	g, err := a.guard(ctx, p.pol, p.ident)
	if err != nil {
		return failed(err, res), nil // nothing was written
	}
	id := CommentID(r.ExecutionID)
	res["comment_id"] = id
	c, err := a.cfg.Client.AddComment(ctx, id, g.ID, p.body)
	a.cfg.Board.Invalidate(p.pol.Team, p.pol.Label)
	if err != nil {
		return writeErr(err, res)
	}
	url := clean(c.URL, maxURL)
	res["url"] = url
	return ops.Outcome{ExternalRef: refOr(url, g.URL), Result: res}, nil
}

func refOr(a, b string) string {
	if a != "" {
		return clean(a, maxURL)
	}
	return clean(b, maxURL)
}

// ---- intake.move -----------------------------------------------------------

type moveAdapter struct{ base }

var _ ops.Adapter = (*moveAdapter)(nil)

type moveParams struct {
	pol   *policy.Linear
	ident string
	state string // the policy's spelling of the state name
}

func (a *moveAdapter) parse(r *ops.Request) (moveParams, error) {
	var p moveParams
	pol, err := a.policy(r)
	if err != nil {
		return p, err
	}
	if p.ident, err = a.issueTarget(r, pol); err != nil {
		return p, err
	}
	if err := onlyParams(r.Params, "state"); err != nil {
		return p, err
	}
	name, err := paramString(r.Params, "state")
	if err != nil {
		return p, err
	}
	if len(name) > policy.LinearMaxState {
		return p, paramsInvalid("state is longer than %d bytes", policy.LinearMaxState)
	}
	canon, ok := pol.StateAllowed(strings.TrimSpace(name))
	if !ok {
		if len(pol.States) == 0 {
			return p, policyRefused("intake.move is refused for project %s: its policy file lists no linear.states yet (the operator confirms them with `chap intake states`)", clip(r.Project, 60))
		}
		return p, policyRefused("state %q is not one intake.move may set for project %s; allowed: %s", clip(name, 60), clip(r.Project, 60), clip(strings.Join(pol.States, ", "), 250))
	}
	p.pol, p.state = pol, canon
	return p, nil
}

// target finds the policy's state among the issue's team's states.
func (p moveParams) target(g *Guard) (State, error) {
	for _, s := range g.States {
		if strings.EqualFold(s.Name, p.state) {
			return s, nil
		}
	}
	return State{}, paramsInvalid("the team has no state named %q although the policy lists it; run `chap intake states` and fix the policy", clip(p.state, 60))
}

// Check validates the request and reads the issue; it changes nothing.
func (a *moveAdapter) Check(ctx context.Context, r *ops.Request) (ops.CheckResult, error) {
	p, err := a.parse(r)
	if err != nil {
		return ops.CheckResult{}, err
	}
	g, err := a.guard(ctx, p.pol, p.ident)
	if err != nil {
		return ops.CheckResult{}, err
	}
	if _, err := p.target(g); err != nil {
		return ops.CheckResult{}, err
	}
	return ops.CheckResult{Checks: []ops.Check{
		{Name: "team", Passed: true, Detail: g.TeamKey},
		{Name: "label", Passed: true, Detail: p.pol.Label},
		{Name: "state_in_policy", Passed: true, Detail: clean(g.State.Name, maxName) + " -> " + p.state},
	}}, nil
}

// Execute reads the issue again and moves it. A move to the state it is in
// sends nothing.
func (a *moveAdapter) Execute(ctx context.Context, r *ops.Request) (ops.Outcome, error) {
	p, err := a.parse(r)
	if err != nil {
		return failed(err, nil), nil
	}
	res := map[string]any{"identifier": p.ident, "to": p.state}
	g, err := a.guard(ctx, p.pol, p.ident)
	if err != nil {
		return failed(err, res), nil // nothing was written
	}
	to, err := p.target(g)
	if err != nil {
		return failed(err, res), nil // nothing was written
	}
	res["from"] = clean(g.State.Name, maxName)
	if strings.EqualFold(g.State.Name, to.Name) {
		res["moved"] = false
		return ops.Outcome{ExternalRef: refOr(g.URL, ""), Result: res}, nil
	}
	got, err := a.cfg.Client.SetState(ctx, g.ID, to.ID)
	a.cfg.Board.Invalidate(p.pol.Team, p.pol.Label)
	if err != nil {
		return writeErr(err, res)
	}
	res["moved"] = true
	if !strings.EqualFold(got, to.Name) {
		// Linear acted but reports another state: say so, do not claim success.
		res["error"] = "Linear reports the state " + clean(got, maxName) + " after the move"
		res["now"] = clean(got, maxName)
		return ops.Outcome{Unconfirmed: true, Result: res}, nil
	}
	return ops.Outcome{ExternalRef: refOr(g.URL, ""), Result: res}, nil
}
