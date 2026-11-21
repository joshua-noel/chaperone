package sentry

import (
	"context"
	"strings"

	"github.com/joshua-noel/chaperone/internal/connectors/kit"
	"github.com/joshua-noel/chaperone/internal/connectors/sentry/sentryspec"
	"github.com/joshua-noel/chaperone/internal/ops"
)

// The writes of the connector change one issue of an allowed project. Each one
// reads the issue first, with the whole fence, in Check and again in Execute, so
// a project that changed between the two stops the write. Sentry has no
// conditional update: the milliseconds between that read and Sentry's answer
// remain. Each write is sent at most once and never retried.

// plan is what one write call has found out before it writes: the request
// resolved once, the issue as Sentry describes it, and the project as the
// policy spells it.
type plan struct {
	res     resolved
	id      string
	issue   Issue
	project string
}

// checks are the lines the caller sees for a write.
func (p plan) checks() []ops.Check {
	return []ops.Check{
		{Name: "project_in_scope", Passed: true, Detail: p.project},
		{Name: "issue", Passed: true, Detail: p.id + " is " + oneOf(p.issue.Status, "unresolved", "resolved", "ignored")},
	}
}

// result starts the result of a write: fixed fields, none of Sentry's text.
func (p plan) result() map[string]any {
	return map[string]any{"issue": p.id, "project": p.project}
}

// readPlan reads the issue under the fence.
func (b base) readPlan(ctx context.Context, res resolved, r *ops.Request, id string) (plan, error) {
	is, slug, err := b.readIssue(ctx, res, r, id)
	if err != nil {
		return plan{}, err
	}
	return plan{res: res, id: id, issue: is, project: slug}, nil
}

// ---- errors.resolve and errors.unresolve ----------------------------------------

// statusAdapter sets an issue's status to want: "resolved" or "unresolved". It
// changes only an issue that has the other of the two: an ignored issue (one
// that is archived) is refused, because setting it resolved or unresolved would
// end the archive and its conditions. An issue that already has the status is
// left alone and nothing is sent.
type statusAdapter struct {
	base
	op   kit.Op
	want string
}

var _ ops.Adapter = (*statusAdapter)(nil)

func (a *statusAdapter) parse(r *ops.Request) (resolved, string, error) {
	res, err := a.resolve(r)
	if err != nil {
		return res, "", err
	}
	id, err := issueRef(r)
	if err != nil {
		return res, "", err
	}
	return res, id, onlyParams(r.Params, a.op.ParamNames()...)
}

// plan reads the issue and decides whether there is anything to change. A
// *ops.Refusal is a "no".
func (a *statusAdapter) plan(ctx context.Context, r *ops.Request) (plan, bool, error) {
	res, id, err := a.parse(r)
	if err != nil {
		return plan{}, false, err
	}
	p, err := a.readPlan(ctx, res, r, id)
	if err != nil {
		return plan{}, false, err
	}
	switch p.issue.Status {
	case a.want:
		return p, false, nil
	case "resolved", "unresolved":
		return p, true, nil
	}
	return p, false, policyRefused("status_allows_change: issue %s is %s; %s changes an issue that is resolved or unresolved, not an ignored one", p.id, oneOf(p.issue.Status, "ignored"), r.Op)
}

// Check validates the request and reads the issue; it changes nothing.
func (a *statusAdapter) Check(ctx context.Context, r *ops.Request) (ops.CheckResult, error) {
	p, change, err := a.plan(ctx, r)
	if err != nil {
		return ops.CheckResult{}, err
	}
	detail := "nothing to change: the issue is " + a.want
	if change {
		detail = "will set the status to " + a.want
	}
	return ops.CheckResult{Checks: append(p.checks(), ops.Check{Name: "status_change", Passed: true, Detail: detail})}, nil
}

// Execute reads the issue again and sets the status once.
func (a *statusAdapter) Execute(ctx context.Context, r *ops.Request) (ops.Outcome, error) {
	p, change, err := a.plan(ctx, r)
	if err != nil {
		return failed(err, nil), nil // nothing was written
	}
	res := p.result()
	res["status"] = a.want
	if !change {
		res["changed"] = false
		return ops.Outcome{ExternalRef: p.res.permalink(p.id), Result: res}, nil
	}
	got, err := a.cfg.Client.SetStatus(ctx, p.res.scope, p.id, a.want)
	if err != nil {
		return writeErr(err, res, "look at issue "+p.id+" in Sentry"), nil
	}
	if got.Status != a.want {
		res["error"] = "Sentry answered, but not with the status that was asked for: look at issue " + p.id + " in Sentry"
		return ops.Outcome{Unconfirmed: true, Result: res}, nil
	}
	res["changed"] = true
	return ops.Outcome{ExternalRef: p.res.permalink(p.id), Result: res}, nil
}

// ---- errors.assign ------------------------------------------------------------

type assignAdapter struct{ base }

var _ ops.Adapter = (*assignAdapter)(nil)

type assignParams struct {
	res    resolved
	id     string
	member string // the policy's spelling
}

func (a *assignAdapter) parse(r *ops.Request) (assignParams, error) {
	var p assignParams
	res, err := a.resolve(r)
	if err != nil {
		return p, err
	}
	if p.id, err = issueRef(r); err != nil {
		return p, err
	}
	if err := onlyParams(r.Params, sentryspec.Assign.ParamNames()...); err != nil {
		return p, err
	}
	to, err := paramString(r.Params, "to")
	if err != nil {
		return p, err
	}
	if !assigneeRE.MatchString(to) {
		return p, paramsInvalid("param to must be an email address or a username, as the policy lists it")
	}
	member, ok := res.pol.AssigneeAllowed(to)
	if !ok {
		if len(res.pol.Assignees) == 0 {
			return p, policyRefused("assignee_in_policy_list: errors.assign is refused for project %s: its policy file lists no sentry.assignees", clip(r.Project, 60))
		}
		return p, policyRefused("assignee_in_policy_list: that member is not one that errors.assign may use for project %s (sentry.assignees)", clip(r.Project, 60))
	}
	p.res, p.member = res, member
	return p, nil
}

func (a *assignAdapter) plan(ctx context.Context, r *ops.Request) (plan, assignParams, bool, error) {
	ap, err := a.parse(r)
	if err != nil {
		return plan{}, ap, false, err
	}
	p, err := a.readPlan(ctx, ap.res, r, ap.id)
	if err != nil {
		return plan{}, ap, false, err
	}
	// An issue that is assigned to this member already needs no call. Sentry
	// shows an assigned user by email address; a member listed by username is
	// sent again, and Sentry sets the same assignee.
	same := p.issue.AssignedTo != nil && strings.EqualFold(p.issue.AssignedTo.Email, ap.member)
	return p, ap, !same, nil
}

// Check validates the request and reads the issue; it changes nothing.
func (a *assignAdapter) Check(ctx context.Context, r *ops.Request) (ops.CheckResult, error) {
	p, ap, change, err := a.plan(ctx, r)
	if err != nil {
		return ops.CheckResult{}, err
	}
	detail := "nothing to change: already assigned to " + ap.member
	if change {
		detail = "will assign to " + ap.member
	}
	return ops.CheckResult{Checks: append(p.checks(),
		ops.Check{Name: "assignee_in_policy_list", Passed: true, Detail: ap.member},
		ops.Check{Name: "assignment", Passed: true, Detail: detail},
	)}, nil
}

// Execute reads the issue again and assigns it once.
func (a *assignAdapter) Execute(ctx context.Context, r *ops.Request) (ops.Outcome, error) {
	p, ap, change, err := a.plan(ctx, r)
	if err != nil {
		return failed(err, nil), nil
	}
	res := p.result()
	res["assigned_to"] = ap.member
	if !change {
		res["changed"] = false
		return ops.Outcome{ExternalRef: p.res.permalink(p.id), Result: res}, nil
	}
	if _, err := a.cfg.Client.Assign(ctx, p.res.scope, p.id, ap.member); err != nil {
		return writeErr(err, res, "look at issue "+p.id+" in Sentry"), nil
	}
	res["changed"] = true
	return ops.Outcome{ExternalRef: p.res.permalink(p.id), Result: res}, nil
}

// ---- errors.comment -----------------------------------------------------------

// commentAdapter adds one note. Sentry has no idempotency key for a note, and a
// marker in the text would change what is posted, so a second Execute with the
// same execution id posts again. chapd does not call Execute twice for one
// execution id; the conformance test of the connector declares the operation
// NotRepeatable, and says why.
type commentAdapter struct{ base }

var _ ops.Adapter = (*commentAdapter)(nil)

type commentParams struct {
	res  resolved
	id   string
	body string
}

func (a *commentAdapter) parse(r *ops.Request) (commentParams, error) {
	var p commentParams
	res, err := a.resolve(r)
	if err != nil {
		return p, err
	}
	if p.id, err = issueRef(r); err != nil {
		return p, err
	}
	if err := onlyParams(r.Params, sentryspec.Comment.ParamNames()...); err != nil {
		return p, err
	}
	if p.body, err = paramString(r.Params, "body"); err != nil {
		return p, err
	}
	if err := a.guardNote(p.body); err != nil {
		return p, err
	}
	p.res = res
	return p, nil
}

// Check validates the request and reads the issue; it changes nothing.
func (a *commentAdapter) Check(ctx context.Context, r *ops.Request) (ops.CheckResult, error) {
	cp, err := a.parse(r)
	if err != nil {
		return ops.CheckResult{}, err
	}
	p, err := a.readPlan(ctx, cp.res, r, cp.id)
	if err != nil {
		return ops.CheckResult{}, err
	}
	return ops.CheckResult{Checks: append(p.checks(), ops.Check{Name: "note_plain_text", Passed: true, Detail: "plain text, no mention, no secret"})}, nil
}

// Execute reads the issue again, with the whole fence, and posts the note once.
func (a *commentAdapter) Execute(ctx context.Context, r *ops.Request) (ops.Outcome, error) {
	cp, err := a.parse(r)
	if err != nil {
		return failed(err, nil), nil
	}
	p, err := a.readPlan(ctx, cp.res, r, cp.id)
	if err != nil {
		return failed(err, nil), nil // nothing was written
	}
	res := p.result()
	note, err := a.cfg.Client.Comment(ctx, p.res.scope, p.id, cp.body)
	if err != nil {
		return writeErr(err, res, "look at the activity of issue "+p.id+" in Sentry to see whether the note is there"), nil
	}
	if id := string(note.ID); noteIDRE.MatchString(id) {
		res["comment_id"] = id
	}
	return ops.Outcome{ExternalRef: p.res.permalink(p.id), Result: res}, nil
}
