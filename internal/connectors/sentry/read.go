package sentry

import (
	"context"
	"errors"

	"github.com/joshua-noel/chaperone/internal/connectors/sentry/sentryspec"
	"github.com/joshua-noel/chaperone/internal/ops"
)

// ---- errors.list --------------------------------------------------------------

type listAdapter struct{ base }

var _ ops.Adapter = (*listAdapter)(nil)

type listParams struct {
	res     resolved
	project string // the policy's spelling of the project slug
	ListParams
}

// parse is the one place a request is validated. Check and Execute both call
// it, so a request that Check refuses is refused again by Execute.
func (a *listAdapter) parse(r *ops.Request) (listParams, error) {
	var p listParams
	res, err := a.resolve(r)
	if err != nil {
		return p, err
	}
	if !projectRefRE.MatchString(r.Target.Ref) {
		return p, paramsInvalid("target.ref must be a Sentry project slug, such as web")
	}
	if !res.pol.ProjectAllowed(r.Target.Ref) {
		return p, scopeRefused("project %s is not listed in sentry.projects of project %s; the Sentry ops touch listed projects only", clip(r.Target.Ref, 60), clip(r.Project, 60))
	}
	if err := onlyParams(r.Params, sentryspec.List.ParamNames()...); err != nil {
		return p, err
	}
	if p.Status, err = optString(r.Params, "status", statusRE, "unresolved, resolved or ignored"); err != nil {
		return p, err
	}
	if p.Status == "" {
		p.Status = "unresolved"
	}
	if p.Level, err = optString(r.Params, "level", levelRE, "fatal, error, warning, info or debug"); err != nil {
		return p, err
	}
	if p.Cursor, err = optString(r.Params, "cursor", cursorRE, "the next_cursor of a previous page"); err != nil {
		return p, err
	}
	n, ok, err := optInt(r.Params, "limit", 1, sentryspec.MaxLimit)
	if err != nil {
		return p, err
	}
	if !ok {
		n = sentryspec.DefaultLimit
	}
	p.Limit, p.res, p.project = n, res, r.Target.Ref
	return p, nil
}

// Check validates the request; it reads nothing.
func (a *listAdapter) Check(_ context.Context, r *ops.Request) (ops.CheckResult, error) {
	p, err := a.parse(r)
	if err != nil {
		return ops.CheckResult{}, err
	}
	return ops.CheckResult{Checks: []ops.Check{{Name: "project_in_scope", Passed: true, Detail: p.project}}}, nil
}

// Execute reads one page. An issue of another project than the one asked for is
// left out of the page, whatever Sentry was asked: a filter that Sentry applied
// wrongly must not put such an issue in a result. A read has no effect, so every
// failure of it is `failed`.
func (a *listAdapter) Execute(ctx context.Context, r *ops.Request) (ops.Outcome, error) {
	p, err := a.parse(r)
	if err != nil {
		return failed(err, nil), nil
	}
	page, err := a.cfg.Client.ListIssues(ctx, p.res.scope, p.project, p.ListParams)
	if err != nil {
		return failed(credentialRefusal(err), nil), nil
	}
	issues, truncated := page.Issues, false
	if len(issues) > p.Limit {
		issues, truncated = issues[:p.Limit], true
	}
	items := make([]any, 0, len(issues))
	for _, is := range issues {
		if !issueIDRE.MatchString(is.ID) || is.Project.Slug != p.project {
			continue
		}
		items = append(items, a.item(is))
	}
	res := map[string]any{"untrusted_text": true, "project": p.project, "status": p.Status, "count": len(items), "items": items}
	switch {
	case truncated:
		// Sentry gave more than was asked for. Its cursor would skip the items cut
		// here, so it is not passed on.
		res["page_truncated"] = true
	case page.Next != "" && cursorRE.MatchString(page.Next):
		// The cursor is Sentry's text. It is returned only in the shape this
		// adapter accepts back; any other cursor is withheld, and the result says so.
		res["next_cursor"] = page.Next
	case page.Next != "":
		res["cursor_withheld"] = true
	}
	return ops.Outcome{Result: res}, nil
}

// ---- errors.get ---------------------------------------------------------------

type getAdapter struct{ base }

var _ ops.Adapter = (*getAdapter)(nil)

func (a *getAdapter) parse(r *ops.Request) (resolved, string, error) {
	res, err := a.resolve(r)
	if err != nil {
		return res, "", err
	}
	id, err := issueRef(r)
	if err != nil {
		return res, "", err
	}
	return res, id, onlyParams(r.Params, sentryspec.Get.ParamNames()...)
}

// Check validates the request; it reads nothing.
func (a *getAdapter) Check(_ context.Context, r *ops.Request) (ops.CheckResult, error) {
	res, _, err := a.parse(r)
	if err != nil {
		return ops.CheckResult{}, err
	}
	return ops.CheckResult{Checks: []ops.Check{{Name: "organization", Passed: true, Detail: res.scope.Org}}}, nil
}

// Execute reads the issue and applies the fence before any of its text is
// returned, then reads the latest event and keeps its essentials.
func (a *getAdapter) Execute(ctx context.Context, r *ops.Request) (ops.Outcome, error) {
	res, id, err := a.parse(r)
	if err != nil {
		return failed(err, nil), nil
	}
	is, slug, err := a.readIssue(ctx, res, r, id)
	if err != nil {
		return failed(err, nil), nil
	}
	out := map[string]any{"untrusted_text": true, "project": slug, "issue": a.item(is)}
	ev, err := a.cfg.Client.LatestEvent(ctx, res.scope, id)
	switch {
	case errors.Is(err, ErrNotFound):
		out["no_event"] = true
	case errors.Is(err, ErrTooLarge):
		out["event_omitted"] = "the latest event is too large to read"
	case err != nil:
		return failed(credentialRefusal(err), nil), nil
	default:
		out["latest_event"] = a.event(ev)
	}
	return ops.Outcome{ExternalRef: res.permalink(id), Result: out}, nil
}

// event is the essentials of an event as a result carries them. The stack is
// withheld whole when any of its text looks like a secret.
func (a *getAdapter) event(ev EventSummary) map[string]any {
	m := map[string]any{"date": stamp(ev.Date)}
	if eventIDRE.MatchString(ev.ID) {
		m["event_id"] = ev.ID
	}
	texts := []string{ev.ExceptionType}
	for _, f := range ev.Frames {
		texts = append(texts, f.File, f.Function)
	}
	if a.looksSecret(texts...) {
		m["stack_withheld"] = true
		return m
	}
	m["exception_type"] = line(ev.ExceptionType, maxType)
	frames := ev.Frames
	if len(frames) > maxFrames {
		frames, m["stack_truncated"] = frames[:maxFrames], true
	}
	out := make([]any, 0, len(frames))
	for _, f := range frames {
		fr := map[string]any{"file": line(f.File, maxFile), "function": line(f.Function, maxFunc), "in_app": f.InApp}
		if f.Line > 0 && f.Line < 10_000_000 {
			fr["line"] = f.Line
		}
		out = append(out, fr)
	}
	m["stack"] = out
	return m
}
