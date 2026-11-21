package sentry

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/connectors/kit"
	"github.com/joshua-noel/chaperone/internal/connectors/sentry/sentryspec"
	"github.com/joshua-noel/chaperone/internal/connectors/untrusted"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/redact"
)

// The op kinds. The names, the classes and every other fact about an op are
// declared once, in [sentryspec]; this file holds what the adapters do.
const (
	OpList      = sentryspec.NameList
	OpGet       = sentryspec.NameGet
	OpResolve   = sentryspec.NameResolve
	OpUnresolve = sentryspec.NameUnresolve
	OpAssign    = sentryspec.NameAssign
	OpComment   = sentryspec.NameComment
)

// Ops lists the op kinds of the connector.
var Ops = sentryspec.Connector.Names()

// AdapterName is the target adapter every op names.
const AdapterName = sentryspec.Adapter

// Caps of the text a result carries. Sentry's text is written by programs and by
// the people whose input they print: it is not ours to trust.
const (
	maxTitle   = 200
	maxCulprit = 200
	maxShortID = 60
	maxName    = 80
	maxType    = 100
	maxFile    = 160
	maxFunc    = 100
	// maxFrames is how many stack frames errors.get returns.
	maxFrames = 10

	withheld = "[withheld: the text looks like a secret]"
)

var (
	projectRefRE = regexp.MustCompile(sentryspec.ProjectRefPattern)
	statusRE     = regexp.MustCompile(sentryspec.StatusPattern)
	levelRE      = regexp.MustCompile(sentryspec.LevelPattern)
	cursorRE     = regexp.MustCompile(sentryspec.CursorPattern)
	assigneeRE   = regexp.MustCompile(sentryspec.AssigneePattern)

	shortIDRE = regexp.MustCompile(`^[A-Z0-9][A-Z0-9_-]{0,58}-[0-9A-Z]{1,10}$`)
	countRE   = regexp.MustCompile(`^[0-9]{1,18}$`)
	eventIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	noteIDRE  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,40}$`)
)

// PolicyFunc returns the project's `sentry:` block, or nil when the project file
// has none or is invalid.
type PolicyFunc func(project string) *policy.Sentry

// Redactor is the part of *redact.Registry the adapters use.
type Redactor interface {
	Redact(s string) (string, redact.Result)
}

var _ Redactor = (*redact.Registry)(nil)

// Config builds the adapters.
type Config struct {
	Client *Client
	Policy PolicyFunc
	// Redactor is how an adapter tells that text looks like a secret. Set it in
	// chapd (the registry of the process); without it nothing is withheld and
	// no note is refused for it.
	Redactor Redactor
}

// Adapters returns the adapters by op kind. [kit.Bind] refuses to return them
// when an operation of [sentryspec.Connector] has no adapter here, or an adapter
// here has no declaration.
func Adapters(cfg Config) (map[string]ops.Adapter, error) {
	if cfg.Client == nil || cfg.Policy == nil {
		return nil, errors.New("sentry: the adapters need a client and a policy")
	}
	b := base{cfg: cfg}
	return kit.Bind(sentryspec.Connector, map[string]ops.Adapter{
		OpList:      &listAdapter{base: b},
		OpGet:       &getAdapter{base: b},
		OpResolve:   &statusAdapter{base: b, op: sentryspec.Resolve, want: "resolved"},
		OpUnresolve: &statusAdapter{base: b, op: sentryspec.Unresolve, want: "unresolved"},
		OpAssign:    &assignAdapter{base: b},
		OpComment:   &commentAdapter{base: b},
	})
}

type base struct{ cfg Config }

// ---- refusals ---------------------------------------------------------------
//
// A request that is not allowed is a *ops.Refusal with a cause code from
// internal/ops/denial.go. A plain error means "Sentry could not be asked", and
// chapd fails closed.

func paramsInvalid(format string, a ...any) error {
	return &ops.Refusal{Code: ops.CodeParamsInvalid, Why: clip(fmt.Sprintf(format, a...), 400)}
}

func policyRefused(format string, a ...any) error {
	return &ops.Refusal{Code: ops.CodePolicyRefused, Why: clip(fmt.Sprintf(format, a...), 400)}
}

func scopeRefused(format string, a ...any) error {
	return &ops.Refusal{Code: ops.CodeScopePath, Surface: "scope", Why: clip(fmt.Sprintf(format, a...), 400)}
}

// credentialRefusal turns a missing or refused auth token into a refusal the
// operator can read: asking again cannot help. Any other error is returned as it
// is. Every message here is a fixed sentence.
func credentialRefusal(err error) error {
	var ae *AuthError
	switch {
	case errors.Is(err, ErrNotConnected):
		return policyRefused("%v", ErrNotConnected)
	case errors.As(err, &ae):
		return policyRefused("%v", ae)
	}
	return err
}

// ---- the request -------------------------------------------------------------

// resolved is what one request is allowed to touch: the project's policy block
// and the scope made from it. It is made once per call of Check or Execute, and
// the read and the write of that call both use it.
type resolved struct {
	pol   *policy.Sentry
	scope Scope
}

// resolve checks who asks and returns the project's block. Only an orchestrator
// token asks for a Sentry op: no run profile lists them, a custom key cannot
// hold them, and the adapter refuses anything else as well.
func (b base) resolve(r *ops.Request) (resolved, error) {
	if r.Caller == nil || r.Caller.Kind != ops.KindOrchestrator {
		return resolved{}, &ops.Refusal{Code: ops.CodePolicyRefused, Surface: "scope",
			Why: r.Op + " is for the orchestrator token only, never for a run or a key"}
	}
	if r.Target.Adapter != AdapterName {
		return resolved{}, paramsInvalid("target.adapter must be %s", AdapterName)
	}
	pol := b.cfg.Policy(r.Project)
	switch {
	case pol == nil:
		return resolved{}, policyRefused("%s is refused for project %s: its policy file has no valid sentry: block", r.Op, clip(r.Project, 60))
	case pol.Invalid != nil:
		return resolved{}, policyRefused("%s is refused for project %s: %s", r.Op, clip(r.Project, 60), clip(pol.Invalid.Error(), 900))
	}
	return resolved{pol: pol, scope: Scope{BaseURL: pol.BaseURL, Org: pol.Organization}}, nil
}

// issueRef checks a target that names an issue and returns its id.
func issueRef(r *ops.Request) (string, error) {
	if !issueIDRE.MatchString(r.Target.Ref) {
		return "", paramsInvalid("target.ref must be the numeric id of a Sentry issue, such as 4501234567")
	}
	return r.Target.Ref, nil
}

// permalink is the address of an issue in Sentry's web pages, built from the
// policy's own values. It is not taken from Sentry's answer.
func (res resolved) permalink(id string) string {
	return res.scope.BaseURL + "/organizations/" + url.PathEscape(res.scope.Org) + "/issues/" + id + "/"
}

// fence applies the policy to an issue as Sentry describes it: the issue is the
// one that was asked for, and its project is one the policy lists. It returns
// the policy's own spelling of the project. The decision is made on Sentry's
// value as it is, by an exact match, and only then does any text go into a
// message.
func (res resolved) fence(r *ops.Request, id string, is Issue) (string, error) {
	if is.ID != id {
		return "", fmt.Errorf("sentry: the server answered for a different issue than %s", id)
	}
	for _, p := range res.pol.Projects {
		if p == is.Project.Slug {
			return p, nil
		}
	}
	return "", scopeRefused("issue %s is not in a project that the policy of project %s lists (sentry.projects); nothing was done", id, clip(r.Project, 60))
}

// readIssue reads the issue and applies the fence. It is the one function every
// call that touches an issue goes through. A *ops.Refusal is a "no"; any other
// error means Sentry could not be asked.
func (b base) readIssue(ctx context.Context, res resolved, r *ops.Request, id string) (Issue, string, error) {
	is, err := b.cfg.Client.GetIssue(ctx, res.scope, id)
	if errors.Is(err, ErrNotFound) {
		return Issue{}, "", paramsInvalid("Sentry has no issue %s that the token can see", id)
	}
	if err != nil {
		return Issue{}, "", credentialRefusal(err)
	}
	slug, err := res.fence(r, id, is)
	return is, slug, err
}

// ---- params ------------------------------------------------------------------

// onlyParams refuses a param the op does not declare. It is given the declared
// names, so the allowed keys and the declaration are the same list.
func onlyParams(p map[string]any, allowed ...string) error {
	for k := range p {
		ok := false
		for _, a := range allowed {
			ok = ok || k == a
		}
		if !ok {
			return paramsInvalid("unknown param %q; this op takes %s", clip(k, 40), paramList(allowed))
		}
	}
	return nil
}

func paramList(allowed []string) string {
	if len(allowed) == 0 {
		return "no params"
	}
	return strings.Join(allowed, ", ")
}

func paramString(p map[string]any, key string) (string, error) {
	s, ok := p[key].(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", paramsInvalid("param %s is required and must be a non-empty string", key)
	}
	return s, nil
}

// optString reads an optional string that must match a closed pattern.
func optString(p map[string]any, key string, re *regexp.Regexp, want string) (string, error) {
	v, ok := p[key]
	if !ok {
		return "", nil
	}
	s, isStr := v.(string)
	if !isStr || !re.MatchString(s) {
		return "", paramsInvalid("param %s must be %s", key, want)
	}
	return s, nil
}

// optInt reads an optional whole number from min to max.
func optInt(p map[string]any, key string, min, max int) (int, bool, error) {
	v, ok := p[key]
	if !ok {
		return 0, false, nil
	}
	n := -1
	switch x := v.(type) {
	case float64:
		if x == float64(int(x)) && x >= 1 && x <= 1<<31 {
			n = int(x)
		}
	case int:
		n = x
	}
	if n < min || n > max {
		return 0, true, paramsInvalid("param %s must be a whole number from %d to %d", key, min, max)
	}
	return n, true, nil
}

// ---- text of results ----------------------------------------------------------

// clip shortens s to n bytes on a rune boundary and replaces control
// characters, for text that goes into an error or a refusal.
func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n-3], "") + "..."
}

// line is text from Sentry on one line: cleaned by [untrusted.Line] and capped.
func line(s string, n int) string {
	s = untrusted.Line(s)
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n-3], "") + "..."
}

// looksSecret reports whether text would trip the redaction check. A result
// that holds such text is withheld whole.
func (b base) looksSecret(texts ...string) bool {
	if b.cfg.Redactor == nil {
		return false
	}
	_, res := b.cfg.Redactor.Redact(strings.Join(texts, "\n"))
	return res.Blocked()
}

// scan refuses text that looks like a secret, before it is sent.
func (b base) scan(where, s string) error {
	if b.cfg.Redactor == nil || s == "" {
		return nil
	}
	if _, res := b.cfg.Redactor.Redact(s); res.Blocked() {
		rules := make([]string, 0, len(res.Hits))
		for _, h := range res.Hits {
			rules = append(rules, h.Rule)
		}
		return &ops.Refusal{Code: ops.CodeRedactionBlocked, Why: clip(fmt.Sprintf(
			"%s holds something shaped like a secret (rule: %s); it was not sent", where, strings.Join(rules, ", ")), 400)}
	}
	return nil
}

// oneOf returns s when it is one of the words, else "other".
func oneOf(s string, words ...string) string {
	for _, w := range words {
		if s == w {
			return w
		}
	}
	return "other"
}

// stamp returns an RFC 3339 time in UTC, or "" when s is not one.
func stamp(s string) string {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// item is one issue as a result carries it: fixed fields, each cleaned, capped
// or reduced to a closed set of words. The title, the culprit and the assignee
// are Sentry's text; when any of the text looks like a secret, the item is
// withheld whole.
func (b base) item(is Issue) map[string]any {
	m := map[string]any{
		"id":         is.ID,
		"level":      oneOf(is.Level, "fatal", "error", "warning", "info", "debug"),
		"status":     oneOf(is.Status, "unresolved", "resolved", "ignored"),
		"first_seen": stamp(is.FirstSeen),
		"last_seen":  stamp(is.LastSeen),
	}
	if c := string(is.Count); countRE.MatchString(c) {
		m["count"] = c
	}
	if shortIDRE.MatchString(is.ShortID) {
		m["short_id"] = is.ShortID
	}
	assignee := ""
	if is.AssignedTo != nil {
		assignee = is.AssignedTo.Name
	}
	if b.looksSecret(is.Title, is.Culprit, is.ShortID, assignee) {
		m["title"], m["withheld"] = withheld, true
		return m
	}
	m["title"] = line(is.Title, maxTitle)
	m["culprit"] = line(is.Culprit, maxCulprit)
	if assignee != "" {
		m["assigned_to"] = line(assignee, maxName)
	}
	return m
}

// failed is the outcome of an op that did not change anything: a refusal, or a
// read that did not work, so the caller may ask again.
func failed(err error, res map[string]any) ops.Outcome {
	if res == nil {
		res = map[string]any{}
	}
	text := err.Error()
	var ref *ops.Refusal
	if errors.As(err, &ref) {
		text = ref.Why
	}
	res["error"] = clip(text, 300)
	return ops.Outcome{Failed: true, Result: res}
}

// writeErr turns the error of a write into an outcome. A refusal, and an error
// that certainly means Sentry did not act, is `failed`. Anything else leaves the
// op `unconfirmed`, and the result says what to look up. A write is never sent
// again by the adapter.
func writeErr(err error, res map[string]any, lookup string) ops.Outcome {
	err = credentialRefusal(err)
	var ref *ops.Refusal
	if errors.As(err, &ref) || Definite(err) {
		return failed(err, res)
	}
	res["error"] = clip("the answer of Sentry does not show whether the change was made: "+lookup, 300)
	return ops.Outcome{Unconfirmed: true, Result: res}
}
