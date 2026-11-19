package linear

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/joshua-noel/chaperone/internal/connectors/kit"
	"github.com/joshua-noel/chaperone/internal/connectors/linear/linearspec"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/redact"
)

// The op kinds. The names, the classes and every other fact about an op are
// declared once, in [linearspec]; this file holds what the adapters do.
const (
	OpList    = linearspec.NameList
	OpComment = linearspec.NameComment
	OpMove    = linearspec.NameMove
	OpStates  = linearspec.NameStates
)

// Ops lists the op kinds of the connector.
var Ops = linearspec.Connector.Names()

// AdapterName is the target adapter every intake op names.
const AdapterName = linearspec.Adapter

// Limits of what a caller may send.
const (
	// MaxCommentBytes is the longest comment. "Picked up by the orchestrator" and a few
	// links need a fraction of it.
	MaxCommentBytes = linearspec.MaxCommentBytes
)

var (
	teamRefRE  = regexp.MustCompile(linearspec.TeamRefPattern)
	identRefRE = regexp.MustCompile(linearspec.IssueRefPattern)
)

// PolicyFunc returns the project's `linear:` block, or nil when the project
// file has none or is invalid.
type PolicyFunc func(project string) *policy.Linear

// Redactor is the part of *redact.Registry the adapters use.
type Redactor interface {
	Redact(s string) (string, redact.Result)
}

var _ Redactor = (*redact.Registry)(nil)

// Config builds the four adapters.
type Config struct {
	Client   *Client
	Board    *Board
	Policy   PolicyFunc
	Redactor Redactor // optional
	Now      func() time.Time
}

func (c Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c Config) check() error {
	if c.Client == nil || c.Board == nil || c.Policy == nil {
		return errors.New("linear: the intake ops need a client, a board and a policy")
	}
	return nil
}

// Adapters returns the adapters by op kind. [kit.Bind] refuses to return them
// when an operation of [linearspec.Connector] has no adapter here, or an
// adapter here has no declaration.
func Adapters(cfg Config) (map[string]ops.Adapter, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	b := base{cfg: cfg}
	return kit.Bind(linearspec.Connector, map[string]ops.Adapter{
		OpList:    &listAdapter{base: b},
		OpComment: &commentAdapter{base: b},
		OpMove:    &moveAdapter{base: b},
		OpStates:  &statesAdapter{base: b},
	})
}

type base struct{ cfg Config }

func paramsInvalid(format string, a ...any) error {
	return &ops.Refusal{Code: ops.CodeParamsInvalid, Why: clip(fmt.Sprintf(format, a...), 400)}
}

func policyRefused(format string, a ...any) error {
	return &ops.Refusal{Code: ops.CodePolicyRefused, Why: clip(fmt.Sprintf(format, a...), 400)}
}

func scopeRefused(format string, a ...any) error {
	return &ops.Refusal{Code: ops.CodeScopePath, Surface: "scope", Why: clip(fmt.Sprintf(format, a...), 400)}
}

// policy checks who asks and returns the project's block. Only an orchestrator
// token asks for an intake op: no run profile lists them, and the
// adapter refuses a run as well.
func (b base) policy(r *ops.Request) (*policy.Linear, error) {
	if r.Caller == nil || r.Caller.Kind != ops.KindOrchestrator {
		return nil, &ops.Refusal{Code: ops.CodePolicyRefused, Surface: "scope",
			Why: r.Op + " is for the orchestrator token only, never for a run"}
	}
	if r.Target.Adapter != AdapterName {
		return nil, paramsInvalid("target.adapter must be %s", AdapterName)
	}
	pol := b.cfg.Policy(r.Project)
	if pol == nil {
		return nil, policyRefused("%s is refused for project %s: its policy file has no valid linear: block", r.Op, clip(r.Project, 60))
	}
	return pol, nil
}

// BoardRef is the target ref of intake.list and intake.states that means "the
// team of the project's linear: block", for a caller that does not know the key.
const BoardRef = linearspec.BoardRef

// teamTarget checks a target that names a team (intake.list, intake.states):
// the project's team key, or [BoardRef].
func (b base) teamTarget(r *ops.Request, pol *policy.Linear) error {
	if r.Target.Ref == BoardRef {
		return nil
	}
	if !teamRefRE.MatchString(r.Target.Ref) {
		return paramsInvalid("target.ref must be the team key, for example %s, or %s", pol.Team, BoardRef)
	}
	if r.Target.Ref != pol.Team {
		return scopeRefused("team %s is not the team of project %s (%s); the intake reads and writes one team only", r.Target.Ref, clip(r.Project, 60), pol.Team)
	}
	return nil
}

// issueTarget checks a target that names an issue (intake.comment,
// intake.move) and returns its identifier.
func (b base) issueTarget(r *ops.Request, pol *policy.Linear) (string, error) {
	m := identRefRE.FindStringSubmatch(r.Target.Ref)
	if m == nil {
		return "", paramsInvalid("target.ref must be an issue identifier such as %s-12", pol.Team)
	}
	if m[1] != pol.Team {
		return "", scopeRefused("issue %s is in team %s; project %s allows team %s only", r.Target.Ref, m[1], clip(r.Project, 60), pol.Team)
	}
	return r.Target.Ref, nil
}

// onlyParams refuses a param the op does not define.
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

func paramBool(p map[string]any, key string) (bool, error) {
	v, ok := p[key]
	if !ok {
		return false, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, paramsInvalid("param %s must be true or false", key)
	}
	return b, nil
}

func paramString(p map[string]any, key string) (string, error) {
	s, ok := p[key].(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", paramsInvalid("param %s is required and must be a non-empty string", key)
	}
	return s, nil
}

// checkText refuses text a person could misread on the board: invalid UTF-8,
// control characters (a tab and a newline are fine) and Unicode format
// characters (bidi overrides, zero-width joiners, the BOM).
func checkText(what, s string, max int) error {
	if len(s) > max {
		return paramsInvalid("%s is longer than %d bytes", what, max)
	}
	if !utf8.ValidString(s) {
		return paramsInvalid("%s is not valid UTF-8", what)
	}
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n':
		case r < ' ' || r == 0x7f || unicode.Is(unicode.C, r):
			return paramsInvalid("%s has a control or invisible character (U+%04X)", what, r)
		}
	}
	return nil
}

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

// guard reads the issue and applies the policy. A *ops.Refusal is a "no"; any
// other error means Linear could not be asked. It is the one function every
// write goes through, in Check and again in Execute.
func (b base) guard(ctx context.Context, pol *policy.Linear, ident string) (*Guard, error) {
	g, err := b.cfg.Client.Guard(ctx, ident, pol.Label)
	if errors.Is(err, ErrNotFound) {
		return nil, paramsInvalid("Linear has no issue %s that the app can see", ident)
	}
	if err != nil {
		return nil, credentialRefusal(err)
	}
	switch {
	case g.TeamKey != pol.Team:
		return nil, scopeRefused("issue %s is in team %s, not %s: the identifier is an old one; nothing was written", ident, clip(g.TeamKey, 12), pol.Team)
	case strings.EqualFold(strings.TrimSpace(g.TeamName), "engineering"):
		return nil, scopeRefused("issue %s is in the Engineering team, which the intake never writes to", ident)
	case !g.HasLabel:
		return nil, policyRefused("issue %s does not carry the label %q now: the intake writes only to items labelled so", ident, pol.Label)
	}
	return g, nil
}

// credentialRefusal turns a missing or refused Linear credential into a
// refusal the operator can read ("not connected", "Linear refused the app's
// credentials"): retrying cannot help. Any other error is returned as it is.
func credentialRefusal(err error) error {
	var te *TokenError
	switch {
	case errors.Is(err, ErrNotConnected):
		return policyRefused("%v", err)
	case errors.As(err, &te) && te.Status >= 400 && te.Status < 500:
		return policyRefused("Linear refused the app's client credentials (%s); check the OAuth app and the two vault secrets (docs/runbooks/linear-intake.md)", te.Code)
	}
	return err
}

// failed is the outcome of a write that Linear certainly did not carry out.
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

// writeErr turns the error of a write into an outcome. A refusal that had no
// effect is `failed`; anything else leaves the op `unconfirmed`, and res says
// what to look up.
func writeErr(err error, res map[string]any) (ops.Outcome, error) {
	var ref *ops.Refusal
	if errors.As(err, &ref) {
		return failed(errors.New(ref.Why), res), nil
	}
	if Definite(err) || errors.Is(err, ErrNotConnected) {
		return failed(err, res), nil
	}
	return ops.Outcome{Result: res}, err
}

// ---- text of results -------------------------------------------------------

// clean shortens s to max bytes on a rune boundary and removes control and
// format characters, keeping tabs and newlines. It is how Linear's text (which
// is not ours to trust) is put into a result.
func clean(s string, max int) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n':
			return r
		case r == '\r':
			return -1
		case r < ' ' || r == 0x7f || unicode.Is(unicode.C, r):
			return ' '
		}
		return r
	}, s)
	if len(s) <= max {
		return s
	}
	return strings.ToValidUTF8(s[:max-3], "") + "..."
}
