package resend

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/joshua-noel/chaperone/internal/connectors/kit"
	"github.com/joshua-noel/chaperone/internal/connectors/resend/resendspec"
	"github.com/joshua-noel/chaperone/internal/connectors/untrusted"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/redact"
)

// The op kinds. The names, the classes and every other fact about an op are
// declared once, in [resendspec]; this file holds what the adapters do.
//
// mail.send is one name for two connectors: the Google connector's adapter
// (target.adapter google) and this one (target.adapter resend). chapd puts both
// behind [ops.ByTarget]. The policy (enabled, rate, token scope) is per op name,
// so the name being on turns neither connector on by itself: this adapter
// refuses every project whose policy file has no valid `resend:` block.
const (
	OpSend   = resendspec.NameSend
	OpStatus = resendspec.NameStatus
)

// Ops lists the op kinds the adapters serve.
var Ops = resendspec.Served.Names()

// AdapterName is the target adapter every op names.
const AdapterName = resendspec.Adapter

// Caps of the text a result carries. Resend's text is not ours to trust.
const (
	maxMessageID = 64
	withheld     = "[withheld: the text looks like a secret]"
)

var (
	senderRE = regexp.MustCompile(resendspec.AddressPattern)
	// recipientRE is the same shape as a sender: one bare, lower-case ASCII
	// address. No display name, no <> characters, no quotes, no comments, no
	// IDN, no upper case: a header-injection or look-alike trick has no
	// character to hide in, and the card shows exactly what is sent.
	recipientRE = senderRE
)

// PolicyFunc returns the project's `resend:` block, or nil when the project file
// has none.
type PolicyFunc func(project string) *policy.Resend

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
	// no message is refused for it.
	Redactor Redactor
}

// Adapters returns the adapters by op kind. [kit.Bind] refuses to return them
// when an operation of [resendspec.Served] has no adapter here, or an adapter
// here has no declaration.
func Adapters(cfg Config) (map[string]ops.Adapter, error) {
	if cfg.Client == nil || cfg.Policy == nil {
		return nil, errors.New("resend: the adapters need a client and a policy")
	}
	if cfg.Redactor == nil {
		return nil, errors.New("resend: the adapters need a redactor")
	}
	b := base{cfg: cfg}
	return kit.Bind(resendspec.Served, map[string]ops.Adapter{
		OpSend:   &sendAdapter{base: b},
		OpStatus: &statusAdapter{base: b},
	})
}

type base struct{ cfg Config }

// ---- refusals ---------------------------------------------------------------
//
// A request that is not allowed is a *ops.Refusal with a cause code from
// internal/ops/denial.go. A plain error means "Resend could not be asked", and
// chapd fails closed. A refusal never repeats a name that the request made and
// the policy does not list.

func paramsInvalid(format string, a ...any) error {
	return &ops.Refusal{Code: ops.CodeParamsInvalid, Why: clip(fmt.Sprintf(format, a...), 400)}
}

func policyRefused(format string, a ...any) error {
	return &ops.Refusal{Code: ops.CodePolicyRefused, Why: clip(fmt.Sprintf(format, a...), 400)}
}

// resolve checks who asks and returns the project's block. Only an orchestrator
// token asks: the host-interim profile lists mail.send for a run, and this
// connector does not accept that; a custom key cannot hold either op.
func (b base) resolve(r *ops.Request) (*policy.Resend, error) {
	if r.Caller == nil || r.Caller.Kind != ops.KindOrchestrator {
		return nil, &ops.Refusal{Code: ops.CodePolicyRefused, Surface: "scope",
			Why: r.Op + " through Resend is for the orchestrator token only, never for a run or a key"}
	}
	if r.Target.Adapter != AdapterName {
		return nil, paramsInvalid("target.adapter must be %s", AdapterName)
	}
	pol := b.cfg.Policy(r.Project)
	switch {
	case pol == nil:
		return nil, policyRefused("%s through Resend is refused for project %s: its policy file has no valid resend: block", r.Op, clip(r.Project, 60))
	case pol.Invalid != nil:
		return nil, policyRefused("%s through Resend is refused for project %s: %s", r.Op, clip(r.Project, 60), clip(pol.Invalid.Error(), 900))
	}
	return pol, nil
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

// paramString reads a required, non-empty string param.
func paramString(p map[string]any, key string) (string, error) {
	s, ok := p[key].(string)
	if !ok || s == "" {
		return "", paramsInvalid("param %s is required and must be a non-empty string", key)
	}
	return s, nil
}

// paramStrings reads a list-of-strings param. A missing key is an empty list.
func paramStrings(p map[string]any, key string) ([]string, error) {
	v, present := p[key]
	if !present {
		return nil, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, paramsInvalid("param %s must be a list of strings", key)
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		s, ok := e.(string)
		if !ok {
			return nil, paramsInvalid("param %s must be a list of strings", key)
		}
		out = append(out, s)
	}
	return out, nil
}

// checkText refuses text a human could misread on a card or in a mail client:
// invalid UTF-8, control characters (a tab and, when multiline, a newline are
// the exceptions) and Unicode format characters (bidi overrides, zero-width
// joiners, the BOM). It is the rule of the Google connector's mail.send.
func checkText(what, s string, multiline bool, max int) error {
	if len(s) > max {
		return paramsInvalid("%s is longer than %d bytes", what, max)
	}
	if !utf8.ValidString(s) {
		return paramsInvalid("%s is not valid UTF-8", what)
	}
	for _, r := range s {
		switch {
		case r == '\t' || (multiline && r == '\n'):
		case r < ' ' || r == 0x7f || unicode.Is(unicode.C, r):
			return paramsInvalid("%s has a control or invisible character (U+%04X)", what, r)
		}
	}
	return nil
}

// ---- text ---------------------------------------------------------------------

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

// looksSecret reports whether text would trip the redaction check. A result
// that holds such text is withheld whole.
func (b base) looksSecret(texts ...string) bool {
	_, res := b.cfg.Redactor.Redact(strings.Join(texts, "\n"))
	return res.Blocked()
}

// scan refuses text that looks like a secret, before it is sent.
func (b base) scan(where, s string) error {
	if s == "" {
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

// serviceText is text from Resend, cleaned of control and format characters by
// [untrusted.Line], capped, and withheld whole when it looks like a secret. It
// is for display only: no decision is made on it.
func (b base) serviceText(s string, max int) (text string, held bool) {
	if b.looksSecret(s) {
		return withheld, true
	}
	s = untrusted.Line(s)
	if len(s) > max {
		s = strings.ToValidUTF8(s[:max-3], "") + "..."
	}
	return s, false
}

// failed is the outcome of an op that changed nothing: a refusal, or a read that
// did not work, so the caller may ask again.
func failed(err error, res map[string]any) ops.Outcome {
	if res == nil {
		res = map[string]any{}
	}
	text := err.Error()
	var ref *ops.Refusal
	if errors.As(err, &ref) {
		text = ref.Why
	}
	res["error"] = clip(text, 400)
	return ops.Outcome{Failed: true, Result: res}
}

// ---- errors from Resend ---------------------------------------------------------

// reason turns an error of the client into one fixed sentence that says what
// happened and what to do. None of it comes from Resend: only the status and a
// word from a closed list are used.
func reason(err error) string {
	var ae *APIError
	switch {
	case errors.Is(err, ErrNoSendKey), errors.Is(err, ErrNoStatusKey):
		return err.Error()
	case errors.As(err, &ae):
		return apiReason(ae)
	}
	return err.Error()
}

func apiReason(ae *APIError) string {
	switch {
	case ae.Code == "restricted_api_key" && ae.Status == 401:
		return "Resend says this API key is restricted to sending email, which cannot do what was asked: a read needs a key with the Full access permission (docs/runbooks/resend.md)"
	case ae.Status == 401 || ae.Status == 403 && (ae.Code == "restricted_api_key" || ae.Code == "suspended_api_key" || ae.Code == "invalid_permission"):
		return fmt.Sprintf("Resend refused the API key (HTTP %d, %s): check that it is active, that it has the permission the operation needs, and the vault secret (docs/runbooks/resend.md)", ae.Status, ae.Code)
	case ae.Status == 429:
		s := fmt.Sprintf("Resend's rate or quota limit is used up (%s)", ae.Code)
		if ae.RetryAfter > 0 {
			s += fmt.Sprintf("; retry in %d s", ae.RetryAfter)
		}
		return s
	case ae.Status >= 300 && ae.Status < 400:
		return fmt.Sprintf("Resend answered with a redirect (HTTP %d), which chapd does not follow", ae.Status)
	case ae.Status == 404:
		return "Resend answered not found (HTTP 404)"
	case ae.Status == 409:
		return fmt.Sprintf("Resend answered with a conflict about the idempotency key (%s)", ae.Code)
	case ae.Status >= 400 && ae.Status < 500:
		return fmt.Sprintf("Resend refused the request (HTTP %d, %s)", ae.Status, ae.Code)
	}
	return fmt.Sprintf("Resend answered HTTP %d", ae.Status)
}

// credentialRefusal turns a missing key into a refusal the operator can read:
// asking again cannot help. Any other error is returned as it is.
func credentialRefusal(err error) error {
	if errors.Is(err, ErrNoSendKey) || errors.Is(err, ErrNoStatusKey) {
		return policyRefused("%v", err)
	}
	return err
}
