// Package conformance is the shared test of the rules in docs/connectors.md. A
// connector's own test calls [Run] with its declared operations, a way to build
// its adapters against a fake service, and a few sample requests for each
// operation. The suite then drives the REAL adapter code against the fake and
// reports, per operation and per rule, what broke.
//
// The seven checks:
//
//  1. [CheckNoSideEffects]: Check sends no write to the service, however often
//     it runs, answers the same each time, and does not change the request.
//  2. [CheckExecuteActsOnce]: Execute twice with one execution id changes the
//     service once. An operation that cannot promise this says so in
//     [Op].NotRepeatable, and the suite then checks that the declaration is
//     true.
//  3. [CheckNoSecretInOutput]: a credential never appears in a CheckResult, an
//     Outcome, an error, a refusal or a log line. The suite plants a canary as
//     the credential where the fake allows it, and also looks for every
//     credential value the fake saw.
//  4. [CheckRefusalCodes]: every refusal is a *ops.Refusal with a cause code
//     chapd knows.
//  5. [CheckParamsAndLimits]: an undeclared param, a missing required param, a
//     value of the wrong kind and a value past a declared limit are refused by
//     the adapter itself, in Check and in Execute.
//  6. [CheckServiceText]: text that came from the service is cleaned of control
//     and format characters and capped, in the result, in the check lines and
//     in refusals. An operation of the [ServiceText] kind also marks the
//     result `untrusted_text` and withholds an item that looks like a secret;
//     an operation that returns no service text echoes none. Rule 5 of
//     docs/connectors.md says which is which.
//  7. [CheckClassMatchesPin]: the operation's declared class and reversibility
//     are the ones written in the independent pin table.
//
// What the suite does not prove is listed in docs/write-a-connector.md.
//
// A connector that cannot yet pass a check for an operation lists the check in
// [Op].Known with the reason. The suite still runs the check: it reports the
// gap as a skip, and fails when the gap has closed, so the list cannot go
// stale.
package conformance

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/connectors/kit"
	"github.com/joshua-noel/chaperone/internal/ops"
)

// CheckID names one of the seven checks.
type CheckID string

// The seven checks, in the order of docs/write-a-connector.md.
const (
	CheckNoSideEffects    CheckID = "check_has_no_side_effects"
	CheckExecuteActsOnce  CheckID = "execute_acts_once"
	CheckNoSecretInOutput CheckID = "no_secret_in_output"
	CheckRefusalCodes     CheckID = "refusals_have_a_known_code"
	CheckParamsAndLimits  CheckID = "params_and_limits_are_enforced"
	CheckServiceText      CheckID = "service_text_is_untrusted"
	CheckClassMatchesPin  CheckID = "class_matches_pin"
)

// Checks lists the checks in the order Run runs them.
var Checks = []CheckID{
	CheckNoSideEffects, CheckExecuteActsOnce, CheckNoSecretInOutput, CheckRefusalCodes,
	CheckParamsAndLimits, CheckServiceText, CheckClassMatchesPin,
}

// Canary is the value the suite hands to [Connector].NewRig to use as the
// connector's credential. It is long enough for the redaction registry and is
// never a real secret.
const Canary = "canary-credential-7f3b91c2e45d8a06b1f94c73d2e8"

// UntrustedFlag is the key of the result that marks service text. It is the
// flag rule 5 of docs/connectors.md names.
const UntrustedFlag = "untrusted_text"

// ExecutionID is the id the suite gives every Execute call.
const ExecutionID = "x-conformance-1"

// Connector is what a connector's test hands to [Run].
type Connector struct {
	// Declared is the connector's declaration (the kit value its spec package
	// exports).
	Declared kit.Connector
	// Pins is the independent table of class and reversibility written by hand
	// (internal/connectors/pintable). It may hold more operations than this
	// connector declares.
	Pins map[string]kit.Pin
	// NewRig builds a fresh fake service and the connector's real adapters
	// against it. canary is the credential value to use where the fake lets
	// the test choose it. Every call must return an independent rig: the suite
	// builds many.
	NewRig func(t testing.TB, canary string) *Rig
	// Ops holds the sample requests of each declared operation. An operation
	// with no entry fails the suite: nothing is skipped by leaving it out.
	Ops map[string]Op
}

// Rig is one fake service with the connector's adapters wired to it.
type Rig struct {
	// Adapters are the connector's adapters by op kind: the same set chapd
	// registers.
	Adapters map[string]ops.Adapter
	// WriteCalls is how many calls that could change the service the fake has
	// received so far, accepted or not. A read, and a call that only mints or
	// revokes the connector's own credential, is not one.
	WriteCalls func() int
	// WritesApplied is how many of those calls the fake accepted and acted on.
	WritesApplied func() int
	// Secrets returns every credential value the connector held or sent so far,
	// including values the fake minted (an access token).
	Secrets func() []string
	// Logs returns what the connector wrote to a logger of its own. Optional:
	// the suite also captures the default slog and log output.
	Logs func() string
	// Hostile, when set, makes the fake behave like a careless service: it
	// rejects the credential and echoes what it received in its error text. The
	// suite runs the valid samples again and looks for the credential.
	Hostile func()
	// World is the connector's own handle on the fake, for sample builders.
	World any
}

// Sample is one request. Req builds it against the rig, so it can name state the
// rig seeded. The suite sets ExecutionID; a sample leaves it empty.
type Sample struct {
	Name string
	Req  func(r *Rig) *ops.Request
	// Code is the cause code a refusal must carry (Invalid samples only). Empty
	// means any known code.
	Code string
}

// Text says what an operation does with text written by the service.
type Text int

const (
	// NoServiceText: the operation's result, checks and errors carry no text
	// the service wrote (a comment write, a move).
	NoServiceText Text = iota + 1
	// ServiceText: the result carries text the service wrote (titles, bodies,
	// comments, names). Rule 5 applies in full: the text is cleaned and capped,
	// the result is marked `untrusted_text`, and an item whose text looks like
	// a secret is withheld by the adapter.
	ServiceText
	// CleanedText: the result, a check or a refusal carries text the service
	// wrote, cleaned and capped, and nothing more: the suite does not ask for
	// the `untrusted_text` mark or for withholding. It is for text that is
	// part of the answer (a path in a risk check, a state name), where the
	// front end marks the result and chapd redacts it as a whole.
	CleanedText
)

// Op is the samples and declarations of one operation.
type Op struct {
	// Valid are requests the adapter must accept: Check passes and Execute
	// succeeds. The first one is the base of the generated parameter checks.
	Valid []Sample
	// Invalid are requests Check must refuse with a refusal. Cover each refusal
	// the adapter makes by hand: a caller who may not ask, a target of another
	// scope, a value the declaration cannot express.
	Invalid []Sample
	// ReadOnly says the operation never writes: the suite then fails it when
	// Execute sends a write. An operation that is not read-only must change the
	// fake for at least one valid sample, or the idempotency check proves
	// nothing.
	ReadOnly bool
	// NotRepeatable, when set, declares the operation not safe to repeat: a
	// second Execute with the same execution id acts again, and the text says
	// why that is accepted. The suite then checks the declaration: the second
	// Execute must change the fake again. Empty means "acts once".
	NotRepeatable string
	// Text says what the operation does with service text. Required.
	Text Text
	// Plant puts the planted text where the first valid sample will read it
	// from the fake: Control as the main text (a title, a name), Long as a long
	// text (a body), Secret as text beside them. A field that is empty is not
	// planted; leave benign text there. The suite calls Plant on a fresh rig,
	// more than once with different fields. Required.
	Plant func(r *Rig, p Planted)
	// Known lists checks this operation does not pass yet, with the reason. See
	// the package comment.
	Known map[CheckID]string
}

// Planted is the hostile service text the suite asks a connector to plant.
type Planted struct {
	// Control has words around a bidi override, a zero-width joiner and a BEL.
	// A connector that cleans text turns the three characters into spaces or
	// drops them, and the words stay.
	Control string
	// Secret is shaped like a GitHub token. The redaction check matches it.
	Secret string
	// Long is far longer than any cap an operation has.
	Long string
}

// ControlWord is the middle word of [Planted].Control: text that must survive
// cleaning, so the suite can tell the text reached the result.
const ControlWord = "bravo"

// NewPlanted returns the planted text.
func NewPlanted() Planted {
	return Planted{
		Control: "alpha\u202e" + ControlWord + "\u200dcharlie\x07delta",
		Secret:  "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
		Long:    strings.Repeat("0123456789abcdef", 24_000),
	}
}

// Run runs the suite: for every declared operation, the seven checks, each as
// a subtest. A connector's test calls it once.
func Run(t *testing.T, c Connector) {
	t.Helper()
	if errs := Problems(c); len(errs) > 0 {
		for _, e := range errs {
			t.Error(e)
		}
		t.FailNow()
	}
	for _, o := range c.Declared.Ops {
		t.Run(o.Name, func(t *testing.T) {
			for _, id := range Checks {
				t.Run(string(id), func(t *testing.T) {
					problems := Evaluate(t, c, o.Name, id)
					reason := c.Ops[o.Name].Known[id]
					switch {
					case reason != "" && len(problems) == 0:
						t.Errorf("this check is listed as a known gap (%q) and now passes: remove it from Known", reason)
					case reason != "":
						t.Skipf("known gap: %s\n    the check says: %s", reason, strings.Join(problems, "\n    "))
					default:
						for _, p := range problems {
							t.Error(p)
						}
					}
				})
			}
		})
	}
}

// Evaluate runs one check of one operation and returns what it found wrong. It
// reports nothing itself: Run turns the answer into test failures, and the
// suite's own tests read it to show that each check can fail.
func Evaluate(t testing.TB, c Connector, op string, id CheckID) []string {
	t.Helper()
	h := &harness{t: t, c: c, op: op, spec: c.Ops[op]}
	for _, o := range c.Declared.Ops {
		if o.Name == op {
			h.decl = o
		}
	}
	if h.decl.Name == "" {
		return []string{fmt.Sprintf("%s is not declared by connector %s", op, c.Declared.Name)}
	}
	switch id {
	case CheckNoSideEffects:
		return h.checkNoSideEffects()
	case CheckExecuteActsOnce:
		return h.checkActsOnce()
	case CheckNoSecretInOutput:
		return h.checkNoSecret()
	case CheckRefusalCodes:
		return h.checkRefusalCodes()
	case CheckParamsAndLimits:
		return h.checkParamsAndLimits()
	case CheckServiceText:
		return h.checkServiceText()
	case CheckClassMatchesPin:
		return h.checkPin()
	}
	return []string{fmt.Sprintf("unknown check %q", id)}
}

// validate checks what the suite needs before it can run anything.
func (c Connector) validate() []string {
	var errs []string
	if err := c.Declared.Validate(); err != nil {
		errs = append(errs, "the declaration is invalid: "+err.Error())
	}
	if c.NewRig == nil {
		errs = append(errs, "Connector.NewRig is not set")
	}
	declared := map[string]bool{}
	for _, o := range c.Declared.Ops {
		declared[o.Name] = true
		spec, ok := c.Ops[o.Name]
		switch {
		case !ok:
			errs = append(errs, fmt.Sprintf("%s: no samples. Add an entry to Connector.Ops; an operation cannot be left out", o.Name))
			continue
		case len(spec.Valid) == 0:
			errs = append(errs, fmt.Sprintf("%s: no valid sample", o.Name))
		case spec.Text != NoServiceText && spec.Text != ServiceText && spec.Text != CleanedText:
			errs = append(errs, fmt.Sprintf("%s: Text is not set: say whether the operation returns text from the service", o.Name))
		case spec.Plant == nil:
			errs = append(errs, fmt.Sprintf("%s: Plant is not set: say where service text lives in the fake", o.Name))
		}
		for _, s := range append(append([]Sample(nil), spec.Valid...), spec.Invalid...) {
			if s.Name == "" || s.Req == nil {
				errs = append(errs, fmt.Sprintf("%s: a sample needs a Name and a Req", o.Name))
			}
		}
		for id, reason := range spec.Known {
			if strings.TrimSpace(reason) == "" {
				errs = append(errs, fmt.Sprintf("%s: Known[%s] has no reason", o.Name, id))
			}
			if !knownCheck(id) {
				errs = append(errs, fmt.Sprintf("%s: Known lists %q, which is not a check", o.Name, id))
			}
		}
	}
	var stray []string
	for name := range c.Ops {
		if !declared[name] {
			stray = append(stray, name)
		}
	}
	sort.Strings(stray)
	for _, name := range stray {
		errs = append(errs, fmt.Sprintf("Connector.Ops has samples for %s, which the connector does not declare", name))
	}
	return errs
}

func knownCheck(id CheckID) bool {
	for _, c := range Checks {
		if c == id {
			return true
		}
	}
	return false
}

// Problems returns what is wrong with the input itself: an operation with no
// samples, a missing Text or Plant, a Known entry with no reason. Run reports
// the same list and stops.
func Problems(c Connector) []string { return c.validate() }
