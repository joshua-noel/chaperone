package declared

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/joshua-noel/chaperone/api"
	"github.com/joshua-noel/chaperone/internal/connectors/github/githubspec"
	"github.com/joshua-noel/chaperone/internal/connectors/google"
	"github.com/joshua-noel/chaperone/internal/connectors/kit"
	"github.com/joshua-noel/chaperone/internal/connectors/linear/linearspec"
	"github.com/joshua-noel/chaperone/internal/connectors/pintable"
	"github.com/joshua-noel/chaperone/internal/connectors/resend/resendspec"
	"github.com/joshua-noel/chaperone/internal/policy"
)

const repoRoot = "../../.."

func TestDeclarationsAreValidAndNamedOnce(t *testing.T) {
	seen := map[string]string{}
	names := map[string]bool{}
	for _, c := range Connectors() {
		if err := c.Validate(); err != nil {
			t.Errorf("%s: %v", c.Name, err)
		}
		if names[c.Name] {
			t.Errorf("connector %s is listed twice", c.Name)
		}
		names[c.Name] = true
		for _, o := range c.Ops {
			if other, dup := seen[o.Name]; dup {
				t.Errorf("%s is declared by %s and by %s: one name, one connector", o.Name, other, c.Name)
			}
			seen[o.Name] = c.Name
		}
	}
	if len(Ops()) != len(seen) {
		t.Errorf("Ops lists %d operations, the connectors declare %d", len(Ops()), len(seen))
	}
}

// pins is the class and reversibility of every declared operation. The table is
// written out by hand in internal/connectors/pintable, where the conformance
// suite reads it too. It is the one table for all connectors: a connector that
// is added to Connectors() without pins fails the test below, and a change of
// class needs this second, deliberate edit beside the declaration and the
// generated manual entry.
var pins = pintable.Pins

func TestEveryDeclaredOpIsPinned(t *testing.T) {
	declaredNames := map[string]bool{}
	for _, c := range Connectors() {
		mine := map[string]kit.Pin{}
		for _, o := range c.Ops {
			declaredNames[o.Name] = true
			if p, ok := pins[o.Name]; ok {
				mine[o.Name] = p
			}
		}
		for _, d := range kit.DiffPins(c, mine) {
			t.Errorf("%s: %s", c.Name, d)
		}
	}
	// mail.send is one name for two connectors and is in no connector's Ops: its
	// catalog entry is written by hand (Gmail's), and Resend's side is
	// resendspec.MailSend. See TestTheSharedMailSendAgreesWithTheCatalogAndGmail.
	declaredNames[resendspec.MailSend.Name] = true
	for name := range pins {
		if !declaredNames[name] {
			t.Errorf("pins lists %s, which no connector declares", name)
		}
	}
}

// The four classes of the kit are the four classes of the policy package, with
// the same spelling, and the same three values of reversibility.
func TestKitClassesAgreeWithPolicy(t *testing.T) {
	for kitClass, policyClass := range map[kit.Class]policy.Class{
		kit.Routine: policy.ClassRoutine, kit.Gated: policy.ClassGated, kit.High: policy.ClassHigh, kit.Critical: policy.ClassCritical,
	} {
		if string(kitClass) != string(policyClass) || !kitClass.Valid() || !policyClass.Valid() {
			t.Errorf("kit class %q and policy class %q disagree", kitClass, policyClass)
		}
	}
	// Nothing the policy package accepts is missing from the kit.
	for _, c := range []policy.Class{"routine", "gated", "high", "critical"} {
		if !kit.Class(c).Valid() {
			t.Errorf("policy class %q is not a kit class", c)
		}
	}
	if kit.Class("low").Valid() || policy.Class("low").Valid() {
		t.Error("an unknown class is valid")
	}
	// Reversibility: the catalog loader accepts exactly these three.
	for _, r := range []kit.Reversibility{kit.Reversible, kit.Compensable, kit.Irreversible} {
		src := "version: 1\nops:\n  x.y:\n    class: routine\n    reversibility: " + string(r) + "\n    surface: op\n    summary: s\n    usage: u\n"
		if r == kit.Irreversible {
			src = strings.Replace(src, "routine", "high", 1)
		}
		if _, err := policy.LoadCatalog([]byte(src)); err != nil || !r.Valid() {
			t.Errorf("reversibility %q: the catalog loader says %v", r, err)
		}
	}
}

// The generated regions of api/manual.yaml and api/openapi.yaml are the
// declarations, byte for byte. A changed declaration with no regeneration, and
// a hand edit inside a region, both fail here.
func TestGeneratedRegionsAreUpToDate(t *testing.T) {
	changed, err := kit.SyncAll(repoRoot, Connectors(), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range changed {
		t.Errorf("%s is out of date with the declarations of internal/connectors; run `%s`", f, kit.Regenerate)
	}
}

// What the loader of the catalog (internal/policy) reads must say what the
// declaration says, and a declared op must not also be written by hand: the
// catalog loader refuses a duplicate key, and this checks the text as well.
func TestCatalogAgreesWithTheDeclarations(t *testing.T) {
	cat, err := policy.DefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := api.Files.ReadFile("manual.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, o := range Ops() {
		e, ok := cat.Lookup(o.Name)
		if !ok {
			t.Errorf("%s is declared and not in the catalog", o.Name)
			continue
		}
		if !policy.Class(o.Class).Valid() || e.Class != policy.Class(o.Class) {
			t.Errorf("%s: catalog class %q, declared %q", o.Name, e.Class, o.Class)
		}
		if e.Reversibility != string(o.Reversibility) || e.Surface != policy.SurfaceOp || e.Summary != o.Summary || e.Usage != o.Usage {
			t.Errorf("%s: the catalog entry %+v differs from the declaration", o.Name, e)
		}
		if n := strings.Count(text, "\n  "+o.Name+":\n"); n != 1 {
			t.Errorf("%s has %d entries in api/manual.yaml, want 1 (the generated one)", o.Name, n)
		}
	}
}

// The baseline pack stays hand-written: it is where an op is turned on. A
// declared op must have its rule there, and the rate must be the declared one.
func TestBaselineHasARuleForEveryDeclaredOp(t *testing.T) {
	_, base, err := policy.Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range Ops() {
		r, ok := base.Ops[o.Name]
		switch {
		case !ok:
			t.Errorf("internal/policy/data/baseline.yaml has no rule for %s; add: %s", o.Name, baselineLine(o))
		case r.RatePerMinute != o.RatePerMinute:
			t.Errorf("%s: the baseline rate is %d per minute and the declaration says %d; change one", o.Name, r.RatePerMinute, o.RatePerMinute)
		}
	}
}

// baselineLine is the line that goes in the baseline for a new op. It is
// always off: turning an op on is a policy change, reviewed on its own.
func baselineLine(o kit.Op) string {
	return fmt.Sprintf("  %s: { enabled: false, rate_per_minute: %d }", o.Name, o.RatePerMinute)
}

// A tiny read-only operation that is not in the shipped catalog. It shows what
// a fifth Linear operation needs: this declaration, and its adapter (here a
// string stands for it). Nothing else is edited. The test generates the manual
// entry and the params schema in memory, loads them with the real loaders, and
// shows the one thing that still lives outside the connector: the baseline rule
// that turns the op on, which is policy and fails closed until it is written.
func TestAFifthOperationNeedsOnlyItsDeclarationAndAnAdapter(t *testing.T) {
	show := kit.Op{
		Name:          "intake.show",
		Class:         kit.Routine,
		Reversibility: kit.Reversible,
		Summary:       "Show one labelled board item.",
		Usage:         "chap intake show <SHOP-12>",
		RatePerMinute: 12,
		Doc:           "Target is `{adapter: linear, ref: \"<issue identifier>\"}`. No params.",
		Target: kit.Target{
			Adapter:    linearspec.Adapter,
			Pattern:    linearspec.IssueRefPattern,
			Why:        "the issue must be an identifier such as SHOP-12",
			Positional: "SHOP-12",
		},
	}
	five := kit.Connector{Name: linearspec.Connector.Name, Ops: append(append([]kit.Op(nil), linearspec.Connector.Ops...), show)}
	if err := five.Validate(); err != nil {
		t.Fatal(err)
	}

	// 1. The adapter is bound: without it, start-up refuses.
	impls := map[string]string{}
	for _, n := range linearspec.Connector.Names() {
		impls[n] = "adapter"
	}
	if _, err := kit.Bind(five, impls); err == nil || !strings.Contains(err.Error(), "intake.show") {
		t.Fatalf("a declared op without an adapter must be refused at start-up: %v", err)
	}
	impls["intake.show"] = "adapter"
	if _, err := kit.Bind(five, impls); err != nil {
		t.Fatal(err)
	}

	// 2. The manual entry and the params schema are generated.
	manual, err := api.Files.ReadFile("manual.yaml")
	if err != nil {
		t.Fatal(err)
	}
	manual, err = kit.Splice(kit.Manual, manual, swapLinear(five))
	if err != nil {
		t.Fatal(err)
	}
	cat, err := policy.LoadCatalog(manual)
	if err != nil {
		t.Fatalf("the generated manual must load: %v", err)
	}
	e, ok := cat.Lookup("intake.show")
	if !ok || e.Class != policy.ClassRoutine || e.Surface != policy.SurfaceOp || e.Usage != show.Usage {
		t.Fatalf("catalog entry = %+v, %v", e, ok)
	}
	openapi, err := api.Files.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	openapi, err = kit.Splice(kit.OpenAPI, openapi, swapLinear(five))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]map[string]any `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(openapi, &doc); err != nil {
		t.Fatal(err)
	}
	if s := doc.Components.Schemas[show.ParamsSchemaName()]; s["additionalProperties"] != false || s["type"] != "object" {
		t.Errorf("params schema = %v", s)
	}

	// 3. The baseline is the one place left, on purpose: without a rule the
	// pack does not load, and the rule the author adds is off.
	if _, err := policy.LoadBaseline(policy.BaselineBytes(), cat); err == nil || !strings.Contains(err.Error(), "intake.show") {
		t.Fatalf("the baseline must refuse a catalog op with no rule: %v", err)
	}
	anchor := "  intake.states:"
	base := string(policy.BaselineBytes())
	i := strings.Index(base, anchor)
	if i < 0 {
		t.Fatal("test anchor not found in the baseline")
	}
	end := i + strings.Index(base[i:], "\n") + 1
	withRule := base[:end] + baselineLine(show) + "\n" + base[end:]
	pack, err := policy.LoadBaseline([]byte(withRule), cat)
	if err != nil {
		t.Fatal(err)
	}
	if pack.ForProject("acme-shop").Enabled("intake.show") {
		t.Error("a new op must be off until a policy change turns it on")
	}
}

// swapLinear is the declared connectors with the Linear one replaced by c, so a
// test can add an operation to Linear and still splice every other region.
func swapLinear(c kit.Connector) []kit.Connector {
	var out []kit.Connector
	for _, d := range Connectors() {
		if d.Name == c.Name {
			d = c
		}
		out = append(out, d)
	}
	return out
}

// paramPins is the params of every operation that is not routine, written out
// by hand like the class pins. The adapter's allow-list is the declaration, so
// adding a param to a declaration widens what the adapter accepts; for an
// operation that needs approval or a gate, that takes this second edit.
var paramPins = map[string][]string{
	"pr.merge": {"base", "head_sha", "method"},
}

func TestNonRoutineOpsPinTheirParams(t *testing.T) {
	for _, o := range Ops() {
		if o.Class == kit.Routine {
			if _, ok := paramPins[o.Name]; ok {
				t.Errorf("%s is routine and has a params pin: delete the pin", o.Name)
			}
			continue
		}
		want, ok := paramPins[o.Name]
		if !ok {
			t.Errorf("%s is %s: add its params to paramPins", o.Name, o.Class)
			continue
		}
		if got := o.ParamNames(); !slices.Equal(got, want) {
			t.Errorf("%s: declared params %v, the pin says %v", o.Name, got, want)
		}
	}
	for name := range paramPins {
		found := false
		for _, o := range Ops() {
			found = found || o.Name == name
		}
		if !found {
			t.Errorf("paramPins lists %s, which no connector declares", name)
		}
	}
}

// issue.comment is one name for two connectors, and the catalog has one entry
// for a name, generated from the GitHub declaration. Linear's declaration of the
// same name (linearspec.IssueComment) is not generated from, so it must agree
// with the GitHub one in everything the catalog states, and the catalog's
// params schema must say what Linear's side takes too.
func TestTheSharedIssueCommentAgreesAcrossConnectors(t *testing.T) {
	gh, ln := githubspec.IssueComment, linearspec.IssueComment
	if gh.Name != ln.Name || gh.Class != ln.Class || gh.Reversibility != ln.Reversibility ||
		gh.Summary != ln.Summary || gh.Usage != ln.Usage || gh.RatePerMinute != ln.RatePerMinute {
		t.Errorf("the two declarations of %s disagree on what the catalog states:\n github %+v\n linear %+v", gh.Name, gh, ln)
	}
	if !strings.Contains(gh.Doc, "`target.adapter`") || !strings.Contains(gh.Doc, "adapter: linear") || !strings.Contains(gh.Doc, "adapter: github") {
		t.Errorf("the catalog's description of %s must name both connectors and say that target.adapter picks one: %q", gh.Name, gh.Doc)
	}
	if !strings.Contains(gh.Doc, fmt.Sprintf("%d bytes", linearspec.MaxCommentBytes)) || !strings.Contains(gh.Doc, fmt.Sprint(githubspec.IssueBodyMax)) {
		t.Errorf("the catalog's description of %s must state both body limits (%d and %d): %q", gh.Name, githubspec.IssueBodyMax, linearspec.MaxCommentBytes, gh.Doc)
	}
	// The pin is one entry, so the Linear side is bound by the same class.
	if p, ok := pins[ln.Name]; !ok || p.Class != ln.Class || p.Reversibility != ln.Reversibility {
		t.Errorf("the pin of %s is %+v", ln.Name, p)
	}
	for _, o := range linearspec.Connector.Ops {
		if o.Name == ln.Name {
			t.Errorf("%s is in linearspec.Connector: it would be generated twice", o.Name)
		}
	}
}

// mail.send is one name for two connectors, Gmail (target.adapter google, not a
// declared connector yet) and Resend (target.adapter resend), and the catalog has
// one entry for a name, written by hand. Resend's declaration of the same name
// (resendspec.MailSend) is not generated from, so it must agree with that entry in
// everything the catalog states, with the baseline rule and the pin, and with
// Gmail's limits: one name has one set of limits, whichever connector the target
// picks. It takes the params of the Gmail side less `attachments`, and the test
// writes the list out by hand, so a new param is a second, deliberate edit.
func TestTheSharedMailSendAgreesWithTheCatalogAndGmail(t *testing.T) {
	s := resendspec.MailSend
	cat, base, err := policy.Default()
	if err != nil {
		t.Fatal(err)
	}
	e, ok := cat.Lookup(s.Name)
	if !ok {
		t.Fatalf("%s is not in the catalog", s.Name)
	}
	if e.Class != policy.Class(s.Class) || e.Reversibility != string(s.Reversibility) || e.Surface != policy.SurfaceOp ||
		e.Summary != s.Summary || e.Usage != s.Usage {
		t.Errorf("the catalog entry %+v and the Resend declaration %+v disagree on what the catalog states", e, s)
	}
	if e.Class != policy.ClassHigh || e.Reversibility != "irreversible" {
		t.Errorf("mail.send is %s/%s: it is high and irreversible, and needs the operator's approval every time", e.Class, e.Reversibility)
	}
	if r, ok := base.Ops[s.Name]; !ok || r.RatePerMinute != s.RatePerMinute || r.Enabled {
		t.Errorf("the baseline rule of mail.send is %+v: the declared rate is %d and it ships off", r, s.RatePerMinute)
	}
	if p, ok := pins[s.Name]; !ok || p.Class != s.Class || p.Reversibility != s.Reversibility {
		t.Errorf("the pin of %s is %+v", s.Name, p)
	}
	for _, o := range resendspec.Connector.Ops {
		if o.Name == s.Name {
			t.Errorf("%s is in resendspec.Connector: its catalog entry would be generated twice", o.Name)
		}
	}
	if !slices.Contains(resendspec.Served.Names(), s.Name) {
		t.Errorf("%s is not served", s.Name)
	}
	if !strings.Contains(s.Usage, "--via resend") {
		t.Errorf("the usage of mail.send does not say how to choose Resend: %q", s.Usage)
	}
	// The params, written out by hand: Gmail's without `attachments`.
	if got, want := s.ParamNames(), []string{"to", "cc", "bcc", "subject", "body"}; !slices.Equal(got, want) {
		t.Errorf("declared params %v, the pin says %v", got, want)
	}
	// One name, one set of limits.
	for _, c := range []struct {
		what          string
		resend, gmail int
	}{
		{"recipients", resendspec.MaxRecipients, google.MaxRecipients},
		{"subject bytes", resendspec.MaxSubjectBytes, google.MaxSubjectBytes},
		{"body bytes", resendspec.MaxBodyBytes, google.MaxBodyBytes},
	} {
		if c.resend != c.gmail {
			t.Errorf("limit of %s: Resend %d, Gmail %d", c.what, c.resend, c.gmail)
		}
	}
	// The ref of the Gmail side is a sending address with the same shape.
	if !strings.Contains(resendspec.AddressPattern, "[a-z0-9._+-]{0,63}@") {
		t.Error("the address pattern is not the one the Google connector and the policy use")
	}
}
