package declared

import (
	"fmt"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/joshua-noel/chaperone/api"
	"github.com/joshua-noel/chaperone/internal/connectors/kit"
	"github.com/joshua-noel/chaperone/internal/connectors/linear/linearspec"
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
	manual, err = kit.Splice(kit.Manual, manual, []kit.Connector{five})
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
	openapi, err = kit.Splice(kit.OpenAPI, openapi, []kit.Connector{five})
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
