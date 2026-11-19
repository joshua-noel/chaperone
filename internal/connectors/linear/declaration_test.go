package linear

import (
	"slices"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/connectors/linear/linearspec"
	"github.com/joshua-noel/chaperone/internal/ops"
)

// The adapters are exactly the declared operations: kit.Bind refuses a
// difference at start-up, and this shows it from the outside.
func TestAdaptersAreTheDeclaredOperations(t *testing.T) {
	r := newRig(t)
	var got []string
	for op := range r.ads {
		got = append(got, op)
	}
	slices.Sort(got)
	want := slices.Sorted(slices.Values(linearspec.Connector.Names()))
	if !slices.Equal(got, want) {
		t.Errorf("adapters %v, declared %v", got, want)
	}
	if !slices.Equal(Ops, linearspec.Connector.Names()) {
		t.Errorf("Ops = %v", Ops)
	}
}

// Each adapter refuses a param its declaration does not list, and names the
// declared ones: the allow-list is the declaration, not a second copy.
func TestEachAdapterTakesTheDeclaredParamsOnly(t *testing.T) {
	r := newRig(t)
	for _, o := range linearspec.Connector.Ops {
		ref := "SHOP-1"
		if o.Target.Flag != "" {
			ref = BoardRef
		}
		q := req(o.Name, ref, map[string]any{"made_up": true})
		_, err := r.ad(o.Name).Check(t.Context(), q)
		ref2 := wantRefusal(t, err, ops.CodeParamsInvalid)
		if !strings.Contains(ref2.Why, `unknown param "made_up"`) || !strings.Contains(ref2.Why, paramList(o.ParamNames())) {
			t.Errorf("%s: refusal %q does not name the declared params %v", o.Name, ref2.Why, o.ParamNames())
		}
	}
}
