package linearspec

import (
	"testing"

	"github.com/joshua-noel/chaperone/internal/policy"
)

func TestConnectorIsValid(t *testing.T) {
	if err := Connector.Validate(); err != nil {
		t.Fatal(err)
	}
}

// The numbers the policy package bounds the same inputs by.
func TestLimitsAgreeWithThePolicyPackage(t *testing.T) {
	if MaxStateBytes != policy.LinearMaxState {
		t.Errorf("MaxStateBytes = %d, policy.LinearMaxState = %d: a state name that the policy accepts must be one the params schema accepts", MaxStateBytes, policy.LinearMaxState)
	}
}

// The command line is generated, and these are the words a person reads. A
// change here is a change of what `chap intake` prints and documents.
func TestGeneratedCommandLines(t *testing.T) {
	want := map[string][2]string{
		"intake.list":    {"chap intake list [--refresh] [--closed] [--team <key>]", "list the board items labelled for the orchestrator"},
		"intake.comment": {"chap intake comment <SHOP-12> [--body <b> | --body-file <f>]", "comment on a labelled operator-board item"},
		"intake.move":    {"chap intake move <SHOP-12> --state <name>", "move a labelled operator-board item to a listed state"},
		"intake.states":  {"chap intake states [--team <key>]", "list the board team's states and which a move may use"},
	}
	for _, o := range Connector.Ops {
		w := want[o.Name]
		if o.CLIUsage() != w[0] || o.CLISummary() != w[1] {
			t.Errorf("%s: usage %q, summary %q", o.Name, o.CLIUsage(), o.CLISummary())
		}
	}
}
