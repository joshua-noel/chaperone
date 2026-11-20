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
	if MaxLabelBytes != policy.LinearMaxLabel {
		t.Errorf("MaxLabelBytes = %d, policy.LinearMaxLabel = %d: a label name that the policy accepts must be one the params schema accepts", MaxLabelBytes, policy.LinearMaxLabel)
	}
}

func TestServedIsTheConnectorAndLinearsIssueComment(t *testing.T) {
	if err := Served.Validate(); err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, o := range Connector.Ops {
		want = append(want, o.Name)
	}
	var got []string
	for _, o := range Served.Ops {
		got = append(got, o.Name)
	}
	if len(got) != len(want)+1 {
		t.Fatalf("served %v, connector %v: Served must hold the connector's operations and issue.comment", got, want)
	}
	for _, n := range want {
		if n == NameIssueComment {
			t.Error("issue.comment is in Connector: its catalog entry is the GitHub one, and a second would be a duplicate")
		}
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
		"issue.get":      {"chap issue get <AGT-12> [--dry-run]", "read one Linear issue of the project's issue team"},
		"issue.list":     {"chap issue list [--state <type>] [--label <l>] [--cursor <c>] [--team <key>] [--dry-run]", "list Linear issues of the issue team, one page at a time"},
		"issue.move":     {"chap issue move <AGT-12> --state <name> [--dry-run]", "move a Linear issue to a state the policy lists"},
		"issue.link":     {"chap issue link <AGT-12> --url <u> [--title <t>] [--dry-run]", "attach a link from a listed host to a Linear issue"},
	}
	for _, o := range Connector.Ops {
		if o.CLI.Custom {
			continue // issue.label: written by hand in cmd/chap
		}
		w := want[o.Name]
		if o.CLIUsage() != w[0] || o.CLISummary() != w[1] {
			t.Errorf("%s: usage %q, summary %q", o.Name, o.CLIUsage(), o.CLISummary())
		}
	}
}
