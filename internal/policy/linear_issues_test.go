package policy

import (
	"strings"
	"testing"
)

const issuesBlock = `
linear:
  team: SHOP
  label: Claude
  states: [Done]
  issues:
    team: AGT
    label: agent
    states: [In Progress, Done]
    labels: [bug, triaged]
    link_hosts: [github.com, linear.app]
    max_mentions: 1
`

func TestLinearIssuesBlockLoads(t *testing.T) {
	eff, err := linearProject(t, issuesBlock)
	if err != nil {
		t.Fatal(err)
	}
	i := eff.Linear.Issues
	if i == nil || i.Team != "AGT" || i.Label != "agent" || len(i.States) != 2 || len(i.Labels) != 2 || len(i.LinkHosts) != 2 || i.MaxMentions != 1 {
		t.Fatalf("block: %+v", i)
	}
	if s, ok := i.StateAllowed("done"); !ok || s != "Done" {
		t.Errorf("StateAllowed(done) = %q %v", s, ok)
	}
	if s, ok := i.LabelAllowed("BUG"); !ok || s != "bug" {
		t.Errorf("LabelAllowed(BUG) = %q %v", s, ok)
	}
	if _, ok := i.LabelAllowed("Claude"); ok {
		t.Error("the intake label is allowed")
	}
	if !i.HostAllowed("github.com") || i.HostAllowed("evil.github.com") || i.HostAllowed("GITHUB.COM") {
		t.Error("HostAllowed is not an exact match on the listed host")
	}
	// The block adds data and enables nothing.
	cat, base := mustDefault(t)
	plain, err := base.LoadProject("acme-shop", []byte("project: acme-shop\n"), cat)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"issue.get", "issue.list", "issue.label", "issue.move", "issue.link"} {
		if eff.Enabled(op) || eff.Enabled(op) != plain.Enabled(op) {
			t.Errorf("%s is enabled, or the issues block changed its enablement", op)
		}
	}
	// No issues block: nil, and the issue ops refuse the project.
	if eff, err := linearProject(t, "linear:\n  team: SHOP\n  label: Claude\n"); err != nil || eff.Linear.Issues != nil {
		t.Errorf("no issues block: %v %v", eff, err)
	}
}

// No field of the issues block can reach the operator board (the security
// review's P1): the intake team and the intake label are refused wherever the
// block could name them, and the whole file is refused.
func TestLinearIssuesBlockCannotNameTheOperatorBoard(t *testing.T) {
	long := strings.Repeat("a", LinearMaxLabel+1)
	for name, c := range map[string]struct{ block, want string }{
		"the intake team":            {"team: SHOP\n    label: agent\n", "intake"},
		"the intake label":           {"team: AGT\n    label: Claude\n", "intake"},
		"the intake label, any case": {"team: AGT\n    label: CLAUDE\n", "intake"},
		"intake label in labels":     {"team: AGT\n    label: agent\n    labels: [bug, claude]\n", "intake"},
		"provenance label in labels": {"team: AGT\n    label: agent\n    labels: [Agent]\n", "provenance"},
		"engineering mirror":         {"team: ENG\n    label: agent\n", "Engineering"},
		"no team":                    {"label: agent\n", "team"},
		"lower-case team":            {"team: agt\n    label: agent\n", "team"},
		"no label":                   {"team: AGT\n", "label"},
		"label too long":             {"team: AGT\n    label: " + long + "\n", "label"},
		"duplicate state":            {"team: AGT\n    label: agent\n    states: [Done, done]\n", "twice"},
		"duplicate label":            {"team: AGT\n    label: agent\n    labels: [bug, BUG]\n", "twice"},
		"too many labels":            {"team: AGT\n    label: agent\n    labels: [" + strings.TrimSuffix(strings.Repeat("l,", LinearMaxIssueLabels+1), ",") + "]\n", "at most"},
		"host with a path":           {"team: AGT\n    label: agent\n    link_hosts: [github.com/x]\n", "host"},
		"upper-case host":            {"team: AGT\n    label: agent\n    link_hosts: [GitHub.com]\n", "host"},
		"host with a port":           {"team: AGT\n    label: agent\n    link_hosts: [\"github.com:443\"]\n", "host"},
		"wildcard host":              {"team: AGT\n    label: agent\n    link_hosts: [\"*.github.com\"]\n", "host"},
		"duplicate host":             {"team: AGT\n    label: agent\n    link_hosts: [github.com, github.com]\n", "twice"},
		"too many mentions":          {"team: AGT\n    label: agent\n    max_mentions: 6\n", "max_mentions"},
		"negative mentions":          {"team: AGT\n    label: agent\n    max_mentions: -1\n", "max_mentions"},
		"unknown field":              {"team: AGT\n    label: agent\n    intake_label_excluded: false\n", ""},
		"an enabled flag":            {"team: AGT\n    label: agent\n    enabled: true\n", ""},
	} {
		_, err := linearProject(t, "linear:\n  team: SHOP\n  label: Claude\n  issues:\n    "+c.block)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want one with %q", name, err, c.want)
		}
	}
}

func TestIntakeItemIsTheIntakeTeamOrTheIntakeLabel(t *testing.T) {
	l := &Linear{Team: "SHOP", Label: "Claude"}
	for _, c := range []struct {
		team   string
		labels []string
		want   bool
	}{
		{"SHOP", nil, true},
		{"AGT", []string{"Claude"}, true},
		{"AGT", []string{"bug", "claude"}, true},
		{"AGT", []string{"CLAUDE"}, true},
		{"AGT", []string{"bug", "agent"}, false},
		{"AGT", nil, false},
	} {
		if got := l.IntakeItem(c.team, c.labels); got != c.want {
			t.Errorf("IntakeItem(%s, %v) = %v, want %v", c.team, c.labels, got, c.want)
		}
	}
}
