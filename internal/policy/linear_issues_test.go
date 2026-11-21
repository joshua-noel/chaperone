package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
    link_hosts: [github.com, docs.example.org]
    comment: true
    max_mentions: 1
`

func TestLinearIssuesBlockLoads(t *testing.T) {
	eff, err := linearProject(t, issuesBlock)
	if err != nil {
		t.Fatal(err)
	}
	i := eff.Linear.Issues
	if i == nil || i.Team != "AGT" || i.Label != "agent" || len(i.States) != 2 || len(i.Labels) != 2 || len(i.LinkHosts) != 2 || i.MaxMentions != 1 || !i.Comment {
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
// block could name them. A mistake in the block turns off the Linear issue operations only (the block is dropped,
// and the error names the project, the file and the field); a key the file format does not know still refuses the
// whole file.
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
		eff, err := linearProject(t, "linear:\n  team: SHOP\n  label: Claude\n  issues:\n    "+c.block)
		if c.want == "" { // not a mistake in the block but in the file: still refused whole
			if err == nil {
				t.Errorf("%s: accepted", name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: the whole project was refused: %v", name, err)
			continue
		}
		if eff.Linear == nil || eff.Linear.Issues != nil || eff.Linear.IssuesInvalid == nil || !strings.Contains(eff.Linear.IssuesInvalid.Error(), c.want) {
			t.Errorf("%s: the block is not off with a reason holding %q: %+v", name, c.want, eff.Linear)
			continue
		}
		if msg := eff.Linear.IssuesInvalid.Error(); !strings.Contains(msg, eff.Project+".yaml") || !strings.Contains(msg, "project "+eff.Project) || !strings.Contains(msg, "linear.issues") {
			t.Errorf("%s: the reason does not name the project and the file: %s", name, msg)
		}
		// The intake block and the rest of the project work.
		if eff.Linear.Team != "SHOP" || eff.Linear.Label != "Claude" || eff.Invalid != nil {
			t.Errorf("%s: the intake block was lost: %+v", name, eff.Linear)
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

// Linear's side of issue.comment has its own switch, off by default: the name
// is on in the baseline for GitHub, so a block with no switch must not turn
// Linear comments on.
func TestLinearIssuesCommentIsOffUnlessTheBlockSaysSo(t *testing.T) {
	block := "linear:\n  team: SHOP\n  label: Claude\n  issues:\n    team: AGT\n    label: agent\n"
	eff, err := linearProject(t, block)
	if err != nil {
		t.Fatal(err)
	}
	if eff.Linear.Issues.Comment {
		t.Error("a block with no comment key turned Linear comments on")
	}
	for _, v := range []string{"true", "false"} {
		eff, err := linearProject(t, block+"    comment: "+v+"\n")
		if err != nil || eff.Linear.Issues.Comment != (v == "true") {
			t.Errorf("comment: %s: %v %+v", v, err, eff)
		}
	}
	if _, err := linearProject(t, block+"    comment: perhaps\n"); err == nil {
		t.Error("comment: perhaps was accepted")
	}
}

// A link to Linear itself could point at an item of the operator board, so the
// host list may not name Linear or any of its subdomains. The mistake turns off
// the Linear issue operations of the project, like every other mistake in the block.
func TestLinearIssuesLinkHostsRefuseLinear(t *testing.T) {
	for _, h := range []string{"linear.app", "www.linear.app", "a.b.linear.app"} {
		eff, err := linearProject(t, "linear:\n  team: SHOP\n  label: Claude\n  issues:\n    team: AGT\n    label: agent\n    link_hosts: [github.com, "+h+"]\n")
		if err != nil || eff.Linear.Issues != nil || eff.Linear.IssuesInvalid == nil ||
			!strings.Contains(eff.Linear.IssuesInvalid.Error(), "linear.app") || !strings.Contains(eff.Linear.IssuesInvalid.Error(), "intake_label_excluded") {
			t.Errorf("link_hosts %s: %v %+v", h, err, eff)
		}
	}
	// A host that only ends in the same letters is not Linear.
	if _, err := linearProject(t, "linear:\n  team: SHOP\n  label: Claude\n  issues:\n    team: AGT\n    label: agent\n    link_hosts: [notlinear.app, linear.app.example.org]\n"); err != nil {
		t.Errorf("an unrelated host was refused: %v", err)
	}
}

// The engine follows the same convention as a bad pr.tiers glob: a mistake in the linear.issues block leaves the
// project usable and the intake block in force, Problems says which block is off, and fixing the file turns the
// issue operations back on on the next read.
func TestEngineTurnsLinearIssuesOffAndBackOn(t *testing.T) {
	cat, base := mustDefault(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "acme-shop.yaml")
	bad := "project: acme-shop\n" + strings.Replace(issuesBlock, "label: agent", "label: Claude", 1)
	if err := os.WriteFile(file, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	eng := NewEngine(cat, base, dir)
	eng.now = func() time.Time { return now }

	eff := eng.For("acme-shop")
	if eff.Invalid != nil {
		t.Fatalf("the project must stay valid: %v", eff.Invalid)
	}
	if eff.Linear == nil || eff.Linear.Team != "SHOP" || eff.Linear.Issues != nil || eff.Linear.IssuesInvalid == nil {
		t.Fatalf("the intake block is lost or the issues block is not off: %+v", eff.Linear)
	}
	for _, want := range []string{"acme-shop.yaml", "project acme-shop", "issues.label"} {
		if !strings.Contains(eff.Linear.IssuesInvalid.Error(), want) {
			t.Errorf("the reason lacks %q: %v", want, eff.Linear.IssuesInvalid)
		}
	}
	problems := eng.Problems()
	if len(problems) != 1 || problems[0].Project != "acme-shop" || problems[0].File != "acme-shop.yaml" || problems[0].Block != "linear.issues" || problems[0].Err == nil {
		t.Errorf("Problems = %+v", problems)
	}

	if err := os.WriteFile(file, []byte("project: acme-shop\n"+issuesBlock), 0o600); err != nil {
		t.Fatal(err)
	}
	now = now.Add(5 * time.Second)
	if eff := eng.For("acme-shop"); eff.Linear == nil || eff.Linear.Issues == nil || eff.Linear.IssuesInvalid != nil {
		t.Errorf("the fixed file is still off: %+v", eff.Linear)
	}
	if p := eng.Problems(); len(p) != 0 {
		t.Errorf("Problems after the fix: %+v", p)
	}
}
