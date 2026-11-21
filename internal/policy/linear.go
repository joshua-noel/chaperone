package policy

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Linear is the connector policy of one project (policy/<project>.yaml,
// `linear:`): the one Linear team and the one label the operator
// board intake may touch, and the workflow states `intake.move` may set. Like
// `pr:` and `google:` it adds data and enables nothing: the baseline keeps the
// intake ops off, and without this block the adapters refuse the project.
//
// It names no credential and no way to widen itself: the team, the label and
// the states are all there is. The adapters refuse any other team, any issue
// that does not carry the label right now, and any state that is not listed.
type Linear struct {
	// Team is the Linear team key ("SHOP"): the part of an issue identifier
	// before the dash. One team only.
	Team string
	// Label is the exact name of the label that marks an item as the orchestrator's.
	Label string
	// States are the workflow state names `intake.move` may move an item to,
	// exactly as the team spells them (`chap intake states` lists them). An
	// empty list means `intake.move` refuses every request.
	States []string
	// Issues is the optional `linear.issues:` block: where the key-facing
	// `issue.*` ops (the generic issue family) may work. It is
	// nil when the file has none, and then every `issue.*` request for Linear
	// is refused. It can never reach the operator board: see [LinearIssues].
	Issues *LinearIssues
	// IssuesInvalid is set when the `linear.issues` block cannot be used (it is dropped: Issues is nil). It names the
	// project, the file and the field. Only the Linear issue operations are off; the intake block and everything else
	// work. nil when the block is fine or absent.
	IssuesInvalid error
}

// LinearIssues is the policy of the generic `issue.get|list|comment|label|move|
// link` ops on Linear. They are for the orchestrator token (a custom key cannot hold an
// `issue.*` op: internal/ops/keyceiling.go), and they
// are fenced away from the operator board: the intake team and the intake label
// (the enclosing [Linear] Team and Label) are never reachable through them,
// whatever this block says (`intake_label_excluded`, the security review's P1).
// validate refuses a block that names either; the adapters check again on
// every read and write, so the exclusion does not rest on this file alone.
type LinearIssues struct {
	// Team is the one team key the issue ops work in. It must differ from the
	// intake team and must not be an Engineering mirror team.
	Team string
	// Label is the provenance label: a write (comment, label, move, link) acts
	// only on an issue that carries it now. It must differ from the intake label.
	Label string
	// States are the workflow state names `issue.move` may set. Empty means
	// `issue.move` refuses every request.
	States []string
	// Labels are the label names `issue.label` may add or remove. Empty means
	// `issue.label` refuses every request. Neither the provenance label nor the
	// intake label may be listed.
	Labels []string
	// LinkHosts are the host names `issue.link` may link to (lower case, exact
	// match, no port). Empty means `issue.link` refuses every request.
	LinkHosts []string
	// MaxMentions is the most people a comment may mention; zero (the default)
	// refuses any mention.
	MaxMentions int
	// Comment turns on Linear's side of `issue.comment`. The name is also the
	// GitHub op of the error watcher and is on in the baseline, so without this
	// switch the block would let every token that holds `issue.comment` comment
	// on Linear. False (the default) refuses every Linear comment.
	Comment bool
}

// Limits of the issues block.
const (
	LinearMaxIssueLabels = 20
	LinearMaxLinkHosts   = 20
	LinearMaxMentions    = 5
)

var linearHostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

func (i *LinearIssues) validate(intake *Linear) error {
	if !linearTeamRE.MatchString(i.Team) {
		return errors.New("issues.team must be a Linear team key: capital letters and digits, 2 to 10 characters")
	}
	if linearForbiddenTeams[i.Team] {
		return fmt.Errorf("issues.team %s is the Engineering mirror; the issue ops never write there", i.Team)
	}
	if i.Team == intake.Team {
		return fmt.Errorf("issues.team %s is the operator-board intake team; the issue ops never work there (intake_label_excluded)", i.Team)
	}
	if err := linearName("issues.label", i.Label, LinearMaxLabel); err != nil {
		return err
	}
	if strings.EqualFold(i.Label, intake.Label) {
		return fmt.Errorf("issues.label %q is the operator-board intake label; the issue ops never touch it (intake_label_excluded)", i.Label)
	}
	if len(i.States) > LinearMaxStates {
		return fmt.Errorf("issues.states lists %d names; at most %d", len(i.States), LinearMaxStates)
	}
	if err := distinctNames("issues.states entry", i.States, LinearMaxState); err != nil {
		return err
	}
	if len(i.Labels) > LinearMaxIssueLabels {
		return fmt.Errorf("issues.labels lists %d names; at most %d", len(i.Labels), LinearMaxIssueLabels)
	}
	if err := distinctNames("issues.labels entry", i.Labels, LinearMaxLabel); err != nil {
		return err
	}
	for _, l := range i.Labels {
		switch {
		case strings.EqualFold(l, intake.Label):
			return fmt.Errorf("issues.labels lists %q, the operator-board intake label (intake_label_excluded)", l)
		case strings.EqualFold(l, i.Label):
			return fmt.Errorf("issues.labels lists %q, the provenance label, which issue.label never adds or removes", l)
		}
	}
	if len(i.LinkHosts) > LinearMaxLinkHosts {
		return fmt.Errorf("issues.link_hosts lists %d hosts; at most %d", len(i.LinkHosts), LinearMaxLinkHosts)
	}
	seen := map[string]bool{}
	for _, h := range i.LinkHosts {
		if !linearHostRE.MatchString(h) || len(h) > 253 {
			return fmt.Errorf("issues.link_hosts entry %q must be a lower-case host name such as github.com", h)
		}
		if h == "linear.app" || strings.HasSuffix(h, ".linear.app") {
			return fmt.Errorf("issues.link_hosts lists %q: a link to Linear itself could point at an item of the operator board (intake_label_excluded)", h)
		}
		if seen[h] {
			return fmt.Errorf("issues.link_hosts lists %q twice", h)
		}
		seen[h] = true
	}
	if i.MaxMentions < 0 || i.MaxMentions > LinearMaxMentions {
		return fmt.Errorf("issues.max_mentions %d is outside 0..%d", i.MaxMentions, LinearMaxMentions)
	}
	return nil
}

// distinctNames checks a list of names: each valid, none repeated (ignoring case).
func distinctNames(what string, names []string, max int) error {
	seen := map[string]bool{}
	for _, s := range names {
		if err := linearName(what, s, max); err != nil {
			return err
		}
		k := strings.ToLower(s)
		if seen[k] {
			return fmt.Errorf("%s %q is listed twice", what, s)
		}
		seen[k] = true
	}
	return nil
}

var (
	linearTeamRE = regexp.MustCompile(`^[A-Z][A-Z0-9]{1,9}$`)
	// linearForbiddenTeams are team keys the connector never accepts. The
	// Engineering team is the one-way mirror of GitHub issues: a write there
	// can flow back to GitHub (work-tracking.md: "never write to Engineering").
	// The adapters also refuse any team whose name is "Engineering".
	linearForbiddenTeams = map[string]bool{"ENG": true, "ENGINEERING": true}
)

// Limits of the names in the block.
const (
	LinearMaxLabel  = 80
	LinearMaxState  = 80
	LinearMaxStates = 20
)

func (l *Linear) validate() error {
	if !linearTeamRE.MatchString(l.Team) {
		return errors.New("team must be a Linear team key: capital letters and digits, 2 to 10 characters, for example SHOP")
	}
	if linearForbiddenTeams[l.Team] {
		return fmt.Errorf("team %s is the Engineering mirror; the intake never writes there", l.Team)
	}
	if err := linearName("label", l.Label, LinearMaxLabel); err != nil {
		return err
	}
	if len(l.States) > LinearMaxStates {
		return fmt.Errorf("states lists %d names; at most %d", len(l.States), LinearMaxStates)
	}
	seen := map[string]bool{}
	for _, s := range l.States {
		if err := linearName("states entry", s, LinearMaxState); err != nil {
			return err
		}
		k := strings.ToLower(s)
		if seen[k] {
			return fmt.Errorf("states lists %q twice", s)
		}
		seen[k] = true
	}
	return nil
}

// issuesProblem checks the `linear.issues` block against the intake block and says what is wrong with it, naming the
// project, the file and the field, or returns nil. A bad block turns off the Linear issue operations and Linear's side
// of issue.comment for the project only: the intake block, the rest of the Linear block and every other block and op
// keep working (the same narrowing as a bad `pr.tiers` glob, [PR].Invalid). The caller drops the block, so a
// problem here is never a block that works.
func (l *Linear) issuesProblem(project string) error {
	if l.Issues == nil {
		return nil
	}
	if err := l.Issues.validate(l); err != nil {
		return fmt.Errorf("its policy file %s.yaml has a linear.issues block that cannot be used, so the Linear issue operations (issue.get, issue.list, issue.comment, issue.label, issue.move and issue.link on Linear) are off for project %s until it is fixed: %w", project, project, err)
	}
	return nil
}

// linearName checks a label or state name: one line of printable text with no
// leading or trailing space.
func linearName(what, s string, max int) error {
	switch {
	case s == "" || s != strings.TrimSpace(s):
		return fmt.Errorf("%s must be a name with no leading or trailing space", what)
	case len(s) > max || !utf8.ValidString(s):
		return fmt.Errorf("%s %q is not valid text of at most %d bytes", what, s, max)
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.C, r) {
			return fmt.Errorf("%s %q has a control character", what, s)
		}
	}
	return nil
}

// StateAllowed returns the policy's spelling of the state name s, compared
// without regard to case, and whether the policy lists it.
func (l *Linear) StateAllowed(s string) (string, bool) {
	for _, a := range l.States {
		if strings.EqualFold(a, s) {
			return a, true
		}
	}
	return "", false
}

// IntakeItem reports whether an issue with this team key and these label names
// is on the operator board: it is in the intake team or carries the intake
// label (compared without regard to case). The issue ops refuse such an item
// on every read and write; no field of [LinearIssues] can switch this off.
func (l *Linear) IntakeItem(teamKey string, labels []string) bool {
	if teamKey == l.Team {
		return true
	}
	for _, x := range labels {
		if strings.EqualFold(x, l.Label) {
			return true
		}
	}
	return false
}

// StateAllowed returns the block's spelling of the state name s, compared
// without regard to case, and whether `issue.move` may set it.
func (i *LinearIssues) StateAllowed(s string) (string, bool) { return foldFind(i.States, s) }

// LabelAllowed returns the block's spelling of the label name s and whether
// `issue.label` may add or remove it.
func (i *LinearIssues) LabelAllowed(s string) (string, bool) { return foldFind(i.Labels, s) }

// HostAllowed reports whether `issue.link` may link to the host.
func (i *LinearIssues) HostAllowed(host string) bool {
	for _, h := range i.LinkHosts {
		if h == host {
			return true
		}
	}
	return false
}

func foldFind(list []string, s string) (string, bool) {
	for _, a := range list {
		if strings.EqualFold(a, s) {
			return a, true
		}
	}
	return "", false
}
