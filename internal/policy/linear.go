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
