// Package linearspec declares the four operations of the Linear connector
// (`intake.list`, `intake.comment`, `intake.move`, `intake.states`) once.
//
// It holds the facts that used to be typed by hand in the adapter map, the
// `chap` command table, the API manual, the params schema and the baseline: the
// name, class, reversibility, summary, usage line, rate, target and parameters
// of each operation. It holds no behaviour. The conditions under which an
// operation is allowed, its idempotency and its handling of Linear's text are
// in the parent package, [github.com/joshua-noel/chaperone/internal/connectors/linear].
//
// The package imports only the kit, so the `chap` client can use it without
// linking the daemon's code.
package linearspec

import "github.com/joshua-noel/chaperone/internal/connectors/kit"

// Adapter is `target.adapter` of every intake operation.
const Adapter = "linear"

// The op kinds.
const (
	NameList    = "intake.list"
	NameComment = "intake.comment"
	NameMove    = "intake.move"
	NameStates  = "intake.states"
)

// BoardRef is the target ref of intake.list and intake.states that means "the
// team of the project's linear: block", for a caller that does not know the key.
const BoardRef = "board"

// The shapes of a target ref. A team key is two to ten capitals and digits; an
// issue identifier is a team key, a dash and a number.
const (
	TeamRefPattern  = `^[A-Z][A-Z0-9]{1,9}$`
	IssueRefPattern = `^([A-Z][A-Z0-9]{1,9})-[1-9][0-9]{0,8}$`
)

// Limits of what a caller may send.
const (
	// MaxCommentBytes is the longest comment. "Picked up by the orchestrator"
	// and a few links need a fraction of it.
	MaxCommentBytes = 4000
	// MaxStateBytes is the longest state name. internal/policy bounds the
	// names of linear.states by the same number (a test checks that they agree).
	MaxStateBytes = 80
)

// Connector is the connector's declaration.
var Connector = kit.Connector{
	Name: "linear",
	Ops:  []kit.Op{List, Comment, Move, States},
}

// teamTarget names a team, by flag: the team of the project when it is left out.
var teamTarget = kit.Target{
	Adapter:     Adapter,
	Pattern:     TeamRefPattern,
	Why:         "--team must be a Linear team key such as SHOP",
	Flag:        "team",
	Placeholder: "key",
	Default:     BoardRef,
	Help:        "team key (default: the project's linear team)",
}

// issueTarget names one issue, as the one positional argument.
var issueTarget = kit.Target{
	Adapter:    Adapter,
	Pattern:    IssueRefPattern,
	Why:        "the issue must be an identifier such as SHOP-12",
	Positional: "SHOP-12",
}

// List is intake.list.
var List = kit.Op{
	Name:          NameList,
	Class:         kit.Routine,
	Reversibility: kit.Reversible,
	Summary:       "List open board items labelled for the orchestrator.",
	Usage:         "chap intake list [--refresh] [--closed]",
	RatePerMinute: 12,
	Doc:           "Phase 1 shape for `intake.list`. Target is `{adapter: linear, ref: \"<team key>\"}`; the team must be the project's `linear.team`. Only the orchestrator token asks. `refresh` asks for a live read (answered from the cache when the last read is under 30 s old); `closed` also returns completed and canceled items (always a live read). Titles, descriptions and comments in the result are untrusted text.",
	Target:        teamTarget,
	Params: []kit.Param{
		{Name: "refresh", Kind: kit.Bool, Help: "read Linear now instead of the cache (chapd still answers from the cache when the last read is under 30 s old)"},
		{Name: "closed", Kind: kit.Bool, Help: "also list completed and canceled items"},
	},
	CLI: kit.CLI{Summary: "list the board items labelled for the orchestrator"},
}

// Comment is intake.comment.
var Comment = kit.Op{
	Name:          NameComment,
	Class:         kit.Routine,
	Reversibility: kit.Compensable,
	Summary:       "Comment on a labelled operator-board item.",
	Usage:         "chap intake comment <SHOP-12> --body <b>",
	RatePerMinute: 6,
	Doc:           "Phase 1 shape for `intake.comment`. Target is `{adapter: linear, ref: \"<issue identifier>\"}`, for example `SHOP-12`; the issue must be in the project's `linear.team` and carry the `linear.label` label when the comment is posted.",
	Target:        issueTarget,
	Params: []kit.Param{
		{Name: "body", Kind: kit.Text, Required: true, MinLength: 1, MaxLength: MaxCommentBytes},
	},
}

// Move is intake.move.
var Move = kit.Op{
	Name:          NameMove,
	Class:         kit.Routine,
	Reversibility: kit.Reversible,
	Summary:       "Move a labelled operator-board item to a listed state.",
	Usage:         "chap intake move <SHOP-12> --state <name>",
	RatePerMinute: 6,
	Doc:           "Phase 1 shape for `intake.move`. Target is `{adapter: linear, ref: \"<issue identifier>\"}`. `state` must be one of the project's `linear.states` and a state of the issue's team.",
	Target:        issueTarget,
	Params: []kit.Param{
		{Name: "state", Kind: kit.String, Required: true, MinLength: 1, MaxLength: MaxStateBytes, Placeholder: "name",
			Help: "the state's name, as `chap intake states` shows it (required)"},
	},
}

// States is intake.states.
var States = kit.Op{
	Name:          NameStates,
	Class:         kit.Routine,
	Reversibility: kit.Reversible,
	Summary:       "List the board team's states and the policy's.",
	Usage:         "chap intake states",
	RatePerMinute: 6,
	Doc:           "Phase 1 shape for `intake.states`. Target is `{adapter: linear, ref: \"<team key>\"}`. No params.",
	Target:        teamTarget,
	CLI:           kit.CLI{Summary: "list the board team's states and which a move may use"},
}
