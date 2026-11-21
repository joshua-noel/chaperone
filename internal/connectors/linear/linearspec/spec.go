// Package linearspec declares the operations of the Linear connector once: the
// four operator-board operations (`intake.list`, `intake.comment`,
// `intake.move`, `intake.states`) and the generic issue operations
// (`issue.get`, `issue.list`, `issue.label`, `issue.move`, `issue.link`, and
// Linear's side of `issue.comment`, see [IssueComment]).
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

// Adapter is `target.adapter` of every operation of the connector.
const Adapter = "linear"

// The op kinds.
const (
	NameList    = "intake.list"
	NameComment = "intake.comment"
	NameMove    = "intake.move"
	NameStates  = "intake.states"
)

// The generic issue op kinds. issue.comment is one name for two connectors
// (GitHub's and Linear's): see [IssueComment].
const (
	NameIssueGet     = "issue.get"
	NameIssueList    = "issue.list"
	NameIssueComment = "issue.comment"
	NameIssueLabel   = "issue.label"
	NameIssueMove    = "issue.move"
	NameIssueLink    = "issue.link"
)

// IssueTeamRef is the target ref of issue.list that means "the team of the
// project's linear.issues block", for a caller that does not know the key.
const IssueTeamRef = "team"

// StateTypes are the workflow state types issue.list may filter by.
var StateTypes = []string{"triage", "backlog", "unstarted", "started", "completed", "canceled"}

// StateTypePattern is the params-schema form of [StateTypes].
const StateTypePattern = `^(triage|backlog|unstarted|started|completed|canceled)$`

// CursorPattern is the shape of a page cursor of issue.list: an opaque value
// that chapd returned.
const CursorPattern = `^[A-Za-z0-9+/=_.:-]{1,200}$`

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
	// MaxLabelBytes is the longest label name. internal/policy bounds the
	// names of linear.issues.labels by the same number.
	MaxLabelBytes = 80
	// MaxLinkURLBytes and MaxLinkTitleBytes bound an issue.link.
	MaxLinkURLBytes   = 300
	MaxLinkTitleBytes = 120
)

// Connector is the connector's declaration.
//
// issue.comment is not in it, because its catalog entry is the GitHub one (the
// catalog has one entry for a name): see [IssueComment] and [Served].
var Connector = kit.Connector{
	Name: "linear",
	Ops:  []kit.Op{List, Comment, Move, States, IssueGet, IssueList, IssueLabel, IssueMove, IssueLink},
}

// Served is every operation the Linear adapters implement: [Connector] and
// Linear's side of issue.comment. [kit.Bind] pairs the adapters with it, and
// the conformance suite runs over it. The generated regions of api/ are written
// from [Connector] alone.
var Served = kit.Connector{
	Name: "linear",
	Ops:  []kit.Op{List, Comment, Move, States, IssueGet, IssueList, IssueComment, IssueLabel, IssueMove, IssueLink},
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

// issueTarget names one issue of the operator board, as the one positional
// argument.
var issueTarget = kit.Target{
	Adapter:    Adapter,
	Pattern:    IssueRefPattern,
	Why:        "the issue must be an identifier such as SHOP-12",
	Positional: "SHOP-12",
}

// issueOpTarget names one issue of the issue team, as the one positional
// argument.
var issueOpTarget = kit.Target{
	Adapter:    Adapter,
	Pattern:    IssueRefPattern,
	Why:        "the issue must be a Linear identifier such as AGT-12",
	Positional: "AGT-12",
}

// dryRunHelp is the help of the --dry-run flag of the issue commands.
const dryRunHelp = "evaluate policy and preconditions only; change nothing"

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

// IssueGet is issue.get.
var IssueGet = kit.Op{
	Name:          NameIssueGet,
	Class:         kit.Routine,
	Reversibility: kit.Reversible,
	Summary:       "Read one issue of the project's issue team.",
	Usage:         "chap issue get <AGT-12> [--dry-run]",
	RatePerMinute: 12,
	Doc:           "`issue.get` on Linear. Target is `{adapter: linear, ref: \"<issue identifier>\"}` in the project's `linear.issues.team`. No params. Read-only. An operator-board item (the intake team or label) is refused. The result is untrusted text (`untrusted_text: true`): title, description and comments are capped and withheld if they look like a secret.",
	Target:        issueOpTarget,
	CLI:           kit.CLI{Summary: "read one Linear issue of the project's issue team", DryRun: dryRunHelp},
}

// IssueList is issue.list.
var IssueList = kit.Op{
	Name:          NameIssueList,
	Class:         kit.Routine,
	Reversibility: kit.Reversible,
	Summary:       "List issues of the issue team, one page at a time.",
	Usage:         "chap issue list [--state <type>] [--label <l>] [--cursor <c>] [--team <key>] [--dry-run]",
	RatePerMinute: 12,
	Doc:           "`issue.list` on Linear. Target is `{adapter: linear, ref: \"<team key>\"}`, or `team` for the project's `linear.issues.team`. One page of at most 25 issues, newest change first, with `next_cursor` when there is more. Operator-board items never appear. `state` is a workflow state type (triage, backlog, unstarted, started, completed or canceled); `label` must not be the operator-board label. Text in the result is untrusted.",
	Target: kit.Target{
		Adapter: Adapter, Pattern: TeamRefPattern, Why: "--team must be a Linear team key such as AGT",
		Flag: "team", Placeholder: "key", Default: IssueTeamRef, Help: "team key (default: the project's linear issue team)",
	},
	Params: []kit.Param{
		{Name: "state", Kind: kit.String, Pattern: StateTypePattern, Why: "--state must be one of triage, backlog, unstarted, started, completed or canceled",
			Placeholder: "type", Help: "a workflow state type: triage, backlog, unstarted, started, completed or canceled"},
		{Name: "label", Kind: kit.String, MinLength: 1, MaxLength: MaxLabelBytes, Placeholder: "l", Help: "only issues with this label"},
		{Name: "cursor", Kind: kit.String, Pattern: CursorPattern, Why: "--cursor must be the next_cursor of a previous page", Placeholder: "c",
			Help: "the next_cursor of the previous page"},
	},
	CLI: kit.CLI{Summary: "list Linear issues of the issue team, one page at a time", DryRun: dryRunHelp},
}

// IssueComment is Linear's side of issue.comment. The name is one name for two
// connectors: the GitHub operation the error watcher uses
// (githubspec.IssueComment) and this one, told apart by `target.adapter`. There
// is one catalog entry and one params schema for a name, and they are generated
// from the GitHub declaration; this declaration is not in [Connector], so no
// region is written from it. It is in [Served], so the adapter is bound to it
// and the conformance suite runs over it. A test in package declared checks
// that it agrees with the GitHub declaration in everything the catalog states.
var IssueComment = kit.Op{
	Name:          NameIssueComment,
	Class:         kit.Routine,
	Reversibility: kit.Compensable,
	Summary:       "Comment on an issue the policy allows.",
	Usage:         "chap issue comment <n|AGT-12> [--body <b> | --body-file <f>]",
	RatePerMinute: 6,
	Doc:           "Linear side of `issue.comment`. Target is `{adapter: linear, ref: \"<issue identifier>\"}`, for example `AGT-12`; the issue must be in the project's `linear.issues.team`, carry `linear.issues.label` when the comment is posted, and never be an operator-board item (`intake_label_excluded`), and the block must set `linear.issues.comment: true`; `body` up to 4000 bytes.",
	Target:        issueOpTarget,
	Params: []kit.Param{
		{Name: "body", Kind: kit.Text, Required: true, MinLength: 1, MaxLength: MaxCommentBytes},
	},
	CLI: kit.CLI{Custom: true},
}

// IssueLabel is issue.label.
var IssueLabel = kit.Op{
	Name:          NameIssueLabel,
	Class:         kit.Routine,
	Reversibility: kit.Reversible,
	Summary:       "Add or remove one label from the policy's list.",
	Usage:         "chap issue label <AGT-12> --add <l> | --remove <l>",
	RatePerMinute: 6,
	Doc:           "`issue.label` on Linear. Target is `{adapter: linear, ref: \"<issue identifier>\"}`. Exactly one of `add` and `remove`: a name from the project's `linear.issues.labels`. The provenance label and the operator-board label are never added or removed. Linear adds or removes that one label; other labels are not touched.",
	Target:        issueOpTarget,
	Params: []kit.Param{
		{Name: "add", Kind: kit.String, MinLength: 1, MaxLength: MaxLabelBytes, Placeholder: "l", Help: "a label to add (one of the policy's list)"},
		{Name: "remove", Kind: kit.String, MinLength: 1, MaxLength: MaxLabelBytes, Placeholder: "l", Help: "a label to remove (one of the policy's list)"},
	},
	// Custom: the command refuses a call with both flags or neither, which a
	// generated command cannot express, and the schema has no one-of yet.
	CLI: kit.CLI{Custom: true},
}

// IssueMove is issue.move.
var IssueMove = kit.Op{
	Name:          NameIssueMove,
	Class:         kit.Routine,
	Reversibility: kit.Reversible,
	Summary:       "Move an issue to a state the policy lists.",
	Usage:         "chap issue move <AGT-12> --state <name> [--dry-run]",
	RatePerMinute: 6,
	Doc:           "`issue.move` on Linear. Target is `{adapter: linear, ref: \"<issue identifier>\"}`. `state` must be one of the project's `linear.issues.states` and a state of the issue's team.",
	Target:        issueOpTarget,
	Params: []kit.Param{
		{Name: "state", Kind: kit.String, Required: true, MinLength: 1, MaxLength: MaxStateBytes, Placeholder: "name",
			Help: "the state's name (one of the policy's list) (required)"},
	},
	CLI: kit.CLI{Summary: "move a Linear issue to a state the policy lists", DryRun: dryRunHelp},
}

// IssueLink is issue.link.
var IssueLink = kit.Op{
	Name:          NameIssueLink,
	Class:         kit.Routine,
	Reversibility: kit.Reversible,
	Summary:       "Attach a link, from a listed host, to an issue.",
	Usage:         "chap issue link <AGT-12> --url <u> [--title <t>] [--dry-run]",
	RatePerMinute: 6,
	Doc:           "`issue.link` on Linear. Target is `{adapter: linear, ref: \"<issue identifier>\"}`. `url` is an https URL whose host is in the project's `linear.issues.link_hosts` (exact match, no port, no user name); one attachment per issue and URL.",
	Target:        issueOpTarget,
	Params: []kit.Param{
		{Name: "url", Kind: kit.String, Required: true, MinLength: 1, MaxLength: MaxLinkURLBytes, Placeholder: "u",
			Help: "an https URL on one of the policy's hosts (required)"},
		{Name: "title", Kind: kit.String, MinLength: 1, MaxLength: MaxLinkTitleBytes, Placeholder: "t", Help: "the link's title (optional)"},
	},
	CLI: kit.CLI{Summary: "attach a link from a listed host to a Linear issue", DryRun: dryRunHelp},
}
