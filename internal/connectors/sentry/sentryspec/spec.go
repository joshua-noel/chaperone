// Package sentryspec declares the operations of the Sentry connector once: the
// facts that the catalog, the params schema, the `chap` command and the
// adapter binding are all made from. It holds no behaviour.
//
// The package imports only the kit, so the `chap` client can use it without
// linking the daemon's code.
package sentryspec

import "github.com/joshua-noel/chaperone/internal/connectors/kit"

// Adapter is `target.adapter` of every operation of the connector.
const Adapter = "sentry"

// The op kinds.
const (
	NameList      = "errors.list"
	NameGet       = "errors.get"
	NameResolve   = "errors.resolve"
	NameUnresolve = "errors.unresolve"
	NameAssign    = "errors.assign"
	NameComment   = "errors.comment"
)

// The shapes of a target ref. errors.list names a Sentry project by its slug;
// every other operation names one issue by its numeric id (the `id` Sentry
// gives, not the short id such as WEB-1A).
const (
	ProjectRefPattern = `^[a-z0-9][a-z0-9_-]{0,49}$`
	IssueRefPattern   = `^[1-9][0-9]{0,17}$`
)

// The filters of errors.list. Each is a closed word list, so the connector
// builds Sentry's search query from fixed pieces and no caller text reaches it.
const (
	StatusPattern = `^(unresolved|resolved|ignored)$`
	LevelPattern  = `^(fatal|error|warning|info|debug)$`
	// CursorPattern is the shape of the page cursor Sentry gives in its Link
	// header: three fields separated by colons, for example 1735689600000:0:0.
	CursorPattern = `^[0-9]{1,20}:[0-9]{1,10}:[01]$`
	// AssigneePattern is the shape of a member: an email address or a username.
	// It has no colon, so the "user:" and "team:" forms cannot be written.
	AssigneePattern = `^[A-Za-z0-9][A-Za-z0-9._%+@-]{0,99}$`
)

// Limits of what a caller may send and of what a result carries.
const (
	// MaxCommentBytes is the longest note.
	MaxCommentBytes = 2000
	// MaxAssigneeBytes is the longest member name.
	MaxAssigneeBytes = 100
	// DefaultLimit and MaxLimit bound a page of errors.list.
	DefaultLimit = 10
	MaxLimit     = 25
)

// Connector is the connector's declaration.
var Connector = kit.Connector{
	Name: "sentry",
	Ops:  []kit.Op{List, Get, Resolve, Unresolve, Assign, Comment},
}

// dryRunHelp is the help of the --dry-run flag.
const dryRunHelp = "evaluate policy and preconditions only; change nothing"

// issueTarget names one issue by its numeric id, as the one positional
// argument.
var issueTarget = kit.Target{
	Adapter:    Adapter,
	Pattern:    IssueRefPattern,
	Why:        "the issue must be the numeric id Sentry gives it, such as 4501234567",
	Positional: "id",
}

// List is errors.list. A read: routine and reversible.
var List = kit.Op{
	Name:          NameList,
	Class:         kit.Routine,
	Reversibility: kit.Reversible,
	Summary:       "List issues of an allowed Sentry project, one page.",
	Usage:         "chap errors list <sentry-project> [--status <s>] [--level <l>] [--limit <n>] [--cursor <c>]",
	RatePerMinute: 12,
	Doc:           "`errors.list` on Sentry. Target is `{adapter: sentry, ref: \"<project slug>\"}`; the slug must be in the project's `sentry.projects`. One page of at most `limit` issues (default 10, at most 25), newest first, with `next_cursor` when there is more. `status` is unresolved (the default), resolved or ignored; `level` is fatal, error, warning, info or debug. Only the orchestrator token asks. Each item has the id, short id, title, culprit, level, status, event count, first and last seen and the assignee's name. Titles and culprits are text from Sentry and are untrusted: they are cleaned, capped and withheld when they look like a secret.",
	Target: kit.Target{
		Adapter:    Adapter,
		Pattern:    ProjectRefPattern,
		Why:        "the Sentry project must be a project slug such as web (this is not --project, which names the Chaperone project)",
		Positional: "sentry-project",
	},
	Params: []kit.Param{
		{Name: "status", Kind: kit.String, Pattern: StatusPattern, Why: "--status must be unresolved, resolved or ignored",
			Placeholder: "s", Help: "unresolved (the default), resolved or ignored"},
		{Name: "level", Kind: kit.String, Pattern: LevelPattern, Why: "--level must be fatal, error, warning, info or debug",
			Placeholder: "l", Help: "only issues of this level: fatal, error, warning, info or debug"},
		{Name: "limit", Kind: kit.Int, Min: 1, Max: MaxLimit, Default: DefaultLimit, Placeholder: "n",
			Help: "how many issues to return (default 10, at most 25)"},
		{Name: "cursor", Kind: kit.String, Pattern: CursorPattern, Why: "--cursor must be the next_cursor of a previous page",
			Placeholder: "c", Help: "the next_cursor of the previous page"},
	},
	CLI: kit.CLI{Summary: "list issues of an allowed Sentry project", DryRun: dryRunHelp},
}

// Get is errors.get. A read: routine and reversible.
var Get = kit.Op{
	Name:          NameGet,
	Class:         kit.Routine,
	Reversibility: kit.Reversible,
	Summary:       "Read one Sentry issue and its latest event's essentials.",
	Usage:         "chap errors get <id> [--dry-run]",
	RatePerMinute: 12,
	Doc:           "`errors.get` on Sentry. Target is `{adapter: sentry, ref: \"<issue id>\"}`, the numeric id; the issue must be in a project of the project's `sentry.projects`. No params. Returns the issue's title, culprit, level, status, event count, first and last seen, and from the latest event the id, the time, the exception type and at most 10 stack frames (the last two parts of the file name, line, function, in-app), innermost first. It never returns request bodies, cookies, headers, user data, local variables, tags, breadcrumbs or exception messages: the connector decodes the fields it lists and no others. Text is from Sentry and is untrusted.",
	Target:        issueTarget,
	CLI:           kit.CLI{Summary: "read one Sentry issue and its latest event", DryRun: dryRunHelp},
}

// Resolve is errors.resolve. Routine: the issue is set back by errors.unresolve.
// What a resolve can start in Sentry (notices, a linked ticket) is in
// docs/runbooks/sentry.md and is not undone by errors.unresolve, so the
// operation is not left on for a project the operator has not checked.
var Resolve = kit.Op{
	Name:          NameResolve,
	Class:         kit.Routine,
	Reversibility: kit.Reversible,
	Summary:       "Resolve one unresolved Sentry issue.",
	Usage:         "chap errors resolve <id> [--dry-run]",
	RatePerMinute: 2,
	Doc:           "`errors.resolve` on Sentry. Target is `{adapter: sentry, ref: \"<issue id>\"}`; the issue must be in a project of the project's `sentry.projects`. No params. Sets the status to resolved, with no release and no commit. An issue that is already resolved is left as it is. An ignored issue is refused: resolving it would end its archive. Sentry may notify people and sync a linked ticket when an issue is resolved.",
	Target:        issueTarget,
	CLI:           kit.CLI{Summary: "resolve one Sentry issue", DryRun: dryRunHelp},
}

// Unresolve is errors.unresolve. Routine and reversible.
var Unresolve = kit.Op{
	Name:          NameUnresolve,
	Class:         kit.Routine,
	Reversibility: kit.Reversible,
	Summary:       "Reopen one resolved Sentry issue.",
	Usage:         "chap errors unresolve <id> [--dry-run]",
	RatePerMinute: 2,
	Doc:           "`errors.unresolve` on Sentry. Target is `{adapter: sentry, ref: \"<issue id>\"}`; the issue must be in a project of the project's `sentry.projects`. No params. Sets the status to unresolved. An issue that is already unresolved is left as it is. An ignored issue is refused: reopening it would end its archive.",
	Target:        issueTarget,
	CLI:           kit.CLI{Summary: "reopen one resolved Sentry issue", DryRun: dryRunHelp},
}

// Assign is errors.assign. Compensable: there is no operation that leaves an
// issue unassigned again, and the member is told when the issue is assigned.
var Assign = kit.Op{
	Name:          NameAssign,
	Class:         kit.Routine,
	Reversibility: kit.Compensable,
	Summary:       "Assign a Sentry issue to a member the policy lists.",
	Usage:         "chap errors assign <id> --to <member> [--dry-run]",
	RatePerMinute: 6,
	Doc:           "`errors.assign` on Sentry. Target is `{adapter: sentry, ref: \"<issue id>\"}`; the issue must be in a project of the project's `sentry.projects`. `to` is a member from the project's `sentry.assignees`, written as the policy writes it (an email address or a username); any other name is refused. The policy lists no member by default, so the operation refuses until it does. Sentry tells the member.",
	Target:        issueTarget,
	Params: []kit.Param{
		{Name: "to", Kind: kit.String, Required: true, Pattern: AssigneePattern, Why: "--to must be an email address or a username, as the policy lists it",
			Placeholder: "member", Help: "a member from the policy's list: an email address or a username (required)"},
	},
	CLI: kit.CLI{Summary: "assign a Sentry issue to a member the policy lists", DryRun: dryRunHelp},
}

// Comment is errors.comment. Compensable: the connector has no way to delete a
// note, and Sentry tells the people who follow the issue.
var Comment = kit.Op{
	Name:          NameComment,
	Class:         kit.Routine,
	Reversibility: kit.Compensable,
	Summary:       "Add a note to a Sentry issue.",
	Usage:         "chap errors comment <id> [--body <b> | --body-file <f>]",
	RatePerMinute: 6,
	Doc:           "`errors.comment` on Sentry. Target is `{adapter: sentry, ref: \"<issue id>\"}`; the issue must be in a project of the project's `sentry.projects`. `body` is plain text of up to 2000 bytes: letters, digits, spaces, line breaks and the marks . , : ; ! ? ( ) ' - _ / + = % and the double quote. A note with an at sign, a number sign, markup, a link bracket, a web address (`://` or `www.`), an invisible character or text shaped like a secret is refused, so a note cannot mention a person or a team. Sentry has no key that makes a repeat safe, so a repeat of one execution posts again.",
	Target:        issueTarget,
	Params: []kit.Param{
		{Name: "body", Kind: kit.Text, Required: true, MinLength: 1, MaxLength: MaxCommentBytes},
	},
	CLI: kit.CLI{Summary: "add a note to a Sentry issue", DryRun: dryRunHelp},
}
