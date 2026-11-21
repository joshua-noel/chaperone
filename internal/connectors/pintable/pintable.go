// Package pintable is the one table of the class and reversibility of every
// declared operation, written out here by hand and nowhere else.
//
// It is the second, deliberate copy of a class. A declaration that loosens a
// class fails the tests that read this table until the table is edited too, in
// the same reviewed change as the declaration and the generated manual entry.
//
// Only tests import this package, so no binary links it: the declared tests
// (internal/connectors/declared) and the conformance suite
// (internal/connectors/conformance) read it, and a connector's own test passes
// it to the suite.
package pintable

import "github.com/joshua-noel/chaperone/internal/connectors/kit"

// Pins is the class and reversibility of every declared operation. A connector
// that is added to the declared list without pins fails the declared tests and
// the conformance suite, and a change of class needs this second edit beside
// the declaration and the generated manual entry. Add a new operation here
// with its class.
var Pins = map[string]kit.Pin{
	"intake.list":    {Class: kit.Routine, Reversibility: kit.Reversible},
	"intake.comment": {Class: kit.Routine, Reversibility: kit.Compensable},
	"intake.move":    {Class: kit.Routine, Reversibility: kit.Reversible},
	"intake.states":  {Class: kit.Routine, Reversibility: kit.Reversible},

	// The generic issue operations of Linear. issue.comment is one name for two
	// connectors and is pinned once, in the GitHub block below: the two
	// declarations must agree on it.
	"issue.get":   {Class: kit.Routine, Reversibility: kit.Reversible},
	"issue.list":  {Class: kit.Routine, Reversibility: kit.Reversible},
	"issue.label": {Class: kit.Routine, Reversibility: kit.Reversible},
	"issue.move":  {Class: kit.Routine, Reversibility: kit.Reversible},
	"issue.link":  {Class: kit.Routine, Reversibility: kit.Reversible},

	// Sentry. Reads are reversible. Resolve and unresolve undo each other, so they
	// are reversible; what Sentry does besides (a notice, a linked ticket) is not
	// undone by the other one, and docs/runbooks/sentry.md says so. Assign and
	// comment are compensable: no operation leaves an issue unassigned again or
	// removes a note, and the member or the people who follow the issue are told.
	"errors.list":      {Class: kit.Routine, Reversibility: kit.Reversible},
	"errors.get":       {Class: kit.Routine, Reversibility: kit.Reversible},
	"errors.resolve":   {Class: kit.Routine, Reversibility: kit.Reversible},
	"errors.unresolve": {Class: kit.Routine, Reversibility: kit.Reversible},
	"errors.assign":    {Class: kit.Routine, Reversibility: kit.Compensable},
	"errors.comment":   {Class: kit.Routine, Reversibility: kit.Compensable},

	// GitHub. pr.merge is the one gated operation: it merges on its own when
	// verify is green on the exact head, and a merge is undone only by a revert
	// commit, hence compensable. Do not loosen it to routine.
	"pr.open":       {Class: kit.Routine, Reversibility: kit.Reversible},
	"pr.update":     {Class: kit.Routine, Reversibility: kit.Reversible},
	"pr.merge":      {Class: kit.Gated, Reversibility: kit.Compensable},
	"pr.view":       {Class: kit.Routine, Reversibility: kit.Reversible},
	"pr.diff":       {Class: kit.Routine, Reversibility: kit.Reversible},
	"pr.checks":     {Class: kit.Routine, Reversibility: kit.Reversible},
	"pr.files":      {Class: kit.Routine, Reversibility: kit.Reversible},
	"issue.open":    {Class: kit.Routine, Reversibility: kit.Reversible},
	"issue.comment": {Class: kit.Routine, Reversibility: kit.Compensable},
	"issue.reopen":  {Class: kit.Routine, Reversibility: kit.Reversible},
	"ci.report":     {Class: kit.Routine, Reversibility: kit.Reversible},

	// Resend. mail.send is one name for two connectors, the Google connector's (Gmail) and
	// this one, and is pinned once. It is the one high, irreversible operation of the
	// table: a message that has gone cannot be recalled, and every send needs the
	// operator's approval. Do not loosen it. The Resend side is declared in
	// resendspec.MailSend, and a test in package declared checks that it agrees with this
	// pin.
	"mail.send": {Class: kit.High, Reversibility: kit.Irreversible},
}
