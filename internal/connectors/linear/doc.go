// Package linear is Chaperone's Linear connector for the operator-board intake
// : the ops `intake.list`, `intake.comment`,
// `intake.move` and `intake.states`.
//
// # Where the facts of an operation are
//
// The name, class, reversibility, summary, usage line, rate, target and params
// of each operation are declared once, in the subpackage [linearspec]. The
// manual entry, the params schema, the `chap` command and the adapter's list of
// allowed params are derived from that declaration (see docs/connectors.md and
// internal/connectors/kit). This package holds what is not a fact: the policy
// checks, the idempotency, the reading of Linear and the handling of its text.
//
// # What an agent can and cannot do
//
// The orchestrator asks chapd for an op; chapd builds the GraphQL itself. The caller never
// sends a query, a mutation, a team, a label or a state id: it names an issue
// identifier ("SHOP-12"), a comment text or a state name, and chapd turns that
// into one of five fixed documents (see queries.go). There is no way to make
// this package run any other document.
//
// The policy is the real guard, because Linear's `write` scope is wider than
// anything the operator decided: it reaches every team of the workspace. So:
//
//   - One team. The project's policy file (`linear:`, [policy.Linear]) names
//     the team key. A request for an identifier of another team is refused
//     (SCOPE_PATH), and so is an issue that Linear says belongs to another
//     team, and any team called Engineering (the one-way mirror of GitHub).
//   - One label. A write is allowed only on an issue that carries the label
//     right now. Check reads the issue; Execute reads it again with the same
//     token just before it writes, so a label taken off in between stops the
//     write. The window that is left is the time between that second read and
//     Linear's answer to the mutation: Linear has no conditional update.
//   - Two writes and no more. A comment, and a move to a state whose name the
//     policy lists. There is no code path that removes or adds a label, edits
//     a title or a description, deletes, archives, assigns or creates an
//     issue; the fixed mutations carry only the fields they need (see
//     queries.go) and the tests record every request the fake Linear got.
//   - The token. chapd mints an OAuth client-credentials token from two vault
//     secrets (linear-client-id, linear-client-secret). The token lives in
//     chapd's memory only, for at most an hour, is refetched after a 401 and is
//     registered with the redaction registry, so it never reaches a log, the
//     ledger or an op result. The caller never holds it.
//   - Rate limits. Beside the op rate limits of the policy pack, the client has
//     a budget of calls per hour of its own, and it stops sending while Linear
//     says its limit is used up (HTTP 429 or the RATELIMITED code, with the
//     Retry-After it names).
//
// # Reading the board
//
// `intake.list` returns the open items of the team that carry the label, with
// state, title, description, comments, links and update time. It is served by a
// [Board]: a cache that a background poller refreshes every poll interval
// (default 15 minutes), and that `refresh` replaces at once. Title,
// description and comments are the operator's and the COO's text: they are
// returned as data, flagged `untrusted_text`, never as instructions. A text
// that looks like a secret is withheld, not returned.
//
// # What a write answers
//
// A write is sent at most once. A definite refusal by Linear is `failed`. An
// answer that does not show whether Linear acted (a timeout, a 5xx) leaves the
// op `unconfirmed`, and the result carries the comment id chapd chose, so the
// comment can be looked up.
package linear
