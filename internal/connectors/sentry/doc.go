// Package sentry is the Sentry connector: it lets the orchestrator read and
// triage the errors of a Sentry organisation through Chaperone, so no agent
// holds a Sentry token. The six operations are errors.list, errors.get,
// errors.resolve, errors.unresolve, errors.assign and errors.comment. They work
// on the Sentry projects that a project's policy lists, for the orchestrator
// token only, and they are off until a policy change turns them on.
//
// What is where:
//
//   - sentryspec/spec.go declares the operations once (name, class,
//     reversibility, usage, rate, target, params).
//   - adapter.go holds what every adapter shares: the policy of the project, the
//     fence that an issue must be in a listed project, the checks of params and
//     the cleaning of Sentry's text. read.go has errors.list and errors.get,
//     write.go the four writes, note.go the guard of the text of a note.
//   - client.go is the HTTP client. It sends the auth token in one header, goes
//     only to a base URL that the policy rule accepts, follows no redirect, and
//     never puts the token, a URL or text from Sentry in an error. It decodes the
//     fields that the connector lists and no others, so request bodies, cookies,
//     headers, user data and local variables of an event never reach chapd's
//     memory as data, let alone a result.
//   - token.go reads the auth token from the vault.
//   - sentrytest/server.go is a fake Sentry for the tests.
//   - conformance_test.go runs the shared connector suite
//     (internal/connectors/conformance) against the real adapters and the fake.
//
// Everything here was tested against the fake only. docs/runbooks/sentry.md says
// what that means for turning the operations on.
package sentry
