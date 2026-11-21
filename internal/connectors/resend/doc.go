// Package resend is the Resend connector. It sends transactional email through
// Resend's API for an agent, so the agent never holds the API key.
//
// It serves two operations.
//
//   - mail.send, with target.adapter `resend`. The operation is not new: it is the
//     one the Google connector serves for Gmail (target.adapter `google`), and
//     the target picks the connector, the way issue.comment is one name for
//     GitHub and Linear ([ops.ByTarget]). Its class (high, irreversible), its
//     approval card and its baseline rule (off) are the existing ones. Every
//     send needs the operator's approval, and the approval is bound to the
//     sender, the recipients, the subject and the body (see sendAdapter).
//   - mail.status, a read of the delivery status of one sent message (routine).
//
// What it will not do, on purpose: attachments, HTML, reply-to, scheduled sends,
// the batch endpoint, templates, tags and custom headers. Each of those is a
// field of Resend's send call that this connector never sets, so an agent cannot
// reach it.
//
// The facts it relies on come from Resend's own documentation, and the runbook
// (docs/runbooks/resend.md) lists the pages. It has been tested only against a
// fake (resendtest) and never against the real service.
//
// What is where:
//
//   - resendspec/spec.go declares the operations once.
//   - adapter.go holds what the two adapters share; send.go and status.go hold
//     the adapters.
//   - client.go is the HTTP client. It sends to one fixed address, never follows
//     a redirect, sends an Idempotency-Key with every send, and puts neither a
//     key nor Resend's text in an error. token.go reads the keys from the vault.
//   - resendtest/server.go is a fake of the service for the tests.
//   - conformance_test.go runs the shared connector suite
//     (internal/connectors/conformance) against the real adapters and the fake.
package resend
