// Package resend is the Resend connector. It sends transactional email through
// Resend's API for an agent, so the agent never holds the API key.
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
//   - resendspec/spec.go declares the operation once.
//   - adapter.go holds what the adapter shares with its helpers; send.go holds
//     the adapter.
//   - client.go is the HTTP client. It sends to one fixed address, never follows
//     a redirect, sends an Idempotency-Key with every send, and puts neither a
//     key nor Resend's text in an error. token.go reads the key from the vault.
//   - resendtest/server.go is a fake of the service for the tests.
//   - conformance_test.go runs the shared connector suite
//     (internal/connectors/conformance) against the real adapters and the fake.
package resend
