package main

import "context"

// Event kinds chapd sends to the helper.
const (
	// EventApprovals (wire name "approvals.pending") carries the number of
	// approvals waiting for the operator.
	// chapd sends the current count when a stream opens, and again on change.
	EventApprovals = "approvals.pending"
	// EventGrant carries one signed execution grant for the helper to run.
	EventGrant = "grant"
)

// Event is one message from chapd.
type Event struct {
	Kind    string
	Pending int    // EventApprovals
	OpID    string // EventGrant: the op this grant executes, used to report back
	Grant   string // EventGrant: the wire form from internal/grant; verified, never trusted
}

// Result is the final report for one grant. It carries codes, never text from
// the script or from an error message.
type Result struct {
	// Status is "succeeded", "failed", "timeout" or "refused".
	Status string
	// Code is a grant.Refusal code or a runner refusal code when Status is
	// "refused"; empty otherwise.
	Code string
	// ExitCode is the script's exit status when it ran.
	ExitCode int
}

// Chapd is everything the helper needs from chapd. The real transport is
// [HTTPChapd]; tests use a fake.
type Chapd interface {
	// Next blocks until chapd has an event for the helper or ctx ends. After an
	// error the next call reconnects.
	Next(ctx context.Context) (Event, error)
	// Output sends one chunk of redacted script output for a grant.
	Output(ctx context.Context, opID string, chunk []byte) error
	// Done reports the final result of a grant.
	Done(ctx context.Context, opID string, r Result) error
}
