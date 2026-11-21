// Package github holds the conformance test of the GitHub connector
// (conformance_test.go). It has no code of its own.
//
// The GitHub operations are declared in [githubspec]. Their adapters live in
// internal/ops, because chapd builds them there from the App client, and the
// fake GitHub they are tested against is internal/gh/ghtest. The test here runs
// the shared connector suite (internal/connectors/conformance) against the real
// adapters and that fake, from the place where connectors live.
package github
