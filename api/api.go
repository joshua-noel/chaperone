// Package api embeds chapd's HTTP contract so the server, `chap` and the tests
// read the same bytes that review saw.
//
//   - openapi.yaml: the routes, the structured denial and the state machine.
//   - manual.yaml: the `chap manual` data and the op class table.
//   - examples/: bodies that tests validate against the spec's schemas.
package api

import "embed"

// Files holds openapi.yaml, manual.yaml and examples/.
//
//go:embed openapi.yaml manual.yaml examples/*.json
var Files embed.FS
