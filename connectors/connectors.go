// Package connectors embeds the connector profiles: one small YAML file per
// connector that Chaperone has built ops for. A
// profile lists the connector's ops with the facts a review needs and the
// catalog cannot hold (the unit, the conditions, the connector standard's own
// name for a built op), and a test (internal/policy, C19) ties each
// profile to api/manual.yaml, the baseline pack and the `chap` usage lines, so
// the three cannot drift apart.
//
// The profiles here are the built part only. The full research profiles (the
// ops not built yet, the presets, the evidence) stay with the standard, a design
// document outside this repository.
package connectors

import "embed"

// Files holds the profile files.
//
//go:embed *.yaml
var Files embed.FS
