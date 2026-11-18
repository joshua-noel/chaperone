// Package spec binds Chaperone to its wire contract: the v0 schemas, golden vectors and examples (L1-01).
//
// What it holds:
//
//   - the contract itself: schemas, golden vectors and examples kept in
//     specdata/ (VERSION names the contract version; MANIFEST holds the hash
//     of every file, and a test checks it);
//   - ParseStrict, the loader every hashed or validated document goes through:
//     JSON plus I-JSON (RFC 8785 section 3.1), so duplicate member names,
//     unsafe integers in any literal form, lone surrogates and nesting deeper
//     than MaxDepth are refused before anything is hashed;
//   - JCS, RFC 8785 canonical JSON, byte-identical to the reference;
//   - OpHash, ApprovalChallenge, EventHash, TraceID and VerifyChain;
//   - the Go forms of the request, approval, run token claims, ledger event
//     and denial, and a Validator that checks a document tree against the
//     JSON Schema 2020-12 documents (Load and LoadTree do parse, validate and
//     decode in one step);
//   - CheckRunTokenClaims, NormalizeUsage and IsContextGateFile, the semantic
//     checks the golden vectors cover.
//
// The golden vectors (specdata/vectors/v0.json) are the conformance suite:
// TestVectors reproduces every entry and fails when a change adds a section it
// does not check. After an edit to specdata, `go run ./scripts/spec-manifest`
// re-seals MANIFEST; then run `go test ./internal/spec`.
package spec
