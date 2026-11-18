// Package runtoken is Chaperone's run-token and orchestrator-token authority
// (ticket L1-04; ADR-005, ADR-007). It answers three questions: is this bearer
// a run, is it the orchestrator, and may the interim issuer mint for it.
//
// # Run tokens
//
// [Verifier.Verify] runs the eight steps of ADR-005 on a JWS compact token and
// refuses with an [*Error] whose Code is the denial cause code (TOKEN_INVALID,
// TOKEN_EXPIRED, TOKEN_REVOKED, OP_NOT_IN_TOKEN, SCOPE_BRANCH). The parser is
// hand-written because the profile is small: three header members, one
// algorithm (EdDSA), one typ (factory-run+jwt), keys only from the pinned
// [KeySet], never from the token. Claims go through the spec's JSON Schema and
// spec.CheckRunTokenClaims (grace 300 s, skew 30 s: the spec owns those
// numbers). SQLite is read on every call, so [Runs.End] and [Runs.Revoke] hold
// on the very next request.
//
// Unrecorded facts the ADRs leave open, decided here:
//
//   - The grant: [Runs.Register] stores the verified claims and the SHA-256 of
//     their JCS form. A token whose claims differ from the grant, or a second
//     token for the same run, is TOKEN_INVALID (spec section 4: "the scope is
//     also equal to the grant Chaperone recorded").
//   - Control tokens (typ factory-ctl+jwt) carry exactly iss, aud (chaperone),
//     iat, exp (at most 60 s after iat), jti (single use), act (run.start,
//     run.end or run.status) and run_id, which must equal the run the call is
//     about. The spec v0.1.0 defines no control claims; run_id is this
//     package's binding. run.status (LF-2) reads a run's state through
//     [Runs.Status], only for a run the same issuer registered.
//   - A run token for an unregistered run is TOKEN_INVALID. A token past exp is
//     TOKEN_EXPIRED only while its run is active (even if the reaper has not
//     run); an ended or revoked run is always TOKEN_REVOKED, also past exp:
//     revocation is checked before time (ADR-005 amendment 7).
//   - Step 6 has no extra 30 s leeway on exp: spec.CheckRunTokenClaims refuses
//     at now >= exp and the spec wins (ADR-005 amendment 5).
//
// # Interim issuer
//
// [Interim.Mint] signs a host-interim token only for a valid orchestrator
// token whose scope has mint_interim, only while the key set has
// allow_interim true, with at most [MaxInterimSeconds] of life, only ops in
// [HostInterimCeiling] (narrowable per key, never wider), a branch under
// agent/, and registers the run in the same transaction. The issuer is
// chaperone.<instance>, not runner.interim as ADR-005 says: run-token.schema.json
// v0.1.0 requires chaperone.* for isolation host.
//
// # Orchestrator tokens
//
// chap_orch_ + base64url(32 random bytes); only SHA-256 is stored; looked up by
// hash and compared in constant time; scope is a row; 30 days at most; issuing
// again for an id revokes the first token in the same transaction. This package
// returns the plaintext from [Orchestrators.Issue] once. Writing it to the
// operator's token file with an owner-only ACL is the caller's (chapd orch issue).
//
// # Ledger
//
// Every state change appends its events through an [Appender] inside the same
// transaction, so a ledger failure rolls the change back (ADR-006). Events:
// grant and run.start on registration, token.revoke and run.end on end,
// op.request and op.result for orchestrator.issue and orchestrator.revoke.
package runtoken
