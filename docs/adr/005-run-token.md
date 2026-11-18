# ADR-005: Run token format and revocation at run end

- **Status:** **Accepted** (operator sign-off). Amended 2026-10-24 for the separate agent account, the orchestrator token and the tagged spec release: see "Amendments" at the end. **Confirms** the format in `factory-spec` **v0.1.0** (`schemas/run-token.schema.json`: JWS compact JWT, protected header `{alg: EdDSA, typ: "factory-run+jwt", kid}`) rather than proposing PASETO. The spec requests below are still open.
- **Contract:** the runner signs one token per run; Chaperone verifies on every call and "never trusts anything else the agent says about itself" (the original plan). Claims (spec, `additionalProperties: false`): `iss` (`runner.<instance>`), `sub` (`run:<run_id>`), `aud` (`chaperone`), `iat`, `exp`, `jti`, `run_id`, `project`, `profile{name,version,digest,overlay_digest?}`, `brief_sha256`, `isolation`, `task_scope{repo,base,branch,paths,ops}`, `budget`.

## Context

- **JWT best current practice** (RFC 8725) says: the library must let the caller fix the set of algorithms and must not use others; "each key MUST be used with exactly one algorithm"; use explicit typing with `typ`; validate issuer, subject, audience (<https://www.rfc-editor.org/rfc/rfc8725.html>, §§3.1, 3.8-3.12).
- **RFC 9864 (2025, standards track)** deprecates the *polymorphic* JOSE identifier `EdDSA` (RFC 8037) in favour of fully-specified identifiers (`Ed25519`, `Ed448`) (<https://www.rfc-editor.org/rfc/rfc9864.html>). Library support lags: `golang-jwt/jwt` v5 registers `EdDSA` (<https://pkg.go.dev/github.com/golang-jwt/jwt/v5>).
- **PASETO v4.public** is Ed25519 with no `alg` header: the version and purpose live in the token header `v4.public.`, and the spec has an "Algorithm Lucidity" guide against algorithm confusion (<https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md>, <https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/03-Algorithm-Lucidity.md>). Go library: `aidanwoods.dev/go-paseto` (v1.6.0 observed on pkg.go.dev, 2025-12-27; a v2 major exists) (<https://pkg.go.dev/aidanwoods.dev/go-paseto>). I found no IETF RFC for PASETO `[INFERENCE: spec lives in a GitHub repo]`.
- Both ends are ours: the runner signs, Chaperone verifies. There is no third-party verifier today.

## Decision

**JWT (JWS compact) signed with Ed25519, exactly as in factory-spec v0, with a strict RFC 8725 verification profile.** Not PASETO.

Why not PASETO even though its design removes algorithm choice: the property we want from PASETO (no negotiation) is achievable in JWT by pinning one algorithm and one key type, which RFC 8725 §3.1 requires anyway. JWT costs us nothing in tooling (the spec repo already validates the schema in JS; Go and every future harness adapter have JWT libraries), keeps `iss/sub/aud/exp/jti` names standard, and leaves the door open for workload-identity federation and token exchange (the original plan: "short-lived token exchange / workload identity"), which are JWT-shaped. PASETO would add a second token ecosystem and a pre-2.0 Go library for no property we cannot pin ourselves.

### Verification profile (Go, `internal/runtoken`)

Reject the token unless **all** hold, in this order (fail closed, one cause code each):

1. Compact form with exactly three segments; header parses; header has no `jku`, `jwk`, `x5u`, `x5c`, `crit`, `zip`. Keys come only from the **pinned key set on disk** (`kid` → Ed25519 public key + issuer), never from the token. (`TOKEN_INVALID`)
2. `alg` equals exactly `EdDSA` (v0). `none`, HS*, RS*, ES* and `Ed25519` are all rejected. The parser is configured with a one-element valid-method list; the key type must be `ed25519.PublicKey`. A test feeds a token signed HS256 with the public key bytes as the HMAC secret. (`TOKEN_INVALID`)
3. `typ` equals `factory-run+jwt` (the library does not check it for us; we check). (`TOKEN_INVALID`)
4. Signature valid under the key named by `kid`; `iss` equals the issuer pinned for that `kid`.
5. `aud == "chaperone"`; `sub == "run:" + run_id`; claims validate against the JSON Schema; no unknown claim.
6. `iat <= now + 30 s`, `exp > now - 30 s` (30 s leeway max), `exp > iat`, and **`exp - iat <= budget.minutes*60 + 120 s`**: the spec says tokens live for the wall-time budget plus a short grace. A token that outlives its own budget is invalid. (`TOKEN_EXPIRED`)
7. `jti` is not in `revoked_jti` and the `runs` row for `run_id` has `state = active` (below). (`TOKEN_REVOKED`)
8. **Scope**, computed from the verified claims only: effective ops = `task_scope.ops` ∩ ops the profile allows ∩ ops enabled in the catalog/project policy. Anything else: `OP_NOT_IN_TOKEN`. Repo and branch checks use `task_scope.repo/base/branch` (`SCOPE_BRANCH`).

Never from the request: run id, profile, repo, or "who I am". Request bodies that disagree with the token are refused. `TOKEN_MISUSE` (stop code) is raised for use after revocation/expiry, bad signature, a source address other than the run's sandbox, or simultaneous use from two sources. Source-address checking needs the runner's proxy to attest the address (Phase 2); in Phase 1 it is recorded but not enforced.

### Revocation at run end

State lives in `chapd`'s SQLite (`runs`, `revoked_jti`), not in the token.

1. **Registration.** A run exists for Chaperone only after the runner calls `POST /v0/runs` with a control JWT (`typ: factory-ctl+jwt`, `aud: chaperone`, claim `act: run.start`, `exp` ≤ 60 s, single-use `jti`) signed by the same runner key set. Chaperone stores `run_id, jti, project, profile, exp, state=active`. A syntactically valid token for an unregistered run is refused.
2. **End.** At run end, kill or crash recovery, the runner calls `POST /v0/runs/{id}/end` (control JWT, `act: run.end`). Chaperone in one transaction: sets `state=ended`, inserts the `jti` into `revoked_jti` (kept until `exp`), cancels the run's pending approvals (status `cancelled`, ledger `op.approve` with `decision: denied`, reason "run ended"), writes the ledger event. After commit it **revokes every GitHub installation token minted for the run** (`DELETE /installation/token`, ADR-002), wipes in-memory caches, and closes open git-proxy streams. Revocation is effective on the next request because step 7 reads SQLite on every call.
3. **Fail-safes if the runner never calls.** (a) `exp` is a hard cap (budget + 120 s). (b) A reaper in `chapd` marks runs ended at `exp` and does the same cleanup. (c) On `chapd` start, it reaps anything past `exp`.
4. **Operator kill.** Console "Stop all" and `chap runs revoke <run>|--all` (Hello-gated) revoke immediately with stop codes `OPERATOR_STOP_RUN` / `OPERATOR_STOP_ALL`.
5. **Ledger.** `grant` (token accepted; carries `factory.token.jti`), `run.start`, `run.end` events; every denial carries the token cause code.
6. **Status read.** The runner learns that Chaperone ended a run (an operator stop, a stop-table stop, the reaper) before the token's `exp` by calling `GET /v0/runs/{id}` with a control JWT (`act: run.status`, `run_id` equal to `{id}`, same claims, 60 s and single use as the others) as the one `Authorization: Bearer` value. The answer is `state`, `ended_at`, `cause_code` and `expires_at`, and nothing else. A control JWT reads only runs its own issuer registered; an unknown run and another issuer's run both answer `404`. A run token, the orchestrator token and every other credential are refused `401 TOKEN_INVALID`. A read writes no ledger event and changes no run. The runner mints a fresh control JWT for every poll.

### Phase 1 interim issuer (before the runner exists)

Agents on the host need a token to call `chap`. `chapd` ships an **interim issuer** with its own Ed25519 key in the vault, issuer `runner.interim` (fits the schema pattern), command `chap dev-token --profile <p> --repo <r> --branch <b> --ops <list> --minutes <n>`. The interim issuer is registered with restrictions in the pinned key set: `exp` at most 2 hours, profile `host-interim` ceiling (`pr.open`, `pr.update`, `pr.merge`, `branch.push`, `health`, `logs`, plus approval-gated ops), and a flag `allow_interim=false` that is flipped at cut-over to the runner. **Who may mint:** `chap dev-token` is a request to `chapd`, which signs with the interim key only for a caller that presents the **orchestrator token** (ADR-007). The token file is in the operator's profile and agents run under their own Windows account, so an agent cannot mint itself a token. **Honest limit:** until the account split has run, and for anything that runs as the operator account, the old limit stands: that caller can mint an interim token. The damage ceiling is whatever the interim profile allows, and every high-impact op in it is either gated by policy that does not depend on the caller (`pr.merge` verify-on-head) or needs an approval an agent cannot produce. Record this as an accepted residual risk in the threat model, closing when the account split runs.

### Token delivery (Phase 2 note)

Best is that the agent never holds the token: the runner's egress proxy injects it into calls to Chaperone (credential attach at the proxy, per the design draft). For Phase 1 the token is an environment variable for the run. Transport inside the runner VM will be TLS with a pinned certificate, or mTLS, tracked in the runner's backlog; loopback HTTP is acceptable only on the host.

## Spec requests

1. Add a sentence to `run-token.schema.json`: RFC 9864 deprecates `EdDSA` in favour of `Ed25519`; v0 pins `EdDSA` because libraries lag; the alg string is part of the spec version and v1 moves to `Ed25519`.
2. Define the control-token claims (`factory-ctl+jwt`, `act`) and `POST /v0/runs`, `POST /v0/runs/{id}/end`.
3. Add denial/cause codes or confirm use of `OP_POLICY_REFUSED` with `checks[]` for the `pr.merge` refusals (verify missing/red, head moved, base behind).

## Alternatives

| Option | Verdict |
| --- | --- |
| **JWT/EdDSA, strict profile** (spec as drafted) | **Chosen** |
| PASETO v4.public | Cleaner by design, no `alg`; but second ecosystem, no federation path, library at v1.6.0 with a v2 major out. Rejected for now; a swap later is a spec-version change because only the runner signs and only Chaperone verifies |
| JWT `alg: Ed25519` (RFC 9864) now | Correct per the newest standard, but Go and JS library support is not there `[INFERENCE: golang-jwt registers only EdDSA; JS not checked]`. Planned for spec v1 |
| Opaque random tokens with a lookup table | Simple revocation, but Chaperone would need a round trip to the runner for scope, and the scope claims must be signed by the runner. Rejected |
| Macaroons / biscuit | Attenuation is attractive for later; not needed for one issuer and one verifier. Not evaluated in depth |
| DPoP / mTLS-bound tokens | Right for Phase 2 transport, not for the token format. Deferred |

## Verify

- Golden tokens from the spec repo verify; negatives: `alg: none`, HS256 with public key bytes, RS256, wrong `typ`, wrong `aud`, unknown `kid`, `jku` header, `exp` in the past, `exp - iat` beyond budget + grace, `jti` revoked, run ended, unregistered run, extra claim.
- Ending a run revokes its GitHub token (live scratch-repo test) and cancels its pending approval.
- Run-token misuse replay.

## Amendments (2026-10-24, first build)

**Amendment 1. The orchestrator has no run token.** The orchestrator (the lead agent that coordinates other agents) authenticates with an **orchestrator token**, a different credential with its own verification path, defined in ADR-007. The eight-step profile above applies to run tokens only. Orchestrator requests are ledgered with `requester.kind: orchestrator` and no `run_id`, as spec v0.1.0 already requires.

**Amendment 2. Who can mint.** The interim issuer (above) now needs the orchestrator token. This replaces the earlier draft's "an agent can mint itself an interim token" with a limit that exists only before the account split.

**Amendment 3. Spec v0.1.0 is tagged.** The run-token schema is the one in the shared spec (`factory-spec`) at v0.1.0; Chaperone carries its own copy of the spec under `internal/spec/specdata`. The three spec requests above remain requests: v0.1.0 defines no control-token claims and no orchestrator credential, which is why ADR-007 is a Chaperone decision.

**Amendment 4. Operator revoke now also covers the orchestrator.** "Operator kill" above gains `chapd orch revoke` and a console button (ADR-007); revocation is effective on the next request.

**Amendment 5. Token lifetime grace is 300 s, not 120 s.** Verifier step 6 and fail-safe (a) above say `exp - iat <= budget.minutes*60 + 120 s`. Spec v0.1.0 (`checkRunTokenClaims`, and the golden run-token vectors) fixes the grace at **300 s**; the spec wins. `internal/spec.TokenGraceSeconds` is 300 and `CheckRunTokenClaims` enforces it; the token verifier must call it, not re-implement a 120 s limit.

**Amendment 6. The interim ceiling leaves out `repo.settings` and `host.scripts.refresh` (RT-52).** The Phase 1 interim issuer's `host-interim` ceiling (`runtoken.HostInterimCeiling`) used to list both critical ops while the policy baseline's `host-interim` profile did not, so a token could hold an op that every request refused as `OP_NOT_IN_TOKEN`. Both lists now leave out every critical kind (the critical ops: `repo.settings`, `host.scripts.refresh`, `approver.add`, `policy.activate`) and the `secrets.*` family; a mint that names one is refused. A test (`TestRT52CeilingMatchesPolicyProfile`) fails if the two lists drift. The ceiling does not include `pr.push.workflow`, which the policy profile lists: a token cannot hold it, so the op is unreachable from an interim run, and the stricter of the two stands.

**Amendment 7. Revocation is checked before time (2026-11-15).** When a token fails more than one check, `internal/runtoken` reports the cause of the highest-ranked problem. The ranking was shape, time, revocation, scope; it is now shape, **revocation**, time, scope (`classify` in `verify.go`). A token past `exp` is `TOKEN_EXPIRED` only while its run is active; a revoked token, or one whose run has ended (a normal end, a stop, or the reaper's `TIME_EXCEEDED`), is `TOKEN_REVOKED`, also past `exp`. Reason: an agent whose run was stopped must not read `TOKEN_EXPIRED`, whose next step suggests a new token. Allow and deny do not change: the same requests are refused, only the cause code of an ended run past `exp` changes from `TOKEN_EXPIRED` to `TOKEN_REVOKED`. The orchestrator verifier (ADR-007) already checked revocation first. Tests: the "jti revoked and exp in the past" and "run ended and exp in the past" cases in `verify_test.go`, and `TestReaperEndsRunsPastExp`.
