# ADR-007: The orchestrator authenticates with an orchestrator token

- **Status:** **Accepted** (the operator decided: "Orchestrator token held by the orchestrator, scoped, revocable from the console"). Written 2026-10-24. The token's wire format and storage below are this ADR's own design; the operator's decision fixed only "orchestrator token, scoped, revocable".
- **Decides:** how Chaperone knows that a request comes from the orchestrator (the lead agent that coordinates other agents) and not from an agent, what that credential may do, and how it is revoked.
- **Inputs:** factory-spec v0.1.0 `docs/spec.md`, section "How the orchestrator authenticates in Phase 1" (options 1 to 3, "not decided here"), `requester.kind: orchestrator` in the request, ledger and denial schemas (`orchestrator_id`, no `run_id`); ADR-005 (run tokens); ADR-003 (accounts); the decisions to split accounts and to use an orchestrator token.

## Context

- A run proves itself with its run token (ADR-005). The orchestrator has no run, so v0.1.0 gives it `requester.kind: orchestrator` and no proof; the spec lists three options and does not pick one.
- Option 1, **OS identity** (read the caller's Windows account), cannot tell the orchestrator from an agent while both run as the operator. Option 3, a **short-lived token released by a Hello confirmation per session**, is the strongest and costs the operator one interaction per orchestrator session. Option 2 is a long-lived token in a file. The operator picked option 2 with two additions: **scoped** and **revocable from the console**.
- The spec's own caveat on option 2: it separates the orchestrator from agents only if agents cannot read the file. The decision to give agents their own Windows account before Phase 1 ships is what makes that true.
- Under every option the spec's rule holds: The orchestrator's high-impact requests need an approval, so a stolen orchestrator token alone cannot deploy or send mail. The token decides who can **ask**, never who can **approve**.

## Decision

**An opaque, random, per-orchestrator bearer token that only `chapd` can verify, stored by hash, scoped to projects and ops, with a hard expiry, revoked from the console in one click.**

1. **Format.** `chap_orch_` followed by the base64url of 32 random bytes (256 bits). Sent as `Authorization: Bearer <token>`. The `chap_orch_` prefix routes it to this verifier; anything that looks like a JWT goes to the run-token verifier (ADR-005), and the two never share a parser. The token is not a JWT because the issuer and the only verifier are both `chapd`: there is nothing to sign for a third party, and an opaque value has no algorithm field to confuse.
2. **Storage.** `chapd` keeps only `SHA-256(token)` in the `orchestrators` table of `state.db`: `id` (for example `main`), `token_sha256`, `scope` (JSON), `issued_at`, `expires_at`, `revoked_at`, `revoked_by`. Lookup is by hash; the comparison is constant-time. The plaintext exists once, in the file that item 5 writes. It is not a vault secret (the vault holds what `chapd` must *use*; this is what `chapd` must *recognise*), and it is added to the `redact` registry so no log or response can print it.
3. **Scope.** A token names the `projects` and `ops` it may ask for, and whether it may mint interim run tokens (`chap dev-token`, ADR-005) while `allow_interim` is true. Effective ops are `scope.ops` ∩ ops enabled for the orchestrator in the catalog and project policy. An op or project outside that set is `OP_NOT_IN_TOKEN`. Scope is data in the row, not claims the caller can change.
4. **Lifetime.** `expires_at` is at most **30 days** after issue (the spec says "long-lived"; this is the cap). There is no refresh: the operator re-issues. An expired token is `TOKEN_EXPIRED`.
5. **Issue, rotate.** `chapd orch issue --id main --project <p> --ops <list> [--days N]`, **run by the operator in an elevated shell** (the same pattern as `chapd enroll`; an agent never runs it). It writes the token to `%LOCALAPPDATA%\Chaperone\orchestrator.token` in the *invoking user's* profile with an ACL granting only that user, and prints only the token's fingerprint (first 8 hex of the SHA-256) and its expiry, never the token. Issuing a second token for the same `id` revokes the first in the same transaction.
6. **Use.** `chap` takes a run token from `CHAP_RUN_TOKEN` when it is set; otherwise it reads the orchestrator token file (override: `CHAP_ORCHESTRATOR_TOKEN_FILE`). No flag accepts a token. An agent under the agent account has its own profile with no such file, so the orchestrator path does not exist for it.
7. **Revoke.** A console button "Revoke orchestrator" and `chapd orch revoke --id main` set `revoked_at`. Verification reads SQLite on every request, so revocation holds on the next call, as for runs (ADR-005 step 7). Revocation only removes authority, so it needs no approval. It also cancels the orchestrator's pending approvals.
8. **Requests and events.** An accepted call writes a `grant` event (carries the token's fingerprint, not the token). Requests and refusals are ledgered with `factory.requester.kind: orchestrator` and `orchestrator_id` = the row `id`, no `run_id` (spec v0.1.0). Denial bodies use `orchestrator_id`. Issue, rotate and revoke are recorded as `op.request` and `op.result` for the operator-only ops `orchestrator.issue` and `orchestrator.revoke`; the spec has not named these ops (spec request 1).
9. **What it can never do.** Approve anything (its own request or another: `POLICY_BREACH`), enrol an approver without an approval, read a secret, or change policy. High-impact ops it asks for return `OP_APPROVAL_REQUIRED` like anyone's.

## What this does and does not defend

| Attacker | Result |
| --- | --- |
| An agent under the agent account | Cannot read the token file. Cannot mint an orchestrator token (needs an elevated operator shell). Can still use its own run token. |
| Anything running as the operator account | Can read the file and ask for whatever the scope allows, within policy. It still cannot approve; a critical or high op still needs a Hello or phone approval. Scope and the 30-day cap bound the damage; the console revokes it. |
| Before the account split (agents still share the operator account) | An agent can read the file. This is the spec's own caveat for option 2. Recorded as an accepted risk with owner and date (ADR-005) until the split runs. |
| Token leaked in a log or a chat | Redaction registry masks it; revoke and re-issue. The store only has the hash, so a copy of `state.db` does not leak it. |
| Replay after revocation or expiry | `TOKEN_REVOKED` / `TOKEN_EXPIRED` on the next request. |

## Alternatives

| Option | For | Against | Verdict |
| --- | --- | --- | --- |
| **Opaque token, hash in SQLite, scoped, 30-day cap** | Smallest thing that satisfies "scoped, revocable"; no JWT parsing in the path; revocation is a row update; hash at rest. | The plaintext sits in one file in the operator's profile; a bearer token is replayable by anyone who holds it. | **Chosen** (the operator's decision) |
| JWT/EdDSA like run tokens | One verifier, one format. | A signature nobody else needs to check; `alg`/`typ` handling to get wrong; revocation needs the same table anyway. | Rejected |
| OS identity (named pipe or loopback and the caller's account) | No file to steal. | Cannot separate the orchestrator from an agent on a shared account; with the account split it separates *accounts*, not *programs* running as the operator account. | Not chosen alone; the account split is still what protects the file |
| Short-lived token released by a Hello confirmation per orchestrator session | Strongest; stolen token dies in hours. | One operator interaction per orchestrator session; the orchestrator runs unattended batches. | Documented upgrade path: shorten `--days` to hours and have the console issue it after a Hello. No schema change needed |
| mTLS client certificate for the orchestrator | Standard. | Certificate lifecycle for one local client; the private key is a file with the same exposure. | Rejected for Phase 1 |

## Verify

- Issue, verify, expire, rotate and revoke an orchestrator token; only the SHA-256 is in the database (grep `state.db` for the plaintext finds nothing); a revoked token is refused on the very next request; scope: an op or project outside it is refused; `chap dev-token` with no orchestrator token is refused.
- The auth middleware routes `chap_orch_` to the orchestrator verifier and anything else to the run-token verifier; a request with both is refused; denial bodies carry `orchestrator_id` and validate against `denial.schema.json`; `chapd orch issue|revoke` exist.
- `chap` uses `CHAP_RUN_TOKEN` first, then the orchestrator file; no flag accepts a token; a missing file gives a plain error.
- The orchestrator's token cannot approve its own request (`POLICY_BREACH`).
- The issue command's file ACL is checked by `chap doctor`; from the agent account the file is unreadable.
- Replay "agent shell finds no orchestrator token"; replay of a revoked token.
- The "Revoke orchestrator" button.

## Spec requests

1. Name the ledger events or op kinds for orchestrator token issue and revoke (this ADR uses `orchestrator.issue` and `orchestrator.revoke`).
2. Say in `docs/spec.md` that Phase 1 uses option 2 with the properties above, so the open question stops being open.
