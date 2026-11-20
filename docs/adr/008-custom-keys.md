# ADR-008: Custom keys: a Chaperone token for a script or an agent

- **Status:** **Accepted** (operator decisions of 3 Nov 2026, as written in the rules below). Written 2026-11-20 from the code that implements them: `internal/keys`, `internal/ops/keyceiling.go`, migration `0010_custom_keys.sql`.
- **Decides:** how a script or an agent gets its own credential for a small part of what Chaperone can do, without the orchestrator's token and without any vendor secret; what that credential can never do; how it is made, shown, limited, ended and written down.
- **Does not decide:** which ops a key may hold beyond the first ones (the list grows in `internal/ops/keyceiling.go`, one reviewed change per op), or how a stopped agent is resumed (not built).

## Context

- Until now Chaperone knew two callers: a run (ADR-005) and the orchestrator (ADR-007). A script or an agent that is not a run had to borrow the orchestrator's token, which holds every op the orchestrator holds.
- A key is **not** a vendor secret. It never holds a GitHub or Linear credential. It names what Chaperone will do, and every call under it goes through the same policy, approval card, rate limit and ledger as any other call.

## Decision

**A key is an opaque bearer token, made in two steps, stored only as its SHA-256, bound to one project, a list of ops and the repositories it covers, with an expiry and an hourly rate that are fixed when it is made.**

1. **Format and storage.** `chap_key_` followed by the base64url of 32 random bytes. The `chap_key_` prefix routes the bearer to the key verifier. The database keeps only `SHA-256(token)` and the first 8 hex characters as a fingerprint. Verification reads the row on every request, so a revoked key stops at the next call.
2. **Making a key takes an approval.** The op `keys.issue` is class **high**: a card the operator signs with Windows Hello or a phone passkey. The card lists the holder, every op (sorted), the repositories, the lifetime and the rate, in the words and the order the key will hold them: the adapter refuses a request whose lists are not already sorted, lower-case and free of repeats, and a request that leaves out the lifetime or the rate. Only the orchestrator's token may ask for it. It ships off in the baseline.
3. **The claim.** The signed card writes the key's row with **no token**. The caller that asked then claims it, once, within one hour: the token is made at that moment, only its hash is stored, and it is registered with the redaction registry before the row commits. The one claim response carries it (`Cache-Control: no-store`); nothing else, not an op result, a ledger event, a log line or an error, ever does. A key not claimed within the hour is revoked by a sweeper.
4. **What a key may hold (rule R1).** A key runs routine ops on its own. For a risky (non-routine) op it can only **ask**: every use raises its own approval card, the operator approves each one with a passkey, and nothing runs until then. The owner decided on 20 Nov 2026 to keep this: a key may hold a risky op ask-only. A key that holds one is *sensitive* (at most 7 days). A key can never hold a critical op, never `keys.*`, `people.*`, `roles.*`, `secrets.*`, `issue.*`, `intake.*`, `ci.report`, `policy.activate`, `approvers.enroll`, `repo.settings` or `host.scripts.refresh`. Only an op that names the unit it is bound to (a repository or the project) can be in a key, so no key means "everything". The ceiling is checked three times: when the card is made, when the key is verified (a hand-edited row is cut down to what a key may hold) and when each op is asked for.
5. **Scope is fixed.** Project, ops, repositories, rate and expiry never change after issue (database triggers refuse an update). A key cannot name another project in a request. A pull-request read under a key is refused before any call to GitHub unless the repository is one the key covers.
6. **Limits.** At most 30 days; a sensitive key at most 7. At least 1 hour. At most 300 calls an hour over all ops, lowered only. The database repeats the lifetime limits in `CHECK`s.
7. **What a key can never do.** Decide an approval card (a key that tries is a `POLICY_BREACH`), issue or revoke another key (it may revoke itself), use the git proxy, or read the ledger.
8. **Revoking.** The orchestrator revokes any key; a key revokes only itself. The revoke, the cancel of the key's pending approvals and waiting ops, and its ledger events are one transaction. A human revoke of an **agent's** key also stops the agent: no key can be issued for it until its owner resumes it ("stopped by a human: ask your owner"). One live key per agent: a new grant replaces the earlier one.
9. **The ledger.** The spec has no key requester, so a key is written in the ledger as the orchestrator `key.<id>` (the one projection is `internal/spec/keyrequester.go`), and the event body names the key, its owner and its holder. The approvals and ops tables keep a separate requester kind `key`.

## What this does and does not defend

| Attacker | Result |
| --- | --- |
| A script that holds a key tries an op outside its list, another repository or another project | Refused with a denial; nothing reaches GitHub |
| A key tries a critical op, `keys.issue` or a card decision | Refused; a card decision is a `POLICY_BREACH` |
| Someone who reads the database | Finds hashes, never a token |
| A stolen key | Works until its expiry or a revoke, inside its scope and rate; a risky op still needs a card |
| A request that tries to widen a key after the card was signed | The card is made from the request: what is signed is what is stored; the row's scope never changes |

## Open

- Resuming a stopped agent has no command yet.
- Owners are the orchestrator that asked: there is no model of people yet.
- The ceiling holds the four pull-request reads, `health`, `logs` and `deploy` (ask-only).

## Tests

`internal/keys` (the limits, the claim, hashes only, concurrent claims, revoke, the stopped agent, idempotent issue, the card text); `internal/ops/key_caller_test.go` (every caller kind handled, the ceiling, the unit binding, the per-key rate, the git proxy, the routes); `internal/approvals/key_requester_test.go`; `internal/store/migrate_keys_test.go`; `cmd/chap/key_test.go`; `cmd/chapd/keys_e2e_test.go` (a key from card to use to revoke). Operator steps: [`../runbooks/custom-keys.md`](../runbooks/custom-keys.md).

## Amendments

**Amendment 1. The agent asks, you tap (2026-11-20).** An agent no longer needs the orchestrator to ask for a key for it. The code is `internal/keys` (`enrol.go`, `requests.go`, `decide.go`, `extend.go`, `scope.go`, `access.go`), migration `0011_agent_requests.sql`, the console's **Agents** pages and `chap agent enrol`, `chap key request`, `chap key extend`. The operator steps are in [`../runbooks/custom-keys.md`](../runbooks/custom-keys.md).

- **Enrolment, once.** The agent starts a device-code flow (the shape of RFC 8628): it gets a short code to read out and a long one only it holds. Neither is stored, only their SHA-256. The owner types the short code at the console, reads "no access at all" and signs a `keys.issue` card with their own Windows Hello. The agent's next poll hands it a **request-only key** once: 30 days, no op, 60 calls an hour. The only thing it can do is ask.
- **Asking.** `keys.request` is routine. It writes the ask down and raises no card. An agent's key holds it without listing it, and no other key does. Identical asks are one request. The owner's reading of the reason is of the agent's own words, shown as text. Caps keep a looping agent from filling its owner's queue: at most 3 requests wait per agent, 6 new per hour per agent, 10 per owner, 20 in all; a denied exact ask is refused for an hour. `--same-as-me-read` is expanded by chapd to the read ops the owner may grant.
- **Answering.** Grant as asked, narrow and grant, or deny. A grant can only remove ops or repositories, shorten the lifetime or lower the rate; the same check runs when the card is made and again when the key is written. Grant and narrow only make a `keys.issue` card, started by chapd as the caller `operator` (an orchestrator id that no token can carry: `chapd orch issue` refuses it). The key exists only when the owner signs that card with their own Hello. Another person's signature does not make it, and another person's agent looks like no agent.
- **Claiming.** The agent claims the granted key; the claim writes it over the request-only key, which is revoked in the same step. One live key per agent.
- **Extending.** `keys.extend` changes the expiry and nothing else, never past 30 days from the day the key was made (7 with a risky op), and only for a live key an owner granted their own agent. The owner taps **Extend 24 hours**, or the agent asks; either way it is a card the owner signs.
- **The routes that need no credential.** `POST /v0/agents/enrolments` and its poll are the only two routes of chapd that take no token, because the agent has none yet. Their bounds, all tested (`cmd/chapd/agent_enrol_bounds_test.go`): at most 5 enrolments wait, even under concurrent starts; one label waits once; an enrolment lives 10 minutes; a wrong code is counted per owner, five in ten minutes lock that owner's code box (also against the right code), and starting new enrolments does not reset the count; the routes answer only on chapd's loopback listeners, only for the Host the rest of the API answers to, and refuse any request with an `Origin` header or without a JSON content type, so a web page in the operator's browser cannot use them. A wrong device code, an unknown id and a malformed id get the same answer.
- **What a local process can still do.** With no credential, a process on the machine can hold the 5 slots, or the one label of the agent it wants to block, for 10 minutes at a time, and repeat. The real agent is then refused with 429 or 409 until the enrolment expires. Nothing tells the operator: no ledger event is written and no page lists a waiting enrolment (the page finds one only by its code). The attacker cannot turn that into a key, because the owner types a code that only the real agent printed. This is accepted for now.
- **The wrong-code count is in memory.** A restart of chapd clears it.
- **Who owns an agent.** Until people are modelled, the owner is the console approver who enrolled the agent (`person:<approver id>`), and every approver's access is everything the policy allows.
