# Custom keys

A key is a Chaperone token for a script or an agent. It is never a vendor secret: it names what Chaperone will do, and every call under it goes through the same policy, approval card and ledger as any other call.

## Build one

1. A policy change turns `keys.issue` on (it ships off in `internal/policy/data/baseline.yaml`), and the orchestrator token that asks lists `keys.issue` in its ops.
2. `chap key create --project <p> --holder <name> --agent|--person --ops pr.view,pr.diff --repo owner/name --ttl 24h --out <file>`
3. A card appears in the console. It states the holder, every op, the repositories, the lifetime and the rate. Approve it with Windows Hello. The card is the grant: ops and units are listed sorted and every number is written on it.
4. `chap` claims the key once and writes it to `--out` (owner-only, never overwritten). Nothing prints the key. Use it with `CHAP_KEY_FILE=<file> chap pr view 12`.
5. `chap key list`, `chap key revoke <k-id>`, `chap key show` (as the key).

A key not claimed within one hour of approval is revoked.

## Rules (operator decisions, 3 Nov 2026)

- A key runs routine ops on its own. For a risky op it can only ask: every use raises its own card, and you approve each one with a passkey. A key may hold a risky op this way (the owner decided to keep it); nothing risky runs without your approval. A critical op is never in a key, nor `keys.*`, `secrets.*`, `issue.*`, `intake.*`, `ci.report`, `policy.activate`, `approvers.enroll`. Only ops with a unit (a repository or the project) can be in a key.
- At most 30 days. A key holding a risky op (sensitive) at most 7 days. Rate default and maximum 300 calls an hour per key, lowered only.
- A key cannot decide a card (a key that tries is a `POLICY_BREACH`), issue or revoke other keys, or use the git proxy.
- A human revoke of an agent's key stops the agent: no key can be issued for it until its owner resumes it ("stopped by a human: ask your owner"). There is no way to resume a stopped agent yet. A key revoking itself does not stop its agent.

## Where it lives

`internal/keys` (store, `keys.issue` adapter, `/v0/keys` admin), migration `0010_custom_keys.sql` (requester kind `key` on `ops` and `approvals`, `keys`, `key_agents`), `internal/ops` (caller kind `key`, unit binding for `pr.*` reads, per-key rate), `internal/spec/keyrequester.go` (the one place a key is projected onto the pinned spec as the orchestrator `key.<id>`).

## The agent asks, you tap

Turn on `keys.request`, `keys.issue` and `keys.extend` for the project in a policy change first (all three ship off).

1. **Enrol the agent (once).** On the machine the agent runs on: `chap agent enrol --label scout --project <p> --out <file>`. It prints a short code and waits (10 minutes). At the console open **Agents**, type the code, read "no access at all", press *Make the enrolment card* and sign it with Windows Hello. The agent then holds a **request-only key** in `<file>` (30 days, no op, 60 calls an hour): it can only ask.
2. **The agent asks.** `CHAP_KEY_FILE=<file> chap key request --ops pr.view,pr.diff --repo owner/name --ttl 8h --reason "review PR 12" --wait`, or `--same-as-me-read`. Ten identical asks are one request. The reason is the agent's own words.
3. **You answer** at **Agents → Answer**: *Grant as asked*, *Narrow and grant* (you can only remove ops or repositories, shorten, or slow down) or *Deny*. Grant and Narrow only make a card; sign it with your own Windows Hello. Nobody else's signature makes the key.
4. **The key lands** in the agent's key file (the claim writes it over the request-only key, which is revoked in the same step). `chap key request --status <kr-id>` shows what was granted and what was removed.
5. **Extend** with one tap: **Agents → Extend 24 hours** (a card, signed with your Hello), or the agent asks with `chap key extend --for 12h --reason "..."`. An extension changes the expiry only, and never past 30 days from the day the key was made (7 with a risky op). After that the agent asks for a new key.

Guardrails: an agent a human stopped cannot ask or be enrolled again ("stopped by a human: ask your owner"); at most 3 requests wait per agent, 6 new per hour per agent, 10 per owner, 20 in all (refused with the rate refusal; the third refusal in 5 minutes is logged as a looping agent); a denied exact request is refused for an hour.

Until people are modelled the owner of an agent is the console approver who enrolled it (`person:<approver id>`), and every approver's access is everything the policy allows.

This part lives in `internal/keys` (`requests.go`, `enrol.go`, `extend.go`, `decide.go`), migration `0011_agent_requests.sql`, `internal/console/screens_agents.go`, `cmd/chap/agent.go`.

The enrolment routes take no credential. They answer only on the loopback addresses, only for chapd's own Host, and refuse a request with an `Origin` header or without a JSON content type. At most 5 enrolments wait, for 10 minutes each. A process on the machine can hold those slots, or the one label of the agent it wants to block, and then the real agent's `chap agent enrol` is refused until they expire; nothing shows this to you. If an enrolment is refused with "too many enrolments are waiting" or "already waits", wait ten minutes and start it again. See [ADR-008, amendment 1](../adr/008-custom-keys.md).
