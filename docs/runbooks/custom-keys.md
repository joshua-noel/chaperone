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

- A key holds routine ops, and risky ops only ask-only: every use still raises its own card. A critical op is never in a key, nor `keys.*`, `secrets.*`, `issue.*`, `intake.*`, `ci.report`, `policy.activate`, `approvers.enroll`. Only ops with a unit (a repository or the project) can be in a key.
- At most 30 days. A key holding a risky op (sensitive) at most 7 days. Rate default and maximum 300 calls an hour per key, lowered only.
- A key cannot decide a card (a key that tries is a `POLICY_BREACH`), issue or revoke other keys, or use the git proxy.
- A human revoke of an agent's key stops the agent: no key can be issued for it until its owner resumes it ("stopped by a human: ask your owner"). There is no way to resume a stopped agent yet. A key revoking itself does not stop its agent.

## Where it lives

`internal/keys` (store, `keys.issue` adapter, `/v0/keys` admin), migration `0010_custom_keys.sql` (requester kind `key` on `ops` and `approvals`, `keys`, `key_agents`), `internal/ops` (caller kind `key`, unit binding for `pr.*` reads, per-key rate), `internal/spec/keyrequester.go` (the one place a key is projected onto the pinned spec as the orchestrator `key.<id>`).
