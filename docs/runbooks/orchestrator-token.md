# Runbook: issue, rotate and revoke the orchestrator token

The orchestrator token is how `chapd` knows a request comes from the orchestrator and not from an agent (ADR-007). The orchestrator (id `main` in the commands and the ledger) is the lead agent that coordinates the other agents. It is an opaque bearer token (`chap_orch_...`), scoped to projects and ops, valid for at most 30 days, and `chapd` keeps only its SHA-256. You issue it from an elevated window; the orchestrator reads it from a file in your profile. Run log: [`logs/orchestrator-token.log`](logs/orchestrator-token.log) (a scratch database and a scratch `chapd`; the token file was a scratch file).

The token decides who may **ask**, not who may **approve**: it cannot approve anything, and high-impact ops it asks for still wait for you in the console.

```powershell
$chapd = 'C:\Program Files\Chaperone\chapd.exe'
$chap  = 'C:\Program Files\Chaperone\chap.exe'
$db   = 'D:\Chaperone\data\state.db'
```

## 1. Issue (first time, or after a revoke)

In an **elevated** window (the database is closed to your normal token by its ACL; `chapd orch` refuses to open the real database from a normal window):

```powershell
& $chapd orch issue -id main -project storefront -ops "pr.merge,pr.open,pr.update,health,logs" -days 30 -db $db
```

```
orchestrator "main" issued
  fingerprint: bb40dd74
  expires:     2026-11-23T15:23:40-04:00
  token file:  ...\orchestrator.token (readable by this user only)
```

- The token is written to `%LOCALAPPDATA%\Chaperone\orchestrator.token` of **the invoking user** (you; an elevated window of the same account has the same profile). Only the fingerprint (first 8 hex of the SHA-256) and the expiry are printed. Override the file with `-token-file`.
- `-project` is a comma-separated list of project ids (`storefront`); a bad one is refused. `-ops` is a comma-separated list of op kinds or `prefix.*` patterns. **Op names are not checked against the catalog**: a typo is accepted and simply gives no access. Read the answer back with `chapd orch list`, and with `chap manual` (step 2).
- `-days` is 1 to 30 (31 is refused: `days must be 1 to 30`).
- `-mint-interim` lets the holder use `chap dev-token` to mint interim run tokens. Leave it off unless the orchestrator really needs it; it only works while the key set allows interim tokens (ADR-005).

Read it back:

```powershell
& $chapd orch list -db $db
```

```
ID    FINGERPRINT  STATE  EXPIRES(-04)               PROJECTS       OPS                                     INTERIM
main  bb40dd74     live   2026-11-23T15:23:40-04:00  storefront  pr.merge,pr.open,pr.update,health,logs  false
```

## 2. Check that the orchestrator can use it

From a **normal** window (this is how the orchestrator runs):

```powershell
& $chap ledger verify          # orchestrator-only; exit 0 and "ledger ok: chain chaperone.host1, head seq ..." means chapd accepted the token
& $chap manual --project storefront
```

`chap manual` lists the ops that are on for this token and project; the ops the baseline has not enabled, or that have no adapter in this `chapd` (no GitHub App yet, say), are not offered. `chap manual --all` shows them as `disabled`. Exit code 4 with `TOKEN_*` is a token problem; exit code 6 means `chapd` is not running.

## 3. Rotate

Rotate before the expiry (read `EXPIRES(-04)` in `chapd orch list`; the cap is 30 days and there is no refresh), after anything that may have exposed the file, and when the scope should change. **Rotating is issuing again with the same `-id`**: the old token is revoked and the new one stored in one transaction, and the file is replaced whole.

```powershell
& $chapd orch issue -id main -project storefront -ops "pr.merge,pr.open,pr.update,health,logs" -days 30 -db $db
& $chapd orch list -db $db
```

```
main  02db59c3  live     2026-11-23T15:23:41-04:00  storefront  ...
main  bb40dd74  revoked  2026-11-23T15:23:40-04:00  storefront  ...
```

From then on `chap` processes that read the file use the new token. A copy of the old token is refused on its next request:

```
DENIED token /v0/ledger/verify (orchestrator main)
why: orchestrator token main was revoked
request: not possible, policy does not allow asking
```

(exit code 4). Anything of the orchestrator's that cached the token text rather than reading the file must be restarted.

## 4. Revoke

Revoke when the orchestrator must stop at once, or when the token may have leaked. Either way removes authority only, so it needs no approval:

- **Console:** `http://localhost:55398`, Runs, **Revoke orchestrator**.
- **Command**, elevated:

  ```powershell
  & $chapd orch revoke -id main -db $db
  ```

  ```
  revoked the orchestrator token of "main"; its next request is TOKEN_REVOKED
  ```

`chapd` reads the database on every request, so the next call fails (`TOKEN_REVOKED`, exit code 4, in `--json` the denial shows `"cause_code": "TOKEN_REVOKED"` and `"orchestrator_id": "main"`). The orchestrator's pending approvals are cancelled in the same transaction. Revoking again says `no live orchestrator token for "main"`. The orchestrator stays locked out until you issue again (step 1).

## 5. If the token may have leaked

1. **Revoke first** (step 4). Do not wait to find out.
2. Issue a new one with the narrowest scope that works (step 1).
3. Find out what the old token did. Everything the orchestrator asked for is in the ledger as `op.request` / `op.result` / `denial` events with `factory.requester.kind = orchestrator` and `orchestrator_id = main` (and no `run_id`); the issue and revoke events carry the token's fingerprint, so the window of the old token is the time between its issue event and its revoke event. See [`ledger-evidence-pack.md`](ledger-evidence-pack.md).
4. Find how it leaked. The token is in one file under your profile; anything that runs as your account can read it (ADR-007, "What this does and does not defend"). A copy in a log or chat is masked by `chapd` and `chap` when it is the exact token or has the `chap_orch_` shape, but that is a net, not a promise for text you paste yourself.

## What is recorded

Issue and revoke are ledgered as `op.request` and `op.result` for the operator-only ops `orchestrator.issue` and `orchestrator.revoke`, with the id, the scope, the fingerprint and the expiry; the event's project is the first project in `-project`. `chap ledger verify` shows the head move (in the log: head seq 1 after the first issue, 3 after the rotation). The token itself is not stored (only its SHA-256), not logged and not printed: `TestOrchTokenIsStoredHashedOnly` and `TestOrchIssueWritesPrivateFileOnly` in `test/redteam` check it.

## What this does not cover

- Where the token file's ACL is checked: `chap doctor` (`acl-agent` proves the `chap-agent` account cannot read it). A scratch run cannot test that.
- Issuing or revoking from the console is not possible; `orch issue` is a command by design (the token must not travel through a browser). Revoke is both.
- The 30-day cap is a hard limit in `chapd`. For a shorter life, use a smaller `-days`; the ADR-007 upgrade path (issue after a Hello, hours not days) is not built.
