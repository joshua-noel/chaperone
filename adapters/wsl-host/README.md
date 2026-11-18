# `deploy` and `health` for the Storefront pilot (tickets L1-15, L1-11)

Code: `internal/ops/deploy*.go` (policy checks, the adapter, `HostBus` that signs grants and serves chap-host's routes) and `internal/ops/health*.go`. This folder holds the rehearsal against a throwaway target. Wiring is `cmd/chapd/deploy.go`.

## What a deploy does

1. **Checks, in order, before any approval card.** The first failure stops the list and refuses the request (`OP_POLICY_REFUSED`, no card). They run again at release.
   1. The SHA is on the project's base branch (`base...sha` is `identical` or `behind`).
   2. `verify` (and the project's `extra_checks`) succeeded on exactly that SHA, judged by pr.merge's `judgeCheck` (latest run wins, GitHub Actions only).
   3. `%LOCALAPPDATA%\Storefront\load-gate.json` says `normal` and `checkedAt` is under 5 minutes old.
   4. `D:\Storefront\health\last-valid-backup.json`: `bytes` > 0, `entries` > 0, `validatedAt` within 26 hours (the hygiene limit). If chapd can stat the dump it names, a missing or empty dump refuses too.
   5. The pilot readiness says `ok` (below).
2. **Card.** Class `high`; ADR-004 section 3. The card shows the SHA and a text with the facts the checks read. The approval is bound to the op hash, so another SHA is `APPROVAL_HASH_MISMATCH`.
3. **Run.** On release, `Execute` reads the pilot again, then `HostBus` signs a grant for the fixed `deploy` runbook (arg `sha`, `script_sha256` of the stable copy of `pilot.sh`, 4 minute life), sends it on chap-host's event stream and waits. chap-host verifies it and runs `pilot.sh deploy <sha>` in WSL as the pilot user.
4. **After.** `Execute` reads readiness until `ok` (3 minutes). Not `ok` is `failed`: `op.result outcome=failed`, an alert through `alerts.ps1`, the GitHub deployment recorded as `failure`. A runbook timeout is `unconfirmed`. A grant nobody took is `failed` (nothing ran).
5. **Record.** Success writes a GitHub deployment (environment `pilot`) and status with the App's own `deployments: write` token (replaces `record-deploy.mjs` with the operator's `gh` login; the runbook's own record step should be dropped when this goes live).

The op result holds `health_after`, `host_outcome`, `exit_code`, `output_tail` (redacted) and `started_at`, `finished_at`, `blast_radius` as `HH:MM`.

## `health`

One `GET http://127.0.0.1:55350/api/health/ready` with `Host: pilot.storefront.net` and `X-Forwarded-Proto: https`, no redirects, loopback URLs only. Answers: `ok`, `unavailable`, `unreachable`, `malformed`. The rate limit is the policy's `rate_per_minute` per caller. It never starts or probes WSL, Docker or the stack.

## Setting it up (operator, once; nothing here is run by the installer)

```powershell
chapd host keygen --seed-out C:\temp\grant.seed --token-out <operator profile>\Chaperone\host.token
chapd vault import --name grant-key --kind ed25519-seed --file C:\temp\grant.seed --delete
```

* Put the printed `chapd_public_key` and the token path in `host\chap-host.json`, with `scripts.deploy` = the stable copy of `pilot.sh`.
* Give `svc-chaperone` read access to the host token file (keygen restricts it to the operator).
* Start chapd with `-deploy-script` (same bytes as chap-host's copy), `-grant-secret grant-key`, `-host-token-file`, `-load-gate-file` (the operator's `%LOCALAPPDATA%`, not the service's), `-backup-file`, and optionally `-alerts-script` and `-alerts-folder`. Any one of these turns deploy on and the rest become required.
* Enable `health` and `deploy` in the baseline (a policy PR with the operator's sign-off; they are `enabled: false` now).

## Rehearsal against a throwaway target

`rehearsal_test.go` runs the real deploy adapter, policy checks (fake GitHub), health client and host bus against a throwaway target: a fake pilot on loopback, `rehearsal/pilot.sh` (prints, changes nothing) and a host emulator that verifies the grant and runs the script with a local bash. It covers a good deploy, a failing runbook, a bad build that leaves the pilot down and a pilot that is down before. It skips when `bash` is the WSL launcher. No WSL distro, Docker, Windows account or live pilot is touched. The first live deploy is operator-attended.
