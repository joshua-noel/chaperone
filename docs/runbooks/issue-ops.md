# Runbook: the monitoring job's token and the GitHub App's Issues permission

A monitoring job on a host (for example one that watches error logs) can file GitHub issues through Chaperone (ADR-002 amendment 11): `chap issue open|comment|reopen`. None of these steps has been tried against real GitHub. It lists what **you** do, once, before the job can file anything. Until then every issue op is refused, and says why.

The job never holds a GitHub credential. It holds one **orchestrator token** (ADR-007) that may ask for three ops in one project and nothing else, and it can write only to issues that carry the label `source:error-watcher`.

```powershell
$chapd = 'C:\Program Files\Chaperone\chapd.exe'
$db   = 'D:\Chaperone\data\state.db'
```

## Why an orchestrator token

The mechanisms `chapd` has are the run token (a run of the runner, the separate project that starts agent runs; it is tied to a branch and a repository) and the orchestrator token. The job is not a run, so only the orchestrator token fits. A second token with its own `-id` is the least privilege available: its scope is `issue.open`, `issue.comment` and `issue.reopen` in project `storefront`. It cannot merge, deploy, mint run tokens (no `-mint-interim`) or approve anything, and revoking it leaves the token with id `main` alone. No new token type and no change to `chapd`'s auth code were needed.

## 1. Grant the Issues permission to the GitHub App (you, in GitHub)

The App `chaperone-app` was set up for pull requests, contents, checks and deployments (ADR-002 item 1). [INFERENCE] It has no Issues permission: ADR-002 lists none, and this page's author could not read the App's settings (that needs the App's key, which agents never read). Until the permission is granted, `issue.open` fails with `GitHub would not give chapd a token with the issues permission (422)` and `issue.comment` and `issue.reopen` are refused with the same words.

1. GitHub, `example-org` organisation, Settings, Developer settings, GitHub Apps, `chaperone-app`, **Permissions & events**.
2. Repository permissions, **Issues**: set **Read and write**. Save changes. Do not change any other permission, and do not add `workflows`.
3. GitHub emails the organisation owners and shows "new permissions requested" on the installation. Open Settings, GitHub Apps, `chaperone-app`, Configure (the installation on `example-org`) and **Accept new permissions**. Until you accept, tokens still cannot carry the permission.
4. Optional: create the label `source:error-watcher` on `example-org/storefront` (Issues, Labels, New label) with a colour and a description. If you do not, GitHub creates it with the first issue.

## 2. Issue the job's token (you, elevated window)

In an **elevated** window, as you (the token file goes to the profile of the invoking user, so the job must run as that user, or point `-token-file` at a file only the job's account can read):

```powershell
& $chapd orch issue -id issue-filer -project storefront -ops "issue.open,issue.comment,issue.reopen" -days 30 -token-file "$env:LOCALAPPDATA\Chaperone\issue-filer.token" -db $db
& $chapd orch list -db $db
```

Expected: `orchestrator "issue-filer" issued`, a fingerprint and an expiry at most 30 days out, and a row in `orch list` showing `issue.open,issue.comment,issue.reopen` for `storefront` with `INTERIM false`. Do not pass `-mint-interim`. The command prints the fingerprint, never the token. Rotate before the expiry exactly as in [orchestrator-token](orchestrator-token.md), with this same `-id`.

The job reads the token from `CHAP_ORCHESTRATOR_TOKEN_FILE` (set it to that file) and reaches chapd at `CHAP_URL` (default `http://127.0.0.1:55398`). It must not read the `orchestrator.token` of the main orchestrator.

## 3. The job's commands

```
chap issue open    --project storefront --repo example-org/storefront --title <one line> --label source:error-watcher [--label <more>] [--body-file <f>]
chap issue comment <n> --project storefront --repo example-org/storefront --body-file <f>
chap issue reopen  <n> --project storefront --repo example-org/storefront
```

`--label source:error-watcher` is required on `open` (chapd refuses the issue without it). `comment` and `reopen` need the issue to carry it already. At most 20 calls per hour and 6 per minute for each of the three ops.

## 4. Check it (you, normal window, after steps 1 and 2)

```powershell
$env:CHAP_ORCHESTRATOR_TOKEN_FILE = "$env:LOCALAPPDATA\Chaperone\issue-filer.token"
chap manual --project storefront        # lists exactly issue.open, issue.comment, issue.reopen
chap issue open --project storefront --repo example-org/storefront --title "chapd issue op smoke test" --label source:error-watcher --body "Delete me."
chap issue open --project storefront --repo example-org/storefront --title "must be refused" --label bug
```

What you should see: the first `issue open` prints the new issue's URL and exits 0; the second exits 3 with `OP_POLICY_REFUSED` and the label named in `why`. Close the smoke-test issue by hand. `chap op show <id>` and the console's ledger screen show each call as `op.request` and `op.result` from orchestrator `issue-filer`.

## Revoke

```powershell
& $chapd orch revoke -id issue-filer -db $db
```

The job's next call is `TOKEN_REVOKED`. The token with id `main` is not touched.
