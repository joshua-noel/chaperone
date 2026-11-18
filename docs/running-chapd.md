# Running chapd

The commands and flags of the `chapd` daemon, and how its parts connect. For a first look, run the demo in the [README](../README.md#build-and-run-from-source). For the install on the server, follow [runbooks/install.md](runbooks/install.md). "The runner" in this page is a separate project that starts agent runs and signs their run tokens; it is not public yet.

```powershell
chapd run -db D:\Chaperone\data\state.db -keys D:\Chaperone\data\run-keys.json -policy-dir <repo>\policy
chapd orch issue -project storefront -ops pr.merge,health -days 30     # elevated, as the operator
chapd orch list
chapd orch revoke -id main
chapd vault init                                                         # once, as the account that runs chapd; prints the recovery identity once
chapd vault import --name github-app-key --file <path-to.pem> --delete   # validates the RSA PEM, stores it, prints the fingerprint, then wipes the file
chapd vault list
chapd vault recover                                                      # after the service account was reset: re-keys the vault; the recovery identity comes in on standard input
chapd profile add -file <profile.json> -profiles-dir D:\Chaperone\data\profiles   # admit a runner profile; prints the digest a run token must carry
chapd profile digest -file <profile.json>                                # the digest only, writes nothing
```

`chapd run` serves `127.0.0.1:55398` (the API under `/v0/` and `/git/`, the console elsewhere) and refuses any non-loopback address. It needs the pinned run-token key set (ADR-005); `-vault-dir`/`-vault-key-dir` turn on secret redaction and, with `-interim-secret` and `-interim-kid`, the interim issuer. Every op is disabled until a policy change enables it in `internal/policy/data/baseline.yaml`; `policy/<project>.yaml` can only narrow that. `-profiles-dir` (default: `profiles\` next to the database, when it exists) is the profile source for `runner.*` run tokens: one factory-spec generic profile per file, named `<digest hex>.json`, re-verified (schema, and the file hashes to its name) on every token. With no profile source every `runner.*` token is refused `TOKEN_INVALID` and `POST /v0/runs` cannot return 201; interim host tokens do not need one. See "Admitting a runner profile" below. `chapd orch issue` writes the token to `%LOCALAPPDATA%\Chaperone\orchestrator.token` (an ACL for the invoking user only) and prints its fingerprint, never the token (ADR-007).

`GET /v0/runs/{id}` tells the runner the state of a run it registered: `state`, `ended_at`, `cause_code` and `expires_at`, nothing else, so the runner sees a Chaperone-side revoke before the token's `exp`. The credential is a runner control JWT (`act run.status`, single use, 60 s at most) as the one `Authorization: Bearer` value; it reads only runs its own issuer registered (another issuer's run and an unknown run both answer `404`), and a run token or the orchestrator token is refused `401 TOKEN_INVALID`.

`chapd vault` keeps the vault next to the database (`vault\` and `vault-keys\`; override with `-vault-dir` and `-vault-key-dir`, and pass the same to `chapd run`). The keys are DPAPI-bound, so run it as the account that runs `chapd` (ADR-003). `import --delete` overwrites the source file with zeros and removes it only after the import succeeded; a rejected or duplicate import leaves the file alone. The GitHub client reads the App key through `gh.NewVaultKey`; the live tests read it from the vault (`CHAP_GH_LIVE_VAULT` = path of `state.db`).

The console's screens are listed in `internal/console/doc.go`: Home (pending approvals, recent denials, health, **Stop all**), Runs (revoke a run, **Revoke orchestrator**), Operations (the catalog, read-only), Ledger (search, integrity check, last anchor) and Secrets (import and rotate: the critical op `secrets.write`, stored only after a fresh Windows Hello approval of its card). The screens only show metadata, never a secret or a token. `chapd` switches them on at start: `Console.UseApprovals`, then `Console.UseScreens`.

An op that needs a human (a medium or high tier `pr.merge`, `deploy`, the critical ops) makes an approval card through the approvals engine (`internal/approvals`; `cmd/chapd/approvals.go` connects it to the op pipeline). The operator decides it on the Approvals screen with a fresh Windows Hello assertion over the card's challenge; chapd then releases the op and spends the approval in the same commit that starts it, so it runs once. A denial is sticky for 60 minutes. The phone wake-up is optional: import the ntfy topic (`chapd vault import --name ntfy-topic --kind ntfy-topic --file topic.txt --delete`) and start chapd with `-ntfy-topic-secret ntfy-topic` (and `-ntfy-url` for a self-hosted server). A critical-class op also raises an alert (an `ERROR` log line, and `alerts.ps1` when `-alerts-script` is set).

`pr.merge` and `pr.update` are on in the baseline, but a project can use them only if `policy/<project>.yaml` has a `pr:` block (`base`, `extra_checks`, `tiers`); for any other project both are refused with `OP_POLICY_REFUSED`. They need the GitHub App: `chapd vault import` the key, then `chapd run -vault-dir ... -github-app-id <id>`. `scripts/demo/merge-on-red.ps1` shows a red PR refused (`CI_RED`) and a green one merged against a fake GitHub; it builds `chapd` with `-tags demo`, whose `-dev-fake-github` flag exists in no shipped binary and never in `chapd svc`.

`ci.report` (ADR-002 amendment 10) posts a finished runner `ci` run's result to GitHub as a check run of Chaperone's own App, and a project whose `pr:` block has `local_ci` (`mode: also` or `instead`, optional `check`, default `local-ci`) makes `pr.merge` read that check run, on exactly the head, besides or instead of `verify`. The op is **on in the baseline** but refuses a project with no `local_ci` block, only the orchestrator may ask (`chap ci report <run-id> --project <p>`), and the App needs `checks: write` (an operator step). The steps are in [`runbooks/ci-report.md`](runbooks/ci-report.md).

`issue.open`, `issue.comment` and `issue.reopen` (ADR-002 amendment 11) are on in the baseline for a dedicated orchestrator token only (for example one held by a monitoring job) (no run profile lists them). They need the GitHub App, and the App needs the Issues permission (read and write), which you grant in GitHub; see [`runbooks/issue-ops.md`](runbooks/issue-ops.md). A project can use them only if its policy file has a `pr:` block: the repository is its `pr.repo`. chapd refuses an `issue.open` whose labels lack `source:error-watcher`, and a comment or reopen on an issue without it. Limits: 6 calls a minute and 20 an hour per op and caller (`rate_per_hour` in the pack).

`pr.view`, `pr.diff`, `pr.checks` and `pr.files` (ADR-002 amendment 12) read a pull request for the orchestrator token: `chap pr view|diff|checks|files <n> --project <p>`. They are **on in the baseline** (`chapd` must be a build that has that policy), need no new GitHub App permission (they ask for `pull_requests: read`, and `checks: read` for `pr.checks`, never `contents` or any write), and a project can use them only if its policy file has a `pr:` block: the repository is its `pr.repo`. The orchestrator token must list the ops ([`docs/runbooks/pr-read-ops.md`](runbooks/pr-read-ops.md)); no run profile does. Limits: `pr.view`, `pr.checks`, `pr.files` 30 a minute and 600 an hour; `pr.diff` 12 and 240, per op and caller. The diff is cut at 256 KiB; a result that holds anything shaped like a secret is stored as `REDACTION_BLOCKED`.

`scripts/demo/approve-a-merge.ps1` is the same fake GitHub with pull requests that change code, so each needs an approval card. It starts a scratch `chapd` (own temp folder and database, port 55415, never 55398), prints one address, and waits while you create a passkey, sign in and press "Approve with Windows Hello" on the card in Edge. Then it checks that GitHub saw exactly one merge, the ledger holds one `op.approve` and one `op.result`, and the approval cannot be used again. `-AlsoDeny` adds a second card to deny first (the same request is then refused). The demo build's `-dev-enroll` flag prints that address; `chapd enroll -addr 127.0.0.1:PORT` moves the console origin with the port.

`mail.send` and `drive.share` (`internal/connectors/google`) are **off in the baseline** and stay off until a policy change enables them. With the vault open `chapd run` installs both adapters (they refuse everything until the op is enabled, the project's policy file has a `google:` block with its recipient allowlist, and Google is connected). The operator's steps (Google Cloud client, consent screen *In production*, scopes, `chapd connect google`) are in [`runbooks/google.md`](runbooks/google.md). All tests use a fake Google (`internal/connectors/google/googletest`); the live flow has not been run.

`intake.list`, `intake.comment`, `intake.move` and `intake.states` (`internal/connectors/linear`) read and update a Linear intake board. They are **on in the baseline**. With the vault open `chapd run` installs the four adapters; they refuse everything until the op is enabled, the project's policy file has a `linear:` block (`team`, `label`, `states`), the vault holds `linear-client-id` and `linear-client-secret`, and the orchestrator token lists the ops (no run profile does). `chapd` reads the board every `-linear-poll-interval` (default 15m, at least 1m, 0 for no poller) and caps its own Linear calls at `-linear-hourly-budget` (default 300) an hour. The operator's steps are in [`docs/runbooks/linear-intake.md`](runbooks/linear-intake.md). All tests use a fake Linear (`internal/connectors/linear/lineartest`); no live call has been made.

## Admitting a runner profile

A run token from the runner names the profile it runs under in `profile.digest`. `chapd` admits the token only when its profile folder holds a profile with exactly that digest. The format is the generic profile of the shared spec (`profile.schema.json`).

| | |
| --- | --- |
| Folder | `-profiles-dir <dir>`. Without the flag, `profiles\` next to `state.db`, when that folder exists. |
| File name | `<64 lowercase hex>.json`: the profile's digest without `sha256:`. |
| Digest | `sha256:` plus the SHA-256 of the profile's JCS (RFC 8785) form. Spaces and member order in the file do not matter. |
| Admitted when | the JSON is strict, it is valid as a generic profile (an overlay is refused), it has a `branch_prefix`, and it hashes to its own file name. |
| Checked | at start (a bad file stops `chapd`) and on every token, so an edited file is refused at once and a new file needs no restart. |

The folder is Chaperone's allowlist: whoever can write to it can admit a profile. Keep it next to `state.db`, under the same ACL as the rest of the data folder (see [install](runbooks/install.md)).

```powershell
chapd profile digest -file C:\work\code-1.0.0.json      # check the file and print its digest; writes nothing
chapd profile add -file C:\work\code-1.0.0.json -profiles-dir D:\Chaperone\data\profiles
```

`add` checks the file the same way, creates the folder if needed and writes `<hex>.json`. Run it again with the same file to repair a copy that somebody edited. The installed service takes the default folder; create `profiles\` and restart the `chapd` service once so that it logs `profile source`.

A caller learns only `TOKEN_INVALID`. The reason is in the `chapd` log:

| Cause | Reason in the log | Fix |
| --- | --- | --- |
| No profile source | `no profile source is configured` | Add a profile and start `chapd` with `-profiles-dir`, or create the default folder. |
| The digest is not a file | `profile digest sha256:... is not admitted` | Compare `chapd profile digest` of the runner's profile with the token. Admit it, or fix the token. |
| The file was edited or renamed | `the file hashes to sha256:..., not to the digest in its name` | Find out who edited it. Then run `chapd profile add` with the real profile. |

A profile that does not match the token (wrong kind, a branch outside `branch_prefix`, an op outside `ops.allow`) is refused as in ADR-005.
