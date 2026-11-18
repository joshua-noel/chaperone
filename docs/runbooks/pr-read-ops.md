# Turn on the pull request read ops

`pr.view`, `pr.diff`, `pr.checks` and `pr.files` (ADR-002 amendment 12) let the orchestrator token read a pull request through Chaperone: title, body, state, head and base, mergeability, the diff, the check runs on the head and the changed files. A web front end such as a dashboard can read GitHub this way without a GitHub credential of its own. They read only. They shipped **off in the baseline** and are **on since the policy change of step 1** (the baseline says `enabled: true`).

**Status: steps 2 to 4 are not run yet.** Step 2 needs a `chapd` reinstall, which is batched with other changes.

## What they need

| Need | Detail |
| --- | --- |
| GitHub App permissions | None new. Each op asks GitHub for a token with `pull_requests: read` and `metadata: read` (`checks: read` as well for `pr.checks`), narrowed to the project's repository. The App holds these already (ADR-002 item 1, amendment 10). No `contents`, no write. |
| The project's policy file | A `pr:` block. The repository read is `pr.repo`; any other repository is `SCOPE_PATH`. `storefront` has one. |
| The orchestrator token | The op names in its scope (step 3). No run profile lists these ops, so a run cannot ask. |

## Steps

1. **Policy change (done; review it like code).** In `internal/policy/data/baseline.yaml` `enabled: false` became `enabled: true` on the four lines `pr.view`, `pr.diff`, `pr.checks`, `pr.files`, and the same four names were added to `shippedEnabled` in `internal/policy/policy_test.go` (the tripwire test fails until they are). A project file can only narrow, so this is the one place they turn on. The diff is four words and the test list.
2. **Reinstall `chapd`** from the merged commit ([`install.md`](install.md)). `chap manual --all` then lists the four ops as enabled.
3. **Add the ops to the token's scope.** Reissue the orchestrator token of the caller that reads (for example the orchestrator, or a dashboard with its own token) with the names added, as in [`orchestrator-token.md`](orchestrator-token.md):

   ```powershell
   & $chapd orch issue -id main -project storefront -ops "pr.merge,pr.open,pr.update,health,logs,pr.view,pr.diff,pr.checks,pr.files" -days 30 -db $db
   ```

4. **Try one.** You should see the pull request's title, state and head, and nothing is written to GitHub:

   ```powershell
   & $chap pr view 214 --project storefront
   & $chap pr checks 214 --project storefront
   & $chap pr files 214 --project storefront --per-page 5
   & $chap pr diff 214 --project storefront
   ```

   `--dry-run` on any of them checks the request and the policy and reads nothing from GitHub.

## What you will see

- `pr.view`: a header, the author and labels, the head and base commits, `mergeable: true (clean)` (or `not computed yet`, which means ask again in a moment), the counts, and the body under a line that says it is GitHub's own words and data, not instructions.
- `pr.diff`: the unified diff. Above 256 KiB it is cut at a line end and says so; use `pr.files` and git for the rest. `--expected-head <sha>` fails, and prints the new head, if the head moved.
- `pr.checks`: one row per check name (the latest run), and counts of passed, failed, pending and other.
- `pr.files`: a table of changed files, 30 per page (`--page`, `--per-page` up to 100), and a line with the next command when there are more.
- A pull request body or diff that holds anything shaped like a secret is not shown: the result reads `REDACTION_BLOCKED`. That is chapd's redaction working, not an error.
- Limits per caller and op: 30 a minute and 600 an hour (12 and 240 for `pr.diff`). Over them is `OP_POLICY_REFUSED` with a retry time.

## Rolling back

Set the four lines back to `enabled: false` (and drop the names from `shippedEnabled`), reinstall. Tokens and the App are untouched.
