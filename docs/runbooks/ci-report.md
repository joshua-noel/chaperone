# Runbook: let Chaperone report a local CI result (`ci.report`)

ADR-002 amendment 10 lets `pr.merge` accept the result of a local CI run (a `ci` run of the runner, the separate project that starts agent runs and signs run tokens; it is not public yet) as a check run that Chaperone's own App posts. It needs **one permission change on the GitHub App** that only you can approve, and **two policy changes** (which are pull requests). Until the permission is approved, `ci.report` fails with a message that names this page and posts nothing. Nothing else in Chaperone depends on it: `pr.merge` for every project is unchanged until a project's policy file has a `pr.local_ci` block.

Who runs it: you, in a normal browser window, signed in to GitHub as an owner of `example-org`. About 5 minutes. No key changes, nothing is imported, and `chapd` does not restart for the permission step.

## 1. Give the App `checks: write` (the operator step)

1. GitHub, **Settings** of the organisation `example-org`, **Developer settings**, **GitHub Apps**, `chaperone-app`, **Edit**.
2. **Permissions & events**, **Repository permissions**, **Checks**: change **Read-only** to **Read and write**. Leave every other permission as it is (in particular, still no `workflows`).
3. **Save changes**. GitHub now tells the installations that the App asks for more.
4. **Installation**: organisation Settings, **GitHub Apps**, `chaperone-app`, **Configure**. A yellow banner says the App requests an updated permission. Press **Review request**, check that the only change is **Checks: Read and write**, and press **Accept new permissions**.

What you will see: after step 4 the banner is gone and the installation's permission list shows "Read and write" for Checks. Until then a request for `checks: write` is answered `422` by GitHub.

Check it from a normal window once the policy below is on (step 3), with a finished `ci` run (the runner prints its run id):

```powershell
& 'C:\Program Files\Chaperone\chap.exe' ci report <run-id> --project storefront --dry-run
& 'C:\Program Files\Chaperone\chap.exe' ci report <run-id> --project storefront
```

The dry run lists what chapd found in its own record of the run (project, profile, ended, repository, commit) and posts nothing. The second call posts a check run named `local-ci` on that commit, from the App; GitHub's PR page shows it under the checks, with the App `chaperone-app` as its author. If the permission is missing, the second call ends `failed` and its result says `GitHub refused a token with checks: write ... (operator step, docs/runbooks/ci-report.md)`.

## 2. Put `ci.report` in the orchestrator's token

`ci.report` is asked for by the orchestrator only. Issue or rotate the orchestrator token with `ci.report` in `-ops` (see [orchestrator-token](orchestrator-token.md)); a token without it gets `OP_NOT_IN_TOKEN`.

## 3. The two policy changes (the operator merges them)

- **Turn the op on (a pull request):** `internal/policy/data/baseline.yaml`, `ci.report: { enabled: false, ... }` to `enabled: true`, and add `ci.report` to `shippedEnabled` in `internal/policy/policy_test.go`. A project file cannot do this; it is a baseline change. Until it is merged the op is `OP_DISABLED`.
- **Say which projects use it:** in each project's `policy/<project>.yaml`, under `pr:`:

  ```yaml
  pr:
    repo: example-org/storefront
    base: main
    local_ci:
      mode: also        # `also`: verify AND local-ci. `instead`: local-ci replaces verify.
      check: local-ci   # optional; the default
  ```

  Start with `also`. Switch to `instead` only after the hosted Linux job no longer runs on PRs; `instead` makes a green `local-ci` check from Chaperone's App the only CI that gates the merge (the `extra_checks` still come from GitHub Actions). A PR that changes `.github/workflows/**` still needs your approval card either way.

## What `ci.report` will not do

It never takes a repository, a commit or a conclusion from the caller: only the run id. It refuses a run that is not of the `ci` profile, is still running, belongs to another project, checked another repository than the project's, or ended before Chaperone kept run outcomes. A run cannot ask for it. Every refusal is `OP_POLICY_REFUSED` with the reason, and posts nothing.

## What was and was not executed

Executed (Go tests against the fake GitHub server, `internal/ops`, `internal/policy`, `internal/runtoken`, `cmd/chap`): the adapter's refusals and posts, `pr.merge` with `also` and `instead`, the round trip from a posted check run to a merge verdict, the missing-permission message, the `chap ci report` output. **Not executed:** the GitHub UI steps above and a real `POST /check-runs` against GitHub. [INFERENCE] The labels in step 1 follow GitHub's documentation of App permissions; read them on the page and, if they differ, say so in the pull request that follows.
