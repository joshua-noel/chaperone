# Runbooks

One page per procedure. Each says who runs it, where, and what was **executed** in a scratch setup (a temp directory database and vault; the real data folder `D:\Chaperone\data` is never touched) and what was not. The logs are in [`logs/`](logs/).

"The orchestrator" (its id is `main` in commands and in the ledger) is the lead agent that coordinates the other agents. "The runner" is a separate project that starts agent runs and signs their run tokens. It is not public yet.

| Runbook | When | Run as | Log |
| --- | --- | --- | --- |
| [install](install.md) | First install of Chaperone on the server | you, elevated once | none |
| [orchestrator-token](orchestrator-token.md) | Issue, rotate or revoke the orchestrator's token | you, elevated for `chapd orch` | [log](logs/orchestrator-token.log) |
| [issue-ops](issue-ops.md) | Let a monitoring job file GitHub issues: grant the App the Issues permission, issue the job's token | you, in GitHub, then elevated for `chapd orch` | not run yet, see the page |
| [pr-read-ops](pr-read-ops.md) | Use `pr.view`, `pr.diff`, `pr.checks`, `pr.files` (read a pull request through Chaperone) | you, review one policy change, then reinstall `chapd` | not run yet, see the page |
| [custom-keys](custom-keys.md) | Give a script or an agent its own key: turn `keys.issue` on, build the key, sign the card, claim it, revoke it | you, in a policy change and the console | tested against fakes only; no real passkey, see the page |
| [vault-recovery](vault-recovery.md) | The vault will not open; you hold the offline identity | you, elevated, then as `svc-chaperone` for one command | [log](logs/vault-recovery.log) |
| [github-app-key](github-app-key.md) | Rotate the App's private key | you, in the console | not completed, see the page |
| [ci-report](ci-report.md) | A project's `pr.merge` should accept a local CI result: approve the App's `checks: write`, enable `ci.report`, add `pr.local_ci` | you, in the GitHub UI, then two policy changes | GitHub UI and a real post not executed, see the page |
| [ntfy-topic](ntfy-topic.md) | Rotate the phone wake-up topic | you, in the console, then restart `chapd` | not completed, see the page |
| [linear-intake](linear-intake.md) | Connect a Linear intake board: OAuth app, vault secrets, policy block, state names | you, in Linear and the console, then a policy change | Chaperone side tested against a fake Linear; Linear's pages not run, see the page |
| [google](google.md) | Connect Google for mail and Drive | you, in Google Cloud and the console, then a policy change | tested against a fake Google only, see the page |
| [phone](phone.md) | Approve from your phone: Tailscale Serve, passkey, number matching | you, at the server with the phone in hand | browser flow rehearsed headless; Tailscale not run, see the page |
| [dashboard-frame](dashboard-frame.md) | Show the console's approvals, ledger and runs pages inside your own dashboard | you, elevated, then restart `chapd` | not run, see the page |
| [ledger-evidence-pack](ledger-evidence-pack.md) | Read, verify and hand over the ledger | the orchestrator or you, normal window | `chap ledger verify` in the logs above |
| [mcp](mcp.md) | Use Chaperone's ops from Claude Code, Codex or Cursor on the same machine (`chap mcp`) | you, normal window | Claude Code connect and both protocol eras run against a fake `chapd`; no model call, no live `chapd`; Codex handshake and Cursor not run, see the page |

The generated command manual is [`../manual.md`](../manual.md). The ADR, threat-model and red-team crosswalk is [`../manual-crosswalk.md`](../manual-crosswalk.md).

Conventions: PowerShell blocks start with the variables they use (`$chapd`, `$db`). Nothing here asks you to put a secret in a command line. The recovery identity goes in on standard input or a prompt. Never run a procedure that handles the recovery identity under `Start-Transcript`.
