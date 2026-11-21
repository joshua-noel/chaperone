# Runbook: connect a Linear intake board to Chaperone

You do this once, from your own account, on the server. It lets the orchestrator (the lead agent that coordinates the other agents) **read** an intake board and **write back** to it through Chaperone: a comment ("Picked up by the orchestrator" and the GitHub links) and a move to the state the work is in. It does not turn anything on: the four ops (`intake.list`, `intake.comment`, `intake.move`, `intake.states`) stay disabled in the baseline policy until a policy change enables them (step 4).

Design: the intake board is one Linear team (the examples use the team key `SHOP`, so items are `SHOP-12`); the items to read carry one label (the examples use `agent`); **the orchestrator never removes the label**.

**Status:** the Chaperone side was run against a fake Linear (`internal/connectors/linear/lineartest`) and the rest is untested against Linear itself. No step below that happens in Linear's web pages was run, and no real Linear request was made: Linear's field names were checked against Linear's published GraphQL schema, not against your workspace. Step 1 asks you to check four things in your workspace that the documents do not settle (marked **check**).

## What you are agreeing to

| | |
| --- | --- |
| **What the orchestrator can do** | Read the open items of the intake team that carry the label `agent` (title, description, comments, links, state, update time). Add a comment to such an item. Move such an item to a state **you list in the policy**. Nothing else. |
| **What the orchestrator cannot do** | Remove or add a label, change a title or description, assign, archive, delete, create an issue, or touch any other team. There is no command and no code path for those: `chapd` builds the five GraphQL documents it sends, and the caller gives only an item id, a comment text or a state name. |
| **Why that holds although Linear's `write` scope is wide** | Linear has no scope that can change a state and nothing more: `write` reaches the whole workspace. The **policy** is the guard: one team key, one label, a list of state names. `chapd` reads the item again just before every write and refuses if it is not in that team or no longer has the label. The one gap is the few milliseconds between that read and Linear's answer: Linear has no conditional update. |
| **Where the credential lives** | Two vault secrets (the OAuth app's client id and secret). `chapd` makes a short-lived token from them in memory only (at most one hour, replaced after a refusal), registers it with the redaction check so it cannot reach a log, the ledger or a result, and never gives it to anyone. The orchestrator and every agent never hold a Linear credential. |
| **What is untrusted** | Titles, descriptions and comments on the board are text people wrote. `intake.list` returns them as data, marked `untrusted_text`. A text that looks like a secret is withheld, not returned. |

## Step 1: create the Linear OAuth app (browser, about 10 minutes)

1. In Linear open **Settings, API** (<https://linear.app/settings/api>). Your plan allows OAuth applications. Choose **OAuth applications, Create new**.
2. Name it `chaperone-app-intake`. Developer name: your own name. Developer URL: any page you own. The form may ask for a **callback URL** although no sign-in happens: give `http://localhost/linear-unused`. **check:** if Linear refuses an app with no real callback, use any `https` page of yours; the URL is never called.
3. Turn on **Client credentials tokens** (a toggle on the app's page). `chapd` uses this grant (`client_credentials`) and asks for the scopes `read` and `write`; there is no consent screen and no sign-in.
4. Press **Create** and keep the page open: it shows the **client id** and the **client secret**. You copy them straight into the console in step 3. **Do not paste either into chat, a file, a note or a ticket.** Linear shows the secret again only by rotating it.
5. **Limit the app to the intake team.** Open the app under <https://linear.app/settings/applications/> and its team access (**check:** the page may call it "Team access" or "Teams"). The default is *all public teams*. Remove every team except the intake team. **check:** if the intake team is *private*, the app cannot see it until an admin adds the app to that team there. If your plan has no team access control for apps, note it for yourself: the policy still limits what `chapd` does, but the app itself could then reach more than Chaperone ever asks for.
6. **check:** note the team key of the intake team. It is the letters before the dash on any item of the team (`SHOP-12` has the key `SHOP`; Linear makes the key from the team's name, so it may differ). Also note the exact name of each state you want the orchestrator to use.

## Step 2: do not turn on GitHub's sync for the board

Leave **Settings, Integrations, GitHub** as it is. If you use Linear's GitHub sync for another team, do not add it to the intake team: a sync that moves items by itself would work outside this policy.

## Step 3: put the two secrets in the vault (console, no file)

In the Chaperone console open **Secrets**, then **Import a new secret**, twice:

| Id | Kind | Value |
| --- | --- | --- |
| `linear-client-id` | `linear-oauth-client` | the client id from step 1 |
| `linear-client-secret` | `linear-oauth-client` | the client secret from step 1 |

(Vault ids take no dot, so the names are written with a dash.) Each import is the critical op `secrets.write`: press **Request approval**, read the card (it names the id and the kind, never the value) and approve it with Windows Hello. The approval stores the value by itself; there is no commit button after a successful approval, and the page says "Secret stored". If it says the value could not be stored, open **Secrets** and press **Try again** (that button is only on the Secrets page). A value saved with a trailing newline is fine: `chapd` strips white space and masks both forms.

Then close the Linear page and clear the clipboard. `chapd` reads the secrets when it needs a token, so no restart is needed for this step.

## Step 4: the policy change

One pull request, reviewed like code:

1. **`internal/policy/data/baseline.yaml`:** change `enabled: false` to `enabled: true` on the four `intake.*` lines. (Only the baseline can turn an op on.)
2. **`policy/storefront.yaml`:** replace the commented `linear:` block at the end with the real one:

   ```yaml
   linear:
     team: SHOP           # the team key from step 1, point 6
     label: agent
     states: []           # filled in step 6, after you have seen the real names
   ```

   An empty `states` list is legal and means `intake.move` refuses every request. **Take care with this block:** a project file is all or nothing, so a mistake in it makes *every* op of the project refuse (including `pr.merge`) until it is fixed; CI loads the shipped files, so a typo is caught before the merge. The team key must not be an Engineering key (`ENG`, `ENGINEERING` are refused, and `chapd` also refuses any team whose name is Engineering).
3. After the merge, deploy as usual. The project file is re-read on change without a restart; the baseline change comes with the new `chapd`.
4. **Give the orchestrator the new ops.** Re-issue the orchestrator token with the intake ops added (see [orchestrator-token.md](orchestrator-token.md), step 3; keep the ops it already has):

   ```powershell
   & $chapd orch issue -id main -project storefront -ops "pr.merge,pr.open,pr.update,health,logs,intake.list,intake.comment,intake.move,intake.states" -days 30 -db $db
   ```

## Step 5: see the real states (normal window, the orchestrator's token)

```powershell
& $chap intake states --project storefront
```

What you see: a table of every state of the intake team (name, type) and a column *intake.move MAY SET* (all `no` while `states` is empty), and the line `the policy lists no linear.states yet: intake.move refuses every request`. **This is also your connection test.**

| You see | It means | Do |
| --- | --- | --- |
| the table | Linear accepted the app, the secrets and the team key | go on |
| `the vault has no linear-client-id and linear-client-secret` (a refusal) | step 3 was not done, or an id is misspelled | repeat step 3 |
| `Linear refused the app's client credentials (invalid_client)` | the id or the secret is wrong, or client credentials tokens are off | check the toggle in step 1; import the values again (the console's *Rotate an existing secret*) |
| `Linear has no team SHOP that the app can see` | wrong team key, or the intake team is private and the app is not in it | step 1, points 5 and 6 |

## Step 6: fill in the state names

Read the table of step 5 and choose the states the orchestrator may move an item to. A typical set is: *in progress* when the work starts, a waiting or blocked state, and a done state. Use the names **exactly** as the table shows them (capitals and spaces; `chapd` compares without regard to case, but the policy keeps your spelling). A second small change changes `states: []` to the list, for example:

```yaml
  states:
    - In Progress
    - Waiting/Blocked
    - Done
```

After it is deployed, `chap intake states` shows `yes` against exactly these, and says so if the policy lists a name the team does not have (`in the policy but not a state of the team`). A name the policy lists that the team lacks is refused at the move with the same hint.

## Step 7: look at it work

```powershell
& $chap intake list --project storefront                 # the open items labelled agent, from the cache if fresh
& $chap intake list --project storefront --refresh        # read Linear now (answered from the cache when the last read is under 30 s old)
& $chap intake comment SHOP-12 --body "Picked up by the orchestrator: https://github.com/<owner>/<repo>/issues/1" --project storefront
& $chap intake move SHOP-12 --state "In Progress" --project storefront
```

Try the mistakes as well: a state that is not in the policy (`OP_POLICY_REFUSED`, the allowed names are listed), an item of another team (`SCOPE_PATH`), an item without the label (`OP_POLICY_REFUSED`). Every call is in the ledger as `op.request` and `op.result` (or `op.request` and `denial`), with the op, the target identifier and the outcome, and with **no** text of the board.

## How often chapd reads the board

`chapd` re-reads the board every **15 minutes** (the start value) and keeps the answer in memory; `intake.list` answers from that copy and says how old it is (`source`, `fetched_at`, `age_seconds`). A copy older than two intervals is not trusted: the next list reads Linear. After the orchestrator writes, the copy is dropped, so the next list shows the change. Nothing is stored on disk except the op's own result row.

- **Why a poller and not only on demand:** the number of Linear calls then depends on the clock, not on how often the orchestrator asks (15 minutes is 4 calls an hour; Linear allows an app 5 000), and an ordinary list is instant. `--refresh` is the "check Linear now" of the decision.
- **Change the interval:** re-run the installer with the new value (it keeps every other setting; a re-run without the parameter keeps the one recorded before):

  ```powershell
  .\scripts\windows\install.ps1 -LinearPollInterval 10m     # at least 1m; 0 turns the poller off (every list reads Linear)
  ```

  or start `chapd run` / `chapd svc` with `-linear-poll-interval 10m`. `-linear-hourly-budget N` (default 300) caps the calls `chapd` makes in any 60 minutes, polling included.
- The poller only refreshes a board that was asked for in the last day, and the first list after `chapd` starts reads Linear live.

## Limits you can rely on

| What | Value |
| --- | --- |
| Per caller, per minute (policy pack) | `intake.list` 12, the other three 6 (`rate_per_minute` in the baseline; a project file may lower them) |
| `chapd`'s calls to Linear per hour | 300 by default, counted over any 60 minutes; the call that would pass it is refused with the seconds to wait |
| Linear's own limit | When Linear answers 429 (or `RATELIMITED`), or reports 20 or fewer requests left, `chapd` stops sending until the time Linear names |
| Items per list | 50 (`truncated` says when there are more) |
| Comment | 4 000 bytes of text, no control or invisible characters, no secret |
| Text in a list | title 200, description 2 000, each comment 600 bytes; up to 8 comments and 8 links per item |

## When it stops working

| Symptom | Cause | Do |
| --- | --- | --- |
| Every intake call: `Linear refused the app's client credentials` | The client secret was rotated or the app deleted | Import the new secret (console: *Rotate an existing secret*, id `linear-client-secret`). No restart. |
| A write is `unconfirmed` | Linear did not answer after `chapd` sent it | Do **not** repeat it. The result names the comment id; open the item on the board and look. `chapd` never resends a write. |
| `intake.list` says `source: cache` and an old `age_seconds` | The poller cannot reach Linear but the copy is under two intervals old | Look for `the board poll failed` in `chapd.log`; the next list after two intervals reports the cause. |
| Move refused: `the team has no state named ...` | A state was renamed in Linear | `chap intake states`, then a policy change. |

## Rotate or remove

- **Rotate the secret:** in Linear, *Rotate secret* on the app (this ends every token `chapd` holds; the next call makes a new one after you import the new value in the console).
- **Switch the connector off at once:** a policy change that sets the four ops back to `enabled: false`, or delete the two secrets, or delete the app in Linear.
- **Rules about GitHub:** the orchestrator never writes `Fixes`, `Closes` or `Resolves` with a Linear identifier in a PR title, body or branch name: Linear would move the item by itself, outside this policy.

## The generic issue ops (optional, off; ADR-003 amendment 7)

Six more ops use the same two vault secrets and the same Linear app: `issue.get`, `issue.list`, `issue.comment`, `issue.label`, `issue.move` and `issue.link`. They are for the orchestrator token (a custom key cannot hold an `issue.*` operation) and they are **separate from the operator board**: they work in one other Linear team and never touch an item that is in the intake team or carries the intake label. Nothing about the operator board above changes. **Nothing in Linear was tried: the first real run is a live test on a scratch workspace, before the policy change below.**

| What | Where |
| --- | --- |
| Off by default | `issue.get`, `issue.list`, `issue.label`, `issue.move`, `issue.link` are `enabled: false` in the baseline. `issue.comment` is one name for two connectors (the GitHub error watcher, ADR-002 amendment 11, and this one), so the name is on; the Linear side is off for every project whose policy file has no `linear.issues` block |
| Turn on | A policy change flips the five names in `internal/policy/data/baseline.yaml` (and `shippedEnabled` in the policy test), and the project's file gets the block below |
| Never | Opening or editing an issue (`issue.open`, `issue.update` are not built: they wait for the operator's yes), assigning, archiving, deleting, another team, an operator-board item |

The project file's block (inside `linear:`; all of it is checked when the file loads, and a mistake refuses the whole file):

```yaml
linear:
  team: SHOP           # the operator board (unchanged)
  label: agent         # the operator board (unchanged)
  states: [In Progress, Waiting/Blocked, Done]
  issues:
    team: AGT          # the one team the issue ops work in; must not be the board's team
    label: ai-ok       # a write acts only on an issue that carries this label now; must not be the board's label
    states: [In Progress, Done]   # what issue.move may set
    labels: [bug, triaged]        # what issue.label may add or remove (not the two labels above)
    link_hosts: [github.com]      # issue.link: exact host names, https only; linear.app is refused
    comment: false                # Linear comments are off unless this is true (issue.comment is on for GitHub)
    max_mentions: 0               # people a comment may mention
```

How to see it work (after the policy change, with a token that holds `issue.*`): `chap issue list --project <p>`, `chap issue get AGT-12`, `chap issue move AGT-12 --state Done`. An item of the operator board comes back refused with `intake_label_excluded` in the reason.

**Comments need their own switch.** `issue.comment` is one name for GitHub's error watcher and for Linear, and it is on in the baseline. A `linear.issues` block alone does not let anyone comment on Linear: the block must also say `comment: true`. The two share one rate budget (6 a minute, 20 an hour per caller): a Linear comment counts against the error watcher's GitHub comments. A comment, a link URL or a link title that names an issue of the intake team (`SHOP-12`, in any case, however it is escaped or dressed in markdown or HTML), that holds `linear.app`, that has an invisible character, or that has a word mixing Latin with look-alike letters (Cyrillic, Greek) is refused, and `link_hosts` may not list `linear.app`. **This is a best-effort guard against accidental and simple references, not a barrier.** An agent can always describe an item in words ("the second item on the board"), and nothing here was tried against real Linear. The real protection is that the operations cannot act on the board: every read and every write of an issue is refused for an item of the intake team or with the intake label, whatever a comment says. **A mistake in the `linear.issues` block turns off only the Linear issue operations** (and Linear's `issue.comment`) for that project: chapd logs a warning at start, each refusal names the project, the file and the field, and the intake and everything else keep working until the file is fixed (a key the file format does not know still refuses the whole file).

**Before turning `issue.move`, `issue.label` and `issue.link` on, check in Linear** (nothing in Chaperone can check these, and none of them was run against real Linear):

- The `linear.issues.team` has **no two-way GitHub sync**. A move to a done state can close the linked GitHub issue; only the Engineering mirror is blocked by name.
- No **webhook** or integration on that team starts a deploy, a build or another action when an issue changes state, gets a label or an attachment. A move notifies subscribers and fires webhooks and Slack.
- The **provenance label is not in a label group**. In Linear only one label of a group can be on an issue, so adding another label of that group could remove the provenance label, and the agent would lose the right to write to that issue.
- A parent issue may close by itself when its last sub-issue is moved to a done state.
