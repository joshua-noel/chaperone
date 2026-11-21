# Runbook: connect Sentry to Chaperone

You do this once, from your own account. It lets the orchestrator (the lead agent that coordinates the other agents) **read** the errors of a Sentry organisation and **triage** them through Chaperone: list issues, read one with its latest event, resolve it, reopen it, assign it to a member you name, and add a note. It does not turn anything on: the six ops (`errors.list`, `errors.get`, `errors.resolve`, `errors.unresolve`, `errors.assign`, `errors.comment`) stay off in the baseline policy until a policy change turns them on (step 4).

**Status. This connector was tested only against a fake Sentry** (`internal/connectors/sentry/sentrytest`). It never talked to a real Sentry: not Sentry's own service, not a self-hosted server. Every route, field name, scope name and behaviour below is written from the author's knowledge of Sentry's API, not from a run. Step 1 and the list in "Before you turn it on" mark what you must check. Do the first real calls on a scratch project.

## What you are agreeing to

| | |
| --- | --- |
| **What the orchestrator can do** | List the issues of the Sentry projects you name (one page at a time). Read one issue: title, culprit, level, status, event count, first and last seen, and from the latest event the id, the time, the exception type and at most 10 stack frames (file name cut to its last two parts, with nothing from a `?` or `#` on). Resolve an issue, or reopen it. Assign it to a member you list. Add a plain-text note of up to 2000 bytes. Nothing else. |
| **What it cannot do** | Delete, merge, ignore or archive an issue, create one, remove an assignee, delete a note, set a release, touch an alert rule, a member, a team, a project setting or any other project. There is no command and no code path for those: `chapd` sends five fixed kinds of request, and the caller gives only an issue id, a project slug from your list, a filter word, a member from your list or the text of a note. |
| **What it never returns** | Request bodies, cookies, headers, user data (email, address, id), local variables, tags, breadcrumbs, contexts and the exception's message. `chapd` decodes the fields it lists and no others, so the rest is not kept: the answer is read into memory whole while it is decoded, and dropped after. A stack frame's file name is cut to its **last two path components**, with everything from a `?` or `#` on removed, then cleaned and capped. So `/home/alice/shop/app/cart.py` comes back as `app/cart.py`, and `https://app.example.org/static/app.js?session=x` as `static/app.js`. The last two components can still name a folder. The title of an issue is Sentry's own text and often holds the exception's message: see the list below. |
| **Why the policy is the guard** | A Sentry auth token reaches the whole organisation. It cannot be limited to some projects. The **policy** is the limit: the project's `sentry:` block lists the Sentry projects, and `chapd` reads the issue again just before every write and refuses it if its project is not listed. **The token can also delete issues.** Sentry's `event:write` scope allows `DELETE` of an issue through its API. This connector has no operation that does it and no code path that sends a `DELETE`, but the token itself can. **Where the token is kept is the real guard:** the vault, never a file, a chat or a ticket. |
| **Where the credential lives** | One vault secret, `sentry-auth-token`. `chapd` reads it for each call, registers it with the redaction check so it cannot reach a log, the ledger or a result, and sends it in one header to the one server your policy names. The orchestrator and every agent never hold it. |
| **What is untrusted** | Titles, culprits, names and stack text are written by programs and by the people whose input they print. They come back as data, marked `untrusted_text`, cleaned of control characters and capped. Text that looks like a secret is withheld. |

## Step 1: make the token in Sentry (browser, about 10 minutes)

Use an **internal integration**. It is owned by the organisation, so it does not stop working when a person leaves, and its notes show under its own name.

1. In Sentry open **Settings, Developer Settings, Custom Integrations, Create New Integration, Internal Integration**.
2. Name it `chaperone`. Leave the **Webhook URL** empty. Do not turn on **Alert Rule Action** and add no **Redirect URL**.
3. Under **Permissions** give the smallest set that works:

   | You want | Permission | Scope behind it |
   | --- | --- | --- |
   | the two reads only (`errors.list`, `errors.get`) | **Issue & Event: Read** | `event:read` |
   | the four writes as well | **Issue & Event: Read & Write** | `event:read`, `event:write` |

   Leave every other permission at **No Access**: Project, Team, Release, Distribution, Organization, Member, Alerts, Settings. **check:** if Sentry's page names these differently, pick the ones that give the scopes `event:read` (and `event:write`) and nothing more.
4. Press **Save**. The page shows the **token**. Keep it open: you copy it straight into the console in step 3. **Do not paste it into chat, a file, a note or a ticket.** **check:** whether Sentry shows the token again later. If it does not, make a new token and delete the old one.
5. **check:** note the **organisation slug** (the part of the address after `/organizations/`, for example `acme`), the **slugs of the projects** the orchestrator may use (the project's address ends with its slug, for example `web`), and the **server**:

   | Your Sentry | `base_url` |
   | --- | --- |
   | sentry.io, US data region | `https://sentry.io` (**check:** or `https://us.sentry.io`: use the host your organisation's pages show) |
   | sentry.io, EU data region | `https://de.sentry.io` |
   | self-hosted | `https://` and your server's DNS name, for example `https://sentry.example.com`, and a port when it is not 443 |

   The server must be **https** with a certificate that this machine trusts. `chapd` takes no IP address, no `localhost`, no user name, no path and no trailing slash.
6. To use a member's name in `errors.assign`, write it as Sentry shows it: the **email address** or the **username**. **check:** that Sentry accepts it as `assignedTo` (step 5 does this on a scratch issue).

If you cannot make an internal integration, a personal token of your own account with the same two scopes also works. It acts as you, so notes and assignments show your name, and it stops when your account does. Do not use it for a long-lived setup.

## Step 2: check what an issue change starts

Read the list "Before you turn it on" below, and look at the integrations and alert rules of the organisation. A resolve, an assignment and a note can start work in other tools. Do this before step 4.

## Step 3: put the token in the vault (console, no file)

In the Chaperone console open **Secrets**, then **Import a new secret**:

| Id | Kind | Value |
| --- | --- | --- |
| `sentry-auth-token` | `sentry-auth-token` | the token from step 1 |

The import is the critical op `secrets.write`: press **Request approval**, read the card (it names the id and the kind, never the value) and approve it with your passkey. The approval stores the value by itself. A value saved with a trailing newline is fine: `chapd` strips white space and masks both forms. Then close the Sentry page and clear the clipboard. `chapd` reads the secret when it needs it, so no restart is needed for this step.

## Step 4: the policy change

One pull request, reviewed like code:

1. **`internal/policy/data/baseline.yaml`:** change `enabled: false` to `enabled: true` on the `errors.*` lines you want. Turn on the two reads first. The rest can wait. (Only the baseline can turn an op on.) Add the same names to `shippedEnabled` in `internal/policy/policy_test.go`.
2. **`policy/storefront.yaml`:** add the block:

   ```yaml
   sentry:
     base_url: https://sentry.example.com    # step 1, point 5: https, an exact DNS name, no path
     organization: acme                      # the organisation slug
     projects: [web, api]                    # the Sentry projects the ops may touch; at least one
     assignees: [dev@example.com]            # who errors.assign may use; leave it out and assign refuses everyone
   ```

   Every field is checked when the file is loaded. A mistake in this block turns off the Sentry ops of the project only: the other ops and blocks of the file keep working, `chapd` says so once at start (a `Warn` line that names the project, the file and the field), and the ops refuse with the same reason. A key that the file format does not know (a typo such as `project:`) refuses the whole file, as for every project file. CI loads the shipped files, so an unknown key is caught before the merge. A bad value is not: it turns the Sentry ops off and is logged, so read the log after the first deploy.
3. A project can turn single ops off with `ops: { errors.resolve: { enabled: false } }` in its own file. It cannot turn one on.
4. After the merge, deploy as usual. The project file is re-read on change without a restart. The baseline change comes with the new `chapd`.
5. **Give the orchestrator the new ops.** Re-issue the orchestrator token with them added (see [orchestrator-token.md](orchestrator-token.md), keep the ops it already has). In an elevated window:

   ```powershell
   $chapd = 'C:\Program Files\Chaperone\chapd.exe'
   $db    = 'D:\Chaperone\data\state.db'
   & $chapd orch issue -id main -project storefront -ops "pr.merge,pr.open,pr.update,health,logs,errors.*" -days 30 -db $db
   ```

   A custom key can never hold an `errors.*` op, and no run profile lists one.

## Step 5: try it on a scratch project

In a normal window, with the orchestrator's token:

```powershell
$chap = 'C:\Program Files\Chaperone\chap.exe'
& $chap errors list web --project storefront
& $chap errors get 4501234567 --project storefront
& $chap errors assign 4501234567 --to dev@example.com --dry-run --project storefront
```

`errors.list` is also your connection test.

| You see | It means | Do |
| --- | --- | --- |
| a list of issues | Sentry accepted the token, the organisation and the project | go on |
| `the vault has no sentry-auth-token` (a refusal) | step 3 was not done, or the id is misspelled | repeat step 3 |
| `the server refused the auth token (HTTP 401)` or `(HTTP 403)` | the token is wrong, was deleted, or lacks the scope | check step 1; import the value again (the console's *Rotate an existing secret*) |
| `the server answered HTTP 404` or `Sentry has no issue ... that the token can see` | wrong organisation slug, wrong project slug, or the token cannot see it | check the `sentry:` block |
| `the server answered HTTP 301` or `302`, a redirect | `base_url` is not the address Sentry answers on (for example the data region host is another one) | fix `base_url`; `chapd` follows no redirect |
| `the server's certificate does not verify` | the server's certificate is not trusted by this machine | install the certificate authority of the server |
| `its policy file has a sentry block that cannot be used` | a field of the block is wrong; the reason names it | fix the file |
| `project web is not listed in sentry.projects` | the slug is not in `projects` | add it, by a policy change |
| `status_allows_change` | the issue is ignored (archived); resolve and reopen do not change it | change it in Sentry if you mean to |
| `assignee_in_policy_list` | the member is not in `assignees` | add it, by a policy change |
| `note_plain_text` | the note has an at sign, a number sign, markup or a link bracket | rewrite it as plain text |

Try the mistakes as well: a project that is not listed (`SCOPE_PATH`), an issue of another project (`SCOPE_PATH`), a note with `@name` (`OP_POLICY_REFUSED`). Every call is in the ledger as `op.request` and `op.result` (or `op.request` and `denial`), with the op, the target and the outcome, and with **no** text of Sentry.

## Before you turn it on: what only you can check in Sentry

Nothing in Chaperone can check these, and none of them was run against Sentry.

- **Turn `errors.resolve` (and `errors.unresolve`) on only if the organisation has no outbound status sync and no paging on resolve.** That means no Jira, GitHub, Linear or other tracker integration that closes or reopens a ticket when an issue changes status, and no chat or paging integration that fires on it. The text the orchestrator reads comes from the monitored program, and so from whoever can make it print something. The same token resolves, and a closed ticket or a sent page is not undone by `errors.unresolve`. If the organisation has any of these, **change the class of both ops to high**, so every use is an approval card. Four places change, in one reviewed change: (1) `Class: kit.High` in `Resolve` and `Unresolve` in `internal/connectors/sentry/sentryspec/spec.go`; (2) the two pins in `internal/connectors/pintable/pintable.go`; (3) `class:` of the two ops in `connectors/sentry.yaml`; (4) the regenerated catalog entries (`go generate ./internal/connectors/...`, then `go run ./docs/manualgen` and `go test ./cmd/chap -update`). The conformance test and the declared tests fail until all four agree. The shipped caps are low on purpose: 2 a minute and 10 an hour for each of the two.
- **Resolving can start things.** When an issue is resolved Sentry can notify its followers, post to a chat or paging integration, and **close a linked ticket** if an issue tracker integration (Jira, GitHub, GitLab and others) syncs status. Look at **Settings, Integrations** and at the **Alerts** page. `errors.unresolve` puts the issue back, but it does not unsend a notice or reopen a ticket for you. `errors.resolve` is routine for this reason only when you have looked.
- **A resolved issue comes back.** Resolved with no release, an issue that gets a new event is reopened by Sentry as a regression, and that can alert people. That is a safety net, and also a reason an agent that resolves a real problem is not hiding it for long.
- **Assigning notifies the member.** Assignment sends the member a notice. There is no way to unassign through Chaperone.
- **Notes notify the people who follow the issue.** The text is limited to plain words so a note cannot mention a person or a team, and it may not hold `://` or `www.`: a link would take a person who clicks it to a host the agent chose. The check for secret-shaped text in a note catches a token written as it is. It does **not** catch one that is split (`ghp_ A1b2...`), encoded (base64, hex) or otherwise disguised, and it does not try to. It can still be wrong or misleading. There is no way to delete a note through Chaperone.
- **Titles can hold personal data.** Sentry builds a title from the exception's message, for example `KeyError: 'user bob@example.com'`. `errors.list` and `errors.get` return titles and culprits to the orchestrator. A title that looks like a secret is withheld. Personal data in a title is not recognised. If your programs put personal data in exception messages, fix that first, or do not turn the reads on.
- **The token reaches the whole organisation.** Keep the integration's permissions to the two in step 1, and keep the `projects` list short.
- **Self-hosted servers differ by version.** The routes `chapd` uses are listed under "What was tested". Run step 5 against your version.
- **Rate limits.** Sentry answers HTTP 429 when a limit is used up. `chapd` reports it and sends nothing again. The baseline also caps each op per minute and per hour. A dry run is not rate-limited by Chaperone and makes one read of Sentry, so an orchestrator with a write op on can use up the token's Sentry rate limit with dry runs.

## What was tested, and what was not

Tested, against a fake Sentry that runs in the test process and listens on a loopback port (`internal/connectors/sentry`, `cmd/chapd/sentry_test.go`, `internal/policy/sentry_test.go`):

- The shared connector suite (`internal/connectors/conformance`) passes for all six ops. `errors.comment` is declared not repeatable, and the suite checks that the declaration is true.
- No request body, cookie, header, user data, local variable, tag, breadcrumb or exception message reaches a result, in a fake event that holds a planted secret in all of them.
- A write is read first and refused for an issue of a project that is not listed; the second `errors.resolve` of an issue sends nothing; an ignored issue is refused.
- The token is in the `Authorization` header and in no URL, query or body; a hostile server that repeats the token in its error text does not get it into any result, refusal or log.
- A redirect is not followed. A base URL that is not an https origin with an exact DNS name is refused before anything is sent.
- A lost answer to a write leaves the op unconfirmed, and the write is sent once.
- The whole path in `chapd`: token in the vault, policy block, orchestrator token, approval-free ops, the ledger holds no text of Sentry.

**Known limit: the list route is the deprecated one.** Sentry's documentation marks `GET /api/0/projects/{org}/{project}/issues/` as deprecated in favour of `GET /api/0/organizations/{org}/issues/`. `errors.list` still uses the project route. The organisation route takes projects by numeric id (a search term `project:slug` may also work), which the connector would have to look up or rely on without a check, and this was not settled from the documentation. The fence does not depend on either route: every item that comes back is checked for its project. Moving the route is left for the first live test.

**Not tested: anything against real Sentry.** In particular these are the author's reading of Sentry's API and are exercised only by the fake:

- the routes `GET /api/0/projects/{org}/{project}/issues/`, `GET` and `PUT /api/0/organizations/{org}/issues/{id}/`, `GET .../events/latest/` and `POST .../comments/`;
- the `limit` parameter of the list (if a server ignores it, `chapd` cuts the page and says `page_truncated`), the `Link` header with `rel="next"; results="true"; cursor="..."`, and the shape of a cursor;
- the field names of an issue and of an event, and `count` as a string;
- `assignedTo` taking an email address or a username;
- the scope names `event:read` and `event:write`, and that they are enough for each route;
- what a resolve starts in Sentry.

If a route or a field differs, the op fails with a fixed sentence (`the server answered HTTP 404`, `the answer is not the expected JSON`) and nothing is written. The first real run belongs on a scratch project, before the policy change that turns the ops on for a real one.

## Turn it off

- One op, one project: `ops: { errors.resolve: { enabled: false } }` in the project's file.
- One project: delete its `sentry:` block, or break it on purpose.
- Everything: flip the baseline lines back to `enabled: false`.
- The credential: delete the integration (or make a new token) in Sentry, and delete `sentry-auth-token` in the console's **Secrets**.
