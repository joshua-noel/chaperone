# Runbook: set up your GitHub App

Chaperone acts on GitHub as a GitHub App that you own (ADR-002). This page makes that App. There are two ways:

- **Guided** (`chapd connect github`): you open one address, press two buttons on GitHub, and Chaperone puts the App's private key straight into the vault. About 5 minutes.
- **By hand** (the fallback, at the end of this page): you make the App in GitHub's settings, download the key and import it. About 15 minutes.

The key is the credential. Whoever holds it can act as the App on every repository the App is installed on. In the guided path the key goes from GitHub's answer into the vault and is never written to a file, printed or logged.

**Status of this page:** the command was tested against a fake of GitHub's two endpoints (see "What was and was not tested"). It has **not** been run against the real GitHub. The first real run needs you at a browser. Read that section before you rely on it.

## Who runs it, and where

You run it, at a normal terminal on the computer where `chapd` runs, **as the account that runs `chapd`** (like `chapd vault import`, ADR-003: the vault's keys are bound to that account). You need:

- a vault: `chapd vault init` has been run for this database (it shows a recovery identity once; keep that offline);
- a web browser on the same computer, signed in to GitHub as the owner of the account (or an owner of the organization) that will own the App;
- GitHub reachable from this computer.

**Where this does not work today:** the Windows install of [install.md](install.md). There the vault belongs to the `svc-chaperone` account, whose sign-in is closed after the install, so you cannot run this command as that account. Use "By hand" below and import the key on the console's Secrets screen. A guided path for that install needs a change to the installer.

It works on the quickstart folder, on a development vault, and on any system where you can run `chapd` as the vault's own account. See "From the quickstart" below.

## What the App can do

The manifest asks for the smallest set that the GitHub operations Chaperone ships need. The set is computed from the same code that mints the tokens (`internal/gh.ManifestPermissions`), and a test fails if a new permission set is added and not placed:

| Permission | Level | Needed by |
| --- | --- | --- |
| `contents` | write | the git proxy (fetch and push of task branches), `pr.merge`, `pr.update`; read for `pr.open` |
| `pull_requests` | write | `pr.open`, `pr.merge`, `pr.update`; read for `pr.view`, `pr.diff`, `pr.files`, `pr.checks` |
| `checks` | read | the CI check before a merge, `pr.checks` |
| `metadata` | read | GitHub always grants it |

There is **no webhook**, **no event**, no callback address, and the App is **private** to its owner. It has no `workflows`, `administration`, `actions`, `statuses`, `members` or organization permission.

Three operations are off or opt-in, so their permissions are **not** in the default. Add them with `-with`, a comma-separated list. You can also add one later in GitHub's App settings; GitHub then asks the owner to accept the new permission on each installation.

| `-with` | Adds | For |
| --- | --- | --- |
| `deploy` | `deployments` write | the `deploy` op ([ADR-002, item 1](../adr/002-github-identity.md)) |
| `issues` | `issues` write | `issue.open`, `issue.comment`, `issue.reopen` ([issue-ops.md](issue-ops.md)) |
| `ci-report` | `checks` write (instead of read) | `ci.report` ([ci-report.md](ci-report.md)) |

## Steps (guided)

1. **Make the vault** if there is none. Skip this if `chapd vault list` works.

   ```powershell
   chapd vault init -db <path of state.db>
   ```

   Keep the recovery identity offline. On Linux with no keyring, add `-vault-wrapper age-passphrase` to every `chapd vault` and `chapd connect` command and to `chapd run` (see [running-chapd.md](../running-chapd.md)).

2. **Run the command.** Use the same `-db` (and `-vault-dir`, `-vault-key-dir`, `-vault-wrapper`) that `chapd run` uses. You must say whose App this is, with exactly one of `-user <your GitHub login>` (a personal account) or `-org <name>` (an organization). The command refuses to start without one: it compares the owner GitHub reports with that name and stores nothing when they differ, and it can only do that if you say which account is yours.

   ```powershell
   chapd connect github -user <your login> -db <path of state.db>
   ```

   It refuses to run when the vault already holds `github-app-key` or `github-app.json` exists next to the database: this is a first setup, and a key is replaced only by the rotation in [github-app-key.md](github-app-key.md). It prints the permissions it will ask for and **one address**:

   ```
   http://localhost:51234/start/<random>
   ```

3. **Open that address** in your browser, on this computer. Paste it into the address bar. (A link clicked on another web page is refused, on purpose.) The page says which account will own the App and lists the permissions. Press **Continue to GitHub**. On GitHub's page check the **account** and the **permissions** shown there, not only the name. If either differs from what the start page said, do not press the button.

4. **On GitHub:** check the App's name (you may change it; names are unique on GitHub) and press **Create GitHub App**. GitHub sends the browser back to the port on this computer. The tab says you can close it.

5. **Read the terminal.** The command has already compared the App's owner with the account you named, before it stored anything. It says which App GitHub made, for which account, and the App id. It also says that the key is in the vault (with its fingerprint), that `github-app.json` was written next to the database, and whether GitHub accepted the stored key.

6. **Install the App on the repositories you choose.** The terminal prints the address, `https://github.com/apps/<slug>/installations/new`. Choose **Only select repositories**, pick them, press **Install**. Install it on only what Chaperone should reach.

7. **Check.**

   ```powershell
   chapd connect github status -db <path of state.db>
   ```

   It shows the App, the permissions GitHub reports, and each installation. It exits 1 and says why when nothing is installed yet.

8. **Start `chapd` with the vault open.** `chapd run -vault-dir <dir> -vault-key-dir <dir> ...` reads the App from `github-app.json` when `-github-app-id` is not given. A given `-github-app-id` always wins. Without `-vault-dir` it stops and says so, so it never runs half set up. A project is mergeable only if its policy file has a `pr:` block ([running-chapd.md](../running-chapd.md)).

### How `chapd` learns the installation id

You do not copy it. For each repository, `chapd` asks GitHub which installation of the App covers it (`GET /repos/{owner}/{repo}/installation`, signed with the App's own key), and then asks for a token narrowed to that repository. This is how `pr.merge` already worked; the new App needs no extra step. `chapd connect github status` lists the installations (`GET /app/installations`) so you can see them. Installing after `chapd` has started needs no restart.

## What the command does, and what stops a hostile web page

The command runs a small web server for the few minutes it waits.

- It listens on `127.0.0.1` and `[::1]` only, on a port the system picks, using `internal/loopback`, the same as the console. If another program already holds that port on `[::1]`, it tries another port; it never leaves an address a browser could be sent to in somebody else's hands.
- It answers only the host `localhost:<port>`. A web page that reaches this computer under another name (a DNS rebinding trick) gets `403`. An `Origin` header, when the browser sends one, must be this address (or GitHub's, on the callback). A request that is not a plain page load (`fetch`, a frame, an image) is refused.
- The address you open holds a 256-bit random key and works **once**. A page on another site cannot open it: it does not know the key, and a request that another site started is refused even with the key.
- The `state` value (256 bits, random, shown only on that page) is sent to GitHub and must come back. It is compared in constant time. A **wrong state never uses up the one callback**, so a page that guesses cannot spoil the real one. A right state is accepted **once**; a second callback is refused, and the server closes after the first good one or after the deadline (10 minutes; `-timeout`, at most 30).
- The manifest is built when the command starts. Nothing in a request can change it. Its `redirect_url` is the same string the Host check uses, so GitHub sends the code only to the address that checks it.
- Nothing from a request is written into a page or into the terminal. A refused request prints one fixed phrase; at most 20 are shown.

The temporary code travels in the query string of a `GET`, so it stays in your browser's history. It is useless there: GitHub's documentation says the three steps must finish within one hour, and the command uses the code within a second of receiving it and never accepts a second one. GitHub's documentation does not say that a code works only once; the command treats it as single use anyway.

**What if a hostile page makes you create an App an attacker controls?** The manifest is fixed by the command, and its address holds a one-time key. A page cannot make *this* server send a different manifest or redirect. A page can still send you to GitHub with *its own* manifest, as anyone can; then GitHub shows its own page with the attacker's App name and you must press the button yourself. That is GitHub's protection, not this command's. Read the page GitHub shows.

**What if an attacker's code is fed to the callback?** It needs the state, which only the page of this command shows. If the state leaked anyway, the command still stores nothing unless the App behind the code is the one the manifest described: its description must carry this setup's random value, its permissions must be exactly the ones asked for, it must have no event, and **its owner must be the account you named with `-user` or `-org`**, compared without regard to case (an owner with no login, such as an Enterprise, is refused). The owner is checked before anything is stored. This matters for a personal account: whoever has seen the start page can post the same manifest from their own GitHub account and send the code to the callback, and only the owner check stops the command from storing their App. When the owner differs, the command stores nothing and says so. The App belongs to somebody else, so you cannot delete it and there is nothing to clean up. If you did press "Create GitHub App" while signed in as another account, delete the App there. (The start page's Referrer-Policy is `strict-origin`: see "What was and was not tested".)

## If something goes wrong

| You see | Cause and fix |
| --- | --- |
| `there is no vault yet` | Run `chapd vault init` first (step 1). |
| `the vault already holds github-app-key` | A first setup was done. To check it: `chapd connect github status`. To replace the key: [github-app-key.md](github-app-key.md). |
| `github-app.json already exists` | An earlier setup recorded an App. Delete the file only if you are sure that App is not in use. |
| `refused a request to the setup page (...)` | Something asked the port for what it does not serve. The reason is one fixed phrase. If it says `started from another site`, paste the address into the address bar instead of clicking it. |
| `This page was already opened` | The address works once. Run the command again for a new one. |
| `the browser did not come back in time` | Nothing was stored. If GitHub already made an App, delete it (the message names the page) and run the command again. |
| `GitHub did not give the App over` | The code was refused (used, expired, or too many tries). Nothing was stored. Delete any App GitHub made and run again. |
| `... was not made from the manifest chapd sent`, `permissions are not the ones the manifest asked for` | The App behind the code is not the one this command asked for. Nothing was stored. Delete the App it names. |
| `the App GitHub made belongs to the account X, not to Y` | The App was made under another account than the one you named. Nothing was stored. If you pressed the button while signed in as the wrong account, delete the App from that account. If somebody else made it, you cannot delete it and need do nothing. |
| `give exactly one of -org ORG or -user LOGIN` | The command must know whose App it makes. Say which. |
| `the vault did not take the key` | The App exists but its key is lost (GitHub shows a key once). Delete the App and run again. |
| `the key is stored, but the App could not be recorded` | Start `chapd run` with the `-github-app-id` the message prints instead. |
| `Could not check the App with GitHub yet` | The key is stored. GitHub may need a minute. Run `chapd connect github status`. |
| `status` says `PROBLEM: GitHub did not accept the stored key` | The record and the vault key do not belong together, or the App was deleted. Look at the App's page. |

## From the quickstart

The quickstart (`chapd quickstart`) runs a playground: a fake GitHub inside the program, with no vault. It never talks to the real GitHub, and this page does not change that. To move the same folder to your real account:

1. Stop the quickstart (Ctrl+C in its window). Note its folder; it printed it. Below it is `$qs` (`%LOCALAPPDATA%\chaperone-quickstart`, `~/Library/Application Support/chaperone-quickstart` or `~/.config/chaperone-quickstart`).

2. Make the folder's vault and the App:

   ```powershell
   chapd vault init -db "$qs\state.db"
   chapd connect github -user <your login> -db "$qs\state.db"
   ```

   Then do steps 3 to 7 above. The vault goes into `$qs\vault` and `$qs\vault-keys`, and the record into `$qs\github-app.json`.

3. Point the policy at your real repository. Edit `$qs\policy\playground.yaml`: set `pr.repo` to `<owner>/<repo>` and `pr.base` to its default branch. (The project name `playground` stays; the orchestrator token the quickstart made is for that project and for `pr.view`, `pr.diff`, `pr.files`, `pr.checks` and `pr.merge`.)

4. Start `chapd run` on the folder. Use the same address the quickstart used (it is in `$qs\quickstart.json`; the default is `127.0.0.1:55421`), so the passkey you made there still works:

   ```powershell
   chapd run -db "$qs\state.db" -keys "$qs\run-keys.json" -policy-dir "$qs\policy" -instance quickstart `
     -addr 127.0.0.1:55421 -vault-dir "$qs\vault" -vault-key-dir "$qs\vault-keys" -log-dir "$qs\logs" `
     -approver-authenticators any
   ```

   (`-approver-authenticators any` is what the quickstart used. Leave it out if your passkey is the device's own.) On macOS and Linux write `\` for the line break, `$qs` as a shell variable, and `/` in the paths.

**What changes:**

- A real GitHub App now exists in your account. It is private.
- The folder gains `vault`, `vault-keys` and `github-app.json`. Nothing the quickstart made is changed (the marker, the key set, the token file, the policy file, the database and its passkey stay; you edit the policy yourself in step 3).
- From step 4 on, `pr.view`, `pr.diff`, `pr.files`, `pr.checks` and `pr.merge` for the project `playground` reach **real GitHub**, for the repository in the policy. The fake pull requests are gone. A `pr.merge` of a pull request that needs the passkey still asks for it, and an approved merge merges for real.
- `chapd quickstart` refuses this folder from now on: it reuses only a folder that holds nothing but what it made. Make a new playground with another `--dir` when you want one.

## By hand (the fallback)

Use this where the guided command cannot run (see "Where this does not work today"), or when you prefer to see every setting. [INFERENCE] The names of GitHub's buttons and fields below follow GitHub's documentation and were not clicked through for this page; if one differs, trust the page.

1. GitHub, your account (or the organization), **Settings**, **Developer settings**, **GitHub Apps**, **New GitHub App**.
2. **Name**: for example `chaperone-<something>` (unique on GitHub). **Homepage URL**: any address you own, or `https://github.com/joshua-noel/chaperone`.
3. **Webhook**: clear **Active**. Chaperone uses no webhook.
4. **Repository permissions**: set the four in the table above (Contents: Read and write, Pull requests: Read and write, Checks: Read-only, Metadata: Read-only), plus a group's permission if you use that op. Nothing else. No Account or Organization permission.
5. **Where can this GitHub App be installed?** **Only on this account.**
6. Press **Create GitHub App**. Write down the **App ID** and the **Client ID** from the App's page.
7. **Generate a private key.** A `.pem` downloads. It is the secret.
8. Import it and delete the file, as the account that runs `chapd`:

   ```powershell
   chapd vault import --name github-app-key --file <path-to.pem> --delete
   ```

   Where that account cannot sign in (the Windows install), paste it on the console's Secrets screen instead, and delete the file yourself. See [github-app-key.md](github-app-key.md) for the approval.
9. **Install the App**: the App's page, **Install App**, your account, **Only select repositories**.
10. Start `chapd run` with `-vault-dir`, `-vault-key-dir` and `-github-app-id <Client ID or App ID>` (the Windows installer takes `-GitHubAppId`). Check with a `pr` command from [pr-read-ops.md](pr-read-ops.md).

The guided path records the Client ID, which GitHub recommends as the `iss` of the App's token; the App ID also works.

## What was and was not tested

**Executed** (Go tests, no network, against `internal/gh/ghtest`, a fake of the manifest form post on github.com, the code exchange, `GET /app`, `GET /app/installations` and the installation lookup; a Go HTTP client plays the browser):

- the whole command: the address, the page, the manifest posted to the fake, the redirect to the loopback port, the exchange, the key in the vault (it opens and signs as the fake App), the record, the output, `status`, and finding the installation with the stored key and recorded id;
- the manifest's content (no webhook, no event, private, the exact permissions) and that each shipped operation can mint its token on an App with exactly these permissions;
- each refusal of the callback: another host, another origin, `null` origin, another site, not a page load, a wrong or missing or repeated start key, a wrong state (and that guesses do not use up the chance), a second callback, a callback before the start page, a bad code, a wrong method, a path, that nothing is reflected, the deadline, interruption, and a port that `[::1]` does not give;
- a code from another App with the right state, a wider permission, an event, another owner (including the same manifest and state posted from another personal account, an owner in another case, and an owner with no login) and a key that is not RSA (each stores nothing);
- that the key, the client secret and the webhook secret are not in the output, in `chapd`'s log, in the database, in the ledger, or in any file of the folder in the clear;
- the quickstart folder going through the command and then `chapd run` configuration and a start of `chapd` on it.

**Not executed:** anything against the real GitHub. In particular: that GitHub accepts the manifest as it is (no `hook_attributes`, an empty `default_events`, `public: false`, a `redirect_url` on `localhost`); that its page and its redirect behave as its documentation says (the exact `Origin` and fetch-metadata headers a real browser sends on the redirect back; if they differ, the command refuses the callback and prints the fixed reason, and the fix is a small change to the checks); that the description, permissions and `events` in its answer match the manifest exactly (a mismatch makes the command refuse and store nothing, after the App was made); that a new App's key is accepted at once; that `GET /app` and `GET /app/installations` answer as documented; how a real organization with an App-creation policy behaves. [INFERENCE] These follow GitHub's documentation ("Registering a GitHub App from a manifest"; "REST API endpoints for GitHub Apps"). The first real run needs you at a browser; do it with a throwaway account or organization first and delete the App after.

**Not tested here either:** the Windows install (see the top of this page), a Linux keyring, macOS Keychain.

## Starting over

The command makes a first setup only. It refuses while either of these exists, so to start over from nothing **both must go**:

1. the file `github-app.json` next to the database (delete it);
2. the vault secret `github-app-key`. `chapd` has no command that deletes a secret today. The secret is the file `<vault-dir>\github-app-key.age` and one row, with id `github-app-key`, in the table `vault_secrets` of `state.db`. The simple way that needs no edit of the database is a **new database folder with a new vault** (`chapd vault init` there). To replace only the key of an App you still use, rotate it instead: [github-app-key.md](github-app-key.md).

Also delete the App on GitHub, if it is yours, at the address in the message. An App that belongs to somebody else cannot be deleted by you, and the command never stores one.

## Your first real run

No one has run this against the real GitHub yet. Do it once, on purpose, before you rely on it:

1. **Be signed in to GitHub first**, recently, in the browser you will use, before you open the address. A login or password-confirmation step in the middle may lose the form contents. [INFERENCE]
2. **Read the owner line.** The command checks it, but look: GitHub's page, the terminal and the App's page on GitHub must all show your account. Run without `-org` (`-user <your login>`) the first time.
3. **Write down exactly what GitHub does.** If it rejects the form post (the Referrer-Policy and `Origin` question below), or the command refuses the redirect back and prints a fixed reason, note the message and the step. Then delete the App at `https://github.com/settings/apps`.
4. **Compare what GitHub returns with what was asked.** `chapd connect github status` shows the permissions and events GitHub reports. If they differ from the manifest (the command refuses after the App exists), delete the App and report the difference.
5. **Use throwaway things:** a throwaway database folder, a fresh vault and a throwaway account or organization. Afterwards delete the App, the vault secret and `github-app.json` (see "Starting over"), or the whole folder.

**Referrer-Policy.** The start page sets `strict-origin`, in a header and in a meta tag. With `no-referrer` a browser sends `Origin: null` on the form post to GitHub, which GitHub may refuse; GitHub does not document either way. `strict-origin` sends only `http://localhost:PORT`, never the path, which holds the start key. A test pins the exact policy and that the page holds the key nowhere else. **This is untested against real GitHub.** If GitHub still refuses the post, note exactly what it says (step 3).
