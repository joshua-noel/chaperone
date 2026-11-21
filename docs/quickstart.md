# Quickstart

Try Chaperone on your own computer in about ten minutes. No account, no administrator rights, no real repository.

You start `chapd quickstart`. It makes a private scratch folder in your user profile and starts Chaperone in your terminal. It uses a **playground**: a fake GitHub that lives inside the program. The agent gets a **key of its own** (not your orchestrator token): it can read the playground pull requests and ask you for more, and you give it that key with your passkey. Then you play the orchestrator, ask to merge a pull request, and approve the approval card with your passkey.

The playground is not real. No real repository, key or network is touched. Real GitHub is not in this version (see [Real GitHub](#real-github)).

## What was tested

Read this first. This page is only as good as these tests.

| Step | Tested | Where |
| --- | --- | --- |
| Build `chapd` and `chap` from source | Yes | Windows 11 (10.0.26200), Go 1.26.10 |
| `chapd quickstart` starts and prints the four steps | Yes | Windows 11 |
| The first-passkey page answers `200` on this computer, and `403` to a wrong `Host` | Yes | Windows 11 |
| `chap` with the generated orchestrator token: refused, then an approval card | Yes | Windows 11 |
| A pull request with failing checks is refused | Yes | Windows 11 |
| `claude mcp add` with the printed line, then `claude mcp list` shows `Connected` | Yes, in a scratch user profile | Windows 11, Claude Code 2.1.302 |
| Starting again reuses the folder and prints a new first-passkey address, or the sign-in address once you have a passkey | Yes (automated tests) | Windows 11 |
| The quickstart holds both `127.0.0.1` and `[::1]` and refuses to start when another program already listens on `[::1]` at its port | Yes (automated tests) | Windows 11 |
| The scratch folder is made by the quickstart itself with an owner and a protected ACL for your user from the instant it exists; a folder that already exists is refused; the parent must not let others rename it away | Yes (automated tests, ACL and owner read back) | Windows 11 |
| The same folder rules on Linux (mode 0700, owner, writable-parent refusal, unknown entries refused), run from the Linux test binary | Yes, under WSL (Ubuntu); the second-account case was not tried | Windows 11 + WSL |
| The agent's key, from the printed commands, with the real `chap` binary: `chap agent enrol` prints a code and writes the key file into the folder; `chap key request --wait` is answered and the key in the file is replaced; the key reads pull requests, is refused `pr.merge` (`OP_NOT_IN_TOKEN`), and `chap manual` and `chap mcp` list only what it may do. The passkey tap is the test's stand-in. | Yes (`TestQuickstartWithTheRealChap`, with `CHAP_BIN` set) | Windows 11 |
| What a restart does with an existing key: valid, request-only, revoked, expired, stopped by a human, unknown | Yes (automated test, with the stand-in) | Windows 11 |
| **The two enrolment taps on the Agents page in a real browser** (look up the code, make the card, answer the request) | **No.** Their screens were read from the code and the page tests, and the commands were run. A person has not tapped them. | Nowhere yet |
| **Claude Code using the agent's key** | **No.** The key file, the printed `claude mcp add` line and the tool list (below) were tested with `chap mcp`. Claude Code was not run against a key. | Nowhere yet |
| **Creating the passkey, signing in, approving the card, and seeing the pull request merged** | **No.** It needs a person to tap. | Nowhere yet |
| **A real model calling a tool through `chap mcp`** | **No** | Nowhere yet |
| **Everything on macOS** | **No.** It compiles for macOS. It has never run there. | Nowhere yet |
| **Everything on Linux** | **No.** It compiles for Linux. It has never run there. | Nowhere yet |

If a step below fails on macOS or Linux, that is news. Please open an issue and say what you saw.

## What you need

- Go 1.26 or newer, to build from source. Release binaries are planned and do not exist yet.
- A browser on the same computer, with a passkey available (see [The passkey](#the-passkey)).
- Optional: [Claude Code](https://claude.com/claude-code), for step 4.

You do not need a C compiler, administrator rights, or a network (the dependencies are in the repository).

## 1. Build

```
git clone https://github.com/joshua-noel/chaperone
cd chaperone
go build -trimpath -o dist/ ./cmd/chapd ./cmd/chap
```

This writes `chapd` and `chap` (`chapd.exe` and `chap.exe` on Windows) into the `dist` folder.

## 2. Start

macOS and Linux:

```
./dist/chapd quickstart
```

Windows (PowerShell):

```
.\dist\chapd.exe quickstart
```

Leave this window open. It is the running Chaperone. Press Ctrl+C in it to stop it.

You will see this (the folder, the passkey address and the commit hashes differ on your computer; on macOS and Linux the setup lines use `export`):

```
Chaperone quickstart: PLAYGROUND

PLAYGROUND: the GitHub in this run is a fake one inside this program (playground/storefront). Nothing here can reach a real repository.
Folder: C:\Profiles\you\AppData\Local\chaperone-quickstart
Log:    C:\Profiles\you\AppData\Local\chaperone-quickstart\logs\chapd.log
Leave this window open. Press Ctrl+C in it to stop.

1. Make your first passkey
   Open this address in a browser on this computer. It works once, only from this computer, for 15 minutes:

   http://localhost:55421/enroll#Xk3m...

   Press "Create passkey" and approve with your system's passkey prompt. Then sign in at http://localhost:55421/login.

2. The agent's own key
   The agent gets a key of its own, not your orchestrator token. It can read the playground pull requests and ask you for more, and
   nothing else. Making it takes two taps of your passkey, the same two a real agent needs. Sign in first (step 1).
   In a terminal for the agent, tell chap where chapd is and where the key goes:

   $env:CHAP_URL = 'http://127.0.0.1:55421'
   $env:CHAP_KEY_FILE = 'C:\Profiles\you\AppData\Local\chaperone-quickstart\agent.key'

   a. Enrol the agent. It prints a short code and waits for you:
      chap agent enrol --label playground-agent --project playground --out C:\Profiles\you\AppData\Local\chaperone-quickstart\agent.key
      Open http://localhost:55421/agents, type the code, press "Look up the agent", then "Make the enrolment card". The Approvals page opens with the
      card. It says the agent gets no access at all. Approve it with your passkey. The agent now holds a key that can only ask.

   b. The agent asks for what it needs, and waits for you:
      chap key request --ops pr.checks,pr.diff,pr.files,pr.view --repo playground/storefront --ttl 8h --reason "read the playground pull requests" --wait 600
      Open http://localhost:55421/agents. Under "Waiting for your answer" press Answer, read what it asks for, press "Grant as asked", and approve the second
      card with your passkey. The key in the file is then replaced by one that can read the four pull-request operations.

3. Connect Claude Code (optional)
   Run this in another terminal. It adds the PLAYGROUND tools, and gives Claude Code the AGENT'S KEY, never the orchestrator token:

   claude mcp add --scope user chaperone-playground -e CHAP_URL=http://127.0.0.1:55421 -e CHAP_KEY_FILE=C:\Profiles\you\AppData\Local\chaperone-quickstart\agent.key -- C:\Profiles\you\dev\chaperone\dist\chap.exe mcp

   Run it after step 2: the key file does not exist until the agent has been enrolled. Claude Code sees tools only for what the key may do: the four pull-request reads, and keys_request, with which it can ask you for access itself (you still answer at Agents).

   When you stop using the quickstart, remove it:

   claude mcp remove chaperone-playground --scope user

   Why: the entry stays in Claude Code's user settings and keeps pointing at port 55421 and the key file. Once the quickstart is stopped, another program could listen on that port and receive the key on the next tool call.

4. Try it (PLAYGROUND repository playground/storefront)
   As the AGENT, in the terminal that has CHAP_URL and CHAP_KEY_FILE set (step 2):

   a. Read pull request 3. This works once the key can read, and needs no approval:
      chap pr view 3 --repo playground/storefront
   b. Try to merge it. A key can never hold pr.merge, so this is refused, whatever you approve:
      chap pr merge 3 --head 6f1c... --base main --repo playground/storefront

   As YOU, the operator, in a second terminal. The merge demo uses the ORCHESTRATOR token, because a key cannot ask for a
   merge: the orchestrator is the role that holds pr.merge, and here you play it. Do not give this token to an agent.

   $env:CHAP_URL = 'http://127.0.0.1:55421'
   $env:CHAP_PROJECT = 'playground'
   $env:CHAP_ORCHESTRATOR_TOKEN_FILE = 'C:\Profiles\you\AppData\Local\chaperone-quickstart\orchestrator.token'
   $env:PATH = 'C:\Profiles\you\dev\chaperone\dist' + ';' + $env:PATH

   c. Ask to merge it. It changes code, so Chaperone refuses: it needs your approval.
      chap pr merge 3 --head 6f1c... --base main --repo playground/storefront
   d. Ask again for an approval card:
      chap pr merge 3 --head 6f1c... --base main --repo playground/storefront --request --reason "reword the checkout button"

   Then open http://localhost:55421/approvals, read the card and approve it with your passkey. Run (a) again, as the agent: it shows the pull request merged.

   Extra: pull request 2 has failing checks, so Chaperone refuses to merge it:
      chap pr merge 2 --head 91ab... --base main --repo playground/storefront
```

The commit hashes are new on every start. Copy the commands from your own window, not from this page.

Where the folder is:

| System | Default folder |
| --- | --- |
| Windows | `%LOCALAPPDATA%\chaperone-quickstart` |
| macOS | `~/Library/Application Support/chaperone-quickstart` |
| Linux | `~/.config/chaperone-quickstart` |

Use `--dir PATH` for another place and `--addr 127.0.0.1:PORT` for another port. The port is never 55398 (the real Chaperone service).

`--dir` must be **inside your own home folder**, and it must **not exist yet**: the quickstart makes the folder itself, private to you from the moment it exists, and refuses one that already exists (even an empty one), because it cannot know who held it open or put something in it first. Missing parent folders inside your home folder are made private too. The quickstart also checks every folder between your home folder and the new one: if another user could rename a folder out of one of them (on macOS and Linux: writable by group or others without the sticky bit, or owned by somebody other than you or root; on Windows: an entry for anybody but exactly these principals: you, SYSTEM, Administrators, CREATOR OWNER and TrustedInstaller (`S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464`; no other service account), that lets them add to it, delete in it or change its permissions, or an entry type the quickstart does not understand) it stops and says which, because they could swap your folder for theirs. A folder that was made by an administrator's (elevated) shell is owned by Administrators: a later normal run refuses it. Start it from the same kind of shell each time, or use a new `--dir`. A link in the `--dir` path is followed once, up front: the folder it leads to must be inside your home folder and the path must go through no further link (on Windows a junction is not followed and is refused). Everything after that uses that one resolved path, which is the one printed.

## 3. Try it

### Make the passkey

Open the address from part 1 in a browser on this computer. Press **Create passkey**. Answer your system's passkey prompt. Then sign in at the `/login` address.

The address works once and for 15 minutes. If it has expired, or you lost it, stop `chapd quickstart` (Ctrl+C) and start it again. A new address is printed, and the old one stops working.

### The passkey

Chaperone asks for a passkey that checks it is you (a PIN, a fingerprint or a face). The playground accepts any of three kinds: the one built into this computer (Windows Hello on Windows, Touch ID or your password on a Mac), a hardware security key that asks for its PIN or fingerprint, and a phone used through the browser's "use a phone" prompt. A Linux desktop usually has no built-in authenticator, so there you use a security key or a phone. The console refuses any of them that does not verify you. A hardware key must be a FIDO2 key that can hold a passkey (a discoverable credential) and that has a PIN set; the browser offers to set one.

This is the playground only. The real service, `chapd run`, accepts only the built-in kind until its operator turns on `-approver-authenticators any` (see [running-chapd.md](running-chapd.md) and ADR-004, amendment 15).

None of these was tried by a person on a Mac or a Linux computer, with a security key, or with a phone. These are open items (see [Open items](#open-items)).

### Give the agent a key

Do this after you have made your passkey and signed in. It is the real flow, and it takes your passkey twice.

1. **Enrol.** In the agent's terminal run command (a) of step 2 (`chap agent enrol ...`). It prints a code such as `ABCD-EFGH` and waits up to 10 minutes. In the console open **Agents** and type the code under **Enrol an agent**. Press **Look up the agent**. The page shows what you are enrolling, with **no access at all**. Press **Make the enrolment card**. The **Approvals** page opens with a card; read it and approve it with your passkey. `chap agent enrol` then writes the key file and prints `enrolled: the request-only key ... is in ...`. That key holds no access: it can only ask.
2. **Ask.** In the same terminal run command (b) (`chap key request ...`). It says what the agent wants, for how long and why, and waits. In the console open **Agents**. The request is under **Waiting for your answer**. Press **Answer**, read what is asked (the four pull-request reads, on `playground/storefront`, 8 hours) and the reason the agent wrote, and press **Grant as asked** (**Narrow and grant** lets you remove an operation or shorten it). A second card opens on **Approvals**; approve it with your passkey. `chap key request` then replaces the key in the file with one that can read, and says so.
3. **Look.** **Agents** lists the key, who holds it, what it may do and when it ends. **Revoke** there takes it away at once and stops that agent for good (the name cannot be enrolled again; the next start of the quickstart uses a new one).

What the key may do: read pull requests on `playground/storefront` (`pr.view`, `pr.diff`, `pr.checks`, `pr.files`) on its own, and ask. Under it, `chap manual` lists those four and the ask, and `chap mcp` offers the tools `pr_view`, `pr_diff`, `pr_checks`, `pr_files`, `keys_request`, `chaperone_manual` and `chaperone_op_status`. Under the orchestrator token the tools are `pr_view`, `pr_diff`, `pr_checks`, `pr_files`, `pr_merge`, `chaperone_manual` and `chaperone_op_status`.

**Why the merge uses a different token.** A key can never hold `pr.merge`. The ceiling on what a key may hold (the four pull-request reads, `health`, `logs` and `deploy`, ask-only) has no merge in it, and the quickstart does not widen it for a demo. So an agent with a key cannot even ask for a merge, and the "an action that needs your approval" demo cannot be done by the agent. The merge demo is done by you, with the orchestrator token, which is the role that holds `pr.merge` in the real design. The orchestrator token stays in `orchestrator.token` in the folder and is never printed or given to Claude Code.

Which tokens do what, in one table:

| Token | Held by | May do | Needs your passkey for |
| --- | --- | --- | --- |
| The agent's key (`agent.key`) | The agent (Claude Code) | Read pull requests on `playground/storefront`; ask for access | Making it (twice) and anything it asks for beyond reads |
| The orchestrator token (`orchestrator.token`) | You, in your own terminal | Read pull requests; ask to merge | The merge card |

### Ask for the merge (you, with the orchestrator token)

In a second terminal, paste the setup lines from the "As YOU" part of step 4, then run commands (c) and (d). Expected results (the real output was captured on Windows; ids and times differ).

(a), as the agent, reads the pull request. It succeeds.

```
pr.view playground/storefront#3: succeeded
...
#3  feat: reword the checkout button  (open)
...
mergeable: true (clean)
```

(b), as the agent, is refused. A key does not hold `pr.merge`. Exit code 3, with `cause: OP_NOT_IN_TOKEN`.

(c), as you, is refused until you approve. Exit code 3.

```
DENIED pr.merge on playground/storefront#3 (orchestrator main)
cause: OP_APPROVAL_REQUIRED
why: pr.merge needs an approval for this exact head: tier medium: src/checkout.py
```

(d), as you, makes an approval card. Exit code 0. Nothing has run.

```
pr.merge playground/storefront#3: pending_approval
...
  ok   risk_tier: tier medium: src/checkout.py; needs an approval bound to this exact head
approval: a-... pending, expires ...
waiting for the operator to approve in the console; nothing has run
```

The extra command refuses the red pull request:

```
DENIED pr.merge on playground/storefront#2 (orchestrator main)
cause: OP_POLICY_REFUSED
why: CI_RED: verify: latest verify run concluded failure, not success
```

### Approve

Open `http://localhost:55421/approvals` in the browser where you signed in. Read the card. It names the pull request, the head commit and the file. Press the approve button and answer the passkey prompt.

Then run (a) again, as the agent. **Expected, not yet seen by a person:** the pull request shows as merged.


## 4. Connect Claude Code (optional)

Run step 2 first, so the key file exists. Then run the line from part 3 of the output, in a terminal. Then:

```
claude mcp list
```

It should show `chaperone-playground: ... Connected`. In Claude Code, ask it to list the Chaperone tools, then to read pull request 3 of `playground/storefront` through Chaperone. Claude Code holds only the agent's key (`CHAP_KEY_FILE`): it sees the four pull-request reads, `keys_request` and the two helper tools, and no `pr_merge`. If it needs more access it can ask with `keys_request`; you answer at **Agents**, with your passkey, never in Claude Code. The merge is yours to run in your own terminal (step 4, "As YOU").

Tested: with the real `chap` binary, `chap mcp` started with only `CHAP_URL` and `CHAP_KEY_FILE` (no `CHAP_PROJECT`) lists exactly those tools under the key, and `pr_merge` plus the same helpers under the orchestrator token. Earlier, the printed `claude mcp add` line (with the orchestrator token) was run in a scratch user profile on Windows with Claude Code 2.1.302, and `claude mcp list` showed `Connected`. **Not tested:** Claude Code against the key, and a real model calling a tool with it. More on `chap mcp`: [runbooks/mcp.md](runbooks/mcp.md).

Remove it when you are done: `claude mcp remove chaperone-playground --scope user`. The entry is in your user settings, so it outlives the quickstart. While the quickstart is stopped it still points at port 55421 and the key file, and another program that listens on that port would receive the key on the next tool call. The key works only against the quickstart's own scratch database, for the hours or days it was granted (here 8 hours).

## Stop, start again, start over

- **Stop:** Ctrl+C in the quickstart window.
- **Start again:** run `chapd quickstart` again. It reuses the folder, the database, your passkey, the orchestrator token and the agent's key. If you already made a passkey, step 1 prints the sign-in address. If not, it prints a new passkey address. The playground GitHub starts fresh: pull request 3 is open again, with a new head commit. Step 2 says what state the agent's key file is in:
  - **no key yet:** both commands are printed;
  - **a key that can only ask** (enrolled, not yet granted): only the `chap key request` command is printed;
  - **a valid key** that can read: nothing to do, and the output lists what it may do and when it ends;
  - **an ended key** (expired, revoked, or not a key this folder's database knows): the file is removed so `chap agent enrol --out` can create it again, the output says why, and both commands are printed;
  - **a key a person stopped for good** (Agents, Revoke): that name can never be enrolled again, so the file is removed and the commands use a new name (`playground-agent-2`, then `-3`, and so on).
  The agent key file is made by `chap` (private to your user from the moment it exists, internal/privfile), never by `chapd`; `chapd` only reads it, to tell you its state, and never prints it.
- **Start over:** stop it, then delete the folder named in the first lines of its output. Your passkey for the old folder is then useless. Delete it in your browser's passkey list too.
- **Another port:** a folder keeps its port, because the passkey is tied to the address. Use a new `--dir` to change it.

## How the first-passkey address is protected

The moment before the first passkey exists is the risky one: whoever opens the address first becomes the approver. So:

- **This computer only.** `chapd quickstart` listens on `127.0.0.1` and on `[::1]` (the IPv6 loopback), because a browser may send `localhost` to either. If another program already listens on `[::1]` at that port, it refuses to start, so nothing else can receive the address. On a machine without IPv6 only `127.0.0.1` is used. It refuses any other address. The console answers only a request whose `Host` is `localhost:PORT`, so a web page cannot reach it through your browser by a DNS trick.
- **The secret is in the part after `#`.** A browser does not send that part to a server when it opens the address, so it is not in a request line or the log, and not on the enrolment page. The page's script then sends the token in the body of one request to the console to start the passkey step. The address, with the part after `#`, may stay in your browser history (and in history sync). That is why the token works once and only for 15 minutes.
- **Random and stored as a hash.** 128 random bits. Chaperone keeps only the SHA-256.
- **Once.** The first passkey spends it. Two browsers racing with one address: only one wins.
- **15 minutes.** Long enough to open a browser and answer one prompt on a first run, including setting up a screen lock. The cost of a longer life is small and bounded: the address is shown only in your terminal, and starting again spends it. The passkey step itself must finish within 5 minutes of pressing the button.
- **Only while there is no approver.** Once a passkey exists, no first-passkey address exists, and a restart prints the sign-in address.
- **Starting again spends the old address.** Only the one in the newest output works.

**What this does not protect against.** Anyone or anything that can read your terminal window, its scrollback or your screen during those 15 minutes can use the address first. A program running as you can also read the scratch folder. The quickstart is for trying Chaperone on a computer you control, not for a shared one.

## What the quickstart does not do

- **The agent's key limits what the agent can ask Chaperone to do. It does not hide the other files in the folder from an agent that runs as you.** Claude Code runs as your user, and the orchestrator token is a file in the same scratch folder that your user can read (mode 0600 on macOS and Linux; one entry for your user on Windows; administrators can read it too). An agent that reads that file, or the database, can do what you can, including editing the database and making itself an approver. The passkey and the key protect you from an agent that runs somewhere else or as another user, and from an agent that stays inside the tools you gave it (the key's tools do not read files). They do not protect you from one that runs as you and goes looking. In real use the agent runs somewhere else, in a virtual machine or another account. See the [README](../README.md).
- **The key operations are on here and off everywhere else.** `keys.issue`, `keys.request` and `keys.extend` ship off in the baseline policy. A project file cannot turn an op on, so `chapd quickstart` starts its own chapd, which knows the one project `playground`, with a copy of the baseline in which those three are on. `chapd run` and the Windows service are not changed.
- **It has no vault.** The playground needs no secret of its own. Nothing here stores a real credential. Do not paste one into the folder.
- **It is not the real service.** It uses its own port, folder and database. It refuses port 55398. Its folder lies inside your home folder and must not exist yet, so it can never be a real install's folder (a real install is not in your home folder, and it exists). As a second check, on Windows it also refuses the default real install folder and anything above it, below it or reached through a link or junction. It cannot be started from `chapd run` or the Windows service: the fake GitHub is wired in only by `chapd quickstart`.
- **What it does to keep its folder private, and what it does not defend against.** It keeps the folder inside your own home folder. It creates the folder itself, private to you from the instant it exists (mode 0700; on Windows an owner and a protected ACL for you alone, set in the same call that creates it), and refuses one that already exists. It refuses a path with a folder above it that other users could rename things in. Every file in it is made exclusively. On a later run it refuses any entry it does not know (a leftover SQLite journal would be replayed into the database), and each entry it uses must be owned by you and closed to others. Before it prints or serves anything it checks that the path still leads to the same folder. It does **not** defend against another program running as you, against an administrator (root or a Windows administrator), or against someone to whom you gave rights inside your own home folder. On macOS and Linux, extended ACLs (`chmod +a`, `setfacl`) are not examined; only the owner and the mode bits are. The checks above are for other local users who have no such rights. It also trusts your operating system's idea of your home folder (on macOS and Linux that comes from the `HOME` setting).

## Real GitHub

The playground never talks to the real GitHub. `chapd quickstart --playground=false` and `--github-app-id` say so and stop. To use a real repository, stop the quickstart and run `chapd vault init` and `chapd connect github` on its folder, then start `chapd run` on the same folder. [runbooks/github-app-setup.md](runbooks/github-app-setup.md), section "From the quickstart", lists each command and what changes. That path was tested against a fake GitHub only. To set the App up by hand instead, see "By hand" on the same page.

## If something goes wrong

| You see | Cause and fix |
| --- | --- |
| `cannot listen on 127.0.0.1:55421` or `cannot listen on [::1]:55421` | Another program, or another `chapd quickstart`, uses the port. For `[::1]` it may be an unknown program: a browser could send `localhost` to it. Stop it, or use `--addr 127.0.0.1:55422`. A folder that already has a port keeps it. |
| `... already exists and was not made by chapd quickstart` | `--dir` names a folder that exists and has no `quickstart.json`. It is refused even when empty, and might be a real install. Use a path that does not exist yet. |
| `... is outside your home folder` | `--dir` must be inside your home folder (the message names it). Pick a path inside it, or leave out `--dir`. |
| `... can be written by group or others ... chmod go-w` (macOS, Linux) or `... lets S-1-... add to it, delete from it or change its permissions` (Windows) | A folder above the new one could be changed by another user, who could then swap your folder for theirs. Fix that folder's permissions (the message names it), or use a path under a folder only you can change. |
| `is a link or junction` | A folder on the path is a link. Use a path that does not go through one. |
| `... is owned by ... not by the current user` or `owned by S-1-5-32-544` | The folder was made by another user, or by an elevated (administrator) shell, and this shell is not that. Run from the same kind of shell, or use a new `--dir`. |
| `... holds "...", which the quickstart did not make` | The folder of an earlier run has an entry the quickstart does not put there. Nothing was used. If you did not add it, somebody else may have: use a new `--dir`. |
| `... is no longer the folder that was prepared` | The folder was renamed and replaced while the quickstart started. Nothing was served. Look at who can change the parent folder. |
| `... is, or holds, the real Chaperone install's folder` | `--dir` points at, above or below the real install. Use another folder. |
| `... is not private to you` | The folder is from an older start that did not make it private, or its permissions changed. Use a new `--dir`. |
| `will not use ...` or `refusing ...: owned by ...` | A file or folder the quickstart would trust is owned by another user, or is open to other users. If you did not do that, somebody else may have. Use a new `--dir`. |
| `port 55398 is the real Chaperone service's` | Use another port. |
| `this folder was set up for 127.0.0.1:55421 ...` | The passkey is tied to that address. Use that `--addr`, or a new `--dir`. |
| The passkey address answers "not found" or is refused | It expired, was used, or a newer start replaced it. Stop and start again. |
| The browser refuses the passkey | Check that it asks for a PIN, a fingerprint or a face. The console refuses an authenticator that does not verify you. See [The passkey](#the-passkey). |
| `chap: no token` or `chapd is not reachable` | The setup lines were not run in this terminal. Run them again. The agent's terminal needs `CHAP_URL` and `CHAP_KEY_FILE`; yours needs `CHAP_URL`, `CHAP_PROJECT` and `CHAP_ORCHESTRATOR_TOKEN_FILE`. Do not set both in one terminal: a key file is used before the orchestrator token. |
| `chap agent enrol` says the file already exists | `chap` never overwrites a key file. Start `chapd quickstart` again: it removes the file of a key that has ended. A key that is still valid is kept on purpose (step 2 says so). |
| `chap agent enrol` says the agent is "stopped by a human" | A person revoked that agent at **Agents**; the name can never be enrolled again. Start `chapd quickstart` again: it prints a new name. |
| The Agents page says "Agent keys are off" | You are not on the quickstart's chapd (the key operations are on only there), or the project is not `playground`. |
| `chap: unknown command` or `chap` is not found | Run the `PATH` line from the output, or use the full path of `chap`. |
| `chap` says the token or key is invalid after a long break | The orchestrator token lasts 7 days and the agent's key what it was granted (8 hours here). Start `chapd quickstart` again: an orchestrator token with less than a day left is replaced, and an ended key is removed so the agent can be enrolled again. |

## Open items

- **Passkeys on macOS and Linux, security keys and phones.** Not tried by a person. The code accepts all three kinds in the playground (see [The passkey](#the-passkey)); someone with a real security key, a phone and a Linux desktop has to confirm it.
- **Wording.** The Windows demo script still says "Windows Hello" and "Edge". The console pages and this page do not.
- **Release binaries.** Until they exist you build from source.
- **A model approving its way to a merge.** Claude Code has run the playground through `chap mcp` on Windows with the orchestrator token (before the agent got its own key): it listed the tools, read pull request 3, was refused the merge (`OP_APPROVAL_REQUIRED`), asked for an approval card and got one (`pending`), and was refused the red pull request (`CI_RED`). Nobody has yet tapped a passkey on that card and watched the merge go through, and Claude Code has not been run against the agent's key.
- **The merge by the agent.** A key cannot hold `pr.merge`, so the agent cannot ask for a merge: you run it with the orchestrator token. If a later version puts a merge-like operation in the key ceiling, the demo can move to the agent.
