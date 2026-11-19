# Quickstart

Try Chaperone on your own computer in about ten minutes. No account, no administrator rights, no real repository.

You start `chapd quickstart`. It makes a private scratch folder in your user profile and starts Chaperone in your terminal. It uses a **playground**: a fake GitHub that lives inside the program. An agent asks to merge a pull request in the playground. Chaperone refuses, makes an approval card, and waits for you to approve it with a passkey.

The playground is not real. No real repository, key or network is touched. Real GitHub is not in this version (see [Real GitHub](#real-github)).

## What was tested

Read this first. This page is only as good as these tests.

| Step | Tested | Where |
| --- | --- | --- |
| Build `chapd` and `chap` from source | Yes | Windows 11 (10.0.26200), Go 1.26.10 |
| `chapd quickstart` starts and prints the three things | Yes | Windows 11 |
| The first-passkey page answers `200` on this computer, and `403` to a wrong `Host` | Yes | Windows 11 |
| `chap` with the generated token: refused, then an approval card | Yes | Windows 11 |
| A pull request with failing checks is refused | Yes | Windows 11 |
| `claude mcp add` with the printed line, then `claude mcp list` shows `Connected` | Yes, in a scratch user profile | Windows 11, Claude Code 2.1.302 |
| Starting again reuses the folder and prints a new first-passkey address, or the sign-in address once you have a passkey | Yes (automated tests) | Windows 11 |
| The quickstart holds both `127.0.0.1` and `[::1]` and refuses to start when another program already listens on `[::1]` at its port | Yes (automated tests) | Windows 11 |
| The scratch folder gets a protected ACL with one entry for your user, and what is made in it inherits it (so `--dir` outside your profile is private) | Yes (automated test, ACL read back) | Windows 11 |
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

2. Connect Claude Code (optional)
   Run this in another terminal. It adds the PLAYGROUND tools:

   claude mcp add --scope user chaperone-playground -e CHAP_URL=http://127.0.0.1:55421 -e CHAP_PROJECT=playground -e CHAP_ORCHESTRATOR_TOKEN_FILE=C:\Profiles\you\AppData\Local\chaperone-quickstart\orchestrator.token -- C:\Profiles\you\dev\chaperone\dist\chap.exe mcp

   When you stop using the quickstart, remove it:

   claude mcp remove chaperone-playground --scope user

   Why: the entry stays in Claude Code's user settings and keeps pointing at port 55421 and the token file. Once the quickstart is stopped, another program could listen on that port and receive the token on the next tool call.

3. Three commands to try (PLAYGROUND repository playground/storefront)
   Open another terminal. Tell chap where this chapd is:

   $env:CHAP_URL = 'http://127.0.0.1:55421'
   $env:CHAP_PROJECT = 'playground'
   $env:CHAP_ORCHESTRATOR_TOKEN_FILE = 'C:\Profiles\you\AppData\Local\chaperone-quickstart\orchestrator.token'
   $env:PATH = 'C:\Profiles\you\dev\chaperone\dist' + ';' + $env:PATH

   a. Read pull request 3:
      chap pr view 3 --repo playground/storefront
   b. Ask to merge it. It changes code, so Chaperone refuses: it needs your approval.
      chap pr merge 3 --head 6f1c... --base main --repo playground/storefront
   c. Ask again for an approval card:
      chap pr merge 3 --head 6f1c... --base main --repo playground/storefront --request --reason "reword the checkout button"

   Then open http://localhost:55421/approvals, read the card and approve it with your passkey. Run (a) again: it is merged.

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

## 3. Try it

### Make the passkey

Open the address from part 1 in a browser on this computer. Press **Create passkey**. Answer your system's passkey prompt. Then sign in at the `/login` address.

The address works once and for 15 minutes. If it has expired, or you lost it, stop `chapd quickstart` (Ctrl+C) and start it again. A new address is printed, and the old one stops working.

### The passkey

Chaperone asks for a passkey that checks it is you (a PIN, a fingerprint or a face). **This version is built for a passkey that lives on this computer: the built-in authenticator.** Windows Hello is that on Windows. Touch ID or your password is that on a Mac. The console rejects a passkey when the browser says it is not a built-in one (a security key or a phone passkey usually says so). Some browsers say nothing, and then it is accepted. Which security keys and phones work has not been tested. On Linux, whether your browser offers a built-in passkey depends on your setup.

None of these was tried by a person on a Mac or a Linux computer. Passkeys on all three systems are an open item (see [Open items](#open-items)). The console page may still say "Windows Hello" on other systems. It means the passkey your system offers.

### Ask for the merge

In a second terminal, paste the three setup lines from part 3 of the output, then run commands (a), (b) and (c). Expected results (the real output was captured on Windows; ids and times differ):

(a) reads the pull request. It succeeds.

```
pr.view playground/storefront#3: succeeded
...
#3  feat: reword the checkout button  (open)
...
mergeable: true (clean)
```

(b) is refused. Exit code 3.

```
DENIED pr.merge on playground/storefront#3 (orchestrator main)
cause: OP_APPROVAL_REQUIRED
why: pr.merge needs an approval for this exact head: tier medium: src/checkout.py
```

(c) makes an approval card. Exit code 0. Nothing has run.

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

Then run (a) again. **Expected, not yet seen by a person:** the pull request shows as merged.

## 4. Connect Claude Code (optional)

Run the line from part 2 of the output, in a terminal. Then:

```
claude mcp list
```

It should show `chaperone-playground: ... Connected`. In Claude Code, ask it to list the Chaperone tools, then to read pull request 3 of `playground/storefront` through Chaperone. If it asks to merge, you approve in the console, never in Claude Code.

Tested: the printed line, then `claude mcp list` showing `Connected`, in a scratch user profile on Windows with Claude Code 2.1.302. **Not tested:** a real model calling a tool. More on `chap mcp`: [runbooks/mcp.md](runbooks/mcp.md).

Remove it when you are done: `claude mcp remove chaperone-playground --scope user`. The entry is in your user settings, so it outlives the quickstart. While the quickstart is stopped it still points at port 55421 and the token file, and another program that listens on that port would receive the token on the next tool call. The token works only against the quickstart's own scratch database, and for at most 7 days.

## Stop, start again, start over

- **Stop:** Ctrl+C in the quickstart window.
- **Start again:** run `chapd quickstart` again. It reuses the folder, the database, your passkey and the token. If you already made a passkey, part 1 prints the sign-in address. If not, it prints a new passkey address. The playground GitHub starts fresh: pull request 3 is open again, with a new head commit.
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

- **It does not keep an agent away from the token or the folder.** The orchestrator token is a file in the scratch folder that your user can read (mode 0600 on macOS and Linux; one entry for your user on Windows). Administrators (root, or a Windows administrator) can read it too. A program that runs as you can read it and ask Chaperone for the same things you can. It can also change the scratch folder: it can edit the database and make itself an approver, replace the key set, or edit the policy. So the passkey protects you from an agent that runs somewhere else or as another user, not from one that runs as you. In real use the agent runs somewhere else, in a virtual machine or another account. See the [README](../README.md).
- **It has no vault.** The playground needs no secret of its own. Nothing here stores a real credential. Do not paste one into the folder.
- **It is not the real service.** It uses its own port, folder and database. It refuses port 55398. It refuses any folder that holds files but was not made by `chapd quickstart` (it has no `quickstart.json`). That marker rule is what protects a real install wherever it is, on any system. As a second check, on Windows it also refuses the default real install folder, and a folder above it, below it or reached through a link or junction. It cannot be started from `chapd run` or the Windows service: the fake GitHub is wired in only by `chapd quickstart`. The scratch folder is private to your user: mode 0700, or on Windows a protected ACL with one entry for you, set whatever the parent folder allows (so `--dir` may be outside your profile).

## Real GitHub

A real GitHub App is not in this version of the quickstart. `chapd quickstart --playground=false` says so and stops. To use a real repository today, set up the App by hand: [runbooks/github-app-key.md](runbooks/github-app-key.md).

## If something goes wrong

| You see | Cause and fix |
| --- | --- |
| `cannot listen on 127.0.0.1:55421` or `cannot listen on [::1]:55421` | Another program, or another `chapd quickstart`, uses the port. For `[::1]` it may be an unknown program: a browser could send `localhost` to it. Stop it, or use `--addr 127.0.0.1:55422`. A folder that already has a port keeps it. |
| `... is not empty and was not made by chapd quickstart` | `--dir` names a folder that holds other files. It might be a real install, so it is left alone. Use an empty folder. |
| `... is, or holds, the real Chaperone install's folder` | `--dir` points at, above or below the real install. Use another folder. |
| `port 55398 is the real Chaperone service's` | Use another port. |
| `this folder was set up for 127.0.0.1:55421 ...` | The passkey is tied to that address. Use that `--addr`, or a new `--dir`. |
| The passkey address answers "not found" or is refused | It expired, was used, or a newer start replaced it. Stop and start again. |
| The browser refuses the passkey | The console rejects a passkey that the browser reports as not built in. See [The passkey](#the-passkey). |
| `chap: no token` or `chapd is not reachable` | The three setup lines were not run in this terminal. Run them again. |
| `chap: unknown command` or `chap` is not found | Run the `PATH` line from the output, or use the full path of `chap`. |
| `chap` says the token is invalid after a long break | The token lasts 7 days. Start `chapd quickstart` again: a token with less than a day left is replaced. |

## Open items

- **Passkeys on macOS and Linux, and security keys and phones.** Not tried. The console is built for a built-in passkey.
- **Wording.** The console pages still say "Windows Hello" and the Windows demo script says "Edge". This page does not.
- **Release binaries.** Until they exist you build from source.
- **A real model call through `chap mcp`.** Not yet recorded.
