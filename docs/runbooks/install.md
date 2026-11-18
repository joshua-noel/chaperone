# Runbook: install Chaperone on the server

You run this once, from your own Windows account, in an elevated Windows PowerShell 5.1. Everything after it runs from a normal window. The scripts are in `scripts\windows\`; this page is the whole procedure.

## What gets installed

| Who | What it is | Where it can go |
| --- | --- | --- |
| **You** (the operator, normal token) | The orchestrator (the lead agent that coordinates the other agents) runs here; holds the orchestrator token (ADR-007) | Reads the ledger export; works in `agent-work`; **no access** to the vault, `state.db`, logs or dumps |
| **`svc-chaperone`** | Local account that runs the `chapd` service. Random password nobody sees; sign-in blocked (interactive, remote, network, batch) once the vault exists | Full control of `D:\Chaperone\data\`; modify on the ledger export |
| **`chap-agent`** | Local account that runs the agents. Random password kept DPAPI-protected for you only in `%LOCALAPPDATA%\Chaperone\agent-account.dpapi` | Modify on `agent-work`; read and run the programs; nothing else. Remote desktop sign-in denied |
| **Administrators / SYSTEM** | Needed in the data ACL: `chapd orch issue` and `chapd enroll` open `state.db` from an elevated window | Full control |

| Path | Purpose | ACL (no inheritance) |
| --- | --- | --- |
| `C:\Program Files\Chaperone\` | `chapd.exe`, `chap.exe`, `chap-host.exe` (copied from `D:\Chaperone\bin-src`) | SYSTEM, Administrators full; Users read and run. The agent can not swap `chapd.exe` |
| `D:\Chaperone\data\` | `state.db`, `vault\`, `vault-keys\`, `logs\`, `dumps\` | SYSTEM, Administrators, `svc-chaperone` full. **You and `chap-agent` are not listed, so you have no access** |
| `D:\Chaperone\ledger\` | Daily ledger JSONL export (ADR-006) | SYSTEM, Administrators full; `svc-chaperone` modify; **you read only** |
| `D:\Chaperone\agent-work\` | Where agents work | SYSTEM, Administrators full; `chap-agent` and you modify |
| `%LOCALAPPDATA%\Chaperone\` | Your side: agent password file, `orchestrator.token`, `host\` (chap-host config and logs) | You, SYSTEM, Administrators |
| `C:\ProgramData\Chaperone\install.json` | Install manifest. What `chap doctor` and `uninstall.ps1` read. No secret in it | Administrators write; everyone reads |

The wrapped vault keys live in `D:\Chaperone\data\vault-keys\`, not in the `svc-chaperone` profile. That is safe because DPAPI binds a key to the **account** (`svc-chaperone`), not to the folder it sits in. The ACL on the folder is the second lock.

Service `chapd`: runs as `svc-chaperone`, starts automatically (delayed), restarts after 5 s, 5 s and 30 s when it fails (counter resets after 24 h), also for non-crash exits. It listens on `127.0.0.1:55398` only. Its log is `D:\Chaperone\data\logs\chapd.log` (10 MiB, 10 files, then the oldest is deleted). Crash dumps for `chapd.exe` are turned off in Windows Error Reporting; if Windows still writes one, it goes to `dumps\` (mini dump, one file) and nobody but the service account and administrators can read it `[INFERENCE]`: Microsoft documents `WerAddExcludedApplication` as excluding the app from reporting, not explicitly from LocalDumps, which is why both are set.

## Before you start

1. The three programs are built in `D:\Chaperone\bin-src\` (`chapd.exe`, `chap.exe`, and `chap-host.exe` for `-WithHost`). Build steps: [development.md](../development.md) and the README.
2. If `D:\Chaperone\data\` already holds a vault from a test run (`vault-keys\` has files): that vault is bound to **your** account, and the service account could not open it. The installer stops with a message and changes nothing. Rename the folder first (`Rename-Item D:\Chaperone\data chaperone.test`); it is kept, not deleted. A real secret in it (for example the GitHub App key) is imported again after the install.
3. Do not run the installer under `Start-Transcript` or a recorder: with `-WithVault` it prints the vault's recovery identity to the window, once.
4. Ten minutes at the server. Have the offline place ready for the recovery identity (a printer or a USB stick that is not the server).

## Step 1: preview (normal window, changes nothing)

```powershell
cd <your checkout of chaperone>
.\scripts\windows\install.ps1 -WithVault -WithHost -WhatIf
```

It lists every folder, account, ACL, registry value, service and task it would create. Read it.

## Step 2: install (elevated window)

Start menu, "Windows PowerShell", right-click, **Run as administrator**:

```powershell
cd <your checkout of chaperone>
.\scripts\windows\install.ps1 -WithVault -WithHost
```

Type `INSTALL` when asked. In order, it:

1. creates `svc-chaperone` and `chap-agent` (random 40-character passwords), adds both to the local Users group, grants `svc-chaperone` "log on as a service", hides both from the sign-in screen;
2. creates the folders and sets the ACLs above;
3. copies the programs and checks their hashes;
4. stores the `chap-agent` password wrapped for your account only;
5. excludes `chapd.exe` from Windows Error Reporting and points any local dump at `dumps\`;
6. with `-WithVault`: runs **`chapd vault init` as `svc-chaperone`** (the vault's keys are wrapped with that account's DPAPI scope, ADR-003). The recovery identity is printed once, framed by `=====` lines. **Copy it to the offline place now**, then press Enter: the window is cleared. It is shown nowhere else and written nowhere;
7. registers and starts the `chapd` service with the recovery settings above;
8. only after the vault exists, denies `svc-chaperone` every sign-in type (starting a process as an account counts as a sign-in, which is why the vault step comes first);
9. with `-WithHost`: registers the scheduled task `\Chaperone\ChapHost` (at your sign-in, as you, not elevated). It is not started: chap-host has no config yet (below);
10. writes `C:\ProgramData\Chaperone\install.json`.

Running it again is safe. It keeps what exists, copies the programs again (stopping the service for that), resets the ACLs and re-registers the service path. It never touches an account it did not create (their description starts with `Chaperone install`). It does not reset `svc-chaperone`'s password once vault keys exist: **that would make the vault unreadable for good**. If the service is ever lost while the vault exists, the script stops and tells you; see "Uninstall".

## Step 3: issue your orchestrator token (same elevated window)

```powershell
& "C:\Program Files\Chaperone\chapd.exe" orch issue -project storefront -ops "pr.*,health,logs" -db D:\Chaperone\data\state.db
```

(Adjust `-project` and `-ops`; `chapd orch issue` prints the options.) It writes `%LOCALAPPDATA%\Chaperone\orchestrator.token`, readable by you only, and prints its fingerprint. Then enrol Windows Hello once: `& "C:\Program Files\Chaperone\chapd.exe" enroll -db D:\Chaperone\data\state.db`.

## Step 4: check (a NORMAL window)

```powershell
& "C:\Program Files\Chaperone\chap.exe" doctor
```

It refuses in an elevated window: an elevated token is a member of Administrators, which the ACLs let in, so every "denied" probe would pass for the wrong reason. It never changes anything. Add `--json` for scripts; exit code 5 means at least one FAIL.

| Check | FAIL or warn means |
| --- | --- |
| `token` | You are elevated. Open a normal window |
| `manifest` | `install.json` missing or incomplete: run `install.ps1` |
| `service` | Not running, not automatic, not `svc-chaperone`, image is not `chapd.exe svc` inside the program folder, or fewer than three restart actions / reset not 24 h / non-crash failures not covered |
| `acl-operator` | **You** can read or write something you must not (vault, keys, `state.db`, logs, dumps, the export for writing), or can not do what you should (read the export, work in `agent-work`) |
| `acl-agent` | The same from `chap-agent`'s side, tested by a real network sign-in with the stored password: it can read the vault, keys, `state.db`, your orchestrator token, can write the program folder, or can not work in `agent-work`. It also proves your own profile folder is closed to the agent |
| `listener` | Nothing answers on `127.0.0.1:55398`, or the port also answers on another local address (chapd must be loopback only) |
| `clock` | More than 5 minutes off the time server (FAIL) or 30 s (warn). Warns, not fails, when offline. Tokens and the ledger depend on the clock |
| `disk` | Under 2 GiB (FAIL) or 10 GiB (warn) free on the drive of the data root |
| `crash-dumps` | `chapd.exe` not excluded from WER, or the dump folder is wrong (warn) |
| `chap-host` | The task is missing, elevated, disabled, not at logon, or not yours (warn) |
| `chapd` / `hello` / `ledger` / `vault` | chapd does not answer or refuses the orchestrator token; no Windows Hello credential is enrolled (warn); the ledger hash chain does not verify; the vault is not initialised. A running chapd with an initialised vault is also the proof that DPAPI unwraps in `svc-chaperone`'s scope |

Before step 3, `chapd` reports a refusal (no token): that is expected until the token exists.

## Starting an agent as `chap-agent`

From your normal window:

```powershell
.\scripts\windows\run-agent.ps1 "C:\Program Files\Chaperone\chap.exe" manual -WorkingDirectory D:\Chaperone\agent-work -Environment @{ CHAP_RUN_TOKEN = $tok } -CaptureOutput
```

The program runs as `chap-agent` with that account's profile and a **cleared environment**: none of yours (no `GH_TOKEN`, no orchestrator token path). It gets a minimal set (`PATH`, `TEMP`, `USERPROFILE`, `CHAP_URL`, ...) plus what `-Environment` adds; `GH_*`, `GITHUB_*` and `CHAP_ORCHESTRATOR_TOKEN_FILE` are refused. Add `-WhatIf` to see what would start. Without `-CaptureOutput` the program opens its own console window (how Windows starts a process under another account). Needs the "Secondary Logon" service, which Windows leaves on manual start: that is fine.

## What is not done yet

- **chap-host has no config.** `host\chap-host.json` needs the grant public key and the host token. `chapd host keygen` makes both (see `adapters/wsl-host/README.md`), but the operator has to run it, import the seed, give `svc-chaperone` read access to the host token file and start `chapd` with the deploy flags: none of that is done by the installer. The task is registered and not started; `chap doctor` warns for `chap-host` until the config exists and the task has run once.
- Moving the data root to another drive is not supported by the scripts (ACLs, manifest and service path would all change). Uninstall, move, install again.
- Updating the programs: build again, then `install.ps1` again (same switches).

## Uninstall

Preview, then run from an elevated window:

```powershell
.\scripts\windows\uninstall.ps1 -WhatIf
.\scripts\windows\uninstall.ps1
```

It removes what the manifest says the installer created: the `ChapHost` task, the WER and LocalDumps settings, the copied programs, `chap-agent` (account, profile, sign-in rights, sign-in-screen entry, password file), and the manifest. It **keeps your data**: the data root, the ledger export, `agent-work` and the chap-host config. While the vault holds keys it also **keeps the `chapd` service (stopped, disabled) and `svc-chaperone`**, because the keys are bound to that account; deleting it makes the vault unreadable. `.\uninstall.ps1 -RemoveData` (type `DELETE EVERYTHING`) removes those as well, but only folders the installer created. The manifest of a partial uninstall stays (state `partly-uninstalled`) so the second run can finish the job.

## If something goes wrong

- The installer stops on the first error and tells you why. It is safe to run again.
- `chapd` will not start: read `D:\Chaperone\data\logs\chapd.log` from an elevated window (you have no access from a normal one), and the Windows System event log (Service Control Manager).
- If the `svc-chaperone` account was reset or deleted but the data folder survived, the vault cannot open. Move `vault-keys` aside (for example to `vault-keys.lost`), run `install.ps1` again **without** `-WithVault`, then follow [vault-recovery.md](vault-recovery.md) with the offline recovery identity. Copy the data folder first.
- Never reset `svc-chaperone`'s password by hand, never `takeown` the data folders from a window you leave open, and never run `chap doctor` elevated.
