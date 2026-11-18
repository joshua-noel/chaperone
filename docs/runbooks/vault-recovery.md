# Runbook: recover the vault with the offline identity

Use this when `chapd` can no longer open the vault because the **service account's DPAPI key is gone**, and you still have the **offline recovery identity** from the install. It re-keys the vault: every secret is read with the offline identity and written again for a new service identity that the current `svc-chaperone` can unwrap. Run log: [`logs/vault-recovery.log`](logs/vault-recovery.log). ADR-003 ("Loss of the server profile or reset of `svc-chaperone`") is the design.

## When to use it, and when not

| Situation | Use this? |
| --- | --- |
| `svc-chaperone`'s password was reset by an administrator, the account was deleted and made again, or its profile folder was lost. `chapd` stops at start-up with `chapd: open the vault: ... CryptUnprotectData ...` or `... vault-identity.dpapi: The system cannot find the file`; `chap doctor` shows `vault` FAIL | **Yes** |
| The server was rebuilt but `D:\Chaperone\data\` kept | **Yes**, once the installer has made the service account and the service again (run `install.ps1` without `-WithVault`, then come back here) |
| `chapd` starts and `chapd vault list` works | **No.** `chapd vault recover` refuses ("the vault opens normally"): the fault is somewhere else |
| You lost the offline identity **and** the vault does not open | **No tool can help.** The secrets are gone; see "What this cannot do" |
| One secret is wrong or leaked | No: rotate it ([`github-app-key.md`](github-app-key.md), [`ntfy-topic.md`](ntfy-topic.md)) |

## What it does and does not change

- Every `<id>.age` file is decrypted with the offline identity first. If **any** file fails, nothing is changed.
- Then it writes a **new** service identity and fingerprint key (wrapped by the account that runs the command), re-encrypts each secret to the new service recipient **and to the same recovery recipient**, and recomputes each fingerprint under the new key. **The offline identity stays valid; nothing new is printed or needs filing.**
- Secret values do not change, so nothing has to be reissued at GitHub, Google or ntfy. Fingerprints shown by `chapd vault list` change once (they are keyed by the lost fingerprint key).
- The dead wrapped key files are **moved** to `vault-keys\retired-<time>\`, not deleted. A command that stops half way is run again.
- `state.db` (ledger, approvals, passkeys, orchestrator tokens) is not touched except for the vault's index tables.

## What you need

1. The offline recovery identity (an `AGE-SECRET-KEY-1...` line) from the safe or USB stick.
2. An elevated Windows PowerShell 5.1 and your checkout of this repository.
3. Ten minutes. `chapd` is stopped during the procedure, so agents get `chap: chapd unavailable` (exit code 6) meanwhile.
4. **No transcript and no recorder.** Do not run this under `Start-Transcript`, do not paste the identity into a chat.

## Steps

```powershell
$chapd = 'C:\Program Files\Chaperone\chapd.exe'
$root = 'D:\Chaperone\data'
$db   = "$root\state.db"
```

**1. Stop `chapd`.** It is the vault's only writer.

```powershell
Stop-Service chapd
```

**2. Check the diagnosis.** The vault must fail to open. Run `chapd` as `svc-chaperone` (step 5 shows how) or read the service log from the elevated window:

```powershell
Get-Content "$root\logs\chapd.log" -Tail 20
```

and run `& $chapd vault list -db $db` as `svc-chaperone`. The failure in the scratch run looked like this (a wrapper that cannot unwrap):

```
chapd: vault: dpapi-user: CryptUnprotectData: The parameter is incorrect.
```

**3. Keep a copy before you change anything.**

```powershell
Copy-Item -Recurse $root "$root.before-recover"
```

**4. Make `svc-chaperone` runnable for one command.** The vault keys are wrapped for the account that runs the command, so `recover` must run **as `svc-chaperone`**. That account is denied every sign-in type on purpose (`install.ps1` step 8), and starting a process as an account is a sign-in, so the rights come off for this one command and go back on. The same code is in `install.ps1` (`Invoke-VaultInit`); the helpers are in `scripts\windows\ChaperoneInstall.Common.ps1`.

> **Do this only because the vault is already unreadable.** Setting the account's password invalidates the DPAPI keys of everything the account wrapped, so on a vault that still opens it would lock the service out until the next recovery. Step 2 proves the keys are already gone.

```powershell
. "<repo>\scripts\windows\ChaperoneInstall.Common.ps1"        # New-RandomPassword, ConvertTo-Secure, Set-AccountRight
$sid  = (Get-LocalUser -Name svc-chaperone).SID.Value
$deny = 'SeDenyInteractiveLogonRight','SeDenyRemoteInteractiveLogonRight','SeDenyNetworkLogonRight','SeDenyBatchLogonRight'
$pw   = New-RandomPassword
Set-LocalUser -Name svc-chaperone -Password (ConvertTo-Secure $pw)
foreach ($r in $deny) { Set-AccountRight -Sid $sid -Right $r -Enable $false }
```

**5. Recover.** The identity goes in on standard input, never as a flag.

```powershell
function Invoke-AsSvcChaperone([string]$Arguments, [string]$StdIn) {
  $psi = New-Object Diagnostics.ProcessStartInfo
  $psi.FileName = $chapd; $psi.Arguments = $Arguments
  $psi.UseShellExecute = $false
  $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  $psi.UserName = 'svc-chaperone'; $psi.Domain = '.'; $psi.Password = ConvertTo-Secure $pw
  $psi.LoadUserProfile = $true; $psi.WorkingDirectory = $root
  $p = [Diagnostics.Process]::Start($psi)
  if ($StdIn) { $p.StandardInput.WriteLine($StdIn) }
  $p.StandardInput.Close()
  $err = $p.StandardError.ReadToEndAsync(); $out = $p.StandardOutput.ReadToEnd(); $p.WaitForExit()
  $out; $err.Result; "exit code $($p.ExitCode)"
}
$secure = Read-Host 'Recovery identity (AGE-SECRET-KEY-1...)' -AsSecureString
$id = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
Invoke-AsSvcChaperone "vault list -db `"$db`""                  # still fails: the diagnosis, as svc-chaperone
Invoke-AsSvcChaperone "vault recover -db `"$db`"" $id
$id = $null; $secure = $null
```

On success the second command prints:

```
recovered: 2 secrets re-keyed to a new service identity (the recovery identity is unchanged)
start chapd again, then run: chapd vault list
exit code 0
```

(With the identity on a file instead of the prompt, for a rehearsal: `Get-Content E:\chaperone-recovery.txt | & $chapd vault recover -db $db`; this is what the scratch log runs.)

**6. Give the service the new password and lock the account again.** The service keeps its own copy of the logon password, which is now stale.

```powershell
$svc = Get-CimInstance Win32_Service -Filter "Name='chapd'"
(Invoke-CimMethod -InputObject $svc -MethodName Change -Arguments @{ StartName = '.\svc-chaperone'; StartPassword = $pw }).ReturnValue   # 0 = ok
foreach ($r in $deny) { Set-AccountRight -Sid $sid -Right $r -Enable $true }
$pw = $null
Start-Service chapd
```

**7. Check.** From a **normal** (not elevated) window:

```powershell
& 'C:\Program Files\Chaperone\chap.exe' doctor            # service, listener, vault, ledger: all OK
& 'C:\Program Files\Chaperone\chap.exe' vault status      # initialized, the same secret names as before
& 'C:\Program Files\Chaperone\chap.exe' ledger verify     # ledger ok; the head is where it was
```

The `vault` check of `chap doctor` passing with `chapd` running is the proof that DPAPI unwraps in the new account's scope. If the GitHub App is on, also prove the key itself works: `chap pr merge <n> --head <sha> --dry-run --project <p>` must get as far as the policy checks (a bad key stops it at the GitHub call).

**8. Clean up.** After a week of normal running, delete `vault-keys\retired-*` (dead wrapped keys, useless to anyone) and `chaperone.before-recover`. Write down the date and the reason.

## If it does not work

| You see | It means | Do |
| --- | --- | --- |
| `that is not this vault's recovery identity` | A typo, a copy from another vault, or the wrong file | Nothing was changed. Check the offline copy; try the other copies you hold. The identity must be the one `chapd vault init` printed for **this** database |
| `the vault opens normally; nothing to recover` | The vault is fine in this account; the failure is elsewhere | Read `chapd.log`; run `chap doctor` |
| `recover <id>: ... decrypt`, or `file for <id>.age is missing` | One ciphertext is damaged, belongs to another vault, or is gone | Nothing was changed. Restore `vault\` from the nightly backup or from `chaperone.before-recover`, then run again. A secret whose file is lost for good cannot be dropped by any command today: see "What this cannot do" |
| `not initialised` | The database you named has no vault index | Wrong `-db`, or a fresh database |
| The command was interrupted | Fine | Run step 5 again. Both old and new ciphertext open with the offline identity |

## What this cannot do

- **A lost offline identity cannot be replaced.** There is no command that makes a new recovery identity for an existing vault, and none that removes a secret from the index. If the identity is lost but the vault still opens, nothing is urgent, but the next account reset is unrecoverable: note it as a risk (owner: operator) and plan an export, a new vault and a fresh import of every secret.
- **The offline identity is not rotated** by recovery. If it may have been seen by someone, treat every vault secret as exposed and rotate each one at its source.
- Wrong-account decryption is covered by a Windows test (`TestDPAPIWrongAccount`, manual two-account check in `internal/vault/vault.go`); this runbook's scratch run replaced the account reset with a file overwrite and was run as one user, with the real DPAPI wrapper.
