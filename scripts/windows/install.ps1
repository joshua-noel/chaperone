<#
.SYNOPSIS
  Installs Chaperone on the server (ticket L1-17, step H2). The operator runs it ONCE, elevated, from his own account.

.DESCRIPTION
  Creates the two local accounts (svc-chaperone runs chapd; chap-agent runs the factory's agents), the folders and their
  ACLs, the chapd Windows service with restart-on-failure, the crash-dump settings, optionally the vault
  (-WithVault) and the chap-host logon task (-WithHost), and writes the install manifest
  C:\ProgramData\Chaperone\install.json that `chap doctor` and uninstall.ps1 read. Read
  docs/runbooks/install.md first. Preview everything without changing anything: run it with -WhatIf (works from a normal,
  not elevated, window).

  Safe to run again: accounts and folders it already made are kept; the service's binary path and the folder ACLs are
  set again.

  Never run under Start-Transcript: with -WithVault the vault's recovery identity is printed to this window, once.

.PARAMETER BinSource
  Folder with the built chapd.exe, chap.exe (and chap-host.exe for -WithHost). They are copied to -BinDir, which only
  administrators can write, so the agent account can not swap the program that runs as svc-chaperone.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [string]$BinSource = 'D:\Chaperone\bin-src',
  [string]$BinDir = (Join-Path $env:ProgramFiles 'Chaperone'),
  [string]$Root = 'D:\Chaperone\data',
  [string]$ExportDir = 'D:\Chaperone\ledger',
  [string]$AgentWork = 'D:\Chaperone\agent-work',
  [int]$Port = 55398,
  # The GitHub App id (chaperone-app). Turns on the git proxy and the pr.* and branch.push ops; the App's key is
  # read from the vault (import it as github-app-key on the console's Secrets page). Empty leaves GitHub off.
  [string]$GitHubAppId = '',
  # How often chapd re-reads the Linear operator board for intake.list, as a Go duration: 15m, 90s, 1h.
  # 0 turns the poller off (every list then reads Linear on demand). Empty keeps chapd's own default (15m), or the
  # value an earlier run recorded in the manifest. At least 1m otherwise.
  [string]$LinearPollInterval = '',
  # The project policies (policy\<project>.yaml) copied next to the programs, where svc-chaperone can read them.
  # Default: the repository's policy folder (set below: $PSScriptRoot is empty inside a PS 5.1 param block).
  [string]$PolicySource = '',
  [switch]$WithVault,
  [switch]$WithHost,
  [switch]$Yes
)

$ErrorActionPreference = 'Stop'
if (-not $PolicySource) { $PolicySource = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'policy' }
. (Join-Path $PSScriptRoot 'ChaperoneInstall.Common.ps1')

# ---- what will be installed, checked before anything changes ----------------------------------------------------

$dryRun = $WhatIfPreference
if (-not $dryRun -and -not (Test-Elevated)) {
  throw 'Run this from an elevated Windows PowerShell (right-click, Run as administrator). To only preview, add -WhatIf: that works from a normal window.'
}
if ($PSVersionTable.PSVersion.Major -ne 5) { Write-Warning "Written for Windows PowerShell 5.1; this is $($PSVersionTable.PSVersion)." }

foreach ($pair in @(@('BinSource', $BinSource), @('BinDir', $BinDir), @('Root', $Root), @('ExportDir', $ExportDir), @('AgentWork', $AgentWork))) {
  $v = $pair[1]
  if (-not [IO.Path]::IsPathRooted($v) -or $v -match '["`;&|<>%$]' -or $v -like '\\*') {
    throw "-$($pair[0]) '$v' must be a plain local absolute path (a drive letter, no quotes, no shell characters)."
  }
}
if ($Root -like "$env:USERPROFILE*" -or $ExportDir -like "$env:USERPROFILE*" -or $AgentWork -like "$env:USERPROFILE*") {
  throw 'The Chaperone folders must not be inside a user profile.'
}
if ($Port -lt 1024 -or $Port -gt 65535) { throw '-Port must be 1024 to 65535.' }
foreach ($exe in @('chapd.exe', 'chap.exe')) {
  if (-not (Test-Path -LiteralPath (Join-Path $BinSource $exe))) { throw "$exe is not in -BinSource ($BinSource). Build it first (README, Developing)." }
}
if ($WithHost -and -not (Test-Path -LiteralPath (Join-Path $BinSource 'chap-host.exe'))) { throw "chap-host.exe is not in -BinSource ($BinSource)." }
if (-not (Test-Path -LiteralPath (Split-Path -Qualifier $Root))) { throw "The drive of -Root ($Root) does not exist." }

$operator = [Security.Principal.WindowsIdentity]::GetCurrent()
$operatorName = $operator.Name
$operatorSid = $operator.User.Value
$localApp = Join-Path $env:LOCALAPPDATA 'Chaperone'
$agentPwFile = Join-Path $localApp 'agent-account.dpapi'
$hostDir = Join-Path $localApp 'host'
$hostLogs = Join-Path $hostDir 'logs'
$db = Join-Path $Root 'state.db'
$vaultDir = Join-Path $Root 'vault'
$keyDir = Join-Path $Root 'vault-keys'
$logDir = Join-Path $Root 'logs'
$dumpDir = Join-Path $Root 'dumps'
$chapdExe = Join-Path $BinDir 'chapd.exe'
$manifestPath = Get-ManifestPath

# Existing accounts must be ours; a stranger's is never taken over. Both calls throw otherwise.
$svcUser = Get-OurAccount $script:SvcAccount
$agentUser = Get-OurAccount $script:AgentAccount
$vaultAlready = Test-VaultInitialized $keyDir
$useVault = [bool]$WithVault -or $vaultAlready   # once initialised, chapd always runs with it
$svcExisting = Get-Service -Name $script:ServiceName -ErrorAction SilentlyContinue
if ($svcUser -and $vaultAlready -and -not $svcExisting) {
  throw "The vault in $keyDir is already initialised and is bound to the $($script:SvcAccount) account, but the '$($script:ServiceName)' service is gone. Registering it needs that account's password, which is not stored anywhere, and resetting it would make the vault unreadable. Run uninstall.ps1 -RemoveData, then install.ps1 -WithVault, and import the secrets again (they stay recoverable with the offline recovery identity)."
}
if (-not $svcUser -and $vaultAlready) {
  throw "There is already a vault in $keyDir, but the $($script:SvcAccount) account does not exist yet. That vault was made by another account (a test run as you?), its keys are wrapped with that account's DPAPI scope, and chapd could not open it as $($script:SvcAccount). Nothing was changed. Rename the folder $Root (for example to $Root.test) so it is kept, or pass another -Root, then run again. If it holds a real secret, import that secret again after the install."
}

Write-Host ''
Write-Host 'Chaperone install plan'
Write-Host "  operator (stays a normal user)  $operatorName"
Write-Host "  programs                       $BinDir   (administrators write; everyone reads)"
Write-Host "  data root                      $Root   (SYSTEM, Administrators, $($script:SvcAccount) only)"
Write-Host "  ledger export                  $ExportDir   ($($script:SvcAccount) writes; you read)"
Write-Host "  agent work folder              $AgentWork   (agent account and you)"
Write-Host "  accounts                       $($script:SvcAccount), $($script:AgentAccount)  (hidden from the sign-in screen)"
Write-Host "  service                        $($script:ServiceName) as $($script:SvcAccount), 127.0.0.1:$Port, restarts on failure"
Write-Host "  vault                          $(if ($WithVault) { 'initialised now (recovery identity shown once)' } else { 'not installed (-WithVault)' })"
Write-Host "  chap-host logon task            $(if ($WithHost) { $script:HostTaskPath + $script:HostTaskName } else { 'not installed (-WithHost)' })"
Write-Host "  manifest                       $manifestPath"
Write-Host ''
if (-not $dryRun -and -not $Yes) {
  $answer = Read-Host 'Type INSTALL to continue'
  if ($answer -cne 'INSTALL') { Write-Host 'Nothing changed.'; return }
}

# ---- bookkeeping: what this run created, so uninstall removes that and nothing else ----------------------------

$old = $null
if (-not $dryRun) { $old = Read-Manifest }
$created = [ordered]@{ accounts = @(); group_members = @(); rights = @(); dirs = @(); files = @(); registry = @(); wer_excluded = $false; service = $false; task = $false; hidden = @() }
if ($old -and $old.PSObject.Properties['created']) {
  foreach ($k in @($created.Keys)) {
    if ($old.created.PSObject.Properties[$k]) { $created[$k] = $old.created.$k }
  }
}
function Add-Created([string]$Key, $Value) {
  $cur = @($created[$Key])
  if ($cur -notcontains $Value) { $created[$Key] = $cur + @($Value) }
}

function Save-Manifest([string]$State) {
  if ($dryRun) { return }
  $dir = Split-Path $manifestPath
  if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $bins = [ordered]@{}
  foreach ($exe in @('chapd.exe', 'chap.exe', 'chap-host.exe')) {
    $p = Join-Path $BinDir $exe
    if (Test-Path -LiteralPath $p) { $bins[$exe] = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower() }
  }
  $m = [ordered]@{
    version = 1; state = $State; installed_at = (Get-Date).ToUniversalTime().ToString('o')
    bin_dir = $BinDir; root = $Root; db = $db; vault_dir = $vaultDir; vault_key_dir = $keyDir; log_dir = $logDir
    dump_dir = $dumpDir; export_dir = $ExportDir; agent_work = $AgentWork
    service = $script:ServiceName; service_account = ".\$($script:SvcAccount)"; agent_account = ".\$($script:AgentAccount)"
    agent_password_file = $agentPwFile
    host_task = $(if ($WithHost) { $script:HostTaskPath + $script:HostTaskName } else { '' })
    host_config = $(if ($WithHost) { Join-Path $hostDir 'chap-host.json' } else { '' })
    port = $Port; with_vault = $useVault; github_app_id = $GitHubAppId; linear_poll_interval = $LinearPollInterval
    operator = $operatorName; operator_sid = $operatorSid; local_app = $localApp; host_dir = $hostDir
    binaries = $bins; created = $created
  }
  Write-Utf8NoBom $manifestPath ($m | ConvertTo-Json -Depth 6)
  Set-LockedAcl -Path $manifestPath -Grants @((New-Grant $script:SidSystem 'FullControl'), (New-Grant $script:SidAdmins 'FullControl'), (New-Grant $script:SidUsers 'Read'))
}

function Ensure-Dir([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) {
    if ($PSCmdlet.ShouldProcess($Path, 'create folder')) {
      New-Item -ItemType Directory -Path $Path -Force | Out-Null
      Add-Created 'dirs' $Path
    }
  }
}

# ---- 1. accounts --------------------------------------------------------------------------------------------------

$svcPlain = $null    # known only on a run that created or reset the account; never written anywhere
$agentPlain = $null

Ensure-Dir (Split-Path $manifestPath)
if ($PSCmdlet.ShouldProcess($manifestPath, 'lock the manifest folder (administrators write, everyone reads)')) {
  Set-LockedAcl -Path (Split-Path $manifestPath) -Grants @((New-Grant $script:SidSystem 'FullControl'), (New-Grant $script:SidAdmins 'FullControl'), (New-Grant $script:SidUsers 'ReadAndExecute'))
}

if (-not $svcUser) {
  if ($PSCmdlet.ShouldProcess($script:SvcAccount, 'create local account (random password, no interactive use)')) {
    $svcPlain = New-RandomPassword
    New-LocalUser -Name $script:SvcAccount -Password (ConvertTo-Secure $svcPlain) -FullName 'Chaperone service (chapd)' `
      -Description "$($script:AccountMarker) (service account)" -PasswordNeverExpires -UserMayNotChangePassword -AccountNeverExpires | Out-Null
    Add-Created 'accounts' $script:SvcAccount
    Save-Manifest 'installing'
  }
} elseif (-not $vaultAlready -and $PSCmdlet.ShouldProcess($script:SvcAccount, 'set a new random password (no vault keys exist yet, so nothing is bound to the old one)')) {
  # The password is never stored, so a later run needs a new one. Safe only while no vault key exists.
  $svcPlain = New-RandomPassword
  Set-LocalUser -Name $script:SvcAccount -Password (ConvertTo-Secure $svcPlain)
}
if (-not $agentUser) {
  if ($PSCmdlet.ShouldProcess($script:AgentAccount, 'create local account (random password, kept DPAPI-protected for you only)')) {
    $agentPlain = New-RandomPassword
    New-LocalUser -Name $script:AgentAccount -Password (ConvertTo-Secure $agentPlain) -FullName 'Chaperone agents' `
      -Description "$($script:AccountMarker) (agent account)" -PasswordNeverExpires -UserMayNotChangePassword -AccountNeverExpires | Out-Null
    Add-Created 'accounts' $script:AgentAccount
    Save-Manifest 'installing'
  }
}
if (-not $dryRun) {
  $svcSid = (Get-LocalUser -Name $script:SvcAccount).SID.Value
  $agentSid = (Get-LocalUser -Name $script:AgentAccount).SID.Value
  $usersGroup = Get-LocalGroup -SID $script:SidUsers
  foreach ($acct in @($script:SvcAccount, $script:AgentAccount)) {
    $member = Get-LocalGroupMember -Group $usersGroup -Member $acct -ErrorAction SilentlyContinue
    if (-not $member -and $PSCmdlet.ShouldProcess($acct, "add to the local group $($usersGroup.Name) (needed for a profile and for the vault step)")) {
      Add-LocalGroupMember -Group $usersGroup -Member $acct
      Add-Created 'group_members' $acct
    }
  }
  if ($PSCmdlet.ShouldProcess($script:SvcAccount, 'grant "Log on as a service"')) {
    Set-AccountRight -Sid $svcSid -Right 'SeServiceLogonRight' -Enable $true
    Add-Created 'rights' "$svcSid|SeServiceLogonRight"
  }
  foreach ($acct in @($script:SvcAccount, $script:AgentAccount)) {
    if ($PSCmdlet.ShouldProcess($acct, 'hide from the sign-in screen')) { Hide-Account $acct; Add-Created 'hidden' $acct }
  }
} else {
  $svcSid = 'S-1-5-21-0-0-0-1001'; $agentSid = 'S-1-5-21-0-0-0-1002'
}

# ---- 2. folders and ACLs ------------------------------------------------------------------------------------------

$full = 'FullControl'
$rootAcl = @((New-Grant $script:SidSystem $full), (New-Grant $script:SidAdmins $full), (New-Grant $svcSid $full))
foreach ($d in @($Root, $vaultDir, $keyDir, $logDir, $dumpDir)) { Ensure-Dir $d }
Set-LockedAcl -Path $Root -Grants $rootAcl -ErrorAction Stop
Ensure-Dir $ExportDir
Set-LockedAcl -Path $ExportDir -Grants @((New-Grant $script:SidSystem $full), (New-Grant $script:SidAdmins $full), (New-Grant $svcSid 'Modify'), (New-Grant $operatorSid 'ReadAndExecute'))
Ensure-Dir $AgentWork
Set-LockedAcl -Path $AgentWork -Grants @((New-Grant $script:SidSystem $full), (New-Grant $script:SidAdmins $full), (New-Grant $agentSid 'Modify'), (New-Grant $operatorSid 'Modify'))
Save-Manifest 'installing'

# The operator's own folder: the agent password and the chap-host config. Operator, SYSTEM and Administrators only.
Ensure-Dir $localApp
Set-LockedAcl -Path $localApp -Grants @((New-Grant $script:SidSystem $full), (New-Grant $script:SidAdmins $full), (New-Grant $operatorSid $full))

# ---- 3. programs --------------------------------------------------------------------------------------------------

$exes = @('chapd.exe', 'chap.exe')
if ($WithHost) { $exes += 'chap-host.exe' }
Ensure-Dir $BinDir
if ($PSCmdlet.ShouldProcess($BinDir, "copy $($exes -join ', ') from $BinSource")) {
  # A running chapd keeps its file locked; stop it, copy, start it again below.
  $running = Get-Service -Name $script:ServiceName -ErrorAction SilentlyContinue
  if ($running -and $running.Status -ne 'Stopped') { Stop-Service -Name $script:ServiceName -Force; $running.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) }
  foreach ($exe in $exes) {
    $src = Join-Path $BinSource $exe
    $dst = Join-Path $BinDir $exe
    Copy-Item -LiteralPath $src -Destination $dst -Force
    if ((Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $dst -Algorithm SHA256).Hash) { throw "$exe changed while it was copied." }
    Add-Created 'files' $dst
  }
}
$policyDir = Join-Path $BinDir 'policy'
if (Test-Path -LiteralPath $PolicySource) {
  Ensure-Dir $policyDir
  if ($PSCmdlet.ShouldProcess($policyDir, "copy the project policies from $PolicySource")) {
    foreach ($p in Get-ChildItem -LiteralPath $PolicySource -Filter '*.yaml' -File) {
      $dst = Join-Path $policyDir $p.Name
      Copy-Item -LiteralPath $p.FullName -Destination $dst -Force
      Add-Created 'files' $dst
    }
  }
}
Set-LockedAcl -Path $BinDir -Grants @((New-Grant $script:SidSystem $full), (New-Grant $script:SidAdmins $full), (New-Grant $script:SidUsers 'ReadAndExecute'))
Save-Manifest 'installing'

# ---- 4. the agent account's password: DPAPI-protected to the operator only -----------------------------------------

if (-not $dryRun) {
  if ($agentPlain -or -not (Test-Path -LiteralPath $agentPwFile)) {
    if ($PSCmdlet.ShouldProcess($agentPwFile, 'store the agent account password, DPAPI-protected to your account')) {
      if (-not $agentPlain) {
        $agentPlain = New-RandomPassword
        Set-LocalUser -Name $script:AgentAccount -Password (ConvertTo-Secure $agentPlain)
      }
      Add-Type -AssemblyName System.Security
      $bytes = [Text.Encoding]::UTF8.GetBytes($agentPlain)
      try {
        $blob = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
      } finally { [Array]::Clear($bytes, 0, $bytes.Length) }
      $tmp = "$agentPwFile.new"
      [IO.File]::WriteAllText($tmp, [Convert]::ToBase64String($blob), [Text.Encoding]::ASCII)
      Set-LockedAcl -Path $tmp -Grants @((New-Grant $script:SidSystem $full), (New-Grant $operatorSid $full))
      Move-Item -LiteralPath $tmp -Destination $agentPwFile -Force
      Add-Created 'files' $agentPwFile
    }
  }
  # The agent account is only denied remote sign-in: the launcher and `chap doctor` log it on locally and over the network.
  if ($PSCmdlet.ShouldProcess($script:AgentAccount, 'deny remote desktop sign-in')) {
    Set-AccountRight -Sid $agentSid -Right 'SeDenyRemoteInteractiveLogonRight' -Enable $true
    Add-Created 'rights' "$agentSid|SeDenyRemoteInteractiveLogonRight"
  }
}

# ---- 5. crash dumps: a dump of chapd would hold the vault's keys ---------------------------------------------------

if ($PSCmdlet.ShouldProcess('chapd.exe', 'exclude from Windows Error Reporting and send any local dump to the locked dumps folder')) {
  $hr = [ChapWer]::Exclude('chapd.exe')
  if ($hr -ne 0) { throw ('WerAddExcludedApplication failed: 0x{0:X8}' -f $hr) }
  $created['wer_excluded'] = $true
  $ld = "$($script:WerKey)\LocalDumps\chapd.exe"
  if (-not (Test-Path $ld)) { New-Item -Path $ld -Force | Out-Null; Add-Created 'registry' $ld }
  New-ItemProperty -Path $ld -Name DumpFolder -Value $dumpDir -PropertyType ExpandString -Force | Out-Null
  New-ItemProperty -Path $ld -Name DumpCount -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $ld -Name DumpType -Value 1 -PropertyType DWord -Force | Out-Null   # 1 = mini dump, no heap
}
Save-Manifest 'installing'

# ---- 6. vault: chapd vault init, run as svc-chaperone ----------------------------------------------------------------

# The vault's keys are wrapped with DPAPI in the account that runs chapd (ADR-003), so init MUST run as that account.
# The deny-sign-in rights go on after this step (and come off for it on a later run), because starting a process as an
# account is an interactive-type sign-in.
$denyRights = @('SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight', 'SeDenyNetworkLogonRight', 'SeDenyBatchLogonRight')

function Invoke-VaultInit {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param()
  if ($vaultAlready) { Write-Host "Vault already initialised in $keyDir (left as it is)."; return }
  if (-not $PSCmdlet.ShouldProcess("chapd vault init as $($script:SvcAccount)", 'initialise the vault')) { return }
  if (-not $svcPlain) { throw "The $($script:SvcAccount) password is unknown on this run, so the vault can not be initialised. Run uninstall.ps1 -RemoveData and install.ps1 -WithVault again." }
  foreach ($r in $denyRights) { Set-AccountRight -Sid $svcSid -Right $r -Enable $false }
  $psi = New-Object Diagnostics.ProcessStartInfo
  $psi.FileName = $chapdExe
  $psi.Arguments = 'vault init -db "{0}" -vault-dir "{1}" -vault-key-dir "{2}"' -f $db, $vaultDir, $keyDir
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  $psi.UserName = $script:SvcAccount
  $psi.Domain = '.'
  $psi.Password = ConvertTo-Secure $svcPlain
  $psi.LoadUserProfile = $true
  $psi.WorkingDirectory = $Root
  $out = $null; $err = $null; $code = -1
  try {
    $p = [Diagnostics.Process]::Start($psi)
    $errTask = $p.StandardError.ReadToEndAsync()
    $out = $p.StandardOutput.ReadToEnd()
    $p.WaitForExit()
    $err = $errTask.Result
    $code = $p.ExitCode
  } finally {
    $psi.Password.Dispose()
  }
  if ($code -ne 0) { throw "chapd vault init failed with exit code $code : $err" }
  if (-not (Test-VaultInitialized $keyDir)) { throw 'chapd vault init reported success but no wrapped key exists.' }
  # To the screen only. Never to a file, a log or the pipeline.
  Write-Host ''
  Write-Host '================================================================================'
  Write-Host $out
  Write-Host '================================================================================'
  Read-Host 'Copy the recovery identity to the offline place now. When you have it, press Enter (this window is cleared)' | Out-Null
  Clear-Host
}
if ($WithVault) { Invoke-VaultInit }

# ---- 6b. run-token key set: chapd refuses to start without one (ADR-005) ----------------------------------------
# An empty set pins no issuer, so every run token is refused until an operator pins one (the runner's operator step 10).
# allow_interim is false: no interim key is pinned either. An existing file is never changed.
$keysFile = Join-Path $Root 'run-keys.json'
if (-not (Test-Path -LiteralPath $keysFile)) {
  if ($PSCmdlet.ShouldProcess($keysFile, 'write an empty run-token key set (no issuer pinned, no interim keys)')) {
    [IO.File]::WriteAllText($keysFile, "{`"version`": 1, `"allow_interim`": false, `"keys`": []}`n", (New-Object Text.UTF8Encoding $false))
    Add-Created 'files' $keysFile
  }
}

# ---- 7. the service -----------------------------------------------------------------------------------------------

$chapdArgs = 'svc -db "{0}" -export-dir "{1}" -log-dir "{2}"' -f $db, $ExportDir, $logDir
if ($Port -ne 55398) { $chapdArgs += " -addr 127.0.0.1:$Port" }
if ($useVault) { $chapdArgs += ' -vault-dir "{0}" -vault-key-dir "{1}"' -f $vaultDir, $keyDir }
if (Test-Path -LiteralPath $policyDir) { $chapdArgs += ' -policy-dir "{0}"' -f $policyDir }
# A re-run without -GitHubAppId keeps the id an earlier run recorded in the manifest.
if (-not $GitHubAppId -and $old -and $old.PSObject.Properties['github_app_id']) { $GitHubAppId = [string]$old.github_app_id }
if ($GitHubAppId) {
  if ($GitHubAppId -notmatch '^[A-Za-z0-9.]{1,40}$') { throw "-GitHubAppId '$GitHubAppId' is not an App id or client id." }
  if (-not $useVault) { throw '-GitHubAppId needs the vault (-WithVault): chapd reads the App key from it.' }
  $chapdArgs += " -github-app-id $GitHubAppId"
}
# The Linear board poll interval (chapd's -linear-poll-interval). A re-run without the parameter keeps the manifest's value.
if (-not $LinearPollInterval -and $old -and $old.PSObject.Properties['linear_poll_interval']) { $LinearPollInterval = [string]$old.linear_poll_interval }
if ($LinearPollInterval) {
  if ($LinearPollInterval -notmatch '^(0|([0-9]+(h|m|s))+)$') { throw "-LinearPollInterval '$LinearPollInterval' is not a duration such as 15m, 90s or 1h, or 0 for off." }
  $chapdArgs += " -linear-poll-interval $LinearPollInterval"
}
$imagePath = '"{0}" {1}' -f $chapdExe, $chapdArgs

if ($PSCmdlet.ShouldProcess($script:ServiceName, "register as $($script:SvcAccount), start automatically (delayed), restart on failure")) {
  $svc = Get-CimInstance Win32_Service -Filter "Name='$($script:ServiceName)'" -ErrorAction SilentlyContinue
  if (-not $svc) {
    $cred = New-Object Management.Automation.PSCredential(".\$($script:SvcAccount)", (ConvertTo-Secure $svcPlain))
    New-Service -Name $script:ServiceName -BinaryPathName $imagePath -DisplayName 'Chaperone (chapd)' `
      -Description 'Chaperone: the policy and approval service for the factory (chapd).' -StartupType Automatic -Credential $cred | Out-Null
    $created['service'] = $true
  } else {
    $chg = @{ PathName = $imagePath }
    if ($svcPlain) { $chg['StartName'] = ".\$($script:SvcAccount)"; $chg['StartPassword'] = $svcPlain }
    $r = Invoke-CimMethod -InputObject $svc -MethodName Change -Arguments $chg
    if ($r.ReturnValue -ne 0) { throw "Changing the chapd service failed (Win32_Service.Change returned $($r.ReturnValue))." }
  }
  & sc.exe config $script:ServiceName start= delayed-auto | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "sc config failed ($LASTEXITCODE)" }
  & sc.exe failure $script:ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "sc failure failed ($LASTEXITCODE)" }
  & sc.exe failureflag $script:ServiceName 1 | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "sc failureflag failed ($LASTEXITCODE)" }
  $svcPlain = $null
}
Save-Manifest 'installing'

# ---- 8. no interactive use of the service account, from now on ----------------------------------------------------

if (-not $dryRun) {
  foreach ($r in $denyRights) {
    if ($PSCmdlet.ShouldProcess($script:SvcAccount, "deny $r")) {
      Set-AccountRight -Sid $svcSid -Right $r -Enable $true
      Add-Created 'rights' "$svcSid|$r"
    }
  }
}

# ---- 9. start chapd ------------------------------------------------------------------------------------------------

if ($PSCmdlet.ShouldProcess($script:ServiceName, 'start and wait until it runs')) {
  Start-Service -Name $script:ServiceName
  (Get-Service -Name $script:ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
}

# ---- 10. chap-host logon task (optional) ---------------------------------------------------------------------------

if ($WithHost) {
  Ensure-Dir $hostDir
  Ensure-Dir $hostLogs
  Set-LockedAcl -Path $hostDir -Grants @((New-Grant $script:SidSystem $full), (New-Grant $operatorSid $full))
  if ($PSCmdlet.ShouldProcess("$($script:HostTaskPath)$($script:HostTaskName)", "register: run chap-host at your sign-in, not elevated")) {
    $action = New-ScheduledTaskAction -Execute (Join-Path $BinDir 'chap-host.exe') -Argument ('run -log-dir "{0}"' -f $hostLogs)
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $operatorName
    $principal = New-ScheduledTaskPrincipal -UserId $operatorName -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
      -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName $script:HostTaskName -TaskPath $script:HostTaskPath -Action $action -Trigger $trigger `
      -Principal $principal -Settings $settings -Description 'Chaperone host agent (chap-host). Needs host\chap-host.json before it can run.' -Force | Out-Null
    $created['task'] = $true
  }
}

Save-Manifest 'complete'

Write-Host ''
if ($dryRun) {
  Write-Host 'Preview only: nothing was changed.'
} else {
  Write-Host 'Installed. Next, in a NORMAL (not elevated) PowerShell window:'
  Write-Host ('    & "{0}" doctor' -f (Join-Path $BinDir 'chap.exe'))
  Write-Host 'It needs an orchestrator token: from this elevated window, `chapd orch issue` first (docs/runbooks/install.md, step 4).'
  if ($WithHost) { Write-Host 'chap-host has no config yet (no grant public key or host token exists): `chap doctor` shows a warning for it until then.' }
}
