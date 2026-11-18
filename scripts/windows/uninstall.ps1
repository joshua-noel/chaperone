<#
.SYNOPSIS
  Removes what install.ps1 created (ticket L1-17), and nothing else. The operator runs it elevated.

.DESCRIPTION
  Reads C:\ProgramData\Chaperone\install.json, which lists what each install run created, and removes exactly
  that: the chap-host task, the crash-dump settings, the copied programs, the agent account with its password file
  and the sign-in rights, and (see below) the service and the service account.

  Your data is kept unless you add -RemoveData: the data root (state.db, vault, logs), the ledger export, the
  agent work folder and the chap-host config. While the vault holds keys, the chapd service is only stopped and
  disabled, and svc-chaperone stays: the keys are bound to that account, and deleting it makes the vault unreadable
  for good. -RemoveData removes those too, after the confirmation prompt.

  Preview with -WhatIf (works from a normal, not elevated, window).
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [switch]$RemoveData,
  [switch]$Yes
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ChaperoneInstall.Common.ps1')

$dryRun = $WhatIfPreference
if (-not $dryRun -and -not (Test-Elevated)) {
  throw 'Run this from an elevated Windows PowerShell. To only preview, add -WhatIf: that works from a normal window.'
}
$m = Read-Manifest
if ($null -eq $m) { throw "No install manifest at $(Get-ManifestPath): nothing recorded, so nothing is removed." }
$c = $m.created
if ($null -eq $c) { throw 'The manifest has no list of what the installer created. Nothing is removed.' }

function Get-List($v) { if ($null -eq $v) { @() } else { @($v) } }

$vaultHasKeys = Test-VaultInitialized $m.vault_key_dir
$keepSvc = $vaultHasKeys -and -not $RemoveData
$problems = New-Object Collections.Generic.List[string]
$retained = New-Object Collections.Generic.List[string]

Write-Host ''
Write-Host 'Chaperone uninstall plan'
Write-Host "  manifest    $(Get-ManifestPath)"
if ($keepSvc) {
  Write-Host "  KEPT        the chapd service (stopped, disabled) and $($script:SvcAccount): the vault's keys are bound to that account"
}
if ($RemoveData) {
  Write-Host "  REMOVED     DATA too, where the installer created the folder: $($m.root), $($m.export_dir), $($m.agent_work), $($m.host_dir)"
} else {
  Write-Host "  KEPT        data: $($m.root), $($m.export_dir), $($m.agent_work)"
}
Write-Host ''
if (-not $dryRun -and -not $Yes) {
  $word = 'UNINSTALL'
  if ($RemoveData) { $word = 'DELETE EVERYTHING' }
  if ((Read-Host "Type $word to continue") -cne $word) { Write-Host 'Nothing changed.'; return }
}

function Try-Step([string]$What, [scriptblock]$Do) {
  if (-not $PSCmdlet.ShouldProcess($What, 'uninstall')) { return }
  try { & $Do } catch { $problems.Add("$What : $($_.Exception.Message)"); Write-Warning "$What failed: $($_.Exception.Message)" }
}

# ---- the service ----------------------------------------------------------------------------------------------------

$svc = Get-Service -Name $m.service -ErrorAction SilentlyContinue
if ($svc) {
  Try-Step "stop service $($m.service)" {
    if ($svc.Status -ne 'Stopped') { Stop-Service -Name $m.service -Force; $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) }
  }
  if ($keepSvc) {
    Try-Step "disable service $($m.service)" { Set-Service -Name $m.service -StartupType Disabled }
    $retained.Add('service')
  } elseif ($c.service) {
    Try-Step "delete service $($m.service)" { & sc.exe delete $m.service | Out-Null; if ($LASTEXITCODE -ne 0) { throw "sc delete returned $LASTEXITCODE" } }
  } else {
    Write-Host "The service '$($m.service)' was not created by this installer; left alone (stopped)."
  }
}

# ---- chap-host task --------------------------------------------------------------------------------------------------

if ($c.task) {
  Try-Step "remove scheduled task $($m.host_task)" {
    $t = Get-ScheduledTask -TaskName $script:HostTaskName -TaskPath $script:HostTaskPath -ErrorAction SilentlyContinue
    if ($t) {
      Stop-ScheduledTask -InputObject $t -ErrorAction SilentlyContinue
      Unregister-ScheduledTask -InputObject $t -Confirm:$false
    }
  }
}

# ---- crash-dump settings --------------------------------------------------------------------------------------------

if ($c.wer_excluded) {
  Try-Step 'allow chapd.exe in Windows Error Reporting again' { [void][ChapWer]::Include('chapd.exe') }
}
foreach ($k in (Get-List $c.registry)) {
  Try-Step "remove registry key $k" { if (Test-Path $k) { Remove-Item -Path $k -Recurse -Force } }
}

# ---- programs ---------------------------------------------------------------------------------------------------------

foreach ($f in (Get-List $c.files)) {
  if ($f -like (Join-Path $m.bin_dir '*')) {
    Try-Step "delete $f" { if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force } }
  }
}

# ---- accounts and sign-in rights -------------------------------------------------------------------------------------

function Remove-OurAccount([string]$Name) {
  $u = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
  if (-not $u) { return }
  if (-not $u.Description -or -not $u.Description.StartsWith($script:AccountMarker)) {
    $problems.Add("$Name : not removed, its description is not the installer's marker"); return
  }
  $sid = $u.SID.Value
  foreach ($r in (Get-List $c.rights)) {
    $parts = $r -split '\|'
    if ($parts[0] -eq $sid) { Try-Step "remove right $($parts[1]) from $Name" { Set-AccountRight -Sid $sid -Right $parts[1] -Enable $false } }
  }
  Try-Step "remove $Name from the sign-in screen list" {
    if (Test-Path $script:WinlogonHideKey) { Remove-ItemProperty -Path $script:WinlogonHideKey -Name $Name -ErrorAction SilentlyContinue }
  }
  Try-Step "delete local account $Name" { Remove-LocalUser -Name $Name }
  Try-Step "delete the profile of $Name" {
    $p = Get-CimInstance Win32_UserProfile -Filter "SID='$sid'" -ErrorAction SilentlyContinue
    if ($p) { Remove-CimInstance -InputObject $p }
  }
}

if ((Get-List $c.accounts) -contains $script:AgentAccount) { Remove-OurAccount $script:AgentAccount }
if ((Get-List $c.accounts) -contains $script:SvcAccount) {
  if ($keepSvc) { $retained.Add($script:SvcAccount) } else { Remove-OurAccount $script:SvcAccount }
}

# ---- the agent password (and every other file the installer wrote in your profile) -----------------------------------

foreach ($f in (Get-List $c.files)) {
  if ($f -notlike (Join-Path $m.bin_dir '*')) {
    Try-Step "delete $f" { if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force } }
  }
}

# ---- folders ----------------------------------------------------------------------------------------------------------

function Remove-IfEmpty([string]$Dir) {
  if ((Test-Path -LiteralPath $Dir -PathType Container) -and -not (Get-ChildItem -LiteralPath $Dir -Force | Select-Object -First 1)) {
    Try-Step "remove empty folder $Dir" { Remove-Item -LiteralPath $Dir -Force }
  }
}

$dataDirs = @($m.root, $m.export_dir, $m.agent_work, $m.host_dir)
if (-not $RemoveData) {
  foreach ($d in $dataDirs) {
    if (((Get-List $c.dirs) -contains $d) -and (Test-Path -LiteralPath $d)) { $retained.Add($d) }
  }
}
if ($RemoveData) {
  foreach ($d in $dataDirs) {
    if ((Get-List $c.dirs) -contains $d -and (Test-Path -LiteralPath $d)) {
      Try-Step "DELETE data folder $d with everything in it" {
        # Administrators are in the ACL of every data folder except the operator's profile one; take ownership if a file is stuck.
        Remove-Item -LiteralPath $d -Recurse -Force
      }
    } elseif (Test-Path -LiteralPath $d) {
      Write-Host "Not removing ${d}: it existed before the installer and is not recorded as created by it."
    }
  }
}
foreach ($d in @($m.bin_dir, (Split-Path $m.bin_dir))) {
  if ((Get-List $c.dirs) -contains $d) { Remove-IfEmpty $d }
}
if ((Get-List $c.dirs) -contains $m.local_app) { Remove-IfEmpty $m.local_app }

# ---- the manifest -----------------------------------------------------------------------------------------------------

if (-not $dryRun) {
  if ($problems.Count -gt 0 -or $retained.Count -gt 0) {
    # Keep a manifest that lists only what is still there, so a later `uninstall.ps1 -RemoveData` can finish the job.
    $left = [ordered]@{}
    foreach ($p in $c.PSObject.Properties) { $left[$p.Name] = $p.Value }
    $left['files'] = @(Get-List $c.files | Where-Object { Test-Path -LiteralPath $_ })
    $left['dirs'] = @(Get-List $c.dirs | Where-Object { Test-Path -LiteralPath $_ })
    if (-not $keepSvc) { $left['service'] = $false }
    $left['task'] = $false
    $left['wer_excluded'] = $false
    $left['registry'] = @()
    $out = [ordered]@{}
    foreach ($p in $m.PSObject.Properties) { $out[$p.Name] = $p.Value }
    $out['state'] = 'partly-uninstalled'
    $out['created'] = $left
    Write-Utf8NoBom (Get-ManifestPath) ($out | ConvertTo-Json -Depth 6)
  } else {
    $mp = Get-ManifestPath
    Remove-Item -LiteralPath $mp -Force
    Remove-IfEmpty (Split-Path $mp)
    Remove-IfEmpty (Split-Path (Split-Path $mp))
  }
}

Write-Host ''
if ($dryRun) { Write-Host 'Preview only: nothing was changed.'; return }
if ($retained.Count -gt 0) {
  Write-Host 'Kept on purpose:'
  foreach ($r in $retained) { Write-Host "  $r" }
  if ($keepSvc) { Write-Host "Run uninstall.ps1 -RemoveData to remove them as well (the vault then becomes unreadable; keep the offline recovery identity)." }
}
if ($problems.Count -gt 0) {
  Write-Host 'Problems (the manifest was kept so you can run this again):'
  foreach ($p in $problems) { Write-Host "  $p" }
  exit 1
}
Write-Host 'Uninstalled.'
