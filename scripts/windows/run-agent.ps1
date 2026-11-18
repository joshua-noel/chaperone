<#
.SYNOPSIS
  Starts a program as the agent account (chap-agent), not as you (ticket L1-17, decision #14).

.DESCRIPTION
  Run from your normal (not elevated) window. It unwraps the agent account's password with your DPAPI key (only your
  account can), starts the program as chap-agent with that account's profile and a CLEARED environment, waits for it
  and returns its exit code. The program sees none of your environment: no GH_TOKEN, no orchestrator token path, none
  of your PATH. It gets a minimal one (plus -Environment, which refuses GitHub credentials), and by default the agent
  work folder as its working directory. The password is never printed or written.

  Without -CaptureOutput the program opens its own console window (that is how Windows starts a process under another
  account). With it, stdout and stderr come back here.

  Preview with -WhatIf: it prints what would start and starts nothing.

.EXAMPLE
  .\run-agent.ps1 "C:\Program Files\Chaperone\chap.exe" manual -WorkingDirectory D:\Chaperone\agent-work -Environment @{ CHAP_RUN_TOKEN = $tok } -CaptureOutput
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory = $true, Position = 0)][string]$FilePath,
  [Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgumentList,
  [string]$WorkingDirectory,
  [hashtable]$Environment = @{},
  [switch]$CaptureOutput
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ChaperoneInstall.Common.ps1')

$m = Read-Manifest
if ($null -eq $m) { throw "No install manifest at $(Get-ManifestPath): run install.ps1 first." }
if (-not (Test-Path -LiteralPath $m.agent_password_file)) { throw "The agent password file $($m.agent_password_file) is missing: run install.ps1 again." }

foreach ($k in $Environment.Keys) {
  if ($k -match '^(GH_|GITHUB_)' -or $k -eq 'CHAP_ORCHESTRATOR_TOKEN_FILE') {
    throw "-Environment may not carry ${k}: an agent never holds a GitHub credential or the orchestrator token (ADR-002, ADR-007)."
  }
  if ($k -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { throw "Invalid environment variable name '$k'." }
}

$exe = Get-Command -Name $FilePath -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $exe) { throw "Cannot find the program '$FilePath'." }
$exePath = $exe.Source

if (-not $WorkingDirectory) { $WorkingDirectory = $m.agent_work }
if (-not (Test-Path -LiteralPath $WorkingDirectory -PathType Container)) { throw "The working directory $WorkingDirectory does not exist." }

# Windows command-line quoting (CommandLineToArgvW rules): each argument as one token.
function ConvertTo-CommandLine([string[]]$Items) {
  $parts = foreach ($a in $Items) {
    if ($a -ne '' -and $a -notmatch '[\s"]') { $a; continue }
    $b = New-Object Text.StringBuilder
    [void]$b.Append('"')
    $slashes = 0
    foreach ($ch in $a.ToCharArray()) {
      if ($ch -eq '\') { $slashes++; continue }
      if ($ch -eq '"') { [void]$b.Append('\', $slashes * 2 + 1); [void]$b.Append('"') } else { [void]$b.Append('\', $slashes); [void]$b.Append($ch) }
      $slashes = 0
    }
    [void]$b.Append('\', $slashes * 2)
    [void]$b.Append('"')
    $b.ToString()
  }
  $parts -join ' '
}

# The agent's own profile folder, or where Windows will create it on the first start.
$agentName = ($m.agent_account -split '\\')[-1]
$agentUser = Get-LocalUser -Name $agentName -ErrorAction SilentlyContinue
if (-not $agentUser) { throw "The local account $agentName does not exist: run install.ps1 first." }
$agentSid = $agentUser.SID.Value
$prof = Get-CimInstance Win32_UserProfile -Filter "SID='$agentSid'" -ErrorAction SilentlyContinue
$agentHome = Join-Path $env:SystemDrive "Users\$agentName"
if ($prof -and $prof.LocalPath) { $agentHome = $prof.LocalPath }
$sysRoot = $env:SystemRoot

$psi = New-Object Diagnostics.ProcessStartInfo
$psi.FileName = $exePath
$psi.Arguments = ConvertTo-CommandLine $ArgumentList
$psi.WorkingDirectory = (Resolve-Path -LiteralPath $WorkingDirectory).Path
$psi.UseShellExecute = $false
$psi.LoadUserProfile = $true
$psi.UserName = $agentName
$psi.Domain = '.'
if ($CaptureOutput) { $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true }

$ev = $psi.EnvironmentVariables
$ev.Clear()
$base = @{
  SystemRoot = $sysRoot; windir = $sysRoot; ComSpec = (Join-Path $sysRoot 'System32\cmd.exe')
  PATH = ('{0};{1};{2}' -f (Join-Path $sysRoot 'System32'), $sysRoot, $m.bin_dir)
  PATHEXT = '.COM;.EXE;.BAT;.CMD'; USERNAME = $agentName; USERPROFILE = $agentHome; HOME = $agentHome
  LOCALAPPDATA = (Join-Path $agentHome 'AppData\Local'); APPDATA = (Join-Path $agentHome 'AppData\Roaming')
  TEMP = (Join-Path $agentHome 'AppData\Local\Temp'); TMP = (Join-Path $agentHome 'AppData\Local\Temp')
  COMPUTERNAME = $env:COMPUTERNAME; CHAP_URL = ('http://127.0.0.1:{0}' -f $m.port)
}
foreach ($k in $base.Keys) { $ev[$k] = [string]$base[$k] }
foreach ($k in $Environment.Keys) { $ev[$k] = [string]$Environment[$k] }

Write-Verbose ("as {0}: {1} {2} (cwd {3}; environment variables: {4})" -f $agentName, $exePath, $psi.Arguments, $psi.WorkingDirectory, (($ev.Keys | Sort-Object) -join ', '))
if (-not $PSCmdlet.ShouldProcess("$exePath $($psi.Arguments)", "start as $agentName (cwd $($psi.WorkingDirectory); environment: $((@($ev.Keys) | Sort-Object) -join ', '))")) { return }

# Unwrap the password (your DPAPI scope), use it once, wipe it.
Add-Type -AssemblyName System.Security
$blob = [Convert]::FromBase64String(((Get-Content -LiteralPath $m.agent_password_file -Raw -Encoding ASCII)).Trim())
$plain = $null
try {
  $plain = [Security.Cryptography.ProtectedData]::Unprotect($blob, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
} catch {
  throw 'Cannot unwrap the agent password: it is protected for the account that ran install.ps1. Run this from that account (not elevated as another user).'
}
$secure = New-Object Security.SecureString
try {
  foreach ($ch in [Text.Encoding]::UTF8.GetString($plain).ToCharArray()) { $secure.AppendChar($ch) }
  $secure.MakeReadOnly()
} finally { [Array]::Clear($plain, 0, $plain.Length) }
$psi.Password = $secure

try {
  $p = [Diagnostics.Process]::Start($psi)
} finally {
  $secure.Dispose()
}
if ($CaptureOutput) {
  $errTask = $p.StandardError.ReadToEndAsync()
  $p.StandardOutput.ReadToEnd() | Write-Output
  $p.WaitForExit()
  $e = $errTask.Result
  if ($e) { [Console]::Error.Write($e) }
} else {
  $p.WaitForExit()
}
exit $p.ExitCode
