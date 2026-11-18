# Helpers shared by install.ps1, uninstall.ps1 and run-agent.ps1 (L1-17). Dot-sourced; it only defines functions and
# constants. Windows PowerShell 5.1, ASCII only (5.1 reads a BOM-less file as the ANSI code page).

Set-StrictMode -Version 2

# Load the modules up front: under -WhatIf, PowerShell would otherwise print a "Set Alias" line for each alias they define.
$wiBefore = $WhatIfPreference; $WhatIfPreference = $false
foreach ($mod in @('CimCmdlets', 'Microsoft.PowerShell.LocalAccounts', 'ScheduledTasks')) { Import-Module $mod -ErrorAction SilentlyContinue }
$WhatIfPreference = $wiBefore

$script:SidSystem = 'S-1-5-18'
$script:SidAdmins = 'S-1-5-32-544'
$script:SidUsers = 'S-1-5-32-545'
$script:SvcAccount = 'svc-chaperone'
$script:AgentAccount = 'chap-agent'
$script:ServiceName = 'chapd'
$script:HostTaskPath = '\Chaperone\'
$script:HostTaskName = 'ChapHost'
$script:AccountMarker = 'Chaperone install'
$script:WerKey = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting'
$script:WinlogonHideKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'

function Get-ManifestPath {
  Join-Path $env:ProgramData 'Chaperone\install.json'
}

function Test-Elevated {
  $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-Sid([string]$Sid) {
  New-Object Security.Principal.SecurityIdentifier($Sid)
}

# ---- passwords ---------------------------------------------------------------------------------------------------

# A random password from the system CSPRNG (rejection sampling, so no modulo bias) that meets the default Windows
# complexity rule (upper, lower, digit, symbol). Returned as a plain string only because CIM's Change method needs one;
# every other use takes the SecureString.
function New-RandomPassword([int]$Length = 40) {
  $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '-_.+=')
  $all = ($sets -join '')
  $rng = New-Object Security.Cryptography.RNGCryptoServiceProvider
  try {
    $buf = New-Object byte[] 1
    $pick = {
      param([string]$chars)
      $limit = 256 - (256 % $chars.Length)
      do { $rng.GetBytes($buf) } while ($buf[0] -ge $limit)
      $chars[$buf[0] % $chars.Length]
    }
    while ($true) {
      $out = New-Object System.Text.StringBuilder
      for ($i = 0; $i -lt $Length; $i++) { [void]$out.Append((& $pick $all)) }
      $s = $out.ToString()
      $ok = $true
      foreach ($set in $sets) {
        $found = $false
        foreach ($c in $set.ToCharArray()) { if ($s.IndexOf($c) -ge 0) { $found = $true; break } }
        if (-not $found) { $ok = $false }
      }
      if ($ok) { return $s }
    }
  } finally { $rng.Dispose() }
}

function ConvertTo-Secure([string]$Plain) {
  $s = New-Object Security.SecureString
  foreach ($c in $Plain.ToCharArray()) { $s.AppendChar($c) }
  $s.MakeReadOnly()
  $s
}

# ---- ACLs --------------------------------------------------------------------------------------------------------

# Replace the ACL of a file or folder with exactly these grants and switch inheritance off. Each grant is
# @{ Sid = 'S-1-...'; Rights = 'FullControl' }. No deny entries: whoever is not listed has no access.
function Set-LockedAcl {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][hashtable[]]$Grants)
  if (-not $PSCmdlet.ShouldProcess($Path, 'set a protected ACL')) { return }
  $isDir = Test-Path -LiteralPath $Path -PathType Container
  $acl = Get-Acl -LiteralPath $Path
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($r in @($acl.Access)) { [void]$acl.RemoveAccessRuleAll($r) }
  foreach ($g in $Grants) {
    $inherit = [Security.AccessControl.InheritanceFlags]::None
    if ($isDir) { $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' }
    $rule = New-Object Security.AccessControl.FileSystemAccessRule((ConvertTo-Sid $g.Sid), $g.Rights, $inherit, 'None', 'Allow')
    $acl.AddAccessRule($rule)
  }
  Set-Acl -LiteralPath $Path -AclObject $acl
}

function New-Grant([string]$Sid, [string]$Rights) { @{ Sid = $Sid; Rights = $Rights } }

# ---- account rights (LSA) ----------------------------------------------------------------------------------------

if (-not ('ChapLsa' -as [type])) {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class ChapLsa {
  [StructLayout(LayoutKind.Sequential)]
  struct LSA_OBJECT_ATTRIBUTES {
    public int Length; public IntPtr RootDirectory; public IntPtr ObjectName; public int Attributes;
    public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService;
  }
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  struct LSA_UNICODE_STRING { public ushort Length; public ushort MaximumLength; public string Buffer; }

  [DllImport("advapi32.dll")] static extern uint LsaOpenPolicy(IntPtr systemName, ref LSA_OBJECT_ATTRIBUTES attrs, uint access, out IntPtr policy);
  [DllImport("advapi32.dll")] static extern uint LsaAddAccountRights(IntPtr policy, byte[] sid, LSA_UNICODE_STRING[] rights, uint count);
  [DllImport("advapi32.dll")] static extern uint LsaRemoveAccountRights(IntPtr policy, byte[] sid, bool all, LSA_UNICODE_STRING[] rights, uint count);
  [DllImport("advapi32.dll")] static extern uint LsaEnumerateAccountRights(IntPtr policy, byte[] sid, out IntPtr rights, out uint count);
  [DllImport("advapi32.dll")] static extern uint LsaFreeMemory(IntPtr p);
  [DllImport("advapi32.dll")] static extern uint LsaClose(IntPtr policy);
  [DllImport("advapi32.dll")] static extern int LsaNtStatusToWinError(uint status);

  const uint POLICY_CREATE_ACCOUNT = 0x10, POLICY_LOOKUP_NAMES = 0x800;
  const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034;

  static IntPtr Open(uint access) {
    LSA_OBJECT_ATTRIBUTES a = new LSA_OBJECT_ATTRIBUTES();
    a.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
    IntPtr h;
    uint st = LsaOpenPolicy(IntPtr.Zero, ref a, access, out h);
    if (st != 0) throw new System.ComponentModel.Win32Exception(LsaNtStatusToWinError(st));
    return h;
  }
  static byte[] SidBytes(string sid) {
    SecurityIdentifier s = new SecurityIdentifier(sid);
    byte[] b = new byte[s.BinaryLength];
    s.GetBinaryForm(b, 0);
    return b;
  }
  static LSA_UNICODE_STRING[] One(string right) {
    LSA_UNICODE_STRING u = new LSA_UNICODE_STRING();
    u.Buffer = right;
    u.Length = (ushort)(right.Length * 2);
    u.MaximumLength = (ushort)(right.Length * 2 + 2);
    return new LSA_UNICODE_STRING[] { u };
  }
  public static void Add(string sid, string right) {
    IntPtr h = Open(POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES);
    try {
      uint st = LsaAddAccountRights(h, SidBytes(sid), One(right), 1);
      if (st != 0) throw new System.ComponentModel.Win32Exception(LsaNtStatusToWinError(st));
    } finally { LsaClose(h); }
  }
  // Removing a right the account does not hold is not an error.
  public static void Remove(string sid, string right) {
    IntPtr h = Open(POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES);
    try {
      uint st = LsaRemoveAccountRights(h, SidBytes(sid), false, One(right), 1);
      if (st != 0 && st != STATUS_OBJECT_NAME_NOT_FOUND) throw new System.ComponentModel.Win32Exception(LsaNtStatusToWinError(st));
    } finally { LsaClose(h); }
  }
  public static string[] List(string sid) {
    IntPtr h = Open(POLICY_LOOKUP_NAMES);
    try {
      IntPtr buf; uint n;
      uint st = LsaEnumerateAccountRights(h, SidBytes(sid), out buf, out n);
      if (st == STATUS_OBJECT_NAME_NOT_FOUND) return new string[0];
      if (st != 0) throw new System.ComponentModel.Win32Exception(LsaNtStatusToWinError(st));
      try {
        string[] r = new string[n];
        int size = Marshal.SizeOf(typeof(LSA_UNICODE_STRING));
        for (int i = 0; i < n; i++) {
          LSA_UNICODE_STRING u = (LSA_UNICODE_STRING)Marshal.PtrToStructure(new IntPtr(buf.ToInt64() + (long)i * size), typeof(LSA_UNICODE_STRING));
          r[i] = u.Buffer;
        }
        return r;
      } finally { LsaFreeMemory(buf); }
    } finally { LsaClose(h); }
  }
}

public static class ChapWer {
  [DllImport("wer.dll", CharSet = CharSet.Unicode)] static extern int WerAddExcludedApplication(string exe, bool allUsers);
  [DllImport("wer.dll", CharSet = CharSet.Unicode)] static extern int WerRemoveExcludedApplication(string exe, bool allUsers);
  public static int Exclude(string exe) { return WerAddExcludedApplication(exe, true); }
  public static int Include(string exe) { return WerRemoveExcludedApplication(exe, true); }
}
'@
}

function Set-AccountRight {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([Parameter(Mandatory = $true)][string]$Sid, [Parameter(Mandatory = $true)][string]$Right, [bool]$Enable = $true)
  $verb = 'remove'
  if ($Enable) { $verb = 'grant' }
  if (-not $PSCmdlet.ShouldProcess("$Sid", "$verb $Right")) { return }
  if ($Enable) { [ChapLsa]::Add($Sid, $Right) } else { [ChapLsa]::Remove($Sid, $Right) }
}

# ---- accounts ----------------------------------------------------------------------------------------------------

# $null when there is no such local account. Throws when there is one this installer did not create: it is never taken
# over (its description is the marker).
function Get-OurAccount([string]$Name) {
  $u = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
  if ($null -eq $u) { return $null }
  if (-not $u.Description -or -not $u.Description.StartsWith($script:AccountMarker)) {
    throw "A local account named '$Name' already exists and was not created by this installer (its description does not start with '$($script:AccountMarker)'). Rename or remove it, then run again."
  }
  $u
}

function Hide-Account([string]$Name) {
  if (-not (Test-Path $script:WinlogonHideKey)) { New-Item -Path $script:WinlogonHideKey -Force | Out-Null }
  New-ItemProperty -Path $script:WinlogonHideKey -Name $Name -Value 0 -PropertyType DWord -Force | Out-Null
}

# ---- manifest ----------------------------------------------------------------------------------------------------

function Read-Manifest {
  $p = Get-ManifestPath
  if (-not (Test-Path -LiteralPath $p)) { return $null }
  Get-Content -LiteralPath $p -Raw -Encoding UTF8 | ConvertFrom-Json
}

# UTF-8 without a BOM: chap doctor reads it with Go's JSON decoder, which rejects a BOM.
function Write-Utf8NoBom([string]$Path, [string]$Text) {
  [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding($false)))
}

function Test-VaultInitialized([string]$KeyDir) {
  if (-not (Test-Path -LiteralPath $KeyDir -PathType Container)) { return $false }
  $null -ne (Get-ChildItem -LiteralPath $KeyDir -Force -File -ErrorAction SilentlyContinue | Select-Object -First 1)
}
