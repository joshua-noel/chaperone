<#
.SYNOPSIS
  Read-only demo against REAL GitHub: pr.merge --dry-run on a red and a green Storefront PR.

.DESCRIPTION
  Starts the shipped chapd (no -tags demo) with the real GitHub App and the operator's
  vault, then asks `chap pr merge --dry-run` for two real pull requests and prints
  the verdicts. NOTHING IS MERGED: --dry-run runs the merge verdict (ADR-002 steps
  2-6) with a read-only installation token and never reaches the merge endpoint
  (internal/ops/pr_merge_adapter.go: Check sets DryRun; PRMerger.Merge returns
  before minting a write token or calling PUT /merge; tested by
  TestAdapterCheckLowTierGreenWritesNothing).

  The vault metadata lives in state.db, so the script runs chapd on a COPY of the
  operator's state.db, vault\ and vault-keys\ in a temp folder: the operator's files
  are only read, never opened by chapd. The copy is deleted at the end. Run it as the
  account that owns the vault (the keys are DPAPI-bound).

  Checks at the end, from GitHub itself: both PRs are still OPEN with the same head.
#>
[CmdletBinding()]
param(
  [string]$Go         = 'D:\Chaperone\tools\go\bin\go.exe',
  [string]$ChaperoneDir = 'D:\Chaperone\data',
  [string]$AppId      = '5456170',
  [string]$Repo       = 'example-org/storefront',
  [string]$Project    = 'storefront',
  [int]$RedPr         = 509,   # verify failing
  [int]$GreenPr       = 510,   # verify green
  [switch]$KeepTemp
)
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('chaperone-real-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $tmp | Out-Null
if (-not $env:GOPATH)  { $env:GOPATH  = 'D:\Chaperone\tools\gopath' }
if (-not $env:GOCACHE) { $env:GOCACHE = 'D:\Chaperone\tools\gocache' }
$env:CGO_ENABLED = '0'; $env:GOFLAGS = '-mod=vendor'; $env:GOTOOLCHAIN = 'local'

$chapdProc = $null; $failed = @(); $pushed = $false
function Step($t) { Write-Host ''; Write-Host "== $t" -ForegroundColor Cyan }
function Expect($ok, $what) {
  if ($ok) { Write-Host "   PASS  $what" -ForegroundColor Green } else { Write-Host "   FAIL  $what" -ForegroundColor Red; $script:failed += $what }
}
function PrState($n) { gh pr view $n --repo $Repo --json state,headRefOid,mergedAt | ConvertFrom-Json }

try {
  Step 'Port 55398 must be free (no other chapd running)'
  $c = [Net.Sockets.TcpClient]::new()
  try { $c.Connect('127.0.0.1', 55398); throw 'something already listens on 127.0.0.1:55398; stop it first' } catch [System.Net.Sockets.SocketException] { } finally { $c.Dispose() }

  Step 'Real pull requests (from GitHub)'
  $red = PrState $RedPr; $green = PrState $GreenPr
  Write-Host ("   {0}#{1}: {2}, head {3}" -f $Repo, $RedPr, $red.state, $red.headRefOid.Substring(0, 12))
  Write-Host ("   {0}#{1}: {2}, head {3}" -f $Repo, $GreenPr, $green.state, $green.headRefOid.Substring(0, 12))
  $base = (gh pr view $RedPr --repo $Repo --json baseRefName -q .baseRefName)
  foreach ($x in @($red, $green)) { if ($x.state -ne 'OPEN') { throw 'a chosen PR is not open; pick other numbers with -RedPr / -GreenPr' } }

  Step 'Build the shipped chapd and chap (no -tags demo)'
  Push-Location $repoRoot; $pushed = $true
  & $Go build -trimpath -o (Join-Path $tmp 'chapd.exe') ./cmd/chapd; if ($LASTEXITCODE) { throw 'build chapd failed' }
  & $Go build -trimpath -o (Join-Path $tmp 'chap.exe') ./cmd/chap;   if ($LASTEXITCODE) { throw 'build chap failed' }
  Pop-Location; $pushed = $false
  $chapd = Join-Path $tmp 'chapd.exe'; $chap = Join-Path $tmp 'chap.exe'

  Step 'Copy the operator state.db, vault and vault-keys (read only) into the scratch folder'
  $db = Join-Path $tmp 'state.db'
  foreach ($f in 'state.db', 'state.db-wal', 'state.db-shm') {
    $src = Join-Path $ChaperoneDir $f
    if (Test-Path $src) { Copy-Item $src (Join-Path $tmp $f) }
  }
  Copy-Item (Join-Path $ChaperoneDir 'vault') (Join-Path $tmp 'vault') -Recurse
  Copy-Item (Join-Path $ChaperoneDir 'vault-keys') (Join-Path $tmp 'vault-keys') -Recurse
  & $chapd vault list -db $db
  if ($LASTEXITCODE) { throw 'vault list failed on the copy (run as the account that owns the vault)' }

  Step 'Scratch run-token key set and orchestrator token (in the copy)'
  $pub = [byte[]]::new(32); $rng = [Security.Cryptography.RandomNumberGenerator]::Create(); $rng.GetBytes($pub); $rng.Dispose()
  $pubB64 = [Convert]::ToBase64String($pub).TrimEnd('=').Replace('+', '-').Replace('/', '_')
  $keys = Join-Path $tmp 'run-keys.json'
  (@{ version = 1; allow_interim = $false; keys = @(@{ kid = 'runner-1'; issuer = 'runner.demo'; public_key = $pubB64 }) } | ConvertTo-Json -Depth 5) | Set-Content -Encoding ascii $keys
  $tokenFile = Join-Path $tmp 'orchestrator.token'
  & $chapd orch issue -db $db -project $Project -ops 'pr.merge' -token-file $tokenFile -days 1
  if ($LASTEXITCODE) { throw 'orch issue failed' }

  Step "Start chapd run against real GitHub (App $AppId)"
  $log = Join-Path $tmp 'chapd.log'
  $chapdProc = Start-Process -FilePath $chapd -PassThru -WindowStyle Hidden -RedirectStandardError $log -RedirectStandardOutput (Join-Path $tmp 'chapd.out') -ArgumentList @(
    'run', '-db', $db, '-keys', $keys, '-policy-dir', (Join-Path $repoRoot 'policy'),
    '-vault-dir', (Join-Path $tmp 'vault'), '-vault-key-dir', (Join-Path $tmp 'vault-keys'), '-github-app-id', $AppId)
  $env:CHAP_URL = 'http://127.0.0.1:55398'
  $env:CHAP_ORCHESTRATOR_TOKEN_FILE = $tokenFile
  $up = $false
  for ($i = 0; $i -lt 60 -and -not $up; $i++) {
    if ($chapdProc.HasExited) { throw "chapd exited early:`n$(Get-Content $log -Raw)" }
    $c = [Net.Sockets.TcpClient]::new()
    try { $c.Connect('127.0.0.1', 55398); $up = $true } catch { Start-Sleep -Milliseconds 500 } finally { $c.Dispose() }
  }
  if (-not $up) { throw "chapd did not start:`n$(Get-Content $log -Raw)" }

  function Ask($label, $cmd) {
    Write-Host ''; Write-Host "> $label" -ForegroundColor Yellow
    $ErrorActionPreference = 'Continue'
    $out = & $chap @cmd 2>&1 | ForEach-Object { "$_" } | Out-String
    $code = $LASTEXITCODE
    Write-Host $out.TrimEnd(); Write-Host "   exit code $code"
    [pscustomobject]@{ Out = $out; Code = $code }
  }
  function DryRun($n, $head) {
    @('pr', 'merge', "$n", '--head', $head, '--base', $base, '--repo', $Repo, '--project', $Project, '--dry-run', '--reason', 'demo: real dry run')
  }

  Step "1. Dry-run merge of the RED PR #$RedPr"
  $r = Ask "chap pr merge $RedPr --dry-run" (DryRun $RedPr $red.headRefOid)
  Expect ($r.Code -ne 0 -and $r.Out -match 'CI_RED') 'red PR refused with CI_RED'

  Step "2. Dry-run merge of the GREEN PR #$GreenPr"
  $r = Ask "chap pr merge $GreenPr --dry-run" (DryRun $GreenPr $green.headRefOid)
  Expect ($r.Out -match 'verify: success') 'verify passed on the exact head'
  # A real PR moves: the green one may be behind its base (CI_STALE: it needs pr.update first). Both that
  # and "would merge" / "needs approval" prove the verdict path; CI_RED or any other refusal does not.
  if ($r.Out -match 'CI_STALE') { Write-Host '   NOTE  the PR is behind its base: refused as CI_STALE until pr.update brings the base in and verify re-runs' -ForegroundColor Yellow }
  Expect ($r.Out -notmatch 'CI_RED' -and ($r.Out -notmatch 'DENIED' -or $r.Out -match 'CI_STALE')) 'green PR: no CI_RED and no refusal other than CI_STALE'

  Step 'What GitHub says now (nothing may have merged)'
  $red2 = PrState $RedPr; $green2 = PrState $GreenPr
  foreach ($p in @(@($RedPr, $red, $red2), @($GreenPr, $green, $green2))) {
    Write-Host ("   #{0}: state {1}, mergedAt '{2}', head {3}" -f $p[0], $p[2].state, $p[2].mergedAt, $p[2].headRefOid.Substring(0, 12))
    Expect ($p[2].state -eq 'OPEN' -and -not $p[2].mergedAt -and $p[2].headRefOid -eq $p[1].headRefOid) "#$($p[0]) is still open, unmerged, same head"
  }
  $sql = Get-Content (Join-Path $tmp 'chapd.log') -Raw
  Expect ($sql -notmatch 'merge_commit_sha') 'chapd log shows no merge'
} finally {
  if ($pushed) { Pop-Location }
  if ($chapdProc -and -not $chapdProc.HasExited) { Stop-Process -Id $chapdProc.Id -Force }
  Remove-Item Env:CHAP_URL, Env:CHAP_ORCHESTRATOR_TOKEN_FILE -ErrorAction SilentlyContinue
  if (-not $KeepTemp) { Start-Sleep -Milliseconds 300; Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
}
Write-Host ''
if ($failed.Count) { Write-Host ("REAL DRY RUN FAILED: " + ($failed -join '; ')) -ForegroundColor Red; exit 1 }
Write-Host 'REAL DRY RUN OK: the red PR was refused (CI_RED), the green PR got a verdict from real GitHub data, nothing merged.' -ForegroundColor Green
