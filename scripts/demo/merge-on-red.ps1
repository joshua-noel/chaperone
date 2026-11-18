<#
.SYNOPSIS
  Demo: Chaperone refuses to merge a pull request whose CI is red.

.DESCRIPTION
  Builds chapd and chap with `-tags demo`, starts chapd against an in-process fake
  GitHub (a Storefront repo with one green PR and one red PR) and the real
  policy in policy\, then asks for merges the way an orchestrator does:

    1. the RED PR      -> refused, CI_RED, nothing written to GitHub
    2. a project with no `pr:` policy block -> refused, OP_POLICY_REFUSED
    3. the GREEN PR    -> merged

  Nothing here touches GitHub, a key, the vault, the real state.db or the network.
  Everything lives in a temp folder that is deleted at the end. The demo build is
  never the shipped chapd: the -dev-fake-github flag does not exist without
  `-tags demo`, and `chapd svc` never has it.

  Needs the Go toolchain of the README (set GOROOT/GOPATH/GOCACHE first, or let
  this script use D:\Chaperone\tools).
#>
[CmdletBinding()]
param(
  [string]$Go = 'D:\Chaperone\tools\go\bin\go.exe',
  [switch]$KeepTemp
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$tmp  = Join-Path ([IO.Path]::GetTempPath()) ('chaperone-demo-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $tmp | Out-Null

if (-not $env:GOPATH)  { $env:GOPATH  = 'D:\Chaperone\tools\gopath' }
if (-not $env:GOCACHE) { $env:GOCACHE = 'D:\Chaperone\tools\gocache' }
$env:CGO_ENABLED = '0'; $env:GOFLAGS = '-mod=vendor'; $env:GOTOOLCHAIN = 'local'

$chapdProc = $null
$failed = @()
function Step($t) { Write-Host ''; Write-Host "== $t" -ForegroundColor Cyan }
function Expect($ok, $what) {
  if ($ok) { Write-Host "   PASS  $what" -ForegroundColor Green } else { Write-Host "   FAIL  $what" -ForegroundColor Red; $script:failed += $what }
}

try {
  Step 'Build chapd and chap with -tags demo'
  Push-Location $repo
  & $Go build -tags demo -trimpath -o (Join-Path $tmp 'chapd.exe') ./cmd/chapd; if ($LASTEXITCODE) { throw 'build chapd failed' }
  & $Go build -trimpath -o (Join-Path $tmp 'chap.exe') ./cmd/chap;               if ($LASTEXITCODE) { throw 'build chap failed' }
  Pop-Location
  $chapd = Join-Path $tmp 'chapd.exe'; $chap = Join-Path $tmp 'chap.exe'

  Step 'Scratch state: database, run-token key set, orchestrator token'
  $db = Join-Path $tmp 'state.db'
  $pub = [byte[]]::new(32); $rng = [Security.Cryptography.RandomNumberGenerator]::Create(); $rng.GetBytes($pub); $rng.Dispose()
  $pubB64 = [Convert]::ToBase64String($pub).TrimEnd('=').Replace('+', '-').Replace('/', '_')
  $keys = Join-Path $tmp 'run-keys.json'
  (@{ version = 1; allow_interim = $false; keys = @(@{ kid = 'runner-1'; issuer = 'runner.demo'; public_key = $pubB64 }) } | ConvertTo-Json -Depth 5) | Set-Content -Encoding ascii $keys
  $tokenFile = Join-Path $tmp 'orchestrator.token'
  # storefront has a `pr:` block in policy\storefront.yaml; acme-shop has no policy file at all.
  & $chapd orch issue -db $db -project 'storefront,acme-shop' -ops 'pr.merge' -token-file $tokenFile -days 1
  if ($LASTEXITCODE) { throw 'orch issue failed' }

  Step 'Start chapd run (demo build) on the fake GitHub'
  $seed = Join-Path $tmp 'seed.json'
  $log  = Join-Path $tmp 'chapd.log'
  $chapdProc = Start-Process -FilePath $chapd -PassThru -WindowStyle Hidden -RedirectStandardError $log -RedirectStandardOutput (Join-Path $tmp 'chapd.out') -ArgumentList @(
    'run', '-db', $db, '-keys', $keys, '-policy-dir', (Join-Path $repo 'policy'), '-dev-fake-github', $seed)
  $env:CHAP_URL = 'http://127.0.0.1:55398'
  $env:CHAP_ORCHESTRATOR_TOKEN_FILE = $tokenFile
  $up = $false
  for ($i = 0; $i -lt 60 -and -not $up; $i++) {
    if ($chapdProc.HasExited) { throw "chapd exited early:`n$(Get-Content $log -Raw)" }
    $c = [Net.Sockets.TcpClient]::new()
    try { $c.Connect('127.0.0.1', 55398); $up = (Test-Path $seed) } catch { Start-Sleep -Milliseconds 500 } finally { $c.Dispose() }
  }
  if (-not $up) { throw "chapd did not start:`n$(Get-Content $log -Raw)" }
  $s = Get-Content $seed -Raw | ConvertFrom-Json
  $red = $s.prs | Where-Object kind -eq 'red'; $green = $s.prs | Where-Object kind -eq 'green'
  Write-Host ("   fake repo {0}, base {1}" -f $s.repo, $s.base)
  Write-Host ("   PR #{0} '{1}'  head {2}  verify = FAILURE" -f $red.number, $red.title, $red.head_sha.Substring(0, 12))
  Write-Host ("   PR #{0} '{1}'  head {2}  verify = success" -f $green.number, $green.title, $green.head_sha.Substring(0, 12))
  Write-Host '   (GitHub Free has no branch protection: left alone, GitHub would merge both.)'

  function Ask($label, $cmd) {
    Write-Host ''; Write-Host "> $label" -ForegroundColor Yellow
    $ErrorActionPreference = 'Continue'   # chap writes its denial to stderr; that is output here, not a script error
    $out = & $chap @cmd 2>&1 | ForEach-Object { "$_" } | Out-String
    $code = $LASTEXITCODE
    Write-Host $out.TrimEnd(); Write-Host "   exit code $code"
    [pscustomobject]@{ Out = $out; Code = $code }
  }

  Step '1. Merge the RED pull request'
  $r = Ask "chap pr merge $($red.number) --head <red head> --project storefront" @('pr', 'merge', "$($red.number)", '--head', $red.head_sha, '--base', $s.base, '--repo', $s.repo, '--project', 'storefront', '--reason', 'demo: merge on red')
  Expect ($r.Code -ne 0 -and $r.Out -match 'CI_RED') 'red PR refused with CI_RED'

  Step '2. A project with no pr: policy block'
  $r = Ask 'chap pr merge ... --project acme-shop --json' @('pr', 'merge', "$($green.number)", '--head', $green.head_sha, '--base', $s.base, '--repo', 'example-org/acme-shop', '--project', 'acme-shop', '--reason', 'demo: no pr policy', '--json')
  Expect ($r.Code -ne 0 -and $r.Out -match 'OP_POLICY_REFUSED') 'project without a pr: block refused with OP_POLICY_REFUSED'

  Step '3. Merge the GREEN pull request (the control)'
  $r = Ask "chap pr merge $($green.number) --head <green head> --project storefront" @('pr', 'merge', "$($green.number)", '--head', $green.head_sha, '--base', $s.base, '--repo', $s.repo, '--project', 'storefront', '--reason', 'demo: CI green on this head')
  Expect ($r.Code -eq 0) 'green PR merged'

  Step 'What the fake GitHub holds now'
  $st = Invoke-RestMethod $s.state_url
  foreach ($p in $st.seed.prs) { Write-Host ("   PR #{0} ({1}): merged = {2}" -f $p.number, $p.kind, $p.merged) }
  Write-Host ("   merge calls that reached GitHub: {0}" -f $st.merge_calls_to_github)
  Expect (-not ($st.seed.prs | Where-Object kind -eq 'red').merged) 'the red PR was not merged'
  Expect (($st.seed.prs | Where-Object kind -eq 'green').merged) 'the green PR was merged'
  Expect ($st.merge_calls_to_github -eq 1) 'exactly one merge call reached GitHub (the green one)'
} finally {
  if ((Get-Location).Path -eq $repo) { Pop-Location }
  if ($chapdProc -and -not $chapdProc.HasExited) { Stop-Process -Id $chapdProc.Id -Force }
  Remove-Item Env:CHAP_URL, Env:CHAP_ORCHESTRATOR_TOKEN_FILE -ErrorAction SilentlyContinue
  if (-not $KeepTemp) { Start-Sleep -Milliseconds 300; Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
}
Write-Host ''
if ($failed.Count) { Write-Host ("DEMO FAILED: " + ($failed -join '; ')) -ForegroundColor Red; exit 1 }
Write-Host 'DEMO OK: a red PR cannot be merged through Chaperone.' -ForegroundColor Green
