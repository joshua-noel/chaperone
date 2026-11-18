<#
.SYNOPSIS
  Demo: approve one merge with your real Windows Hello.

.DESCRIPTION
  Starts a scratch chapd (demo build) on its own port, with a fake GitHub that
  holds a Storefront repo and pull requests. An agent (the `chap` command)
  asks to merge a pull request that changes code. That is a medium-tier merge,
  so Chaperone does not run it: it makes an approval card and waits for you.

  You do three things in Microsoft Edge, from ONE address this script prints
  (the script never opens a browser itself; paste the address into Edge):
    1. Create a passkey (Windows Hello asks once).
    2. Sign in (Windows Hello asks again).
    3. Open Approvals, read the card, press "Approve with Windows Hello"
       (Windows Hello asks a third time, for this card only).

  The script then checks, and prints, that GitHub saw exactly one merge, the
  ledger holds one op.approve and one op.result, and that the approval cannot
  be used a second time.

  Nothing here touches the real Chaperone (D:\Chaperone\data), the vault, a
  GitHub key or the network. The state lives in a temp folder, deleted at the
  end. The console listens on http://localhost:55415 so it can run next to the
  real chapd (which owns 55398). The passkey is bound to that scratch address
  and is worthless anywhere else.

  Needs Go 1.26 or newer: -Go, the portable toolchain under D:\Chaperone\tools,
  or `go` on PATH, in that order.

.PARAMETER AlsoDeny
  Make a second card as well. You deny that one first; the script checks the
  same request is then refused (a denial sticks) and that pull request is never
  merged.
.PARAMETER Port
  Console and API port of the scratch chapd (default 55415).
.PARAMETER WaitMinutes
  How long to wait for each of your decisions (default 15).
.PARAMETER KeepTemp
  Keep the scratch folder.
#>
[CmdletBinding()]
param(
  [string]$Go = '',
  [int]$Port = 55415,
  [int]$WaitMinutes = 15,
  [switch]$AlsoDeny,
  [switch]$KeepTemp
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$tmp  = Join-Path ([IO.Path]::GetTempPath()) ('chaperone-approve-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $tmp | Out-Null

# Go: -Go if given, else the portable toolchain of docs\development.md if it is there, else `go` on PATH.
$tools = 'D:\Chaperone\tools'
if (-not $Go) {
  if (Test-Path (Join-Path $tools 'go\bin\go.exe')) {
    $Go = Join-Path $tools 'go\bin\go.exe'
    if (-not $env:GOPATH)  { $env:GOPATH  = Join-Path $tools 'gopath' }
    if (-not $env:GOCACHE) { $env:GOCACHE = Join-Path $tools 'gocache' }
  } else {
    $found = Get-Command go -ErrorAction SilentlyContinue
    if (-not $found) { throw 'Go 1.26 or newer is needed and was not found. Install it from https://go.dev/dl/ or pass -Go <path to go.exe>.' }
    $Go = $found.Source
  }
}
$env:CGO_ENABLED = '0'; $env:GOFLAGS = '-mod=vendor'; $env:GOTOOLCHAIN = 'local'

$chapdProc = $null
$failed = @()
function Step($t) { Write-Host ''; Write-Host "== $t" -ForegroundColor Cyan }
function Expect($ok, $what) {
  if ($ok) { Write-Host "   PASS  $what" -ForegroundColor Green } else { Write-Host "   FAIL  $what" -ForegroundColor Red; $script:failed += $what }
}
function PortFree($p) {
  $c = [Net.Sockets.TcpClient]::new()
  try { $c.Connect('127.0.0.1', $p); return $false } catch { return $true } finally { $c.Dispose() }
}

try {
  Step 'Check the port is free'
  if ($Port -eq 55398) { throw 'port 55398 belongs to the real chapd. Use another -Port.' }
  if (-not (PortFree $Port)) { throw "port $Port is in use. Stop what uses it, or pass another -Port." }
  Write-Host "   port $Port is free (the real chapd on 55398 is left alone)"

  Step 'Build chapd (demo build) and chap'
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
  & $chapd orch issue -db $db -project 'storefront' -ops 'pr.merge' -token-file $tokenFile -days 1
  if ($LASTEXITCODE) { throw 'orch issue failed' }
  $token = (Get-Content $tokenFile -Raw).Trim()
  $hdr = @{ Authorization = "Bearer $token" }

  Step "Start chapd on 127.0.0.1:$Port (scratch database, fake GitHub)"
  $seed = Join-Path $tmp 'seed.json'
  $out  = Join-Path $tmp 'chapd.out'
  $log  = Join-Path $tmp 'chapd.log'
  $chapdProc = Start-Process -FilePath $chapd -PassThru -WindowStyle Hidden -RedirectStandardError $log -RedirectStandardOutput $out -ArgumentList @(
    'run', '-db', $db, '-keys', $keys, '-addr', "127.0.0.1:$Port", '-policy-dir', (Join-Path $repo 'policy'), '-dev-fake-github', $seed, '-dev-enroll')
  $env:CHAP_URL = "http://127.0.0.1:$Port"
  $env:CHAP_ORCHESTRATOR_TOKEN_FILE = $tokenFile
  $enrol = $null
  for ($i = 0; $i -lt 120 -and -not $enrol; $i++) {
    if ($chapdProc.HasExited) { throw "chapd exited early:`n$(Get-Content $log -Raw)" }
    if ((Test-Path $seed) -and (Test-Path $out)) {
      $m = Select-String -Path $out -Pattern '^Enrol a passkey: (\S+)$' | Select-Object -First 1
      if ($m) { $enrol = $m.Matches[0].Groups[1].Value }
    }
    if (-not $enrol) { Start-Sleep -Milliseconds 500 }
  }
  if (-not $enrol) { throw "chapd did not start:`n$(Get-Content $log -Raw)" }
  $s = Get-Content $seed -Raw | ConvertFrom-Json
  $pr = $s.prs | Where-Object kind -eq 'medium'
  $pr2 = $s.prs | Where-Object kind -eq 'medium-deny'
  Write-Host ("   fake repo {0}, base {1}" -f $s.repo, $s.base)
  Write-Host ("   PR #{0} '{1}': changes src/checkout.py, verify = success on head {2}" -f $pr.number, $pr.title, $pr.head_sha.Substring(0, 12))

  function Ask($label, $cmd) {
    Write-Host ''; Write-Host "> $label" -ForegroundColor Yellow
    $ErrorActionPreference = 'Continue'   # chap writes its denial to stderr; that is output here, not a script error
    $o = & $chap @cmd 2>&1 | ForEach-Object { "$_" } | Out-String
    $code = $LASTEXITCODE
    Write-Host $o.TrimEnd(); Write-Host "   exit code $code"
    [pscustomobject]@{ Out = $o; Code = $code }
  }
  function Merge($p) { @('pr', 'merge', "$($p.number)", '--head', $p.head_sha, '--base', $s.base, '--repo', $s.repo, '--project', 'storefront') }
  function Ledger($name) { (Invoke-RestMethod -Headers $hdr "http://127.0.0.1:$Port/v0/ledger?event_name=$name&limit=100").items }
  function State() { Invoke-RestMethod $s.state_url }

  Step 'An agent asks to merge the pull request'
  $r = Ask "chap pr merge $($pr.number) --head <head>" ((Merge $pr) + @('--reason', 'demo: reword the checkout button'))
  Expect ($r.Code -ne 0 -and $r.Out -match 'needs an approval') 'Chaperone refuses to run it without an approval (OP_APPROVAL_REQUIRED)'
  $r = Ask 'the same, with --request: make the approval card' ((Merge $pr) + @('--reason', 'demo: reword the checkout button', '--request'))
  Expect ($r.Out -match 'pending_approval') 'an approval card is waiting'
  Expect ((State).merge_calls_to_github -eq 0) 'GitHub has seen no merge yet'
  if ($AlsoDeny) {
    # Asked now, while this PR is still up to date: once the first PR merges, the base moves.
    $r = Ask "a second request, for PR #$($pr2.number)" ((Merge $pr2) + @('--reason', 'demo: add a service fee', '--request'))
    Expect ($r.Out -match 'pending_approval') ("a second approval card is waiting (PR #{0}, the one to deny)" -f $pr2.number)
  }

  Step 'YOUR TURN, in Microsoft Edge'
  Write-Host ''
  Write-Host '   Open this address (it works once):' -ForegroundColor Yellow
  Write-Host ''
  Write-Host "   $enrol" -ForegroundColor White
  Write-Host ''
  Write-Host '   1. Press "Create passkey" and approve with Windows Hello.'
  Write-Host '   2. Sign in with Windows Hello.'
  if ($AlsoDeny) {
    Write-Host ("   3. Open `"Approvals`". There are two cards. First DENY the one for PR #{0}: type a reason, press `"Deny`"." -f $pr2.number)
    Write-Host ("   4. Then read the card for PR #{0}: it names the pull request, the head commit and the file it changes." -f $pr.number)
    Write-Host '      Press "Approve with Windows Hello" and approve.'
  } else {
    Write-Host '   3. Open "Approvals". Read the card: it names the pull request, the head commit and the file it changes.'
    Write-Host '      Press "Approve with Windows Hello" and approve.'
  }
  Write-Host ''
  if ($AlsoDeny) {
    Write-Host "   Waiting up to $WaitMinutes minutes for the denial..."
    $deadline = (Get-Date).AddMinutes($WaitMinutes)
    $denied = $false
    while ((Get-Date) -lt $deadline -and -not $denied) {
      if ($chapdProc.HasExited) { throw "chapd exited:`n$(Get-Content $log -Raw)" }
      Start-Sleep -Seconds 2
      $denied = @((Invoke-RestMethod -Headers $hdr "http://127.0.0.1:$Port/v0/ops?limit=20").items | Where-Object { $_.state -eq 'denied' -and $_.target.ref -match "#$($pr2.number)$" }).Count -gt 0
    }
    Expect $denied ("the card for PR #{0} was denied" -f $pr2.number)
    $r = Ask 'the agent asks again for the same merge' ((Merge $pr2) + @('--reason', 'demo: add a service fee', '--request'))
    Expect ($r.Code -ne 0 -and $r.Out -match 'denied' -and $r.Out -notmatch 'pending_approval') 'the same request is refused after a denial (it sticks), and no new card is made'
  }

  Write-Host "   Waiting up to $WaitMinutes minutes for the merge..."
  $deadline = (Get-Date).AddMinutes($WaitMinutes)
  $merged = $false
  while ((Get-Date) -lt $deadline -and -not $merged) {
    if ($chapdProc.HasExited) { throw "chapd exited:`n$(Get-Content $log -Raw)" }
    Start-Sleep -Seconds 2
    $merged = [bool](((State).seed.prs | Where-Object kind -eq 'medium').merged)
  }
  Expect $merged 'the approved pull request was merged'
  if (-not $merged) { throw 'no approval arrived in time' }
  Start-Sleep -Seconds 3   # the page reloads itself 0.8 s after "Approved."; keep the console up for that

  Step 'What happened'
  $st = State
  foreach ($p in $st.seed.prs) { Write-Host ("   PR #{0} ({1}): merged = {2}" -f $p.number, $p.kind, $p.merged) }
  Write-Host ("   merge calls that reached GitHub: {0}" -f $st.merge_calls_to_github)
  Expect ($st.merge_calls_to_github -eq 1) 'exactly one merge call reached GitHub'
  if ($AlsoDeny) { Expect (-not ($st.seed.prs | Where-Object kind -eq 'medium-deny').merged) 'the denied pull request was never merged' }
  Write-Host ''
  Write-Host '   Ledger:'
  $evs = @(); foreach ($n in 'op.request', 'op.approve', 'op.result') { $evs += @(Ledger $n) }
  foreach ($e in ($evs | Where-Object { $_.body } | Sort-Object seq)) { Write-Host ("   #{0,-3} {1,-11} {2}" -f $e.seq, $e.event_name, $e.body) }
  Expect (@(Ledger 'op.approve' | Where-Object { $_.body -match 'approved by' }).Count -eq 1) 'the ledger holds exactly one approval (op.approve, approved)'
  Expect (@(Ledger 'op.result' | Where-Object { $_.body -match 'pr\.merge' }).Count -eq 1) 'the ledger holds exactly one op.result for the merge'

  Step 'The approval cannot be used a second time'
  $ops = (Invoke-RestMethod -Headers $hdr "http://127.0.0.1:$Port/v0/ops?limit=20").items
  $aid = ($ops | Where-Object { $_.approval -and $_.target.ref -match "#$($pr.number)$" } | Select-Object -First 1).approval.id
  $r = Ask "chap pr merge $($pr.number) --head <head> --approval $aid" ((Merge $pr) + @('--reason', 'demo: reuse the approval', '--approval', $aid))
  Expect ($r.Code -ne 0 -and $r.Out -match 'already released an op') 'reusing the approval is refused (APPROVAL_CONSUMED: it already released an op)'
  Expect ((State).merge_calls_to_github -eq 1) 'still exactly one merge call'
} finally {
  if ((Get-Location).Path -eq $repo) { Pop-Location }
  if ($chapdProc -and -not $chapdProc.HasExited) { Stop-Process -Id $chapdProc.Id -Force }
  Remove-Item Env:CHAP_URL, Env:CHAP_ORCHESTRATOR_TOKEN_FILE -ErrorAction SilentlyContinue
  if (-not $KeepTemp) { Start-Sleep -Milliseconds 300; Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
}
Write-Host ''
if ($failed.Count) { Write-Host ("DEMO FAILED: " + ($failed -join '; ')) -ForegroundColor Red; exit 1 }
Write-Host 'DEMO OK: one approval, one merge, and the approval is spent.' -ForegroundColor Green
