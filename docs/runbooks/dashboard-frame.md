# Showing the console's pages inside a dashboard

A dashboard of your own (here at `http://localhost:55440`) can show the approval card, the ledger and the runs page in frames, and open the secrets page in its own window. This is off until `chapd` is started with the origin of the dashboard. Design and limits: ADR-004 amendment 12.

## Turn it on

1. Add `-console-frame-ancestor http://localhost:55440` to the `chapd` service command (repeat the flag for a second origin) and restart it (elevated PowerShell, the same way as `-phone-host` in [phone.md](phone.md), step 5):

   ```powershell
   $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\chapd'
   $p = (Get-ItemProperty $k).ImagePath
   Set-ItemProperty $k -Name ImagePath -Value ($p + ' -console-frame-ancestor http://localhost:55440')
   Restart-Service chapd
   ```

   An origin `chapd` cannot accept (a path, a wildcard, upper case, plain http for a name other than localhost) stops it with a message that quotes that origin; read `D:\Chaperone\data\logs\chapd.log`. `chapd listening` must appear.
2. The dashboard must be opened at `http://localhost:55440`, not `127.0.0.1`: the console's session cookie is `SameSite=Strict`, and `localhost` on another port is the same site, `127.0.0.1` is not.
3. The iframe in the dashboard needs two things:
   - `src="http://localhost:55398/approvals?embed=1"` (or `/ledger?embed=1`, `/runs?embed=1`). `?embed=1` sets the layout of the page to the whole frame. The console draws no header and no navigation in a framed response (`Sec-Fetch-Dest: iframe`, or a window opened with `?from=frame`) whether or not `?embed=1` is there, so a frame that leaves it out still shows no links that lead to pages that are never framed. It is not a security setting and the visibility guard never reads it.
   - `allow="publickey-credentials-get"`. Without it the browser refuses the Windows Hello prompt inside the frame, and Approve fails with a message that does not say why.
4. Sign in at `http://localhost:55398` once with Windows Hello. The frames in the dashboard then carry that session. Loading a page in a frame does not extend the session's idle time (30 minutes), and neither does loading a page's script or style at any time; only using the console does (a page loaded in its own window, or a button pressed). The session also ends 8 hours after sign-in, whatever it did. When the session has ended the frame says "Signed out: sign in at Chaperone": open the link, sign in, then reload the frame.

## What a frame may and may not do

| Page | In a frame of a listed origin | As a top-level window |
|---|---|---|
| `/approvals`, `/ledger`, `/runs` | yes | by its own address |
| `/secrets` | never (it sends `frame-ancestors 'none'`) | its own address, or the link "Secrets: opens in Chaperone" inside a frame (that page is **restricted**, like the others: a read-only view; a waiting secret write's card is folded, and Approve, Deny, Cancel, Try again and the import form are not drawn or are off) |
| sign-in, enrolment, phone, Home, Operations | never | by their own address |

A page of another site cannot load a console page as a top-level window (it is refused, 403): the window opens from a link inside the console, or the operator types the address. A link in a frame that opens a new window does so 650 ms after the click, not at once, and a second click in that time cancels it. However a frame link is opened (a click, a middle click, "Open link in new tab"), the window it opens is **restricted**: every card is folded, Approve, Deny and Revoke are off (a run's row says "Re-open to revoke"), and a note says "Opened from another site: buttons are off here. Re-open here to act". "Re-open here" works like a button: it stays grey until the page has been visible and focused for a second and you have moved the pointer, pressed a key (Tab will do) or touched it; then it gives you the ordinary page. A browser that sends no `Sec-Fetch-Site` header (none of the supported ones) gets the restricted page with no link: use a current browser. On any ordinary top-level page every button that acts stays grey for the same second and the same kind of action; if you click too soon the page says so.

Inside a frame every button stays grey until the browser says it is plainly visible. If a button stays grey, scroll it fully into view and make sure nothing covers it. A browser that cannot tell (no IntersectionObserver v2) shows a note with a link "Open the console in its own window" and no working buttons.

## Turn it off

Remove ` -console-frame-ancestor http://localhost:55440` from the service's `ImagePath` (the same registry key as above) and restart `chapd`. Do this **before** you revert or downgrade `chapd`: an older `chapd` does not know the flag and stops at start-up with "flag provided but not defined". Nothing is stored.
