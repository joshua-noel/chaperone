# Runbook: approve from your phone

You do this once, at the server with the phone in your hand. Afterwards the phone can approve any approval card on its own, with a passkey and a number. The server's Windows Hello keeps working exactly as before; either one device is enough. Design: ADR-004 section 5 and amendment 6 (option A, Tailscale Serve).

**What was run, and what was not.** An agent ran steps 6 and 7 in a scratch setup: a throw-away database, headless Chromium with two virtual authenticators (one for the server at `http://localhost`, one for the phone at `https://server.tail1234.ts.net`), and a self-signed TLS listener standing in for `tailscale serve`. Enrolment of the phone through the QR address, phone sign-in, the right number approving a card, and a wrong number denying a card all worked; screenshots were taken at 1440 px and 390 px. **Not run:** Tailscale itself (it is not installed on the server and no agent ran `tailscale`), a real phone and its screen lock, and the push. Commands that depend on Tailscale's own behaviour are marked `[INFERENCE]`; check them against <https://tailscale.com/kb/1242/tailscale-serve> when you run them, and report what differed.

## What you get

| Piece | What it is |
| --- | --- |
| Tailscale on the server and the phone | A private network (tailnet). The phone reaches the server from anywhere, and nothing is open to the internet. |
| `tailscale serve` | Puts HTTPS (a real certificate, handled by Tailscale) at `https://<server>.<tailnet>.ts.net` in front of the console, which stays on `127.0.0.1:55398`. |
| A phone passkey | Made on the phone, valid only at that address (WebAuthn RP ID = the server's full tailnet name). |
| Number matching | The server card shows a two-digit number. The phone shows the same card text and three numbers. You tap the one on the server; then the phone asks for your passkey. A **wrong number denies the request** and the same action is refused for 60 minutes. |

The ntfy push only wakes the phone. It carries no link and no button. You open the console yourself, from a bookmark.

## What this costs (read once)

- **The server's name goes into a public log.** The HTTPS certificate publishes `<server>.<tailnet>.ts.net` in the public Certificate Transparency logs (<https://tailscale.com/kb/1153/enabling-https>).
- **A phone passkey is normally synced** (iCloud Keychain or Google Password Manager). So an attacker who took over your Apple or Google account could get the key. They would still need a tailnet device that the access rules below allow, your phone's screen lock, and the number on the server's screen. The console records which credentials are synced, so a later policy can forbid them.
- **Renaming the server or the tailnet breaks the passkey.** The passkey belongs to the exact name. Choose the server name and the tailnet name before step 3.
- **The phone cannot approve with the server off or out of sight.** The number is shown on the server.
- **Tailscale is new trust on the server**: its service runs with high rights, and it sees who connects to whom (traffic itself is end-to-end encrypted).

## Before you start

1. `chapd` is installed and running ([install.md](install.md)), and Windows Hello is enrolled (see the install runbook). Sign in at `http://localhost:55398` once to check.
2. You know whether the phone is an iPhone or an Android phone (it only changes the passkey wording).
3. Windows Hello PIN or biometric works on the server, and the phone has a screen lock with a fingerprint, face or PIN. A passkey on a phone without a screen lock cannot do user verification and is refused.

## Step 1: install Tailscale on the server and the phone

1. Server: download the Windows installer from <https://tailscale.com/download>, install it, sign in. The Personal plan is free and enough (<https://tailscale.com/pricing>).
2. Phone: install **Tailscale** from the App Store or Google Play and sign in with **the same account**.
3. In the admin console (<https://login.tailscale.com/admin/machines>) both devices must be listed and connected.
4. Name the server now. In the admin console, open the server's menu, **Edit machine name**, and choose a short stable name (for example `server`). Do not change it later.

## Step 2: switch on MagicDNS and HTTPS certificates

In the admin console, **DNS**:

1. Make sure **MagicDNS** is on.
2. Under **HTTPS Certificates**, click **Enable HTTPS** (you accept that the name is published, see above).
3. Write down the server's full name: `<server>.<tailnet>.ts.net` (for example `server.tail1234.ts.net`). It is shown on the DNS page and on the server's row. This text is **the phone host** below.

## Step 3: limit who can reach the server

Without a rule, every device on your tailnet can reach the sign-in page. Open **Access controls** (<https://login.tailscale.com/admin/acls>) and make the rules allow only the phone to reach the server on port 443:

```json
{
  "tagOwners": {
    "tag:server":    ["autogroup:admin"],
    "tag:phone": ["autogroup:admin"]
  },
  "acls": [
    { "action": "accept", "src": ["tag:phone"], "dst": ["tag:server:443"] }
  ]
}
```

Then, on the **Machines** page, give the server the tag `tag:server` and the phone the tag `tag:phone` (the machine's menu, **Edit ACL tags**). `[INFERENCE]` Tailscale turns key expiry off for tagged devices by default, so a tagged phone does not drop off the tailnet every 180 days; confirm on the machine's menu that expiry is what you want, because a phone whose key expired silently cannot approve. If your tailnet already has other rules you want to keep, add these entries to them instead of replacing the file.

## Step 4: publish the console on the tailnet

In a normal PowerShell window on the server (the installer of Tailscale makes your account the operator on a one-user machine `[INFERENCE]`; if the command says "access denied", run it elevated):

```powershell
tailscale serve --bg --https=443 http://127.0.0.1:55398
tailscale serve status
```

`status` must list exactly one mapping: `https://<server>.<tailnet>.ts.net` to `http://127.0.0.1:55398`. `[INFERENCE]` `tailscale serve` passes the original `Host` header on; if the console later answers "host not allowed" at the tailnet address, report it (the fix is a configured host alias in the console, not in Tailscale). Do **not** use `tailscale funnel`: that puts the console on the public internet.

To take it down again: `tailscale serve --https=443 off`.

## Step 5: tell `chapd` the phone host

`chapd` needs to know the name, because it accepts only the hosts it was told about and it binds each passkey to its host. Add `-phone-host <server>.<tailnet>.ts.net` to the service command and restart it (elevated PowerShell):

```powershell
$k = 'HKLM:\SYSTEM\CurrentControlSet\Services\chapd'
$p = (Get-ItemProperty $k).ImagePath
Set-ItemProperty $k -Name ImagePath -Value ($p + ' -phone-host server.tail1234.ts.net')
Restart-Service chapd
```

Use your own name in place of `server.tail1234.ts.net`. Check the log (`D:\Chaperone\data\logs\chapd.log`): `chapd listening` must appear and no `phone` error. (A later installer version takes this as a parameter; until then this is the supported way.) If the name is not a full tailnet name (an IP address, a bare name, a URL), `chapd` refuses to start and says why.

## Step 6: add the phone (the enrolment is an operation that needs Windows Hello)

Adding a device is the critical-class operation `approvers.enroll`. It needs one approval, from the server.

1. On the server open `http://localhost:55398/approvals` and sign in with your passkey.
2. In the **Phone** panel, leave the name `Phone passkey` (or change it) and click **Ask to add a phone**. A card appears: *Enrol a new approver device*, marked **CRITICAL**, with the origin `https://<server>.<tailnet>.ts.net`. Read it.
3. Click **Approve with your passkey** and approve.
4. The panel now lists the approved request. Click **Show the enrolment address**. The page shows the address as text and as a **QR code**. The address works **once**, for 10 minutes, and the approval is spent when it is shown.
5. On the phone, make sure Tailscale is connected. Scan the QR code with the camera (or type the address) and open it in the phone's browser (Safari on iPhone, Chrome on Android). The page is *Enrol a passkey*; tap **Create passkey** and confirm with the phone's screen lock.
6. Still on the phone, open `https://<server>.<tailnet>.ts.net/login` and tap **Sign in with your passkey**. You are signed in as `operator`. Bookmark `https://<server>.<tailnet>.ts.net/phone`.

Check on the server home screen that the passkey list shows a second row with RP ID `<server>.<tailnet>.ts.net`.

## Step 7: try it with a harmless card

1. Ask for an approval that does no harm (the orchestrator can request a `drive.share` or `mail.send` to a test address).
2. On the server `/approvals` page, under the card, read the **Phone number for this card**.
3. On the phone open `/phone`. The card text is the same as on the server (the `display_sha256` line under it is the same). Tap the number that is on the server.
4. The phone asks for your passkey. Confirm. The card shows *Approved* and the server page lists it under Recent with `approved`.
5. Ask for a second card, and this time tap a number that is **not** the server's. The card must show *denied*, and asking for the same action again must be refused (`OP_APPROVAL_DENIED`) for an hour. This is expected; it is the control working.

If any step shows something different, stop and keep a photo or a copy of the text.

## Using it every day

- The ntfy push says that something is waiting. It has no link. Open the bookmark `/phone`, or the console on the server.
- Read the card before you tap. The number only proves you are looking at the server; it does not prove you read the card.
- A card the phone cannot show (too large) cannot be approved there; use the server.

## If the phone is lost, stolen or replaced

1. On the server console home screen the passkey list shows the phone credential. There is no revoke button yet and no `chapd` command for it `[INFERENCE: checked at the time of writing]`: an administrator who can open `state.db` (from an elevated window) sets `credentials.revoked_at` for that row. **Do this first**: sign-in already refuses a revoked credential.
2. Then remove the phone from the tailnet: admin console, **Machines**, the phone's menu, **Delete**.
3. Change your Apple or Google account password if the phone was a synced-passkey phone and you cannot be sure the account is safe.
4. For a new phone: repeat steps 1 (phone half) and 6.

## If the server or the tailnet is renamed

The passkey stops working (it belongs to the old name). Run step 4 and 5 with the new name, revoke the old phone credential (its `rp_id` column shows the old name), and repeat step 6.

## What `chap doctor` should check

`tailscale serve status` shows exactly the one mapping above and nothing on port 443 other than it; the console is bound to loopback only; the phone host in the service command equals the name Tailscale reports. `[INFERENCE]` these checks are not in `chap doctor` yet.

## Undo everything

`tailscale serve --https=443 off`; remove ` -phone-host ...` from the service's `ImagePath` (step 5) and restart `chapd`; revoke the phone credential in `state.db` as above; delete the phone from the tailnet; uninstall Tailscale if you do not want it.
