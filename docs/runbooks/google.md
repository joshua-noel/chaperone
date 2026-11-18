# Runbook: connect Google to Chaperone

You do this once, on the server, from your own Windows account and your own browser. It gives Chaperone permission to **send mail as one Google account** and, if you choose, **share Drive files**. It does not turn either on: `mail.send` and `drive.share` stay disabled in the baseline policy until a policy change enables them (step 6).

This runbook uses a **consumer** Google account (not Workspace).

## What you are agreeing to

| | |
| --- | --- |
| **Mail** | Scope `gmail.send`: Chaperone can send mail as you. It **cannot read** your mail. Every email needs your approval on a card that shows every recipient, the subject, the **full body** and the SHA-256 of each attachment and of the finished message. It goes only to addresses on the project's allowlist. |
| **Drive** (optional) | Scope `drive`: Google calls it *restricted* and it covers **all** your Drive files. Chaperone only ever uses it to add a person (never "anyone with the link") to one file, with a role no higher than the project's cap, after an approval of a card that shows the file's real name, the people and the role. You may skip Drive for now (step 2 says how). |
| **Where the keys live** | The OAuth client file and the token set go into Chaperone's vault. An agent never holds either. A token that Google stops accepting raises an alert and every mail and Drive op is refused until you sign in again. |

## Step 1: Google Cloud project (browser, 10 minutes)

1. Open <https://console.cloud.google.com/> signed in as the Google account Chaperone should use. Create a project named `Chaperone` (no organisation, since it is a non-company account).
2. **APIs and services, Library:** enable the **Gmail API**. Enable the **Google Drive API** only if you want Drive.

## Step 2: consent screen (browser)

The menu is called *OAuth consent screen* or *Google Auth platform* (Branding, Audience, Data access); Google renames it, the settings below are what matter.

1. **User type: External.** (A consumer `@gmail.com` account cannot choose Internal.)
2. App name `Chaperone`, your e-mail as support and developer contact. Nothing else is needed for a small private app (no logo, no privacy-policy URL) `[INFERENCE: those fields are for verification, which a one-person app does not go through]`.
3. **Scopes (Data access):** add
   - `https://www.googleapis.com/auth/gmail.send` (Google: *sensitive*),
   - `openid` and `https://www.googleapis.com/auth/userinfo.email` (Chaperone reads the verified address of the account from the sign-in, so a card can name the account),
   - `https://www.googleapis.com/auth/drive` **only if you want Drive** (Google: *restricted*). The narrower `drive.file` only reaches files this app created or that you open with it, so it cannot share your existing files: not usable for `drive.share`. Google's Drive page says restricted Drive scopes are meant for backup, productivity and security apps (<https://developers.google.com/workspace/drive/api/guides/api-specific-auth>); a private tool is outside that list, so Google may refuse or limit it `[INFERENCE: not tried]`. **If you want the least exposure, leave Drive out and add it later.**

## Step 3: publish the app, *In production* (browser) — do not skip

On the consent screen (Audience) click **Publish app** so the status reads **In production**.

**Why:** an *external* app left in **Testing** is issued refresh tokens that **expire after 7 days** (<https://developers.google.com/identity/protocols/oauth2>). Chaperone would work for a week and then stop. The expiry would be caught (an alert, and every op refused), but you would repeat the sign-in every week.

What In production without verification means for you:

- Google shows **"Google hasn't verified this app"** when you sign in. Click **Advanced**, then **Go to Chaperone (unsafe)**. The warning is about an app Google has not reviewed; here you wrote the app and you are the only user.
- Google caps an unverified app at **100 new users**. You are one.
- Whether Google will insist on verification for `gmail.send` (sensitive) or `drive` (restricted) for a single-user app: `[INFERENCE: not checked; the docs say verification is for apps launched to users]`. If the sign-in is refused, note what the screen says.

## Step 4: the OAuth client (browser)

1. **Credentials, Create credentials, OAuth client ID.** Application type **Desktop app**, name `Chaperone server`. (Not "Web application": Chaperone's sign-in uses a loopback address and PKCE, <https://developers.google.com/identity/protocols/oauth2/native-app>.)
2. **Download JSON.** Save it somewhere only you can read, for example `%USERPROFILE%\Downloads\client_secret_….json`. It holds a client secret (Google says a desktop app's secret is not confidential, but Chaperone treats it as one). Do not send or sync it.

## Step 5: sign in once (PowerShell, your own window)

`chapd connect google` opens nothing by itself. It prints an address, you open it in your browser, choose the account, click through the unverified-app warning, tick **every** box on the consent page, and Google sends the browser back to a random port on the server (`http://127.0.0.1:<port>/callback`, loopback redirect, PKCE, a one-time `state`). The command checks all of that, and refuses a sign-in that did not grant every scope it asked for.

**The installer closes `svc-chaperone`'s sign-in once the vault exists**, so you cannot run a command as the vault's account. Sign in with **no vault**, then put the two files in through the console, the way you did for the GitHub App key (H1):

```powershell
cd %USERPROFILE%\Projects\chaperone
# add -drive only if you took the Drive scope in step 2
.\dist\windows\chapd.exe connect google -client-file "$HOME\Downloads\client_secret_XXXX.json" -out "$HOME\Downloads\google-token.json"
```

1. Open the address it prints. When the tab says *Chaperone is connected to Google*, the command prints `connected as <you>@gmail.com, scopes: …`. It also prints a **WARNING** if Google says the sign-in ends on a date: then the consent screen is still in Testing, go back to step 3.
2. In the Chaperone console (`http://localhost:55398`, sign in with Windows Hello), open **Secrets** and import two secrets, each approved with Windows Hello:

   | File | Secret id | Kind |
   | --- | --- | --- |
   | the downloaded `client_secret_….json`, unchanged | `google-client` | `google-oauth-client` |
   | `google-token.json` | `google-token` | `google-oauth-token` |

3. **Delete both files** (and empty the Recycle Bin). The token file holds a refresh token.
4. Nothing needs a restart: chapd reads the vault when a request arrives. To see that it works before anything is enabled, ask for a test email to an address on the allowlist (step 6) once `mail.send` is on: a card appears only if Google is connected, the scope is there and the account is the one you named.

Where chapd's own account can run commands (a development vault, or a server set up with `chapd vault init` under your account), `chapd connect google -client-file F -delete` signs in and stores both secrets itself, and `chapd connect google status` shows the account, scopes and when the sign-in ends (no secret is printed). `chapd connect google revoke` tells Google to forget the sign-in.

## Step 6: turn on mail (a policy change that you review)

Both ops are `enabled: false` in `internal/policy/data/baseline.yaml`. When you want mail:

1. A change flips `mail.send` to `enabled: true` (and `drive.share` if you took Drive). You review it like code.
2. The project's policy file gets a `google:` block. Only addresses you list can ever receive anything:

   ```yaml
   google:
     mail:
       allow_recipients: ["alice@example.com", "@example.org"]   # an address, or "@domain" for a whole domain you control
     drive:
       allow_recipients: ["alice@example.com"]
       max_role: reader            # reader, commenter or writer; never owner. Default reader.
   ```

   A project with no `google:` block is refused. A project file cannot enable an op by itself.
3. Attachments: chapd takes only a SHA-256 from the agent and reads the bytes from a staging folder it owns (`chapd run -google-attachments-dir <dir>`, files named by their SHA-256). Without that flag, mail goes without attachments.

## What a card shows, and what is refused before a card exists

The card for `mail.send` lists the sending account, every recipient (To, Cc, Bcc), the subject, the body exactly as sent (invisible and look-alike characters are shown as `\u{…}`), each attachment's name and SHA-256, and the **SHA-256 of the finished message**. That hash is of the exact bytes chapd hands to Gmail. If anything differs by one character after you approve, the op fails with `APPROVAL_HASH_MISMATCH` and nothing is sent.

Refused with no card: a recipient off the allowlist (also in Bcc, also a display name or a look-alike address); a body, subject or attachment that holds something shaped like a secret (`REDACTION_BLOCKED`); an attachment that is not staged or whose SHA-256 differs; more than 10 recipients, 5 attachments, 5 MiB per attachment, an executable type; a request for an account Chaperone is not connected as; Google not connected, the grant refused, or the sign-in expired.

For `drive.share`: the file's name must be the name Drive has; the file must not be in the bin and the account must be allowed to share it; recipients must be on the Drive allowlist; the role must be at or under the project's cap; the link visibility is always `restricted`. Drive sends no notification e-mail from Chaperone's share (the file shows under *Shared with me*).

## When Google stops accepting the sign-in

Google ends a refresh token when you remove the app at <https://myaccount.google.com/permissions>, when you change the Google password (for a token with Gmail scopes), after six months unused, past the 7 days of a Testing-mode app, or past the limit of 100 live tokens per account and client.

chapd refreshes the token every six hours, whether or not anything was asked, so you hear about it early. You get an alert (`google-reauth`, through `alerts.ps1` when chapd runs with `-alerts-script`, else a chapd log error), at most once per outage, and every mail and Drive request is refused with "run `chapd connect google` again" until you repeat step 5. A Testing-mode token also raises `google-refresh-expiring` two days before its end. Three failed refreshes in a row that are not a refusal (network, Google down) raise `google-refresh-failing`.

## Troubleshooting

| You see | It means |
| --- | --- |
| `these scopes were not granted` | You unticked a box on the consent page. Run step 5 again and leave every box ticked. |
| `did not return a refresh token` | Google had a grant already and sent none. Remove Chaperone at <https://myaccount.google.com/permissions>, then sign in again. |
| `a "Web application" client` | Step 4 made the wrong type. Create a **Desktop app** client. |
| `WARNING: … ends at …` | The consent screen is in Testing (7-day tokens). Step 3, then sign in again. |
| `the request is for account X but Chaperone is connected as Y` | The card named an account other than the one you signed in with. |
| `Google hasn't verified this app` | Expected. Advanced, then Go to Chaperone (unsafe). |
| `sharing with … was refused` / op `unconfirmed` | Google said no, or the answer was lost. An `unconfirmed` send is **never retried**: look in the Sent folder before asking again. |

## For reviewers: what is tested, and how

Everything runs against a fake Google (`internal/connectors/google/googletest`); no real account or network is used, and the live flow has **not** been run (it needs this runbook). A demo email is replayed in `test/redteam/rt24_google_test.go`: nothing is sent without an approval, an off-list recipient never gets a card, a changed character is `APPROVAL_HASH_MISMATCH`, the hash on the card equals the hash of the bytes Gmail receives, and a revoked grant fails closed with an alert. `mutation_test.go` removes six of those controls one at a time and requires the replay to fail.

`[INFERENCE]` items not checked against the live services: that Gmail adds `Date` and `Message-ID` to a message that has none, that it honours a `Bcc` header and strips it from the delivered copy, and that Google's token response carries `refresh_token_expires_in` for a Testing-mode app (the fake does; the code treats the field as optional, so its absence only loses the early expiry warning, not the fail-closed behaviour).
