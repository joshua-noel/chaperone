# Runbook: rotate the ntfy topic

The topic is the only secret between the internet and your phone's wake-up: ntfy has no sign-up, so anyone who knows the topic can publish to it and read what is published (ADR-004). A push carries only the op kind, the project, 8 hex characters of the op hash, the expiry and a count, never parameters or a link, so a leaked topic gives spam and a read of those few fields, not authority. Rotate it when it may have leaked (a screenshot, a shared phone), when you change phone, or on a schedule you choose.

`chapd` reads the topic from a **vault secret** whose id you give with `-ntfy-topic-secret` (and the server with `-ntfy-url`, default `https://ntfy.sh`). It reads it **when it starts**, so a rotation ends with a `chapd` restart. There is no command that generates a topic: you make a random 32-character lower-case hex string yourself.

**Status of the scratch run:** the setup, the rotate request and the CRITICAL card were executed against a wired `chapd` with a fake ntfy server. The Hello approval was **not completed** (see [`github-app-key.md`](github-app-key.md), "What was and was not executed"), so the stored value, the restart and the first push to the new topic are not in a log.

## Steps

1. **Make the new topic** (32 lower-case hex characters, 128 bits; `chapd` refuses any other form):

   ```powershell
   -join ((1..16) | ForEach-Object { '{0:x2}' -f (Get-Random -Maximum 256) })
   ```

   `Get-Random` is not a cryptographic generator; for a stronger one use `[Convert]::ToHexString` over `[Security.Cryptography.RandomNumberGenerator]::GetBytes(16)` in PowerShell 7, or `openssl rand -hex 16`.
2. **Rotate the secret in the console** (same form as the App key): Secrets, "Rotate an existing secret", id = the id `chapd` was started with (`ntfy-topic` in the scratch run), value = the new topic, "Request approval". The CRITICAL card names the secret and the fingerprint of the old value. Approve with your passkey: the approval stores the new value by itself, so there is no commit button to press (if the answer says it could not be stored, open Secrets and press Try again).
3. **Restart `chapd`** (elevated): `Restart-Service chapd`. The new topic is read at start; until then pushes still go to the old one.
4. **Subscribe the phone to the new topic**: in the ntfy app, add the new topic (the app has no way to read it from `chapd`; type or paste it) and **remove the old subscription**.
5. **Prove it.** Ask for any approval card (for example a rotation request on the Secrets page and cancel it). The phone must wake with the op kind and a short hash and no link. In the scratch run the fake ntfy server records each publish; the topic appears in the request **body** (`{"topic": ...}`), never in a URL or a log line.
6. Delete any file or note you kept the new topic in.

## What a rotation does not do

- The old topic is not revoked anywhere: ntfy has none to revoke. Anyone who has it can still publish to it, which only matters if you still subscribe to it. Remove the old subscription (step 4).
- Ledger anchors that go to the phone use the same topic and secret; they follow the rotation.
- If `chapd` has no `-ntfy-topic-secret`, there is no push and nothing to rotate: approvals still work on the server.
