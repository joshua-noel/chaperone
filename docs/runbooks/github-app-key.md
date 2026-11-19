# Runbook: rotate the GitHub App key

The App `chaperone-app` signs a short JWT with its private key to get one-hour installation tokens (ADR-002). The key lives in the vault as secret `github-app-key`; `chapd` decrypts and parses it **on every call**, so a rotation needs no restart. Rotation is the critical op `secrets.write`: you paste the new key in the console and approve its card with Windows Hello (ADR-003, item 5).

**Order matters: keep the old key on GitHub until the new one is proven.** The console does not check that a pasted value is a valid PEM, so a bad paste would break every GitHub call until you rotate again; the old key is your way back.

**Status of the scratch run** (see "What was and was not executed"): the form, the request and the CRITICAL card were executed against a real wired `chapd` in a browser; the Hello approval was **not completed**, so the store, the changed fingerprint and the GitHub check below are written from the code and tests, not from a log.

## Steps

1. **Make a new key.** GitHub, Settings, Developer settings, GitHub Apps, `chaperone-app`, "Generate a private key". A `.pem` downloads. The App may hold two keys at once; do not delete the old one.
2. **Open the console** at `http://localhost:55398`, sign in with your passkey, **Secrets**.
3. **Request the rotation.** Action "Rotate an existing secret", Secret id `github-app-key`, Value: the whole PEM text (from `-----BEGIN` to `-----END`), then "Request approval". `chapd` refuses a value shorter than the redactor's minimum, and holds the value in memory only.
4. **Read the card.** It is labelled CRITICAL and says that the requester wants to store a secret named github-app-key (the console asks on your behalf). Under WHAT CHANGES it lists `Secret: vault / github-app-key`; under CHECKS (`vault.target`) it gives the **fingerprint of the key being replaced**. The card never shows the new value, only a keyed commitment. Check the fingerprint against `chapd vault list` (elevated, as the service account) or the table on the Secrets page.
5. **Approve with your passkey.** That is the only step: the approval stores the value in the same request, and the answer says "Secret stored" with the new fingerprint (there is no commit button). If `chapd` restarts or the card expires (30 minutes) before you approve, the value is gone: paste it again. If the answer says the value could not be stored, it says why. When it says the value is still held, open **Secrets** (the "Try again" button is only there, on the request, not on the Approvals page or the phone page) and press **Try again**; the same approval is used, so Windows Hello is not asked again.
6. **Check.** The Secrets page shows the secret's `Rotated` time and a **new fingerprint**. Then prove the key works end to end, from a normal window:

   ```powershell
   & 'C:\Program Files\Chaperone\chap.exe' pr merge <n> --head <sha> --project storefront --dry-run
   ```

   It must get as far as the policy checks (`allow`, or a verdict such as `CI_RED`). A `GitHub` or key error means the new key is bad: **rotate back to the old key now** (same steps, old PEM; you still hold the old file or the old key is still valid on GitHub).
7. **Delete the old key on GitHub** (the App's page, delete the old key entry), **and delete the downloaded `.pem` files** you pasted from (they are the secret).
8. Write down the date of the rotation.

## If the old key may have leaked

Do step 1, 3 to 6 **and 7 immediately**: the old key signs App JWTs for anyone who holds it, and the App's installation tokens are limited to the repositories and permissions of the installation, so also look at GitHub's audit log for the App.

## What was and was not executed

Executed in a scratch setup (real `chapd` built from the main branch, scratch database and vault with real DPAPI, a scratch `ntfy-topic` and `github-app-key`; Edge driven through CDP): sign-in page and nav, the Secrets table (names, kinds, fingerprints, `Last used`), the rotate form, the CRITICAL card with its checks and display hash, the `secret write requested` log line. Not completed: the Windows Hello approval. A Chrome DevTools virtual authenticator enrolled the passkey and passed the `chapd enroll` sign-in, but the console reported "Cancelled, or Windows Hello did not verify you" for the approval, so the store and the new fingerprint were not observed. The same flow, with a software authenticator, is covered by `TestSecretRotate` in `internal/console/screens_secrets_test.go`. Not executed: anything at GitHub.
