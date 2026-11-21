# Runbook: send mail through Resend with Chaperone

You do this once, from your own account. It lets the orchestrator (the lead agent that coordinates the other agents) send a plain-text email through Resend's API, after **you approve each message**. It does not turn anything on: `mail.send` stays off in the baseline policy until a policy change turns it on (step 4).

**Status. This connector was tested only against a fake Resend** (`internal/connectors/resend/resendtest`). It never talked to the real service. The fake is written from Resend's documentation (the pages are listed at the end), not from a run. Where the documentation does not say, this page says so. Do the first real send to an address of your own.

## One name, two connectors

`mail.send` is not a new operation. It is the operation that `internal/connectors/google` already serves for Gmail. The request's **target** picks the service:

| `target.adapter` | Service | `target.ref` |
| --- | --- | --- |
| `google` | Gmail | the Google account that sends |
| `resend` | Resend | the sender address, one of the project's `resend.senders` |

The name, the class (**high**, irreversible), the approval card and the baseline rule are the same for both. One line in the baseline turns the name on, so turning it on enables **both** connectors in principle. Each one refuses a project whose policy file has no valid block of its own (`google:` or `resend:`). Turn the name on only after you have decided which blocks exist.

## What you are agreeing to

| | |
| --- | --- |
| **What the orchestrator can do** | Send one plain-text email: from a sender you list, to people you list, with a subject up to 200 bytes and a body up to 64 KiB. Each message needs your approval, signed with your passkey. Nothing else. |
| **What it cannot do** | Attach a file, send HTML, set a reply-to address, schedule a send, use a template, add tags or custom headers, or use Resend's batch endpoint. The connector never sets those fields of Resend's send call, and an agent has no way to set them: a request that names one is refused. |
| **What you sign** | The card shows the sender, every recipient (to, cc and bcc), the subject and the whole body, exactly as they will be sent. It also shows evidence: the number of recipients, the SHA-256 of the body and the SHA-256 of the exact JSON that goes to Resend. When the approved message is released, `chapd` makes that evidence again and **refuses to send if it is not the same**, so a message that changed after you signed does not go. |
| **Who may receive it** | Only addresses and domains in the project's `resend.allow_recipients`. A listed address is matched exactly. A listed domain (`@team.example.com`) matches that whole domain and **not** a subdomain of it. The total of to, cc and bcc is at most `resend.max_recipients` (5 when the block does not say; 10 at most). A refusal says which recipient failed by its place in the list, and never repeats an address. |
| **Who may ask** | The orchestrator token only. The `host-interim` profile lists `mail.send`, and the Gmail side accepts a run that holds it. The Resend side does **not**: it refuses a run and a custom key. |
| **Where the credential lives** | The vault. `chapd` reads the key for each call, registers it with the redaction check so it cannot reach a log, the ledger or a result, and sends it in one header to one fixed address, `https://api.resend.com`. No policy file, flag or request can change that address. A redirect is never followed. The orchestrator and every agent never hold the key. |
| **What is untrusted** | Whatever Resend answers. The only text of Resend's that comes back is the email id, cleaned of control characters, capped at 64 bytes and withheld if it looks like a secret. Resend's error messages are **never** returned: an error shows the HTTP status and, when it is one of Resend's documented error types, that word. |
| **What it holds, and what it calls** | **One secret:** the sending key, `resend-api-key`. **One route:** `POST /emails`. There is no code path that sends another request to Resend, and no second key. Two tests fix this: one shows that the client has no method but `Send` and a readiness check, and that a request always goes to `POST /emails`; the other records the vault names the connector reads and finds only `resend-api-key`. |

## Step 1: the domain in Resend (browser)

1. Add and verify a sending domain in Resend (**Domains**). Resend recommends a **subdomain** such as `updates.example.com` for transactional mail, because it keeps the reputation apart.
2. Open the domain's **Configuration** tab and check that **open tracking and click tracking are off**. Resend says they are off by default and that the setting applies to all mail from the domain. **check:** the documentation does not say whether tracking touches a plain-text message, so keep both off.
3. Decide the sender addresses, for example `alerts@updates.example.com`. Resend says any address at a verified domain works without more set-up.

## Step 2: the sending key (browser)

1. **API keys**, **Create API key**. Name it `chaperone`.
2. **Permission: Sending access.** Do **not** choose Full access.
3. **Domain: the one domain from step 1.** Resend restricts a `sending_access` key to send only from that domain. Pick it; do not leave it on "all domains".
4. Press **Add**. Resend shows the key **once** and cannot show it again. Keep the page open: you copy it into the console in step 3. Do not paste it into chat, a file or a ticket.

What `sending_access` means, from Resend: the key "can only send emails". Anything else answers 401 `restricted_api_key`. So the key cannot read, list or delete anything, and cannot create another key.

## Step 3: put the key in the vault (console, no file)

In the Chaperone console open **Secrets**, then **Import a new secret**:

| Id | Kind | Value |
| --- | --- | --- |
| `resend-api-key` | `resend-api-key` | the sending key from step 2 |

That is the only secret the connector reads. The import is the critical op `secrets.write`: press **Request approval**, read the card (it names the id and the kind, never the value) and approve it with your passkey. A value saved with a trailing newline is fine. Then close the Resend page and clear the clipboard. `chapd` reads the secret when it needs it, so no restart is needed.


## Step 4: the policy change

One pull request, reviewed like code:

1. **`internal/policy/data/baseline.yaml`:** change `enabled: false` to `enabled: true` on `mail.send` (this also turns the name on for Gmail, see above). Only the baseline can turn an op on.
2. **`policy/storefront.yaml`:** add the block:

   ```yaml
   resend:
     senders: [alerts@updates.example.com]        # exact bare lower-case addresses; at least one
     allow_recipients:                            # an exact address, or @domain for the whole domain; at least one
       - ops@example.com
       - "@team.example.com"
     max_recipients: 3                            # to + cc + bcc together; leave it out for 5; at most 10
   ```

   Prefer exact addresses. An `@domain` entry lets the orchestrator write to **everyone** at that domain. **Never list the domain of a mailbox provider** (`gmail.com`, `outlook.com` and the like): that is every person who has an account there. `chapd` refuses, when the file is loaded, an `@domain` entry for a short built-in list of the largest ones (`gmail.com`, `googlemail.com`, `outlook.com`, `hotmail.com`, `live.com`, `yahoo.com`, `icloud.com`, `me.com`, `proton.me`, `protonmail.com`, `aol.com`, `gmx.com`, `yandex.com`, `mail.com`), and says that an exact address is needed. The list is a guard against the common mistake. It is not complete: a smaller provider is not on it, so the rule is yours to keep. There is no other wildcard: `*`, `@*` and `@com` are refused too.

   A mistake in the block turns off the **Resend side only**: Gmail, the other ops and the other blocks of the file keep working, `chapd` says so once at start (a `Warn` line that names the project, the file and the field), and the Resend ops refuse with the same reason. A key the file format does not know (a typo, or `html:`) refuses the whole file, as for every project file.
3. After the merge, deploy as usual. The project file is re-read on change without a restart. The baseline change comes with the new `chapd`.
4. **Give the orchestrator the op.** Re-issue the orchestrator token with it added (see [orchestrator-token.md](orchestrator-token.md), keep the ops it already has), for example `-ops "pr.merge,pr.open,pr.update,health,logs,mail.send"`.

## Step 5: send one message to yourself

In a normal window, with the orchestrator's token:

```powershell
$chap = 'C:\Program Files\Chaperone\chap.exe'
'Test from Chaperone. Nothing to do.' | & $chap mail send --via resend --from alerts@updates.example.com --to you@example.com --subject 'Chaperone test' --body-file - --project storefront
```

`chap` prints the approval request. Open the console, read the card, check that the sender, the recipient, the subject and the body are what you meant, and approve it. The message goes once. `chap op show <id>` shows the result: the `message_id` is what Resend answered.

| You see | It means | Do |
| --- | --- | --- |
| `its policy file has no valid resend: block` | step 4 point 2 was not done, or the block is wrong | fix the file |
| `allow_recipients entry "@gmail.com" lists a whole public mailbox domain` | the block lists a mailbox provider's domain | list the exact addresses |
| `sender_listed`, `recipients_allowlisted` or `recipient_cap` | the policy does not list it | change the request or, by a policy change, the block |
| `the vault has no resend-api-key` | step 3 was not done, or the id is misspelled | repeat step 3 |
| `Resend refused the API key (HTTP 401 ...)` or `403` | the key is wrong, deleted or inactive; or the sender is not on the key's domain | check steps 1 and 2 |
| `HTTP 403 (validation_error)` | most likely the sender's domain is not the key's domain, or the domain is not verified | check steps 1 and 2 |
| `Resend's rate or quota limit is used up` | see "Limits" below | wait; nothing was sent |
| `the message may or may not have been sent` | the answer was lost (a timeout, a cut connection or an HTTP 5xx) | look in Resend's **Emails** page for the message **before** you ask again |
| `the message to be sent is not the message that was approved` | the evidence at release differs from the card | ask again; a new card is made |

### Why there is no delivery status

Whether a message was delivered, bounced or opened is read in **Resend's dashboard** (the **Emails** page), not through Chaperone. This is on purpose. Reading an email is `GET /emails/{id}`, and Resend gives a `sending_access` key **no read at all**: its error page says a restricted key answers 401 `restricted_api_key` ("This API key is restricted to only send emails") and that the key needs Full access "to perform actions other than sending emails". A Full access key "can create, delete, get, and update any resource" in the account, sends from any domain, and cannot be limited to one domain. Holding that in the vault for one status word is more than the status is worth, so a status operation (`mail.status`) and a second vault secret were built, tested, and then **removed**. The connector holds one key that can do one thing.

## Repeat safety, and what Resend's window means

Resend accepts an `Idempotency-Key` header on `POST /emails`. `chapd` sends `chaperone-mail-send/` and the execution id of the operation. Resend's documentation says:

- A key has 1 to 256 characters. (Ours is 20 characters of prefix and at most 200 of execution id.)
- Resend "checks whether an email with the same idempotency key has already been sent in the last 24 hours". The same request again "will give the same response, without actually sending the email again".
- **Keys are kept for 24 hours.** After that Resend has forgotten the key, and the same request would send the message again.
- The same key with another body answers 409 `invalid_idempotent_request`. The same key while another request with it is running answers 409 `concurrent_idempotent_requests`. `chapd` treats both as **unconfirmed**, never as failed, because a message may have gone.

What this protects: `chapd` runs an `Execute` at most once for an execution id, and the adapter never retries. After a crash, `chapd` marks the operation unconfirmed and does not run it again. So the key matters only if a later path repeats an execution. If that path runs within 24 hours, the key stops a second message. **After 24 hours it does not**: such a path would send a second message. No shipped code does that. A test (`TestAfterTheKeyExpiresARepeatSendsAgain`) fixes the behaviour against the fake, so a change on either side shows.

## Limits (from Resend)

- **Rate:** 10 requests per second per team, across all API keys. Over it, Resend answers 429 `rate_limit_exceeded` with `ratelimit-*` and `retry-after` headers. `chapd` reads `retry-after` for its message and does not retry. The baseline allows 3 `mail.send` a minute, far below that.
- **Quota:** a daily quota (free plan only, resets at midnight UTC) and a monthly quota. Over them, 429 `daily_quota_exceeded` or `monthly_quota_exceeded`. Both sent and received mail count.
- **Recipients:** Resend's page says `to` takes at most 50. This connector allows at most 10 in all, and the policy lowers it.

## Before you turn it on

Check each one. The connector has never run against Resend.

- [ ] The sending key has **Sending access** and a **domain** (step 2). Try a send **from another domain** with it, in the Resend API, and see it refused. The documentation says the restriction exists; this connector's tests only model it.
- [ ] Open and click tracking are **off** on the domain (step 1).
- [ ] The documentation does not show the JSON body of an error. `chapd` reads only the field `name` from it and falls back to the HTTP status. **check:** that an error from the real service shows an HTTP status in the message, and, in parentheses, a word of the documented list when the type is one of them.
- [ ] You read `allow_recipients` as "everyone in this list may be written to by an agent", and each entry is one you would accept that for.
- [ ] You know that the delivery status is read in Resend's dashboard, not through Chaperone.
- [ ] You know that turning `mail.send` on turns on the name for Gmail as well.
- [ ] Your alerts for a failed or unconfirmed op work (an unconfirmed send needs a person to look in Resend).
- [ ] Rotation: Resend keys never expire by themselves. Make a new key with the same permission and domain, import it with **Rotate an existing secret**, check the **Logs** page of Resend for the new key, then delete the old one. Delete a key that has not been used in 30 days.

## If something goes wrong

- A message went that should not have: Resend cannot recall mail. Delete the key in Resend (**API keys**) at once, turn `mail.send` off by a policy change, and read the ledger (`chap ledger verify`, then the events of the op).
- The key leaked: delete it in Resend, make a new one (step 2), and import it again (step 4).
- Stop the connector without a deploy: delete the `resend:` block from the project file. The Resend side then refuses the project.

## What was tested, and what was not

**Tested, against a fake Resend (`go test ./internal/connectors/resend/...` and `./cmd/chapd`):**

- the conformance suite for both operations, with no `Known` entry;
- that the body sent to Resend holds `from`, `to`, `subject`, `text` and `cc` and `bcc` when used, and nothing else;
- the `Idempotency-Key`: one execution is one message, two executions are two, a lost answer is `unconfirmed` and a repeat does not double it, a 409 is `unconfirmed`, and after the key expires a repeat sends again;
- that the approved evidence binds the sender, recipients, subject and body, in the unit tests and through chapd's real approval engine, with a Hello stand-in;
- that the client has no method but `Send` and a readiness check, that every request is `POST /emails`, and that only the vault name `resend-api-key` is read;
- that the key reaches no result, log or ledger, that a careless service that repeats the key in its errors is not echoed, and that no redirect is followed;
- the policy block: each mistake turns off the Resend side only, and chapd warns once.

**Not tested:** anything against the real Resend; a real passkey; that the real service answers as the fake does (the error body, the time format, the effect of a domain restriction); mail landing in an inbox; Resend's behaviour at the end of the 24 hours.

## Facts and where they come from

Read on 2026-11-21 from Resend's documentation (`resend.com/docs`), the pages named here:

- **API Reference, Introduction:** the base URL `https://api.resend.com`, HTTPS only; `Authorization: Bearer`; a request without a `User-Agent` is refused with 403 (`chapd` sends `chapd-resend`); the status codes; 10 requests per second per team.
- **API Reference, Send Email:** `POST /emails`; the answer `{"id": ...}`; `from`, `to` (max 50), `subject`, `bcc`, `cc`, `text`, `html`, `attachments`, `tags`, `headers`, `template`, scheduling and reply-to fields (the ones this connector never sets); the `Idempotency-Key` header, "expire after 24 hours", at most 256 characters.
- **API Reference, Retrieve Sent Email:** `GET /emails/{id}`, which the connector does not call. It is read here only to say why: a `sending_access` key cannot make this call (see "Why there is no delivery status").
- **Dashboard, Idempotency Keys:** the 24 hours, "the same response, without actually sending the email again", the 256 characters, a UUID or an entity-based key.
- **API Reference, Errors:** the error types and their statuses used here (`restricted_api_key` 401, `validation_error` 400, 401 and 403, `invalid_idempotency_key` 400, `invalid_idempotent_request` and `concurrent_idempotent_requests` 409, `rate_limit_exceeded`, `daily_quota_exceeded` and `monthly_quota_exceeded` 429, `application_error` 500, `service_unavailable` 503). The page lists the type, the status and the message. It does not show the JSON body.
- **API Reference, Usage Limits:** the rate limit, its headers, the quotas.
- **API Reference, Create API key** and **Dashboard, Manage API keys:** the permissions: `full_access` "can create, delete, get, and update any resource"; `sending_access` "can only send emails" (with Inboxes calls aside); a domain restriction that is "only used when the `permission` is set to `sending_access`"; the key value is shown once; permission and domain are edited in the dashboard.
- **Knowledge base, How to handle API keys:** keys do not expire; rotate at least every 90 days; delete a key unused for 30 days.
- **Dashboard, Verified Domains** and **Open and Click Tracking:** subdomains; tracking is off by default and is a setting of the domain.
