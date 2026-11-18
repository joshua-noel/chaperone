// Package google holds Chaperone's two Google connectors (ticket L1-16): the
// ops `mail.send` (Gmail API, scope gmail.send) and `drive.share` (Drive API
// permissions), and the OAuth client they share.
//
// # What an agent can and cannot do
//
// Both ops are class high, tier approve, and **disabled in the baseline
// policy**. Turning them on is a policy pull request; the project file's
// `google:` block then supplies the recipient allowlist (and the Drive role
// cap). An agent never holds a Google credential: the OAuth client secret and
// the token set sit in the vault, and only the adapters use them, through
// [Source].
//
// # The path of one email
//
//  1. Check (at submit, at the approval request, and again at release) parses
//     the params strictly, refuses any recipient that is not on the project's
//     allowlist, refuses a body, subject or attachment that holds a secret
//     (REDACTION_BLOCKED), re-reads every attachment from the content-addressed
//     [AttachmentStore] and compares its SHA-256 with the one in the params,
//     checks that Google is connected with the gmail.send scope and as the
//     account the request names, and renders the message. **No approval card
//     exists for a request Check refuses.**
//  2. The card shows the params as the approver must see them (ADR-004
//     section 3: every recipient, the subject, the full body, the attachment
//     names and SHA-256s) and the adapter's evidence: the SHA-256 of the
//     rendered MIME message.
//  3. The approval is bound to the op hash, which covers every param. One
//     changed character is APPROVAL_HASH_MISMATCH.
//  4. Execute renders again from the stored request. The MIME bytes are a pure
//     function of the params and the attachment bytes (no Date, no Message-ID;
//     Gmail adds them), so the bytes sent hash to the number on the card.
//     A send that gets no clear answer is `unconfirmed` and is never retried.
//
// # Tokens
//
// [Connect] runs the loopback + PKCE flow (RFC 8252, RFC 7636) for a Desktop
// app client. The refresh token and the client secret live in the vault ids
// [ClientSecretID] and [TokenSecretID]; [Source] refreshes the access token
// and writes the new set back. A refresh that Google refuses with
// invalid_grant (revoked, expired, a Testing-mode token past its 7 days)
// raises an alert and every Check from then on refuses with a message that
// says to run `chapd connect google`; it is never a silent failure.
package google
