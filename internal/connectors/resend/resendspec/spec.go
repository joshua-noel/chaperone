// Package resendspec declares the operations of the Resend connector once: the
// facts that the catalog, the params schema, the `chap` command and the adapter
// binding are made from. It holds no behaviour.
//
// The connector has two operations.
//
//   - mail.status reads the delivery status of one sent message. It is a new
//     operation: it is in [Connector], so its manual entry and its params schema
//     are generated from [MailStatus].
//   - mail.send is NOT new. It is the operation the Google connector already
//     serves (Gmail), and the target tells the two apart: `target.adapter` is
//     `google` for Gmail and `resend` for Resend, the way `issue.comment` is one
//     name for GitHub and Linear. The catalog has one entry for a name, written
//     by hand, with its class, its card and its baseline rule. [MailSend] is
//     Resend's side of that name. It is not in [Connector], so no region is
//     written from it, and it is in [Served], so the adapter is bound to it and
//     the conformance suite runs over it. A test in package declared checks that
//     it agrees with the catalog entry, the baseline and the class pin.
//
// The package imports only the kit, so the `chap` client can use it without
// linking the daemon's code.
package resendspec

import "github.com/joshua-noel/chaperone/internal/connectors/kit"

// Adapter is `target.adapter` of every operation of the connector.
const Adapter = "resend"

// The op kinds.
const (
	NameSend   = "mail.send"
	NameStatus = "mail.status"
)

// The shapes of a target ref. The ref of mail.send is the sender: a bare,
// lower-case ASCII address, the same shape the Google connector and the policy
// accept. The ref of mail.status is the id Resend gave the message, a UUID in
// lower case.
const (
	AddressPattern   = `^[a-z0-9][a-z0-9._+-]{0,63}@[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`
	StatusRefPattern = `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
)

// Limits of one message. They are the limits of the Google connector's
// mail.send (a test in package declared checks that they agree): one name has
// one set of limits, whichever connector the target picks. The policy's
// resend.max_recipients lowers the recipient count further.
const (
	MaxRecipients   = 10
	MaxAddressBytes = 254
	MaxSubjectBytes = 200
	MaxBodyBytes    = 64 << 10
)

// Connector is the connector's declaration, from which the generated regions of
// api/ are written. mail.send is not in it: see [MailSend] and [Served].
var Connector = kit.Connector{
	Name: "resend",
	Ops:  []kit.Op{MailStatus},
}

// Served is every operation the Resend adapters implement: [Connector] and
// Resend's side of mail.send. [kit.Bind] pairs the adapters with it, and the
// conformance suite runs over it.
var Served = kit.Connector{
	Name: "resend",
	Ops:  []kit.Op{MailSend, MailStatus},
}

// MailSend is Resend's side of mail.send. Its name, class, reversibility,
// summary, usage and rate are the catalog's, written by hand for the Google
// connector; a test in package declared checks that they agree.
//
// The params are the Google connector's, less `attachments`: this version sends
// plain text only, with no attachment, no HTML, no reply-to, no scheduled send,
// no template, no tag and no header. A param that is not declared is refused.
var MailSend = kit.Op{
	Name:          NameSend,
	Class:         kit.High,
	Reversibility: kit.Irreversible,
	Summary:       "Send one email to allowlisted recipients after approval.",
	Usage:         "chap mail send --from <account> --to <a> --subject <s> --body-file <f> [--via resend]",
	RatePerMinute: 3,
	Doc:           "Resend side of `mail.send`. Target is `{adapter: resend, ref: \"<sender address>\"}`; the sender must be one of the project's `resend.senders`. `to` is required; `cc` and `bcc` are optional; every recipient must be on the project's `resend.allow_recipients`, and the total must not pass `resend.max_recipients`. `subject` and `body` are plain text. No attachment, no HTML, no reply-to, no scheduled send, no template, no tag and no header can be sent.",
	Target:        kit.Target{Adapter: Adapter},
	Params: []kit.Param{
		{Name: "to", Kind: kit.List, Required: true, MinItems: 1, MaxItems: MaxRecipients, MaxLength: MaxAddressBytes},
		{Name: "cc", Kind: kit.List, MaxItems: MaxRecipients, MaxLength: MaxAddressBytes},
		{Name: "bcc", Kind: kit.List, MaxItems: MaxRecipients, MaxLength: MaxAddressBytes},
		{Name: "subject", Kind: kit.String, Required: true, MinLength: 1, MaxLength: MaxSubjectBytes},
		{Name: "body", Kind: kit.Text, Required: true, MinLength: 1, MaxLength: MaxBodyBytes},
	},
	CLI: kit.CLI{Custom: true},
}

// MailStatus is mail.status.
var MailStatus = kit.Op{
	Name:          NameStatus,
	Class:         kit.Routine,
	Reversibility: kit.Reversible,
	Summary:       "Read the delivery status of one email sent through Resend.",
	Usage:         "chap mail status <email-id>",
	RatePerMinute: 12,
	Doc:           "Target is `{adapter: resend, ref: \"<email id>\"}`, the `message_id` that `mail.send` returned (a UUID). No params. Returns the id, the last event Resend recorded (one of a closed list of words, else `other`) and the time Resend made the record. The email must have been sent from one of the project's `resend.senders`; any other email is refused and nothing about it is shown. Resend's text (the subject, the body, the addresses, its error messages) is never returned. Needs a separate, optional vault secret with Resend's `full_access` permission, because Resend lets a `sending_access` key send and nothing else.",
	Target: kit.Target{
		Adapter:    Adapter,
		Pattern:    StatusRefPattern,
		Why:        "the email id must be a UUID such as 49a3999c-0ce1-4ea6-ab68-afcd6dc2e794",
		Positional: "email-id",
	},
	CLI: kit.CLI{Summary: "read the delivery status of one email sent through Resend"},
}
