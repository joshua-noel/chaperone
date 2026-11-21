// Package resendspec declares the one operation of the Resend connector: the Resend
// side of `mail.send`. It holds no behaviour.
//
// mail.send is NOT new. It is the operation the Google connector already serves
// (Gmail), and the target tells the two apart: `target.adapter` is `google` for
// Gmail and `resend` for Resend, the way `issue.comment` is one name for GitHub and
// Linear. The catalog has one entry for a name, written by hand, with its class, its
// card and its baseline rule. [MailSend] is Resend's side of that name. It is in
// [Served], so the adapter is bound to it and the conformance suite runs over it. It
// is in no list that the generator reads, so no region is written from it. A test in
// package declared checks that it agrees with the catalog entry, the baseline and the
// class pin.
//
// The connector has no operation that reads. Resend lets a key that can only send
// read nothing, so a read would need a key that can do anything in the account; see
// docs/runbooks/resend.md.
//
// The package imports only the kit, so the `chap` client can use it without linking
// the daemon's code.
package resendspec

import "github.com/joshua-noel/chaperone/internal/connectors/kit"

// Adapter is `target.adapter` of the operation.
const Adapter = "resend"

// NameSend is the op kind.
const NameSend = "mail.send"

// AddressPattern is the shape of the target ref of mail.send, the sender: a bare,
// lower-case ASCII address, the same shape the Google connector and the policy
// accept.
const AddressPattern = `^[a-z0-9][a-z0-9._+-]{0,63}@[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`

// Limits of one message. They are the limits of the Google connector's mail.send (a
// test in package declared checks that they agree): one name has one set of limits,
// whichever connector the target picks. The policy's resend.max_recipients lowers the
// recipient count further.
const (
	MaxRecipients   = 10
	MaxAddressBytes = 254
	MaxSubjectBytes = 200
	MaxBodyBytes    = 64 << 10
)

// Served is every operation the Resend adapters implement. [kit.Bind] pairs the
// adapters with it, and the conformance suite runs over it.
var Served = kit.Connector{
	Name: "resend",
	Ops:  []kit.Op{MailSend},
}

// MailSend is Resend's side of mail.send. Its name, class, reversibility, summary,
// usage and rate are the catalog's, written by hand for the Google connector; a test
// in package declared checks that they agree.
//
// The params are the Google connector's, less `attachments`: this version sends plain
// text only, with no attachment, no HTML, no reply-to, no scheduled send, no template,
// no tag and no header. A param that is not declared is refused.
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
