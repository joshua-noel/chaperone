package console

import (
	"context"
	"slices"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// registrationAttachment is the authenticator attachment the registration options ask for. Platform narrows the browser
// to the device's own authenticator. Empty leaves it open: the browser then offers the built-in one, a phone (the
// cross-device, "hybrid" prompt) and a hardware security key. User verification and a discoverable credential are
// required either way.
func (c *Console) registrationAttachment() protocol.AuthenticatorAttachment {
	if c.authn == AuthenticatorsAny {
		return ""
	}
	return protocol.Platform
}

// attachmentAllowed reports whether a credential whose authenticator attachment is a may be made or used under
// Config.Authenticators. It is asked twice: at registration with what the browser reported, and at every sign-in and
// approval with what was recorded then, so narrowing the setting also stops a credential made while it was wider.
//
// "" (the browser did not say) passes under both settings: it is what a credential made before the browser reported
// attachments looks like, and under the strict setting the registration options already limited the browser to a
// platform authenticator. The library already turns a value the specification does not define into "", as a browser must;
// anything else that reaches here is refused.
func (c *Console) attachmentAllowed(a protocol.AuthenticatorAttachment) bool {
	switch a {
	case "", protocol.Platform:
		return true
	case protocol.CrossPlatform:
		return c.authn == AuthenticatorsAny
	}
	return false
}

// authnFacts copies what an audit needs to know about a credential's authenticator into an event. Whatever the
// database holds, only the two attachments the specification defines and the known transports come out, so an event
// (a ledger body, a terminal line) never carries free text.
func authnFacts(ev Event, cred *webauthn.Credential) Event {
	ev.Attachment = ""
	if a := cred.Authenticator.Attachment; a == protocol.Platform || a == protocol.CrossPlatform {
		ev.Attachment = string(a)
	}
	ev.Transports = nil
	for _, t := range cleanTransports(cred.Transport) {
		ev.Transports = append(ev.Transports, string(t))
	}
	ev.BackupEligible = cred.Flags.BackupEligible
	return ev
}

// knownTransports are the WebAuthn authenticator transports (the specification's list, without the deprecated
// "cable"). The browser reports them as free text in the registration response, and the library casts whatever
// arrives, so nothing else may be stored or reach a ledger line or a terminal.
var knownTransports = map[protocol.AuthenticatorTransport]bool{
	protocol.USB: true, protocol.NFC: true, protocol.BLE: true, protocol.SmartCard: true,
	protocol.Hybrid: true, protocol.Internal: true,
}

// cleanTransports keeps the known transports, once each, in the order given, and drops everything else.
func cleanTransports(in []protocol.AuthenticatorTransport) []protocol.AuthenticatorTransport {
	out := make([]protocol.AuthenticatorTransport, 0, len(in))
	for _, t := range in {
		if knownTransports[t] && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

// recordedAttachment is the attachment to store for a registration that reported a. Under the wider setting a
// registration that did not say (or said something the library dropped) is recorded as cross-platform, the wider
// kind, so narrowing the setting later also stops it; the strict setting leaves "" as it always did.
func (c *Console) recordedAttachment(a protocol.AuthenticatorAttachment) protocol.AuthenticatorAttachment {
	if a == "" && c.authn == AuthenticatorsAny {
		return protocol.CrossPlatform
	}
	return a
}

// RefusedCredentials counts the live credentials of enabled approvers that the current setting refuses (one enrolled
// while it said "any", under "platform" now), and those it still allows. refused > 0 with usable == 0 is a full lockout:
// nobody can sign in or approve at this console until the setting is wide again. chapd logs both cases at start.
func (c *Console) RefusedCredentials(ctx context.Context) (refused, usable int, err error) {
	var total int
	err = c.db.SQL().QueryRowContext(ctx,
		`SELECT count(*), coalesce(sum(CASE WHEN c.attachment NOT IN ('', 'platform') THEN 1 ELSE 0 END), 0)
		 FROM credentials c JOIN approvers a ON a.id = c.approver_id
		 WHERE c.revoked_at IS NULL AND a.disabled_at IS NULL`).Scan(&total, &refused)
	if err != nil {
		return 0, 0, err
	}
	if c.authn == AuthenticatorsAny {
		return 0, total, nil
	}
	return refused, total - refused, nil
}
