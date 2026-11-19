package console

import (
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

// authnFacts copies what an audit needs to know about a credential's authenticator into an event.
func authnFacts(ev Event, cred *webauthn.Credential) Event {
	ev.Attachment = string(cred.Authenticator.Attachment)
	ev.Transports = nil
	for _, t := range cred.Transport {
		ev.Transports = append(ev.Transports, string(t))
	}
	ev.BackupEligible = cred.Flags.BackupEligible
	return ev
}
