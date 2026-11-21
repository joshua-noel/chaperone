package main

import (
	"fmt"

	"github.com/joshua-noel/chaperone/internal/connectors/google"
	"github.com/joshua-noel/chaperone/internal/connectors/resend"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
)

// This file wires the Resend connector: the Resend side of `mail.send`. The op is off
// in the baseline. mail.send is the operation the Google connector already serves, so
// the two adapters go behind one ops.ByTarget and the request's target.adapter
// (`google` or `resend`) picks. The Resend side refuses a project whose policy file has
// no valid `resend:` block, so turning the name on does not turn Resend on. The
// connector reads one vault secret (`resend-api-key`) and calls one route. The
// operator's steps (the API key in the vault, the project's `resend:` block, the policy
// change) are in docs/runbooks/resend.md.

// installResend adds the Resend adapter when the vault is open. It must run after
// installGoogle: mail.send is then the Gmail adapter, and the Resend one joins it.
func (a *App) installResend(ads map[string]ops.Adapter) error {
	if a.vault == nil {
		return nil
	}
	cl, err := resend.NewClient(resend.ClientConfig{
		SendKey:  resend.VaultCredential(a.vault),
		Registry: a.Reg,
		HTTP:     a.cfg.resendHTTP,
	})
	if err != nil {
		return err
	}
	pol := func(project string) *policy.Resend {
		eff := a.Policy.For(project)
		if eff.Invalid != nil {
			return nil
		}
		return eff.Resend
	}
	set, err := resend.Adapters(resend.Config{Client: cl, Policy: pol, Redactor: a.Reg})
	if err != nil {
		return err
	}
	// One name, two connectors: Gmail's mail.send (target google) and Resend's (target
	// resend). The request's target.adapter picks. A name that another adapter holds that
	// is not Gmail's is a wiring mistake, and chapd stops.
	by := ops.ByTarget{resend.AdapterName: set[resend.OpSend]}
	if prev, taken := ads[resend.OpSend]; taken {
		if _, isGmail := prev.(*google.Gmail); !isGmail {
			return fmt.Errorf("chapd: op %s already has an adapter that is not Gmail's; the Resend connector would replace it", resend.OpSend)
		}
		by["google"] = prev
	}
	ads[resend.OpSend] = by
	return nil
}
