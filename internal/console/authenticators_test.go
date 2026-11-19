package console

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/approvals"
)

// ADR-004 amendment 15: which kinds of authenticator may be enrolled and approve. A hardware security key and a
// phone used through the browser's cross-device prompt report "cross-platform"; Windows Hello and Touch ID report
// "platform". User verification is required of every kind, whatever the setting.

func anyRig(t *testing.T) *rig {
	return newRigCfg(t, func(c *Config) { c.Authenticators = AuthenticatorsAny })
}

// roaming is a software security key: it reports cross-platform and USB, and does user verification (a PIN).
func roaming(t *testing.T) *authenticator {
	a := newAuthenticator(t, "localhost")
	a.attachment, a.transports = "cross-platform", []string{"usb"}
	return a
}

// enrolAs registers a ready-made authenticator, as a browser would after the options came back.
func (b *browser) enrolAs(token string, a *authenticator, o opts) (int, map[string]json.RawMessage) {
	b.t.Helper()
	req, _ := json.Marshal(map[string]string{"token": token, "name": "operator", "label": "Key"})
	cer, options := b.begin("/enroll/begin", req)
	return b.post("/enroll/finish", a.create(options, b.origin, o), cer)
}

func credRow(t *testing.T, r *rig) (attachment, transports string, backupEligible bool) {
	t.Helper()
	if err := r.db.SQL().QueryRow(`SELECT attachment, transports, backup_eligible FROM credentials ORDER BY id DESC LIMIT 1`).
		Scan(&attachment, &transports, &backupEligible); err != nil {
		t.Fatal(err)
	}
	return
}

// The registration options follow the setting: strict asks the browser for a platform authenticator (so it offers no
// key and no phone), the wider one leaves the attachment open. Both demand a discoverable key and user verification.
func TestRegistrationOptionsFollowTheAuthenticatorsSetting(t *testing.T) {
	for name, tc := range map[string]struct {
		mut  func(*Config)
		want string
	}{
		"default": {nil, "platform"},
		"strict":  {func(c *Config) { c.Authenticators = AuthenticatorsPlatform }, "platform"},
		"any":     {func(c *Config) { c.Authenticators = AuthenticatorsAny }, ""},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRigCfg(t, tc.mut)
			b := r.browser(pcOrigin)
			req, _ := json.Marshal(map[string]string{"token": r.token()})
			_, options := b.begin("/enroll/begin", req)
			var reg struct {
				PublicKey struct {
					AuthenticatorSelection struct {
						AuthenticatorAttachment string
						ResidentKey             string
						RequireResidentKey      bool
						UserVerification        string
					} `json:"authenticatorSelection"`
					Attestation string
				} `json:"publicKey"`
			}
			if err := json.Unmarshal(options, &reg); err != nil {
				t.Fatal(err)
			}
			sel := reg.PublicKey.AuthenticatorSelection
			if sel.AuthenticatorAttachment != tc.want || sel.ResidentKey != "required" || !sel.RequireResidentKey ||
				sel.UserVerification != "required" || reg.PublicKey.Attestation != "none" {
				t.Fatalf("registration options: %s", options)
			}
		})
	}
	if _, err := New(Config{DB: newRig(t).db, Origins: []Origin{pcOrigin}, Authenticators: "everything"}); err == nil {
		t.Error("an unknown setting was accepted")
	}
	for in, want := range map[string]Authenticators{"": AuthenticatorsPlatform, "platform": AuthenticatorsPlatform, "any": AuthenticatorsAny} {
		if got, err := ParseAuthenticators(in); err != nil || got != want {
			t.Errorf("ParseAuthenticators(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseAuthenticators("roaming"); err == nil {
		t.Error("an unknown setting was parsed")
	}
}

// With the default setting a security key is refused at registration, as it always was; and the refusal does not
// burn the one-time address.
func TestStrictSettingRefusesASecurityKey(t *testing.T) {
	r := newRig(t)
	b := r.browser(pcOrigin)
	token := r.token()
	code, out := b.enrolAs(token, roaming(t), opts{})
	wantRefused(t, r, code, out, ReasonAttachment)
	if e := r.last(); e.Attachment != "cross-platform" {
		t.Errorf("the refusal does not say what kind it was: %+v", e)
	}
	if n := countRows(t, r, "credentials"); n != 0 {
		t.Fatalf("%d credentials after a refusal", n)
	}
	// The address still works for a platform authenticator.
	if code, out := b.enrolAs(token, newAuthenticator(t, "localhost"), opts{}); code != 200 {
		t.Fatalf("the address was spent by a refusal: %d %v", code, out)
	}
	// A value the specification does not define is dropped by the library, as a browser must: it counts as "not
	// reported", which both settings accept, and is recorded as such. (The attachment is the browser's claim, not
	// proof; the protections are user verification, the origin and the one-time address.)
	odd := newAuthenticator(t, "localhost")
	odd.attachment = "satellite"
	r2 := anyRig(t)
	if code, out := r2.browser(pcOrigin).enrolAs(r2.token(), odd, opts{}); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	if e := r2.last(); e.Name != EventEnrolled || e.Attachment != "" {
		t.Fatalf("event: %+v", e)
	}
}

// With the wider setting a security key is accepted, and the event, like the stored row, says what it was.
func TestAnySettingAcceptsASecurityKeyAndRecordsIt(t *testing.T) {
	r := anyRig(t)
	b := r.browser(pcOrigin)
	key := roaming(t)
	code, out := b.enrolAs(r.token(), key, opts{})
	if code != 200 {
		t.Fatalf("enrol: %d %v events=%+v", code, out, r.events())
	}
	e := r.last()
	if e.Name != EventEnrolled || e.Attachment != "cross-platform" || strings.Join(e.Transports, ",") != "usb" || e.BackupEligible || !e.UserVerified || !e.Bootstrap {
		t.Fatalf("enrolled event: %+v", e)
	}
	if att, tr, be := credRow(t, r); att != "cross-platform" || tr != `["usb"]` || be {
		t.Fatalf("stored: %q %q %v", att, tr, be)
	}
	// Sign-in with it, and the event says it was a security key.
	if code, out := b.login(key, opts{}); code != 200 {
		t.Fatalf("login: %d %v", code, out)
	}
	if e := r.last(); e.Name != EventLogin || e.Attachment != "cross-platform" || strings.Join(e.Transports, ",") != "usb" || !e.UserVerified {
		t.Fatalf("login event: %+v", e)
	}
}

// A phone used through the cross-device prompt reports cross-platform with the hybrid transport; a passkey that
// syncs reports backup eligible and backed up. Both are accepted and recorded; the synced one signs with counter 0.
func TestAnySettingAcceptsAPhoneAndASyncedPasskey(t *testing.T) {
	r := anyRig(t)
	b := r.browser(pcOrigin)
	phone := newAuthenticator(t, "localhost")
	phone.attachment, phone.transports, phone.be, phone.bs = "cross-platform", []string{"hybrid", "internal"}, true, true
	if code, out := b.enrolAs(r.token(), phone, opts{}); code != 200 {
		t.Fatalf("enrol: %d %v events=%+v", code, out, r.events())
	}
	if e := r.last(); e.Attachment != "cross-platform" || strings.Join(e.Transports, ",") != "hybrid,internal" || !e.BackupEligible {
		t.Fatalf("enrolled event: %+v", e)
	}
	zero := uint32(0)
	if code, out := b.login(phone, opts{signCount: &zero}); code != 200 {
		t.Fatalf("login: %d %v events=%+v", code, out, r.events())
	}
	if e := r.last(); e.Name != EventLogin || !e.BackupEligible || e.SignCount != 0 {
		t.Fatalf("login event: %+v", e)
	}
}

// The platform flow does not change under the wider setting, and says "platform".
func TestPlatformAuthenticatorStillWorksUnderEitherSetting(t *testing.T) {
	for name, rg := range map[string]*rig{"strict": newRig(t), "any": anyRig(t)} {
		t.Run(name, func(t *testing.T) {
			b := rg.browser(pcOrigin)
			a := mustEnrolled(t, rg, b)
			if e := rg.last(); e.Name != EventEnrolled || e.Attachment != "platform" || e.BackupEligible {
				t.Fatalf("enrolled event: %+v", e)
			}
			if code, out := b.login(a, opts{}); code != 200 {
				t.Fatalf("login: %d %v", code, out)
			}
			if e := rg.last(); e.Attachment != "platform" {
				t.Fatalf("login event: %+v", e)
			}
		})
	}
}

// User verification and user presence are required of every kind, at registration and at sign-in, under both settings.
func TestUserVerificationIsRequiredOfEveryKind(t *testing.T) {
	for name, rg := range map[string]*rig{"strict": newRig(t), "any": anyRig(t)} {
		t.Run(name, func(t *testing.T) {
			// At registration: a key that only touched (no PIN) and a key that did nothing.
			for reason, o := range map[string]opts{ReasonUV: {noUV: true}, ReasonUP: {noUP: true}} {
				key := roaming(t)
				if name == "strict" {
					key = newAuthenticator(t, "localhost")
				}
				code, out := rg.browser(pcOrigin).enrolAs(rg.token(), key, o)
				wantRefused(t, rg, code, out, reason)
			}
			if n := countRows(t, rg, "credentials"); n != 0 {
				t.Fatalf("%d credentials were stored without verification", n)
			}
			// At sign-in.
			b := rg.browser(pcOrigin)
			key := newAuthenticator(t, "localhost")
			if name == "any" {
				key = roaming(t)
			}
			if code, out := b.enrolAs(rg.token(), key, opts{}); code != 200 {
				t.Fatalf("enrol: %d %v", code, out)
			}
			code, out := b.login(key, opts{noUV: true})
			wantRefused(t, rg, code, out, ReasonUV)
			code, out = b.login(key, opts{noUP: true})
			wantRefused(t, rg, code, out, ReasonUP)
		})
	}
}

// Narrowing the setting again stops a credential made while it was wider: at sign-in and at approval. Widening it
// does not touch what the strict setting enrolled.
func TestNarrowingTheSettingStopsAnEnrolledKey(t *testing.T) {
	ar := newApprRigCfg(t, nil, func(c *Config) { c.Authenticators = AuthenticatorsAny })
	b := ar.browser(pcOrigin)
	key := roaming(t)
	if code, out := b.enrolAs(ar.token(), key, opts{}); code != 200 {
		t.Fatalf("enrol: %d %v", code, out)
	}
	zero := uint32(0)
	if code, out := b.login(key, opts{signCount: &zero}); code != 200 {
		t.Fatalf("login: %d %v", code, out)
	}
	card := ar.request(nil)
	bg := ar.begin(b, card.ID)

	ar.con.authn = AuthenticatorsPlatform // chapd restarted without -approver-authenticators any

	rec := ar.finish(b, card.ID, bg, key.get(bg.options, pcOrigin.URL, opts{signCount: &zero}))
	out := wantCode(t, rec, http.StatusForbidden, approvals.CodeAssertion)
	if str(out["why"]) != ReasonAttachment {
		t.Fatalf("why %s", out["why"])
	}
	if ar.state(card.ID) != approvals.StatePending || len(ar.led.named("op.approve")) != 0 {
		t.Fatal("a refused approval changed something")
	}
	b2 := ar.browser(pcOrigin)
	code, out2 := b2.login(key, opts{signCount: &zero})
	wantRefused(t, ar.rig, code, out2, ReasonAttachment)
	if e := ar.last(); e.Attachment != "cross-platform" {
		t.Errorf("the refusal does not say what kind it was: %+v", e)
	}
	if n := countRows(t, ar.rig, "console_sessions"); n != 1 { // only the first sign-in's
		t.Errorf("%d sessions", n)
	}

	// Wider again: the same key works.
	ar.con.authn = AuthenticatorsAny
	if code, out := b2.login(key, opts{signCount: &zero}); code != 200 {
		t.Fatalf("login after widening: %d %v", code, out)
	}
}

// A security key approves a card; the ledger names the kind of authenticator that did, and a platform approval says
// platform. The signed card text is not involved: nothing in this test touches it.
func TestApprovalLedgerNamesTheAuthenticatorKind(t *testing.T) {
	ar := newApprRigCfg(t, nil, func(c *Config) { c.Authenticators = AuthenticatorsAny })
	b := ar.browser(pcOrigin)
	key := roaming(t)
	if code, out := b.enrolAs(ar.token(), key, opts{}); code != 200 {
		t.Fatalf("enrol: %d %v", code, out)
	}
	zero := uint32(0)
	if code, out := b.login(key, opts{signCount: &zero}); code != 200 {
		t.Fatalf("login: %d %v", code, out)
	}
	card := ar.request(nil)
	bg := ar.begin(b, card.ID)
	if rec := ar.finish(b, card.ID, bg, key.get(bg.options, pcOrigin.URL, opts{signCount: &zero})); rec.Code != 200 {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
	evs := ar.led.named("op.approve")
	if len(evs) != 1 || !strings.Contains(evs[0].Body, "on pc;") ||
		!strings.Contains(evs[0].Body, "authenticator=cross-platform; transports=usb; backup_eligible=false") {
		t.Fatalf("ledger: %+v", evs)
	}
	// The same approval with UV off is refused whatever the kind.
	card2 := ar.request(nil)
	bg = ar.begin(b, card2.ID)
	rec := ar.finish(b, card2.ID, bg, key.get(bg.options, pcOrigin.URL, opts{signCount: &zero, noUV: true}))
	if out := wantCode(t, rec, http.StatusForbidden, approvals.CodeAssertion); str(out["why"]) != ReasonUV {
		t.Fatalf("why %s", out["why"])
	}
	if ar.state(card2.ID) != approvals.StatePending {
		t.Fatal("approved without user verification")
	}

	// A platform approval says platform.
	pr := newApprRig(t, nil)
	pb, pa := pr.signedIn()
	pc := pr.request(nil)
	pbg := pr.begin(pb, pc.ID)
	if rec := pr.finish(pb, pc.ID, pbg, pa.get(pbg.options, pcOrigin.URL, opts{signCount: &zero})); rec.Code != 200 {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
	if evs := pr.led.named("op.approve"); len(evs) != 1 || !strings.Contains(evs[0].Body, "authenticator=platform; transports=none; backup_eligible=false") {
		t.Fatalf("ledger: %+v", evs)
	}
}

// The first approver is still enrolled only with the one-time address, whatever the setting: no address, no
// credential; and a spent or unknown address refuses a security key as it refuses anything else.
func TestSecurityKeyStillNeedsTheOneTimeAddress(t *testing.T) {
	r := anyRig(t)
	b := r.browser(pcOrigin)
	req, _ := json.Marshal(map[string]string{"token": "not-an-address", "name": "operator", "label": "Key"})
	if code, out := b.post("/enroll/begin", req, ""); code < 400 {
		t.Fatalf("begin with a made-up address: %d %v", code, out)
	}
	token := r.token()
	if code, out := b.enrolAs(token, roaming(t), opts{}); code != 200 {
		t.Fatalf("enrol: %d %v", code, out)
	}
	// Spent: a second key with the same address is refused.
	req, _ = json.Marshal(map[string]string{"token": token, "name": "operator", "label": "Key"})
	if code, out := b.post("/enroll/begin", req, ""); code < 400 {
		t.Fatalf("begin with a spent address: %d %v", code, out)
	}
}
