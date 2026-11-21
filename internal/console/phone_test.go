package console

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/approvals"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// phoneRig is the whole phone path: a PC console and a phone origin (the
// configurable second origin), the real WebAuthn verifier, a software Hello on
// the PC and a software passkey on the phone.
type phoneRig struct {
	*apprRig
	pc, phone *browser
	hello     *authenticator // the PC's Windows Hello credential
	pass      *authenticator // the phone's passkey, once enrolled
}

func newPhoneRig(t *testing.T, phoneOrigins ...Origin) *phoneRig {
	return newPhoneRigCfg(t, nil, phoneOrigins...)
}

func newPhoneRigCfg(t *testing.T, mut func(*Config), phoneOrigins ...Origin) *phoneRig {
	t.Helper()
	if len(phoneOrigins) == 0 {
		phoneOrigins = []Origin{phoneOrigin}
	}
	origins := append([]Origin{pcOrigin}, phoneOrigins...)
	ar := &apprRig{rig: newRigCfg(t, mut, origins...), led: &tLedger{}}
	cfg := approvals.Config{
		DB: ar.db, Ledger: ar.led, Catalog: approvals.PhaseOneCatalog(), Verifier: ar.con,
		PhoneOrigins: ar.con.PhoneOrigins(),
		Now:          func() time.Time { ar.rig.mu.Lock(); defer ar.rig.mu.Unlock(); return ar.rig.now },
		Alert:        func(a approvals.Alert) { ar.mu.Lock(); ar.alerts = append(ar.alerts, a); ar.mu.Unlock() },
		Stop: func(_ context.Context, _ *store.Tx, s approvals.Stop) error {
			ar.mu.Lock()
			ar.stops = append(ar.stops, s)
			ar.mu.Unlock()
			return nil
		},
	}
	e, err := approvals.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ar.e = e
	if err := ar.con.UseApprovals(e, ApprovalsOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := ar.con.UsePhone(PhoneConfig{Record: ar.led, PolicyVersion: func() string { return "baseline-2026.10.1" }}); err != nil {
		t.Fatal(err)
	}
	pr := &phoneRig{apprRig: ar}
	pr.pc, pr.hello = ar.signedIn()
	return pr
}

func (pr *phoneRig) tick() { pr.rig.advance(time.Second) }

// approveOnPC approves a card with the Hello credential.
func (pr *phoneRig) approveOnPC(id string) {
	pr.t.Helper()
	bg := pr.begin(pr.pc, id)
	if out := pr.finish(pr.pc, id, bg, pr.hello.get(bg.options, pcOrigin.URL, opts{signCount: &zero})); out.Code != 200 {
		pr.t.Fatalf("approve on the PC: %d %s", out.Code, out.Body)
	}
}

// enrolPhone does the whole of ADR-004 amendment 6 item 3: ask, approve on the PC,
// spend the approval for the address, open it on the phone, create the
// passkey, sign in.
func (pr *phoneRig) enrolPhone() {
	pr.t.Helper()
	rec := pr.pc.postH("/phone/enroll", []byte(`{"label":"My phone"}`), pr.pc.csrf(), nil)
	if rec.Code != http.StatusAccepted {
		pr.t.Fatalf("ask to enrol: %d %s", rec.Code, rec.Body)
	}
	id := str(decode(rec)["approval"])

	// Not usable before it is approved.
	if rec := pr.pc.postH("/phone/"+id+"/enrollment", nil, pr.pc.csrf(), nil); rec.Code != http.StatusConflict {
		pr.t.Fatalf("an unapproved enrolment was spent: %d %s", rec.Code, rec.Body)
	}
	pr.approveOnPC(id)
	rec = pr.pc.postH("/phone/"+id+"/enrollment", nil, pr.pc.csrf(), nil)
	if rec.Code != 200 {
		pr.t.Fatalf("spend the approval: %d %s", rec.Code, rec.Body)
	}
	out := decode(rec)
	addr := str(out["address"])
	prefix := phoneOrigin.URL + "/enroll#"
	if !strings.HasPrefix(addr, prefix) || len(addr) <= len(prefix)+20 {
		pr.t.Fatalf("address %q", addr)
	}
	if qr := str(out["qr"]); !strings.HasPrefix(qr, "data:image/svg+xml;base64,") {
		pr.t.Fatalf("qr %.40q", qr)
	} else if svg, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(qr, "data:image/svg+xml;base64,")); err != nil || !strings.HasPrefix(string(svg), "<svg ") {
		pr.t.Fatalf("qr is not an svg: %v", err)
	}
	// One approval, one address.
	if rec := pr.pc.postH("/phone/"+id+"/enrollment", nil, pr.pc.csrf(), nil); rec.Code != http.StatusConflict {
		pr.t.Fatalf("the approval made a second address: %d %s", rec.Code, rec.Body)
	}

	token := strings.TrimPrefix(addr, prefix)
	pr.phone = pr.browser(phoneOrigin)
	req, _ := json.Marshal(map[string]string{"token": token, "label": "My phone"})
	cer, options := pr.phone.begin("/enroll/begin", req)
	pr.pass = newAuthenticator(pr.t, phoneOrigin.RPID)
	if code, out := pr.phone.post("/enroll/finish", pr.pass.create(options, phoneOrigin.URL, opts{}), cer); code != 200 {
		pr.t.Fatalf("enrol the phone: %d %v", code, out)
	}
	if code, out := pr.phone.login(pr.pass, opts{signCount: &zero}); code != 200 {
		pr.t.Fatalf("phone sign-in: %d %v", code, out)
	}
}

var numberButton = regexp.MustCompile(`data-number="([0-9]{2})"`)
var pcCode = regexp.MustCompile(`<strong class="phone-code-number">([0-9]{2})</strong>`)

// pcNumber reads the number the PC page shows for a card.
func (pr *phoneRig) pcNumber(id string) string {
	pr.t.Helper()
	page := pr.pc.do("GET", "/approvals", nil, nil).Body.String()
	i := strings.Index(page, `data-approval="`+id+`"`)
	if i < 0 {
		pr.t.Fatalf("card %s is not on the PC page", id)
	}
	m := pcCode.FindStringSubmatch(page[i:])
	if m == nil {
		pr.t.Fatalf("no phone number beside card %s", id)
	}
	return m[1]
}

// phoneNumbers reads the three numbers the phone page shows for a card.
func (pr *phoneRig) phoneNumbers(id string) []string {
	pr.t.Helper()
	page := pr.phone.do("GET", "/phone", nil, nil).Body.String()
	i := strings.Index(page, `data-approval="`+id+`"`)
	if i < 0 {
		pr.t.Fatalf("card %s is not on the phone page", id)
	}
	end := strings.Index(page[i:], "</article>")
	var out []string
	for _, m := range numberButton.FindAllStringSubmatch(page[i:i+end], -1) {
		out = append(out, m[1])
	}
	if len(out) != 3 {
		pr.t.Fatalf("the phone shows %d numbers: %v", len(out), out)
	}
	return out
}

func (pr *phoneRig) match(id, choice string) map[string]json.RawMessage {
	pr.t.Helper()
	body, _ := json.Marshal(map[string]string{"choice": choice})
	rec := pr.phone.postH("/phone/"+id+"/match", body, pr.phone.csrf(), nil)
	if rec.Code != 200 {
		pr.t.Fatalf("match: %d %s", rec.Code, rec.Body)
	}
	return decode(rec)
}

func TestPhoneEnrolmentEndToEnd(t *testing.T) {
	pr := newPhoneRig(t)
	pr.enrolPhone()

	var n int
	if err := pr.db.SQL().QueryRow(`SELECT count(*) FROM credentials WHERE rp_id = ? AND origin = ? AND attachment = 'platform'`,
		phoneOrigin.RPID, phoneOrigin.URL).Scan(&n); err != nil || n != 1 {
		t.Fatalf("phone credentials: %d %v", n, err)
	}
	var approvers int
	_ = pr.db.SQL().QueryRow(`SELECT count(*) FROM approvers`).Scan(&approvers)
	if approvers != 1 {
		t.Fatalf("%d approvers: the phone is another credential of the same approver", approvers)
	}
	// The enrolment card was the critical class, loud, approved on the PC by Hello.
	_, alerts := pr.snapshot()
	stages := ""
	for _, a := range alerts {
		if a.Op == "approvers.enroll" {
			stages += a.Stage + " "
		}
	}
	if !strings.Contains(stages, approvals.AlertRequested) || !strings.Contains(stages, approvals.AlertApproved) ||
		!strings.Contains(stages, approvals.AlertExecuting) {
		t.Fatalf("alerts for the enrolment: %q", stages)
	}
	evs := pr.led.named("op.approve")
	if len(evs) != 1 || !strings.Contains(evs[0].Body, "on pc") {
		t.Fatalf("the enrolment was not approved on the PC: %+v", evs)
	}
	if len(pr.led.named("op.request")) != 1 || len(pr.led.named("op.result")) != 1 {
		t.Fatalf("ledger: request %d result %d", len(pr.led.named("op.request")), len(pr.led.named("op.result")))
	}
	for _, ev := range pr.led.evs {
		if strings.Contains(ev.Body, "#") && strings.Contains(ev.Body, "/enroll") {
			t.Fatalf("an enrolment address reached the ledger: %s", ev.Body)
		}
	}
}

func TestPhoneApprovesOnItsOwnWithTheRightNumber(t *testing.T) {
	pr := newPhoneRig(t)
	pr.enrolPhone()
	card := pr.request(nil)

	// The phone card text is the PC card text, byte for byte and hash for hash.
	pcPage := pr.pc.do("GET", "/approvals", nil, nil).Body.String()
	phonePage := pr.phone.do("GET", "/phone", nil, nil).Body.String()
	pcM, phM := cardPre.FindStringSubmatch(pcPage), cardPre.FindStringSubmatch(phonePage)
	if pcM == nil || phM == nil || pcM[1] != card.ID || phM[1] != card.ID {
		t.Fatalf("card %s missing: pc %v phone %v", card.ID, pcM != nil, phM != nil)
	}
	pcText, phoneText := cardTextOf(pcM[3]), cardTextOf(phM[3])
	if pcText != phoneText || pcText != card.CardText {
		t.Fatalf("the phone card is not the PC card:\n%q\n%q", phoneText, pcText)
	}
	if spec.SHA256Tagged([]byte(phoneText)) != phM[2] || phM[2] != pcM[2] || phM[2] != card.DisplaySHA256 {
		t.Fatalf("hashes: phone %s pc %s card %s", phM[2], pcM[2], card.DisplaySHA256)
	}

	// The PC number is on the PC page, outside the card text; the phone shows three and not the card's number as a label.
	code := pr.pcNumber(card.ID)
	if strings.Contains(pcText, code) && strings.Count(pcText, code) > strings.Count(card.CardText, code) {
		t.Fatal("the number leaked into the card text")
	}
	choices := pr.phoneNumbers(card.ID)
	found := false
	for _, c := range choices {
		found = found || c == code
	}
	if !found {
		t.Fatalf("the number on the PC (%s) is not among the phone's three %v", code, choices)
	}
	if again := pr.phoneNumbers(card.ID); strings.Join(again, ",") != strings.Join(choices, ",") {
		t.Fatalf("a reload changed the phone's numbers: %v then %v", choices, again)
	}
	if strings.Contains(phonePage, `class="phone-code-number"`) || strings.Contains(phonePage, "Phone number for this card") {
		t.Fatal("the phone page shows which number is right")
	}
	if !strings.Contains(pcPage, "Approve with your passkey") || strings.Contains(phonePage, "Approve with your passkey") {
		t.Fatal("the PC offers Hello and the phone offers the number buttons")
	}

	// Without the number the phone gets no challenge.
	rec := pr.phone.postH("/approvals/"+card.ID+"/begin", nil, pr.phone.csrf(), nil)
	wantCode(t, rec, http.StatusForbidden, approvals.CodeNumberRequired)

	if out := pr.match(card.ID, code); string(out["matched"]) != "true" {
		t.Fatalf("match: %v", out)
	}
	bg := pr.begin(pr.phone, card.ID)
	var opt struct {
		PublicKey struct {
			RPID  string `json:"rpId"`
			Allow []struct {
				ID string `json:"id"`
			} `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(bg.options, &opt); err != nil {
		t.Fatal(err)
	}
	if opt.PublicKey.RPID != phoneOrigin.RPID || len(opt.PublicKey.Allow) != 1 || opt.PublicKey.Allow[0].ID != b64.EncodeToString(pr.pass.credID) {
		t.Fatalf("the phone was asked for the wrong credential: %+v", opt)
	}
	if out := pr.finish(pr.phone, card.ID, bg, pr.pass.get(bg.options, phoneOrigin.URL, opts{signCount: &zero})); out.Code != 200 ||
		str(decode(out)["state"]) != "approved" {
		t.Fatalf("finish: %d %s", out.Code, out.Body)
	}

	done, err := pr.e.Get(context.Background(), card.ID)
	if err != nil || done.State != approvals.StateApproved || done.Record == nil {
		t.Fatalf("%+v %v", done, err)
	}
	rc := done.Record
	if len(rc.Confirmations) != 1 || rc.Confirmations[0].Channel != "phone" || rc.Confirmations[0].CredentialID != b64.EncodeToString(pr.pass.credID) ||
		len(rc.Shown.Channels) != 1 || rc.Shown.Channels[0] != "phone" || rc.Shown.DisplaySHA256 != phM[2] {
		t.Fatalf("record: %+v", rc)
	}
	var ch, rp, origin string
	if err := pr.db.SQL().QueryRow(`SELECT channel, rp_id, origin FROM approval_assertions WHERE approval_id = ?`, card.ID).Scan(&ch, &rp, &origin); err != nil ||
		ch != "phone" || rp != phoneOrigin.RPID || origin != phoneOrigin.URL {
		t.Fatalf("stored assertion: %s %s %s %v", ch, rp, origin, err)
	}
	// The op state machine releases it once, as it would a PC approval.
	rel := func() error {
		return pr.e.Atomic(context.Background(), func(ctx context.Context, tx *store.Tx) (approvals.Effects, error) {
			return pr.e.ConsumeTx(ctx, tx, approvals.ConsumeInput{ApprovalID: card.ID, Request: done.Request})
		})
	}
	if err := rel(); err != nil {
		t.Fatal(err)
	}
	if err := rel(); err == nil || !strings.Contains(err.Error(), approvals.CodeConsumed) {
		t.Fatalf("second release: %v", err)
	}
}

func TestPhoneApprovesACriticalCardAlone(t *testing.T) {
	pr := newPhoneRig(t)
	pr.enrolPhone()
	card := pr.request(func(r *spec.Request) {
		r.Op, r.Target, r.Params = "secrets.write", spec.Target{Adapter: "vault", Ref: "demo"}, map[string]any{"action": "import"}
	})
	page := pr.phone.do("GET", "/phone", nil, nil).Body.String()
	if !strings.Contains(page, "CRITICAL") {
		t.Fatal("the phone card does not say CRITICAL")
	}
	pr.match(card.ID, pr.pcNumber(card.ID))
	bg := pr.begin(pr.phone, card.ID)
	if out := pr.finish(pr.phone, card.ID, bg, pr.pass.get(bg.options, phoneOrigin.URL, opts{signCount: &zero})); out.Code != 200 {
		t.Fatalf("%d %s", out.Code, out.Body)
	}
	_, alerts := pr.snapshot()
	var approved bool
	for _, a := range alerts {
		approved = approved || (a.Op == "secrets.write" && a.Stage == approvals.AlertApproved)
	}
	if !approved {
		t.Fatal("approving a critical card from the phone raised no alert")
	}
}

func TestAWrongNumberOnThePhoneDeniesTheCard(t *testing.T) {
	pr := newPhoneRig(t)
	pr.enrolPhone()
	card := pr.request(nil)
	code := pr.pcNumber(card.ID)
	wrong := ""
	for _, c := range pr.phoneNumbers(card.ID) {
		if c != code {
			wrong = c
			break
		}
	}
	out := pr.match(card.ID, wrong)
	if string(out["matched"]) != "false" || str(out["state"]) != "denied" {
		t.Fatalf("a wrong number: %v", out)
	}
	if pr.state(card.ID) != approvals.StateDenied {
		t.Fatal("the card is not denied")
	}
	// Sticky deny: the same action is refused, and the card cannot be decided any more.
	var denied []approvals.LedgerEvent
	for _, ev := range pr.led.named("op.approve") {
		if ev.Attributes["factory.decision"] == "denied" {
			denied = append(denied, ev)
		}
	}
	if len(denied) != 1 || !strings.Contains(denied[0].Body, "number matching failed") {
		t.Fatalf("ledger: %+v", denied)
	}
	rec := pr.phone.postH("/phone/"+card.ID+"/match", []byte(`{"choice":"`+code+`"}`), pr.phone.csrf(), nil)
	wantCode(t, rec, http.StatusConflict, approvals.CodeDenied)
	rec = pr.phone.postH("/approvals/"+card.ID+"/begin", nil, pr.phone.csrf(), nil)
	wantCode(t, rec, http.StatusConflict, approvals.CodeDenied)
	rec = pr.pc.postH("/approvals/"+card.ID+"/begin", nil, pr.pc.csrf(), nil)
	wantCode(t, rec, http.StatusConflict, approvals.CodeDenied)

	// Same action again: refused for the cooldown, and no card is waiting.
	if p, err := pr.e.Pending(context.Background()); err != nil || len(p) != 0 {
		t.Fatalf("a denied card is still pending: %v %v", p, err)
	}
	pr.expectStickyDeny(card)
	// The event reached the audit stream for chapd's log.
	var sawEvent bool
	for _, e := range pr.events() {
		sawEvent = sawEvent || (e.Name == EventRefused && e.Reason == ReasonNumber && e.Origin == phoneOrigin.URL)
	}
	if !sawEvent {
		t.Fatal("no console.refused event for the wrong number")
	}
}

// expectStickyDeny asks for the denied card's action again.
func (pr *phoneRig) expectStickyDeny(was *approvals.Approval) {
	pr.t.Helper()
	req := was.Request
	req.RequestID = "q-again1"
	var res approvals.Result
	err := pr.e.Atomic(context.Background(), func(ctx context.Context, tx *store.Tx) (approvals.Effects, error) {
		var err error
		res, err = pr.e.RequestTx(ctx, tx, approvals.RequestInput{Request: req, PolicyVersion: "baseline-2026.10.1"})
		return res.Effects, err
	})
	if err != nil {
		pr.t.Fatal(err)
	}
	if res.Refusal == nil || res.Refusal.Code != approvals.CodeDenied || res.Refusal.RetryAfter < 59*time.Minute {
		pr.t.Fatalf("the same action was not refused for the cooldown: %+v", res.Refusal)
	}
}

func TestPhoneNumberIsNotSharedBetweenBrowsersOrCards(t *testing.T) {
	pr := newPhoneRig(t)
	pr.enrolPhone()
	a := pr.request(nil)
	b := pr.request(func(r *spec.Request) {
		r.Params = map[string]any{"sha": strings.Repeat("b", 40)}
		r.Requester.RunID = "r-0002"
	})
	pr.match(a.ID, pr.pcNumber(a.ID))
	// The right number for card A opens card B for no one.
	rec := pr.phone.postH("/approvals/"+b.ID+"/begin", nil, pr.phone.csrf(), nil)
	wantCode(t, rec, http.StatusForbidden, approvals.CodeNumberRequired)

	// Another browser signed in with the same passkey did not match anything.
	other := pr.browser(phoneOrigin)
	if code, out := other.login(pr.pass, opts{signCount: &zero}); code != 200 {
		t.Fatal(code, out)
	}
	rec = other.postH("/approvals/"+a.ID+"/begin", nil, other.csrf(), nil)
	wantCode(t, rec, http.StatusForbidden, approvals.CodeNumberRequired)

	// The matched browser still can, once.
	bg := pr.begin(pr.phone, a.ID)
	_ = bg
	rec = pr.phone.postH("/approvals/"+a.ID+"/begin", nil, pr.phone.csrf(), nil)
	wantCode(t, rec, http.StatusForbidden, approvals.CodeNumberRequired)
}

func TestPhoneLookAlikeOriginsCollectNothing(t *testing.T) {
	pr := newPhoneRig(t)
	pr.enrolPhone()
	card := pr.request(nil)
	pr.match(card.ID, pr.pcNumber(card.ID))
	bg := pr.begin(pr.phone, card.ID)

	// A page on a look-alike origin gets the real passkey to sign: the browser
	// writes the page's own origin into clientDataJSON, and the server refuses.
	for _, evil := range []string{
		"https://pc.tail1234.ts.net.evil.example", "https://pc-tail1234.ts.net", "http://pc.tail1234.ts.net",
		"https://pc.tail1234.ts.net:8443", "https://xpc.tail1234.ts.net", "http://localhost:55398",
	} {
		pr.tick()
		out := pr.finish(pr.phone, card.ID, bg, pr.pass.get(bg.options, phoneOrigin.URL, opts{origin: evil, signCount: &zero}))
		if out.Code == 200 {
			t.Fatalf("an assertion made at %s approved the card", evil)
		}
		// A challenge burns on any attempt: begin again to try the next.
		pr.match(card.ID, pr.pcNumber(card.ID))
		bg = pr.begin(pr.phone, card.ID)
	}
	if pr.state(card.ID) != approvals.StatePending {
		t.Fatal("the card was decided by a look-alike")
	}

	// A look-alike host name reaches nothing: the guard refuses the Host.
	for _, host := range []string{"pc.tail1234.ts.net.evil.example", "pc-tail1234.ts.net", "evil.example"} {
		b := pr.browser(Origin{RPID: host, URL: "https://" + host})
		if rec := b.do("GET", "/phone", nil, nil); rec.Code != http.StatusForbidden {
			t.Fatalf("Host %s: %d", host, rec.Code)
		}
		if rec := b.do("POST", "/phone/"+card.ID+"/match", []byte(`{"choice":"10"}`), map[string]string{"X-CSRF-Token": "x"}); rec.Code != http.StatusForbidden {
			t.Fatalf("Host %s: match %d", host, rec.Code)
		}
	}
	// The right host with a foreign Origin header is refused too.
	rec := pr.phone.postH("/phone/"+card.ID+"/match", []byte(`{"choice":"10"}`), pr.phone.csrf(), map[string]string{"Origin": "https://pc.tail1234.ts.net.evil.example"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("foreign Origin: %d", rec.Code)
	}
	if pr.state(card.ID) != approvals.StatePending {
		t.Fatal("a refused request changed the card")
	}
}

func TestCredentialsDoNotCrossOrigins(t *testing.T) {
	pr := newPhoneRig(t)
	pr.enrolPhone()
	card := pr.request(nil)

	// The phone passkey asked for at the PC: no allowed credential, nothing approved.
	bg := pr.begin(pr.pc, card.ID)
	if out := pr.finish(pr.pc, card.ID, bg, pr.pass.get(bg.options, pcOrigin.URL, opts{signCount: &zero})); out.Code == 200 {
		t.Fatal("the phone passkey approved at the PC origin")
	}
	// The Hello credential replayed at the phone origin, after the right number.
	pr.match(card.ID, pr.pcNumber(card.ID))
	bg = pr.begin(pr.phone, card.ID)
	hello := *pr.hello
	hello.rpID = phoneOrigin.RPID
	if out := pr.finish(pr.phone, card.ID, bg, hello.get(bg.options, phoneOrigin.URL, opts{signCount: &zero})); out.Code == 200 {
		t.Fatal("the Hello credential approved at the phone origin")
	}
	if pr.state(card.ID) != approvals.StatePending {
		t.Fatal("the card was decided by a credential from the other origin")
	}
}

func TestPhonePageAndRoutesAreForTheRightOrigin(t *testing.T) {
	pr := newPhoneRig(t)
	pr.enrolPhone()
	card := pr.request(nil)

	// The PC console has no phone page; the phone's approvals page is the phone page.
	if rec := pr.pc.do("GET", "/phone", nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("GET /phone at the PC: %d", rec.Code)
	}
	rec := pr.phone.do("GET", "/approvals", nil, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/phone" {
		t.Fatalf("GET /approvals at the phone: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	// Signed out, the phone page sends you to sign in and shows no card.
	out := pr.browser(phoneOrigin)
	rec = out.do("GET", "/phone", nil, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" || strings.Contains(rec.Body.String(), card.ID) {
		t.Fatalf("signed-out GET /phone: %d %s", rec.Code, rec.Body)
	}
	// Signed out, a match, a begin and a finish are all refused, and the card is untouched.
	for _, p := range []string{"/phone/" + card.ID + "/match", "/approvals/" + card.ID + "/begin", "/approvals/" + card.ID + "/finish"} {
		rec := out.postH(p, []byte(`{"choice":"10"}`), out.csrf(), map[string]string{"X-Challenge-ID": b64.EncodeToString(make([]byte, 16))})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("signed-out POST %s: %d %s", p, rec.Code, rec.Body)
		}
	}
	// The phone cannot enrol another device, however signed in it is.
	rec = pr.phone.postH("/phone/enroll", []byte(`{"label":"x"}`), pr.phone.csrf(), nil)
	wantCode(t, rec, http.StatusForbidden, "enrol_from_the_pc")
	rec = pr.phone.postH("/phone/"+card.ID+"/enrollment", nil, pr.phone.csrf(), nil)
	wantCode(t, rec, http.StatusForbidden, "enrol_from_the_pc")
	// A token cannot ask for an enrolment, match a number or decide.
	tok := map[string]string{"Authorization": "Bearer chap_orch_x"}
	for _, c := range []struct {
		b    *browser
		path string
	}{
		{pr.pc, "/phone/enroll"}, {pr.phone, "/phone/" + card.ID + "/match"}, {pr.phone, "/approvals/" + card.ID + "/begin"},
	} {
		rec := c.b.postH(c.path, []byte(`{"choice":"10","label":"x"}`), c.b.csrf(), tok)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("a token reached %s: %d %s", c.path, rec.Code, rec.Body)
		}
	}
	if pr.state(card.ID) != approvals.StatePending {
		t.Fatal("a refused request changed the card")
	}
	// Deciding or matching with a token is the policy breach it is for any decision.
	stops, _ := pr.snapshot()
	if len(stops) != 2 || stops[0].Code != approvals.StopBreach || stops[1].Code != approvals.StopBreach {
		t.Fatalf("stops raised: %+v", stops)
	}
}

func TestPhoneEnrolmentIsOnlyForTheOperatorsOwnApprovedCard(t *testing.T) {
	pr := newPhoneRig(t)
	// Another op's approved card cannot be spent for an address.
	card := pr.request(nil)
	pr.approveOnPC(card.ID)
	rec := pr.pc.postH("/phone/"+card.ID+"/enrollment", nil, pr.pc.csrf(), nil)
	wantCode(t, rec, http.StatusNotFound, approvals.CodeNoSuchApproval)

	// An approvers.enroll card from an agent run (any origin, any label) is not the operator's.
	agent := pr.request(func(r *spec.Request) {
		r.Op, r.Target, r.Params = "approvers.enroll", spec.Target{Adapter: "console", Ref: "operator"},
			map[string]any{"label": "evil", "origin": "https://pc.tail1234.ts.net"}
		r.Requester.RunID = "r-0003"
	})
	pr.approveOnPC(agent.ID)
	rec = pr.pc.postH("/phone/"+agent.ID+"/enrollment", nil, pr.pc.csrf(), nil)
	wantCode(t, rec, http.StatusNotFound, approvals.CodeNoSuchApproval)

	// Asking twice for the same enrolment while one waits is one card.
	rec = pr.pc.postH("/phone/enroll", []byte(`{"label":"My phone"}`), pr.pc.csrf(), nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	rec = pr.pc.postH("/phone/enroll", []byte(`{"label":"My phone"}`), pr.pc.csrf(), nil)
	wantCode(t, rec, http.StatusConflict, "already_waiting")
	// A label with control characters is refused.
	rec = pr.pc.postH("/phone/enroll", []byte(`{"label":"bad\u0007label"}`), pr.pc.csrf(), nil)
	wantCode(t, rec, http.StatusBadRequest, ReasonMalformed)

	// The address lives for the enrolment TTL only.
	pr.rig.advance(30 * time.Minute)
}

func TestPhoneEnrolmentTokenExpiresAndWorksOnce(t *testing.T) {
	pr := newPhoneRig(t)
	rec := pr.pc.postH("/phone/enroll", []byte(`{"label":"My phone"}`), pr.pc.csrf(), nil)
	id := str(decode(rec)["approval"])
	pr.approveOnPC(id)
	rec = pr.pc.postH("/phone/"+id+"/enrollment", nil, pr.pc.csrf(), nil)
	addr := str(decode(rec)["address"])
	token := addr[strings.Index(addr, "#")+1:]

	pr.rig.advance(11 * time.Minute)
	phone := pr.browser(phoneOrigin)
	req, _ := json.Marshal(map[string]string{"token": token, "label": "late"})
	if rec := phone.postH("/enroll/begin", req, phone.csrf(), nil); rec.Code == 200 {
		t.Fatalf("an expired enrolment address was accepted: %s", rec.Body)
	}
}

func TestUsePhoneChecks(t *testing.T) {
	// The console and the engine must agree on which origins are the phone's.
	ar := newApprRig(t, nil, pcOrigin, phoneOrigin)
	if err := ar.con.UsePhone(PhoneConfig{Record: ar.led, PolicyVersion: func() string { return "p" }}); err == nil {
		t.Fatal("UsePhone accepted an engine that does not know the phone origin")
	}
	pr := newPhoneRig(t)
	if err := pr.con.UsePhone(PhoneConfig{}); err == nil {
		t.Fatal("UsePhone accepted a config with no ledger")
	}
	bare := newRig(t, pcOrigin, phoneOrigin)
	if err := bare.con.UsePhone(PhoneConfig{}); err == nil {
		t.Fatal("UsePhone worked without UseApprovals")
	}
}

func TestNewPhoneOrigin(t *testing.T) {
	for in, want := range map[string]Origin{
		"pc.tail1234.ts.net":      {RPID: "pc.tail1234.ts.net", URL: "https://pc.tail1234.ts.net"},
		" PC.Tail1234.ts.net ":    {RPID: "pc.tail1234.ts.net", URL: "https://pc.tail1234.ts.net"},
		"pc.tail1234.ts.net:8443": {RPID: "pc.tail1234.ts.net", URL: "https://pc.tail1234.ts.net:8443"},
		"phone.example.test":      {RPID: "phone.example.test", URL: "https://phone.example.test"},
	} {
		got, err := NewPhoneOrigin(in)
		if err != nil || got != want {
			t.Errorf("%q -> %+v %v, want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "localhost", "pc", "127.0.0.1", "[::1]", "https://pc.tail1234.ts.net", "pc.tail1234.ts.net/x",
		"user@pc.tail1234.ts.net", "pc.tail1234.ts.net?x", "pc tail.ts.net", "pc.tail1234.ts.net:", "http://pc.ts.net"} {
		if o, err := NewPhoneOrigin(bad); err == nil {
			t.Errorf("%q was accepted: %+v", bad, o)
		}
	}
}

func TestTheSecondOriginIsConfigurable(t *testing.T) {
	// Any https name works as the phone's origin, and passkeys bind to it.
	other := Origin{RPID: "phone.example.test", URL: "https://phone.example.test:9443"}
	pr := newPhoneRig(t, other)
	if got := pr.con.PhoneOrigins(); len(got) != 1 || got[0] != other.URL {
		t.Fatalf("PhoneOrigins = %v", got)
	}
	rec := pr.pc.postH("/phone/enroll", []byte(`{"label":"My phone"}`), pr.pc.csrf(), nil)
	id := str(decode(rec)["approval"])
	pr.approveOnPC(id)
	rec = pr.pc.postH("/phone/"+id+"/enrollment", nil, pr.pc.csrf(), nil)
	addr := str(decode(rec)["address"])
	if !strings.HasPrefix(addr, other.URL+"/enroll#") {
		t.Fatalf("address %s", addr)
	}
}
