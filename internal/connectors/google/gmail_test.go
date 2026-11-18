package google

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/connectors/google/googletest"
)

func cardHash(t *testing.T, ev string) string {
	t.Helper()
	for _, l := range strings.Split(ev, "\n") {
		if _, after, ok := strings.Cut(l, "SHA-256 "); ok && strings.HasPrefix(l, "Rendered message") {
			return strings.TrimSpace(after)
		}
	}
	t.Fatalf("no rendered-message hash in the evidence:\n%s", ev)
	return ""
}

func TestMailSendExactlyAsShown(t *testing.T) {
	r := newRig(t, true)
	ctx := context.Background()
	att := []byte("quarterly,numbers\n1,2\n")
	sum := r.stage(att)
	p := okMail()
	p["cc"] = []any{"ops@acme.example"}
	p["subject"] = "Quarterly numbers \u2014 draft"
	p["attachments"] = []any{map[string]any{"name": "numbers.csv", "sha256": sum}}
	rq := mailReq(p)

	cr, err := r.gmail.Check(ctx, rq)
	if err != nil {
		t.Fatal(err)
	}
	if len(cr.Evidence) != 1 {
		t.Fatalf("evidence: %+v", cr.Evidence)
	}
	ev := cr.Evidence[0].Text
	if !strings.Contains(ev, sum) || !strings.Contains(ev, "numbers.csv") {
		t.Errorf("the attachment SHA-256 must be on the card evidence:\n%s", ev)
	}
	want := cardHash(t, ev)

	out, err := r.gmail.Execute(ctx, rq)
	if err != nil || out.Failed || out.Unconfirmed {
		t.Fatalf("%+v %v", out, err)
	}
	sent := r.fake.Sent()
	if len(sent) != 1 {
		t.Fatalf("%d messages sent", len(sent))
	}
	got := sha256.Sum256(sent[0].Raw)
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("the hash of the bytes Gmail got is not the hash on the card")
	}
	if out.Result["rendered_sha256"] != want || out.ExternalRef != "gmail:message/msg1" {
		t.Errorf("%+v", out)
	}

	// The bytes are what the card says: parse them back.
	m, err := mail.ReadMessage(bytes.NewReader(sent[0].Raw))
	if err != nil {
		t.Fatal(err)
	}
	if m.Header.Get("From") != "operator@example.com" {
		t.Errorf("From %q", m.Header.Get("From"))
	}
	for _, h := range []string{"Date", "Message-Id"} {
		if m.Header.Get(h) != "" {
			t.Errorf("%s must be left to Gmail so the bytes stay a function of the request", h)
		}
	}
	tos, _ := m.Header.AddressList("To")
	ccs, _ := m.Header.AddressList("Cc")
	if len(tos) != 1 || tos[0].Address != "gilliano@example.com" || len(ccs) != 1 || ccs[0].Address != "ops@acme.example" {
		t.Errorf("recipients: %v %v", tos, ccs)
	}
	subj, err := new(mime.WordDecoder).DecodeHeader(m.Header.Get("Subject"))
	if err != nil || subj != p["subject"] {
		t.Errorf("subject %q %v", subj, err)
	}
	mt, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/mixed" {
		t.Fatalf("%s %v", mt, err)
	}
	mr := multipart.NewReader(m.Body, params["boundary"])
	var parts []string
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(base64.NewDecoder(base64.StdEncoding, strings.NewReader(readAll(part))))
		parts = append(parts, string(b))
		if part.FileName() != "" && part.FileName() != "numbers.csv" {
			t.Errorf("filename %q", part.FileName())
		}
	}
	if len(parts) != 2 || parts[0] != strings.ReplaceAll(p["body"].(string), "\n", "\r\n") || parts[1] != string(att) {
		t.Errorf("parts: %q", parts)
	}
}

func readAll(r io.Reader) string { b, _ := io.ReadAll(r); return string(b) }

func TestMailRefusedBeforeACardExists(t *testing.T) {
	r := newRig(t, true)
	ctx := context.Background()
	big := bytes.Repeat([]byte("x"), MaxAttachmentBytes+1)
	bigSum := r.stage(big)
	secretFile := r.stage([]byte("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n-----END OPENSSH PRIVATE KEY-----\n"))
	okSum := r.stage([]byte("fine"))
	ghTok := "ghp_" + strings.Repeat("a", 36)
	cases := []struct {
		name   string
		mut    func(p map[string]any)
		target string
		code   string
		why    string
	}{
		{"recipient off the list", func(p map[string]any) { p["to"] = []any{"attacker@example.net"} }, "", "OP_POLICY_REFUSED", "allowlist"},
		{"one bad among good", func(p map[string]any) { p["to"] = []any{"gilliano@example.com", "x@example.net"} }, "", "OP_POLICY_REFUSED", "x@example.net"},
		{"bcc off the list", func(p map[string]any) { p["bcc"] = []any{"x@example.net"} }, "", "OP_POLICY_REFUSED", "allowlist"},
		{"suffix is not the domain", func(p map[string]any) { p["to"] = []any{"x@evil.acme.example"} }, "", "OP_POLICY_REFUSED", "allowlist"},
		{"prefix is not the domain", func(p map[string]any) { p["to"] = []any{"x@notacme.example"} }, "", "OP_POLICY_REFUSED", "allowlist"},
		{"display name", func(p map[string]any) { p["to"] = []any{"Gil <gilliano@example.com>"} }, "", "OP_PARAMS_INVALID", "plain"},
		{"upper case", func(p map[string]any) { p["to"] = []any{"Gilliano@example.com"} }, "", "OP_PARAMS_INVALID", "plain"},
		{"header injection in to", func(p map[string]any) { p["to"] = []any{"gilliano@example.com\r\nBcc: x@example.net"} }, "", "OP_PARAMS_INVALID", "plain"},
		{"comma list in one address", func(p map[string]any) { p["to"] = []any{"gilliano@example.com,x@example.net"} }, "", "OP_PARAMS_INVALID", "plain"},
		{"look-alike letter", func(p map[string]any) { p["to"] = []any{"g\u0456lliano@example.com"} }, "", "OP_PARAMS_INVALID", "plain"},
		{"duplicate", func(p map[string]any) { p["to"] = []any{"gilliano@example.com", "gilliano@example.com"} }, "", "OP_PARAMS_INVALID", "twice"},
		{"no recipient", func(p map[string]any) { delete(p, "to") }, "", "OP_PARAMS_INVALID", "recipient"},
		{"header injection in subject", func(p map[string]any) { p["subject"] = "hi\r\nBcc: x@example.net" }, "", "OP_PARAMS_INVALID", "control"},
		{"invisible character", func(p map[string]any) { p["body"] = "pay now\u202Edoc.exe" }, "", "OP_PARAMS_INVALID", "invisible"},
		{"unknown param", func(p map[string]any) { p["reply_to"] = "x@example.net" }, "", "OP_PARAMS_INVALID", "unknown param"},
		{"secret in body", func(p map[string]any) { p["body"] = "the token is " + ghTok }, "", "REDACTION_BLOCKED", "github-token"},
		{"secret in subject", func(p map[string]any) { p["subject"] = ghTok }, "", "REDACTION_BLOCKED", "subject"},
		{"registered secret in body", func(p map[string]any) { p["body"] = "key " + googletest.ClientSecret }, "", "REDACTION_BLOCKED", "rule"},
		{"another account", func(p map[string]any) {}, "ceo@example.com", "OP_POLICY_REFUSED", "connected as operator@example.com"},
		{"attachment not staged", func(p map[string]any) {
			p["attachments"] = []any{map[string]any{"name": "a.txt", "sha256": strings.Repeat("0", 64)}}
		}, "", "OP_PARAMS_INVALID", "no staged file"},
		{"attachment hash is not the content's", func(p map[string]any) {
			p["attachments"] = []any{map[string]any{"name": "a.txt", "sha256": okSum[:63] + "0"}}
		}, "", "OP_PARAMS_INVALID", "no staged file"},
		{"attachment too big", func(p map[string]any) {
			p["attachments"] = []any{map[string]any{"name": "a.txt", "sha256": bigSum}}
		}, "", "OP_PARAMS_INVALID", "too large"},
		{"secret inside an attachment", func(p map[string]any) {
			p["attachments"] = []any{map[string]any{"name": "notes.txt", "sha256": secretFile}}
		}, "", "REDACTION_BLOCKED", "pem"},
		{"executable attachment", func(p map[string]any) {
			p["attachments"] = []any{map[string]any{"name": "setup.exe", "sha256": okSum}}
		}, "", "OP_PARAMS_INVALID", "executable"},
		{"path in attachment name", func(p map[string]any) {
			p["attachments"] = []any{map[string]any{"name": "../../vault/github-app-key.age", "sha256": okSum}}
		}, "", "OP_PARAMS_INVALID", "plain letters"},
		{"attachment extra key", func(p map[string]any) {
			p["attachments"] = []any{map[string]any{"name": "a.txt", "sha256": okSum, "path": "C:/secrets"}}
		}, "", "OP_PARAMS_INVALID", "unknown param"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := okMail()
			c.mut(p)
			rq := mailReq(p)
			if c.target != "" {
				rq.Target.Ref = c.target
			}
			_, err := r.gmail.Check(ctx, rq)
			ref := wantRefusal(t, err, c.code)
			if !strings.Contains(ref.Why, c.why) {
				t.Errorf("why %q does not mention %q", ref.Why, c.why)
			}
			if strings.Contains(ref.Why, ghTok) || strings.Contains(ref.Why, googletest.ClientSecret) {
				t.Errorf("the refusal quotes the secret: %s", ref.Why)
			}
		})
	}
	if n := len(r.fake.Sent()); n != 0 {
		t.Fatalf("%d messages were sent", n)
	}
}

func TestMailRefusedForAProjectWithNoGoogleBlock(t *testing.T) {
	r := newRig(t, true)
	rq := mailReq(okMail())
	rq.Project = "other-shop"
	_, err := r.gmail.Check(context.Background(), rq)
	wantRefusal(t, err, "OP_POLICY_REFUSED")
	r.pol.Mail.AllowRecipients = nil
	rq.Project = testProject
	_, err = r.gmail.Check(context.Background(), rq)
	wantRefusal(t, err, "OP_POLICY_REFUSED")
}

func TestMailNeedsTheGmailScope(t *testing.T) {
	r := newRig(t, true, ScopeDrive)
	_, err := r.gmail.Check(context.Background(), mailReq(okMail()))
	ref := wantRefusal(t, err, "OP_POLICY_REFUSED")
	if !strings.Contains(ref.Why, "gmail.send") {
		t.Error(ref.Why)
	}
}

func TestMailReleaseRechecksTheAllowlistAndTheAttachment(t *testing.T) {
	r := newRig(t, true)
	ctx := context.Background()
	sum := r.stage([]byte("v1"))
	p := okMail()
	p["attachments"] = []any{map[string]any{"name": "a.txt", "sha256": sum}}
	rq := mailReq(p)
	if _, err := r.gmail.Check(ctx, rq); err != nil {
		t.Fatal(err)
	}
	// After the card: the allowlist shrinks.
	r.pol.Mail.AllowRecipients = []string{"someone-else@example.com"}
	out, err := r.gmail.Execute(ctx, rq)
	if err != nil || !out.Failed || len(r.fake.Sent()) != 0 {
		t.Fatalf("a release after the allowlist changed must fail without sending: %+v %v", out, err)
	}
	// After the card: the staged file is swapped.
	r.pol.Mail.AllowRecipients = []string{"gilliano@example.com"}
	r.atts[sum] = []byte("v2-evil")
	out, _ = r.gmail.Execute(ctx, rq)
	if !out.Failed || len(r.fake.Sent()) != 0 {
		t.Fatalf("a swapped attachment must fail without sending: %+v", out)
	}
}

func TestMailSendOutcomes(t *testing.T) {
	ctx := context.Background()
	t.Run("an expired access token is renewed once", func(t *testing.T) {
		r := newRig(t, true)
		r.fake.ExpireAccess() // the vault still says it is fresh; Gmail says 401
		out, err := r.gmail.Execute(ctx, mailReq(okMail()))
		if err != nil || out.Failed || out.Unconfirmed || len(r.fake.Sent()) != 1 || r.fake.RefreshCalls() != 1 {
			t.Fatalf("%+v %v sent=%d refreshes=%d", out, err, len(r.fake.Sent()), r.fake.RefreshCalls())
		}
	})
	t.Run("a refusal is failed", func(t *testing.T) {
		r := newRig(t, true)
		r.fake.SetSendMode(googletest.SendReject)
		out, _ := r.gmail.Execute(ctx, mailReq(okMail()))
		if !out.Failed || out.Unconfirmed || len(r.fake.Sent()) != 0 {
			t.Fatalf("%+v", out)
		}
	})
	t.Run("a 503 is unconfirmed and is not retried", func(t *testing.T) {
		r := newRig(t, true)
		r.fake.SetSendMode(googletest.SendServerErr)
		out, _ := r.gmail.Execute(ctx, mailReq(okMail()))
		if !out.Unconfirmed || out.Failed || len(r.fake.Sent()) != 1 {
			t.Fatalf("%+v sent=%d", out, len(r.fake.Sent()))
		}
	})
	t.Run("a cut connection is unconfirmed and is not retried", func(t *testing.T) {
		r := newRig(t, true)
		r.fake.SetSendMode(googletest.SendDropAnswer)
		out, _ := r.gmail.Execute(ctx, mailReq(okMail()))
		if !out.Unconfirmed || len(r.fake.Sent()) != 1 {
			t.Fatalf("%+v sent=%d", out, len(r.fake.Sent()))
		}
	})
	t.Run("a revoked grant at send time is failed, with the alert", func(t *testing.T) {
		r := newRig(t, true)
		r.fake.RevokeAll()
		r.fake.ExpireAccess()
		out, _ := r.gmail.Execute(ctx, mailReq(okMail()))
		if !out.Failed || len(r.fake.Sent()) != 0 || r.alerts.count(AlertReauth) != 1 {
			t.Fatalf("%+v alerts=%v", out, r.alerts.keys)
		}
	})
	t.Run("the result never holds a token or the body", func(t *testing.T) {
		r := newRig(t, true)
		out, _ := r.gmail.Execute(ctx, mailReq(okMail()))
		s := fmt.Sprint(out.Result)
		if strings.Contains(s, "ya29.") || strings.Contains(s, "Hello from the demo") {
			t.Errorf("result: %s", s)
		}
	})
}

func TestRenderIsPure(t *testing.T) {
	m := Message{From: "a@example.com", To: []string{"b@example.com", "c@example.com"}, Subject: "S", Body: "line1\nline2", Boundary: "q-1",
		Attachments: []Attachment{{Name: "x.bin", Data: []byte{0, 1, 2, 255}, SHA256: ""}}}
	a, b := m.Render(), m.Render()
	if !bytes.Equal(a, b) {
		t.Fatal("two renders differ")
	}
	m.Body = "line1\nline3"
	if bytes.Equal(a, m.Render()) {
		t.Fatal("a changed body must change the bytes")
	}
	m.Body = "line1\nline2"
	m.Boundary = "q-2"
	if bytes.Equal(a, m.Render()) {
		t.Fatal("another request id seeds another boundary")
	}
	// A long ASCII subject stays one header; a non-ASCII one is encoded.
	plain := Message{From: "a@example.com", To: []string{"b@example.com"}, Subject: "plain", Body: "x"}.Render()
	if !bytes.Contains(plain, []byte("Subject: plain\r\n")) || bytes.Contains(plain, []byte("multipart")) {
		t.Errorf("%s", plain)
	}
}
