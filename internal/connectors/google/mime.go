package google

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"mime"
	"strings"
)

// Attachment is one file of a message. Data is the content; SHA256 is its
// lower-case hex digest.
type Attachment struct {
	Name   string
	Data   []byte
	SHA256 string
}

// Message is what [Message.Render] turns into RFC 5322 bytes.
type Message struct {
	From        string
	To, Cc, Bcc []string
	Subject     string
	Body        string
	Attachments []Attachment
	// Boundary seeds the multipart boundary; it must be the same in Check and
	// Execute (the request id).
	Boundary string
}

// Render returns the exact bytes that go to Gmail as `raw`. It is a pure
// function of the Message: no clock, no random number. That is what lets the
// card carry the SHA-256 of the message before it exists: Check and Execute
// both render it, and the bytes are the same.
//
// Date and Message-ID are left out; Gmail adds both when it sends
// `[INFERENCE: Gmail API behaviour, not checked against the live service]`.
// The body is text/plain, UTF-8, base64 so no byte of it is altered by a line
// rule, with CRLF line ends.
func (m Message) Render() []byte {
	var b bytes.Buffer
	hdr := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	hdr("From", m.From)
	hdr("To", strings.Join(m.To, ",\r\n "))
	if len(m.Cc) > 0 {
		hdr("Cc", strings.Join(m.Cc, ",\r\n "))
	}
	if len(m.Bcc) > 0 {
		hdr("Bcc", strings.Join(m.Bcc, ",\r\n "))
	}
	hdr("Subject", encodeSubject(m.Subject))
	hdr("MIME-Version", "1.0")

	text := base64Lines([]byte(strings.ReplaceAll(m.Body, "\n", "\r\n")))
	if len(m.Attachments) == 0 {
		hdr("Content-Type", `text/plain; charset="UTF-8"`)
		hdr("Content-Transfer-Encoding", "base64")
		b.WriteString("\r\n")
		b.WriteString(text)
		return b.Bytes()
	}

	sum := sha256.Sum256([]byte("chaperone-boundary:" + m.Boundary))
	boundary := "=_chaperone_" + hex.EncodeToString(sum[:12])
	hdr("Content-Type", `multipart/mixed; boundary="`+boundary+`"`)
	b.WriteString("\r\n")
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/plain; charset=\"UTF-8\"\r\nContent-Transfer-Encoding: base64\r\n\r\n")
	b.WriteString(text)
	for _, a := range m.Attachments {
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString(`Content-Type: application/octet-stream; name="` + a.Name + "\"\r\n")
		b.WriteString(`Content-Disposition: attachment; filename="` + a.Name + "\"\r\n")
		b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
		b.WriteString(base64Lines(a.Data))
	}
	b.WriteString("--" + boundary + "--\r\n")
	return b.Bytes()
}

// SumHex returns the lower-case hex SHA-256 of data.
func SumHex(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

// encodeSubject leaves a printable-ASCII subject alone and encodes any other as
// RFC 2047 encoded-words (Go's encoder folds long values itself). Check has
// already refused control characters.
func encodeSubject(s string) string {
	for _, r := range s {
		if r > 0x7e {
			return mime.BEncoding.Encode("utf-8", s)
		}
	}
	return s
}

// base64Lines encodes data as standard base64 in 76-character lines, each
// ending CRLF; the last line ends CRLF too, and empty data gives an empty
// string plus CRLF.
func base64Lines(data []byte) string {
	enc := base64.StdEncoding.EncodeToString(data)
	var sb strings.Builder
	for len(enc) > 76 {
		sb.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	sb.WriteString(enc + "\r\n")
	return sb.String()
}
