package main

import (
	"bytes"
	"io"
	"regexp"
)

// The helper holds no vault secrets, so it cannot redact by value. This
// filter masks well-known secret shapes in script output before it leaves the
// helper. It is a first line only: chapd runs its registry redaction (exact
// values from the vault) on everything it receives.

const (
	redacted     = "[REDACTED]"
	maxLineBytes = 64 << 10
)

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}`),                              // GitHub tokens
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}`),                            // fine-grained PAT
	regexp.MustCompile(`\bchap_orch_[A-Za-z0-9_-]{16,}`),                            // orchestrator token (ADR-007)
	regexp.MustCompile(`\blg1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),                     // execution grant
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*`), // JWT
	regexp.MustCompile(`AGE-SECRET-KEY-1[A-Z0-9]{20,}`),                             // age identity
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),                                      // AWS access key id
	regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}`),                    // Authorization header
	regexp.MustCompile(`(://[^/\s:@]+:)[^@\s/]+(@)`),                                // user:password@ in a URL
}

// name=value or name: value where the name says it is a secret.
var namedSecret = regexp.MustCompile(`(?i)(\b[A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|authorization)[A-Za-z0-9_.-]*\b\s*[:=]\s*)("[^"]*"|'[^']*'|\S+)`)

var (
	pemBegin = []byte("-----BEGIN ")
	pemKey   = []byte("PRIVATE KEY-----")
	pemEnd   = []byte("-----END ")
)

func redactLine(line string) string {
	for _, re := range secretPatterns {
		if re.NumSubexp() == 2 {
			line = re.ReplaceAllString(line, "${1}"+redacted+"${2}")
		} else {
			line = re.ReplaceAllString(line, redacted)
		}
	}
	return namedSecret.ReplaceAllString(line, "${1}"+redacted)
}

// lineRedactor is an io.WriteCloser that redacts line by line and writes whole
// lines to out. A PEM private-key block is dropped from its BEGIN to its END
// line. A line longer than maxLineBytes is cut and its remainder discarded, so
// a secret split across the cut is never half-written. Close flushes the last
// partial line.
type lineRedactor struct {
	out      io.Writer
	buf      []byte
	inPEM    bool
	overflow bool
	err      error
}

func newLineRedactor(out io.Writer) *lineRedactor { return &lineRedactor{out: out} }

func (r *lineRedactor) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 && r.err == nil {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			r.add(p)
			break
		}
		r.add(p[:i])
		r.flushLine(true)
		p = p[i+1:]
	}
	return n, r.err
}

func (r *lineRedactor) add(p []byte) {
	if r.overflow {
		return
	}
	if len(r.buf)+len(p) > maxLineBytes {
		r.overflow = true
		r.buf = r.buf[:0]
		return
	}
	r.buf = append(r.buf, p...)
}

func (r *lineRedactor) flushLine(newline bool) {
	line := bytes.TrimSuffix(r.buf, []byte{'\r'})
	var text string
	switch {
	case r.overflow:
		text = "[line too long, dropped]"
	case r.inPEM:
		text = redacted
		if bytes.Contains(line, pemEnd) {
			r.inPEM = false
		}
	case bytes.Contains(line, pemBegin) && bytes.Contains(line, pemKey):
		text = redacted
		r.inPEM = !bytes.Contains(line, pemEnd)
	default:
		text = redactLine(string(line))
	}
	r.buf, r.overflow = r.buf[:0], false
	if newline {
		text += "\n"
	}
	_, r.err = io.WriteString(r.out, text)
}

// Close writes any unterminated final line.
func (r *lineRedactor) Close() error {
	if (len(r.buf) > 0 || r.overflow) && r.err == nil {
		r.flushLine(false)
	}
	return r.err
}
