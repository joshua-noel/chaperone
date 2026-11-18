package main

import (
	"bytes"
	"strings"
	"testing"
)

func redactAll(t *testing.T, chunks ...string) string {
	t.Helper()
	var out bytes.Buffer
	r := newLineRedactor(&out)
	for _, c := range chunks {
		if _, err := r.Write([]byte(c)); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestRedactShapes(t *testing.T) {
	cases := map[string]string{
		"ghp_" + strings.Repeat("a1", 15):                            "[REDACTED]",
		"github_pat_" + strings.Repeat("Z9_", 10):                    "[REDACTED]",
		"chap_orch_" + strings.Repeat("Qw", 22):                      "[REDACTED]",
		"grant lg1.eyJ2IjoxfQ.c2ln":                                  "grant [REDACTED]",
		"jwt eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJydW46MSJ9.c2lnbmF0dXJl": "jwt [REDACTED]",
		"AGE-SECRET-KEY-1" + strings.Repeat("Q", 30):                 "[REDACTED]",
		"key AKIAABCDEFGHIJKLMNOP end":                               "key [REDACTED] end",
		"Authorization: Bearer abcdefghijklmnop1234":                 "Authorization: [REDACTED]",
		"DB_PASSWORD=hunter2":                                        "DB_PASSWORD=[REDACTED]",
		`api_key: "abc def"`:                                         "api_key: [REDACTED]",
		"url postgres://user:pw@host:5432/db":                        "url postgres://user:[REDACTED]@host:5432/db",
		"migration 20261024 applied, 3 tables":                       "migration 20261024 applied, 3 tables",
		"deployed 0123456789abcdef0123456789abcdef01234567 to pilot": "deployed 0123456789abcdef0123456789abcdef01234567 to pilot",
	}
	for in, want := range cases {
		if got := redactAll(t, in+"\n"); got != want+"\n" {
			t.Errorf("%q\n got %q\nwant %q", in, got, want+"\n")
		}
	}
}

func TestRedactChunkBoundaries(t *testing.T) {
	tok := "ghp_" + strings.Repeat("x9", 15)
	// The token is split across writes; nothing partial may come out.
	got := redactAll(t, "tok="+tok[:7], tok[7:]+"\nnext line\npartial", " tail")
	if strings.Contains(got, "ghp_") || strings.Contains(got, "x9x9") {
		t.Fatalf("split token leaked: %q", got)
	}
	if got != "tok=[REDACTED]\nnext line\npartial tail" {
		t.Fatalf("got %q", got)
	}
	if got := redactAll(t, "a\r\nb\r\n"); got != "a\nb\n" {
		t.Fatalf("CRLF: %q", got)
	}
}

func TestRedactPEMBlock(t *testing.T) {
	in := "before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nAAAA\n-----END RSA PRIVATE KEY-----\nafter\n"
	want := "before\n[REDACTED]\n[REDACTED]\n[REDACTED]\n[REDACTED]\nafter\n"
	if got := redactAll(t, in); got != want {
		t.Fatalf("got %q", got)
	}
	// A public certificate is not a private key.
	cert := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	if got := redactAll(t, cert); got != cert {
		t.Fatalf("certificate changed: %q", got)
	}
}

func TestRedactLongLine(t *testing.T) {
	long := strings.Repeat("A", maxLineBytes+10)
	got := redactAll(t, "ok\n", long[:40000], long[40000:], "\nafter\n")
	if got != "ok\n[line too long, dropped]\nafter\n" {
		t.Fatalf("got %q", got)
	}
}
