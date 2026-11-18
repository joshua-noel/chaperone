package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func absPath(name string) string {
	if runtime.GOOS == "windows" {
		return `C:\chap\` + name
	}
	return "/chap/" + name
}

func writeConfig(t *testing.T, body string) string {
	p := filepath.Join(t.TempDir(), "chap-host.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func jsonPath(p string) string { return strings.ReplaceAll(p, `\`, `\\`) }

func goodConfig(t *testing.T, mutate func(string) string) string {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	body := `{"chapd_url":"http://127.0.0.1:55398","chapd_public_key":"` + base64.RawURLEncoding.EncodeToString(pub) +
		`","chapd_token_file":"` + jsonPath(absPath("host.token")) + `","scripts":{"deploy":"` + jsonPath(absPath("pilot.sh")) + `"}}`
	if mutate != nil {
		body = mutate(body)
	}
	return writeConfig(t, body)
}

func TestLoadConfig(t *testing.T) {
	p := goodConfig(t, nil)
	c, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.StateDir != filepath.Dir(p) || c.Scripts["deploy"] != absPath("pilot.sh") {
		t.Fatalf("%+v", c)
	}
	if k, err := c.PublicKey(); err != nil || len(k) != 32 {
		t.Fatal(err)
	}
}

func TestLoadConfigRefusals(t *testing.T) {
	cases := map[string]func(string) string{
		"non-loopback url": func(s string) string { return strings.Replace(s, "127.0.0.1", "10.0.0.5", 1) },
		"https url":        func(s string) string { return strings.Replace(s, "http://", "https://", 1) },
		"url with path":    func(s string) string { return strings.Replace(s, ":55398", ":55398/x", 1) },
		"url with creds":   func(s string) string { return strings.Replace(s, "//", "//u:p@", 1) },
		"hostname":         func(s string) string { return strings.Replace(s, "127.0.0.1", "example.com", 1) },
		"short key": func(s string) string {
			return strings.Replace(s, `"chapd_public_key":"`, `"chapd_public_key":"AAAA`, 1)
		},
		"unknown runbook": func(s string) string { return strings.Replace(s, `"deploy"`, `"shell"`, 1) },
		"relative script": func(s string) string { return strings.Replace(s, jsonPath(absPath("pilot.sh")), "pilot.sh", 1) },
		"relative token":  func(s string) string { return strings.Replace(s, jsonPath(absPath("host.token")), "host.token", 1) },
		"unknown field":   func(s string) string { return strings.Replace(s, `"scripts"`, `"command":"id","scripts"`, 1) },
		"not json":        func(string) string { return "chapd_url=x" },
	}
	for name, mutate := range cases {
		if _, err := LoadConfig(goodConfig(t, mutate)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Error("missing file accepted")
	}
	for _, host := range []string{"localhost", "[::1]"} {
		if _, err := LoadConfig(goodConfig(t, func(s string) string { return strings.Replace(s, "127.0.0.1", host, 1) })); err != nil {
			t.Errorf("%s: %v", host, err)
		}
	}
}
