package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/grant"
)

// The scratch runbook: the test binary itself, re-run with
// CHAP_HOST_TEST_HELPER=1. It reads the "script" from stdin and acts on its
// first word. No real deploy script is ever involved.
func TestMain(m *testing.M) {
	if os.Getenv("CHAP_HOST_TEST_HELPER") == "1" {
		os.Exit(helperMain())
	}
	os.Exit(m.Run())
}

func helperMain() int {
	raw, _ := io.ReadAll(os.Stdin)
	script := strings.TrimSpace(string(raw))
	word, rest, _ := strings.Cut(script, " ")
	switch word {
	case "echo":
		fmt.Printf("ran: %s | args=%s\n", rest, strings.Join(os.Args[2:], ","))
	case "fail":
		fmt.Println("about to fail")
		return 3
	case "sleep":
		time.Sleep(time.Minute)
	case "block": // wait until the file named in rest exists
		fmt.Println("started")
		for {
			if _, err := os.Stat(rest); err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	case "env":
		fmt.Printf("gh_var_present=%v helper=%s\n", os.Getenv("GH_TOKEN") != "", os.Getenv("CHAP_HOST_TEST_HELPER"))
	case "secrets":
		fmt.Println("ghp_" + strings.Repeat("A1", 12))
		fmt.Println("DB_PASSWORD=hunter2hunter2")
		fmt.Println("postgres://app:s3cretpw@127.0.0.1:5432/db")
		fmt.Println("-----BEGIN OPENSSH PRIVATE KEY-----")
		fmt.Println("b3BlbnNzaC1rZXktdjEAAAAA")
		fmt.Println("-----END OPENSSH PRIVATE KEY-----")
		fmt.Println("done")
	default:
		fmt.Fprintf(os.Stderr, "unknown scratch script %q\n", word)
		return 9
	}
	return 0
}

// scratch is a runner over scratch scripts with a key pair we hold.
type scratch struct {
	t        *testing.T
	priv     ed25519.PrivateKey
	pub      ed25519.PublicKey
	dir      string
	tempRoot string
	runner   *Runner
	launched atomic.Int32
	logBuf   *syncBuffer
	timeout  time.Duration
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// newScratch builds a runner whose deploy and logs.pilot runbooks both run
// the scratch script at <dir>/<name>.sh. Pass nil for sources to configure both.
func newScratch(t *testing.T, script string, timeout time.Duration) *scratch {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := &scratch{t: t, pub: pub, priv: priv, dir: t.TempDir(), logBuf: &syncBuffer{}, timeout: timeout}
	s.tempRoot = filepath.Join(s.dir, "tmp")
	s.writeScript("deploy", script)
	s.writeScript("logs.pilot", script)
	s.runner = s.build(map[string]string{"deploy": s.path("deploy"), "logs.pilot": s.path("logs.pilot")})
	return s
}

func (s *scratch) build(sources map[string]string) *Runner {
	s.t.Helper()
	v, err := grant.NewVerifier(s.pub, grant.NewMemoryNonces())
	if err != nil {
		s.t.Fatal(err)
	}
	table := map[string]Runbook{}
	for _, name := range grant.Names() {
		table[name] = Runbook{
			Source:  sources[name],
			Timeout: s.timeout,
			Env:     []string{"CHAP_HOST_TEST_HELPER=1"},
			Argv: func(args []string) []string {
				s.launched.Add(1)
				return append([]string{os.Args[0], "scratch"}, args...)
			},
		}
	}
	r, err := NewRunner(v, table, s.tempRoot, slog.New(slog.NewTextHandler(s.logBuf, nil)))
	if err != nil {
		s.t.Fatal(err)
	}
	return r
}

func (s *scratch) path(name string) string { return filepath.Join(s.dir, name+".sh") }

func (s *scratch) writeScript(name, content string) {
	s.t.Helper()
	if err := os.WriteFile(s.path(name), []byte(content), 0o600); err != nil {
		s.t.Fatal(err)
	}
}

const testSHA = "0123456789abcdef0123456789abcdef01234567"

// grantFor returns a valid unsigned deploy grant for the current script.
func (s *scratch) grantFor(runbook string) grant.Grant {
	s.t.Helper()
	n, err := grant.NewNonce()
	if err != nil {
		s.t.Fatal(err)
	}
	script, err := os.ReadFile(s.path(runbook))
	if err != nil {
		s.t.Fatal(err)
	}
	g := grant.Grant{
		Op: "deploy", Runbook: runbook,
		OpHash:       grant.HashBytes([]byte("op " + n)),
		RunID:        "r-test01",
		ScriptSHA256: grant.HashBytes(script),
		Args:         map[string]string{"sha": testSHA},
		Nonce:        n,
		IssuedAt:     time.Now().Unix(),
		ExpiresAt:    time.Now().Add(time.Minute).Unix(),
	}
	if runbook == "logs.pilot" {
		g.Op, g.Args = "logs", map[string]string{"source": "web"}
	}
	return g
}

func (s *scratch) token(g grant.Grant) string {
	s.t.Helper()
	tok, err := grant.Sign(s.priv, g)
	if err != nil {
		s.t.Fatal(err)
	}
	return tok
}

func (s *scratch) run(token string) (Outcome, string) {
	var out bytes.Buffer
	o := s.runner.Run(context.Background(), token, &out)
	return o, out.String()
}
