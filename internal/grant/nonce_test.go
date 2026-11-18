package grant

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMemoryNoncesExpire(t *testing.T) {
	m := NewMemoryNonces()
	n := strings.Repeat("a", 22)
	if err := m.Consume(n, t0.Add(time.Minute), t0); err != nil {
		t.Fatal(err)
	}
	if err := m.Consume(n, t0.Add(time.Minute), t0.Add(time.Second)); !errors.Is(err, ErrReplay) {
		t.Fatalf("got %v", err)
	}
	// After exp the grant itself is refused by the clock; the entry is pruned.
	if err := m.Consume(n, t0.Add(3*time.Minute), t0.Add(2*time.Minute)); err != nil {
		t.Fatalf("pruned nonce still blocked: %v", err)
	}
}

func TestFileNoncesSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "nonces.jsonl")
	a, b := strings.Repeat("a", 22), strings.Repeat("b", 22)
	s, err := OpenFileNonces(path, t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Consume(a, t0.Add(time.Minute), t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Consume(b, t0.Add(10*time.Second), t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Consume(a, t0.Add(time.Minute), t0); !errors.Is(err, ErrReplay) {
		t.Fatalf("same process: %v", err)
	}
	s.Close()

	s, err = OpenFileNonces(path, t0.Add(20*time.Second)) // b has expired, a has not
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Consume(a, t0.Add(time.Minute), t0.Add(20*time.Second)); !errors.Is(err, ErrReplay) {
		t.Fatalf("after restart: %v", err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), b) {
		t.Fatalf("expired nonce survived compaction: %s", raw)
	}
}

func TestFileNoncesTornTailAndCorruption(t *testing.T) {
	dir := t.TempDir()
	a := strings.Repeat("a", 22)
	good := `{"n":"` + a + `","e":` + "1793000000" + `}` + "\n"

	torn := filepath.Join(dir, "torn")
	if err := os.WriteFile(torn, []byte(good+`{"n":"bbbbbbbbbbbbbbbbbbbbbb","e":17`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenFileNonces(torn, time.Unix(1792000000, 0))
	if err != nil {
		t.Fatalf("torn tail should be dropped: %v", err)
	}
	s.Close()

	for name, content := range map[string]string{
		"garbage line":  good + "not json\n",
		"unknown field": `{"n":"` + a + `","e":1,"x":1}` + "\n",
		"bad nonce":     `{"n":"short","e":1793000000}` + "\n",
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFileNonces(p, time.Unix(1792000000, 0)); err == nil {
			t.Errorf("%s: opened a corrupt file", name)
		}
	}
}

func TestFileNoncesVerifierReplayAcrossRestart(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(t.TempDir(), "n.jsonl")
	var cur *FileNonces
	open := func() *Verifier {
		s, err := OpenFileNonces(path, f.now)
		if err != nil {
			t.Fatal(err)
		}
		cur = s
		v, _ := NewVerifier(f.pub, s)
		v.Now = func() time.Time { return f.now }
		return v
	}
	tok := f.sign(t, f.grant(t))
	if _, err := open().Verify(tok); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileNonces(path, f.now); err == nil {
		t.Fatal("a second open of a held nonce file succeeded")
	}
	cur.Close() // the helper restarts
	_, err := open().Verify(tok)
	cur.Close()
	wantRefusal(t, err, ErrReplay)
}

func TestFileNoncesWriteFailureFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "n.jsonl")
	s, err := OpenFileNonces(path, t0)
	if err != nil {
		t.Fatal(err)
	}
	s.Close() // writes now fail
	err = s.Consume(strings.Repeat("a", 22), t0.Add(time.Minute), t0)
	if err == nil || errors.Is(err, ErrReplay) {
		t.Fatalf("want a store error, got %v", err)
	}
	if err := s.Consume(strings.Repeat("b", 22), t0.Add(time.Minute), t0); err == nil {
		t.Fatal("store kept accepting after a failed write")
	}
}
