package vault

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestPassphraseWrapperRoundTrip(t *testing.T) {
	w, src := newTestPassphraseWrapper(testPassphrase)
	if w.Name() != PassphraseName {
		t.Fatalf("name %q", w.Name())
	}
	plain := []byte("AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ")
	blob, err := w.Wrap(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(blob, []byte("age-encryption.org/v1\n-> scrypt ")) {
		t.Errorf("the blob is not an age passphrase file: %q", blob[:40])
	}
	if bytes.Contains(blob, plain) || bytes.Contains(blob, []byte(testPassphrase)) {
		t.Error("the blob holds the key or the passphrase")
	}
	got, err := w.Unwrap(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Error("round trip changed the key")
	}
	blob2, _ := w.Wrap(plain)
	if bytes.Equal(blob, blob2) {
		t.Error("two wraps gave one blob")
	}
	if src.asked != 1 {
		t.Errorf("the passphrase was asked %d times for one operation; want once", src.asked)
	}
	if len(src.confirms) != 1 || !src.confirms[0] {
		t.Errorf("choosing a passphrase must ask for confirmation: %v", src.confirms)
	}
}

func TestPassphraseWrapperUnwrapDoesNotAskToConfirm(t *testing.T) {
	maker, _ := newTestPassphraseWrapper(testPassphrase)
	blob, err := maker.Wrap([]byte("a key worth keeping"))
	if err != nil {
		t.Fatal(err)
	}
	w, src := newTestPassphraseWrapper(testPassphrase)
	if _, err := w.Unwrap(blob); err != nil {
		t.Fatal(err)
	}
	if len(src.confirms) != 1 || src.confirms[0] {
		t.Errorf("entering a passphrase must not ask twice: %v", src.confirms)
	}
}

func TestPassphraseWrapperWrongPassphraseFailsAndIsNotKept(t *testing.T) {
	maker, _ := newTestPassphraseWrapper(testPassphrase)
	blob, _ := maker.Wrap([]byte("a key worth keeping"))

	w, src := newTestPassphraseWrapper("a different passphrase")
	for range 2 {
		out, err := w.Unwrap(blob)
		if err == nil || out != nil {
			t.Fatalf("a wrong passphrase unwrapped: %v", err)
		}
		if !errors.Is(err, errWrongPassphrase) {
			t.Errorf("got %v", err)
		}
	}
	if src.asked != 2 {
		t.Errorf("a wrong passphrase was cached: asked %d times, want 2", src.asked)
	}
	if strings.Contains(errWrongPassphrase.Error(), "a different") {
		t.Error("the error names a passphrase")
	}
}

func TestPassphraseWrapperRejectsDamagedAndOversizeBlobs(t *testing.T) {
	maker, _ := newTestPassphraseWrapper(testPassphrase)
	blob, _ := maker.Wrap([]byte("a key worth keeping"))
	w, _ := newTestPassphraseWrapper(testPassphrase)
	for name, b := range map[string][]byte{
		"empty":      nil,
		"junk":       []byte("this is not an age file"),
		"truncated":  blob[:len(blob)-5],
		"flipped":    append(append([]byte(nil), blob[:len(blob)-3]...), blob[len(blob)-3]^1, blob[len(blob)-2], blob[len(blob)-1]),
		"too large":  bytes.Repeat([]byte("x"), maxWrappedBlob+1),
		"empty file": []byte("age-encryption.org/v1\n"),
	} {
		if out, err := w.Unwrap(b); err == nil || out != nil {
			t.Errorf("%s: unwrapped", name)
		}
	}
}

func TestPassphraseWrapperEnforcesMinimumAndKeepsNothingOnFailure(t *testing.T) {
	w, src := newTestPassphraseWrapper("short one")
	if _, err := w.Wrap([]byte("k")); err == nil || !strings.Contains(err.Error(), "at least 16") {
		t.Errorf("a short passphrase was accepted: %v", err)
	}
	// Sixteen characters are enough; count characters, not bytes.
	src.pass = "çççççççççççççççç"
	if _, err := w.Wrap([]byte("k")); err != nil {
		t.Errorf("16 characters refused: %v", err)
	}
	src.pass = "fifteen chars 15"[:15]
	w.Forget()
	if _, err := w.Wrap([]byte("k")); err == nil {
		t.Error("15 characters accepted")
	}
	if _, err := w.Wrap(nil); err == nil {
		t.Error("wrapped nothing")
	}
}

func TestPassphraseWrapperSourceFailures(t *testing.T) {
	w := newPassphraseWrapper(&staticPassphrase{err: errBoom}, testWorkFactor)
	if _, err := w.Wrap([]byte("k")); !errors.Is(err, errBoom) {
		t.Errorf("Wrap: %v", err)
	}
	if _, err := w.Unwrap([]byte("age-encryption.org/v1\n")); !errors.Is(err, errBoom) {
		t.Errorf("Unwrap: %v", err)
	}
	empty := newPassphraseWrapper(&staticPassphrase{pass: ""}, testWorkFactor)
	if _, err := empty.Wrap([]byte("k")); err == nil {
		t.Error("an empty passphrase was accepted")
	}
}

func TestPassphraseWrapperForgetZeroesAndAsksAgain(t *testing.T) {
	w, src := newTestPassphraseWrapper(testPassphrase)
	blob, err := w.Wrap([]byte("a key worth keeping"))
	if err != nil {
		t.Fatal(err)
	}
	held := w.pass
	if len(held) == 0 {
		t.Fatal("nothing cached after a success")
	}
	forgetSecrets(w)
	if !bytes.Equal(held, make([]byte, len(held))) {
		t.Error("the cached passphrase was not zeroed")
	}
	if w.pass != nil {
		t.Error("the cache was not dropped")
	}
	if src.forgot != 1 {
		t.Error("the source was not told to forget")
	}
	if _, err := w.Unwrap(blob); err != nil {
		t.Fatal(err)
	}
	if src.asked != 2 {
		t.Errorf("asked %d times; the next use after Forget must ask again", src.asked)
	}
	forgetSecrets(nil)              // safe with no wrapper
	forgetSecrets(newAESWrapper(t)) // safe with a wrapper that keeps nothing
}

func TestPassphraseWrapperIsSafeForConcurrentUse(t *testing.T) {
	w, _ := newTestPassphraseWrapper(testPassphrase)
	blob, err := w.Wrap([]byte("a key worth keeping"))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := w.Unwrap(blob); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

func TestReadLine(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string
		err  string
	}{
		{"hunter2 hunter2\n", "hunter2 hunter2", ""},
		{"with crlf\r\n", "with crlf", ""},
		{"no newline at end", "no newline at end", ""},
		{"  keeps spaces  \n", "  keeps spaces  ", ""},
		{"first\nsecond\n", "first", ""},
		{"", "", "empty"},
		{"\n", "", "empty"},
		{"\r\n", "", "empty"},
		{strings.Repeat("a", maxPassphraseBytes) + "\n", strings.Repeat("a", maxPassphraseBytes), ""},
		{strings.Repeat("a", maxPassphraseBytes+1) + "\n", "", "longer"},
	} {
		got, err := readLine(strings.NewReader(c.in))
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%.20q: err %v, want %q", c.in, err, c.err)
			}
			continue
		}
		if err != nil || string(got) != c.want {
			t.Errorf("%.20q: got %q, %v", c.in, got, err)
		}
	}
}

func TestReadLineLeavesTheRestOfThePipe(t *testing.T) {
	r := strings.NewReader("line one\nline two\n")
	if _, err := readLine(r); err != nil {
		t.Fatal(err)
	}
	rest, _ := io.ReadAll(r)
	if string(rest) != "line two\n" {
		t.Errorf("read past the newline: left %q", rest)
	}
}

func TestReadLineReadError(t *testing.T) {
	if _, err := readLine(errReader{}); err == nil || errors.Is(err, io.EOF) {
		t.Errorf("got %v", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errBoom }

func TestFDPassphrase(t *testing.T) {
	s := &fdPassphrase{r: strings.NewReader(testPassphrase + "\nrest\n")}
	got, err := s.Passphrase(true) // confirm is ignored: a pipe cannot be asked twice
	if err != nil || string(got) != testPassphrase {
		t.Fatalf("got %q, %v", got, err)
	}
	clear(got) // the caller zeroes its copy; the source must not be affected
	again, err := s.Passphrase(false)
	if err != nil || string(again) != testPassphrase {
		t.Fatalf("second ask: %q, %v", again, err)
	}
	s.Forget()
	if _, err := s.Passphrase(false); err == nil {
		t.Error("a forgotten passphrase came back")
	}
	bad := &fdPassphrase{r: strings.NewReader("")}
	if _, err := bad.Passphrase(false); err == nil {
		t.Error("an empty descriptor gave a passphrase")
	}
	if _, err := bad.Passphrase(false); err == nil {
		t.Error("the failure was not remembered")
	}
}

func TestFDPassphraseOverARealPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	s := &fdPassphrase{r: r, close: r.Close}
	go func() { io.WriteString(w, testPassphrase+"\n"); w.Close() }()
	got, err := s.Passphrase(false)
	if err != nil || string(got) != testPassphrase {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestOpenPassphraseFDRefusals(t *testing.T) {
	for _, fd := range []int{-1, 1, 2} {
		if _, err := FDPassphrase(fd); err == nil {
			t.Errorf("descriptor %d accepted", fd)
		}
	}
	if _, err := FDPassphrase(987654); err == nil {
		t.Error("a descriptor that is not open was accepted")
	}
}

// fakeTerminal is a terminal with a scripted keyboard. It records the screen
// and whether echo was on at each read.
type fakeTerminal struct {
	mu         sync.Mutex
	keys       *io.PipeReader
	feed       *io.PipeWriter
	screen     bytes.Buffer
	echoOn     bool
	echoAtRead []bool
	restored   int
	noEcho     error
}

func newFakeTerminal() *fakeTerminal {
	r, w := io.Pipe()
	return &fakeTerminal{keys: r, feed: w, echoOn: true}
}

func (f *fakeTerminal) Read(p []byte) (int, error) {
	f.mu.Lock()
	f.echoAtRead = append(f.echoAtRead, f.echoOn)
	f.mu.Unlock()
	return f.keys.Read(p)
}

func (f *fakeTerminal) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.screen.Write(p)
}

func (f *fakeTerminal) Close() error { return nil }

func (f *fakeTerminal) disableEcho() (func(), error) {
	if f.noEcho != nil {
		return nil, f.noEcho
	}
	f.mu.Lock()
	f.echoOn = false
	f.mu.Unlock()
	return func() { f.mu.Lock(); f.echoOn = true; f.restored++; f.mu.Unlock() }, nil
}

func (f *fakeTerminal) shown() string { f.mu.Lock(); defer f.mu.Unlock(); return f.screen.String() }

func TestPromptOnChoosingAPassphrase(t *testing.T) {
	ft := newFakeTerminal()
	go func() { io.WriteString(ft.feed, testPassphrase+"\n"+testPassphrase+"\n") }()
	got, err := promptOn(ft, true, nil)
	if err != nil || string(got) != testPassphrase {
		t.Fatalf("got %q, %v", got, err)
	}
	if ft.restored != 1 || !ft.echoOn {
		t.Error("echo was not restored")
	}
	for _, on := range ft.echoAtRead {
		if on {
			t.Error("the terminal was read while echo was on")
		}
	}
	if strings.Contains(ft.shown(), testPassphrase) {
		t.Error("the passphrase was written to the screen")
	}
	if n := strings.Count(ft.shown(), "(not shown)"); n != 1 || !strings.Contains(ft.shown(), "Type it again") {
		t.Errorf("prompts: %q", ft.shown())
	}
}

func TestPromptOnMismatch(t *testing.T) {
	ft := newFakeTerminal()
	go func() { io.WriteString(ft.feed, testPassphrase+"\nsomething else entirely\n") }()
	got, err := promptOn(ft, true, nil)
	if err == nil || got != nil || !strings.Contains(err.Error(), "differ") {
		t.Fatalf("got %q, %v", got, err)
	}
	if !ft.echoOn {
		t.Error("echo not restored")
	}
}

func TestPromptOnEnteringOnceAsksOnce(t *testing.T) {
	ft := newFakeTerminal()
	go func() { io.WriteString(ft.feed, testPassphrase+"\n") }()
	got, err := promptOn(ft, false, nil)
	if err != nil || string(got) != testPassphrase {
		t.Fatalf("got %q, %v", got, err)
	}
	if strings.Contains(ft.shown(), "again") {
		t.Error("entering a passphrase asked twice")
	}
}

func TestPromptOnRefusesWithoutEcho(t *testing.T) {
	ft := newFakeTerminal()
	ft.noEcho = errBoom
	got, err := promptOn(ft, false, nil)
	if err == nil || got != nil {
		t.Fatalf("got %q, %v", got, err)
	}
	if ft.shown() != "" {
		t.Errorf("prompted on a terminal that would echo: %q", ft.shown())
	}
}

func TestPromptOnInterruptRestoresTheTerminal(t *testing.T) {
	ft := newFakeTerminal()
	intr := make(chan os.Signal, 1)
	res := make(chan error, 1)
	go func() { _, err := promptOn(ft, false, intr); res <- err }()
	deadline := time.After(5 * time.Second)
	for !strings.Contains(ft.shown(), "passphrase") { // the prompt is up
		select {
		case <-deadline:
			t.Fatal("no prompt")
		case <-time.After(time.Millisecond):
		}
	}
	intr <- os.Interrupt
	select {
	case err := <-res:
		if !errors.Is(err, errInterrupted) {
			t.Errorf("got %v", err)
		}
	case <-deadline:
		t.Fatal("the prompt ignored the interrupt")
	}
	if !ft.echoOn || ft.restored != 1 {
		t.Error("echo was left off after an interrupt")
	}
	ft.feed.Close() // release the blocked reader
}

func TestTerminalPassphraseWithoutATerminal(t *testing.T) {
	old := openTerminal
	openTerminal = func() (terminal, error) { return nil, errNoTerminal }
	t.Cleanup(func() { openTerminal = old })
	w := newPassphraseWrapper(TerminalPassphrase(), testWorkFactor)
	_, err := w.Wrap([]byte("k"))
	if err == nil || !strings.Contains(err.Error(), "descriptor") {
		t.Errorf("got %v", err)
	}
}

// TestTerminalPassphraseOnARealTerminal needs a real terminal, so it only runs
// when VAULT_TEST_REAL_TTY is set, inside a pty:
//
//	printf 'correct horse battery staple\ncorrect horse battery staple\n' | \
//	  VAULT_TEST_REAL_TTY=1 script -qc './vault.test -test.run RealTerminal -test.v' /dev/null
//
// The test checks the passphrase arrives; the person running it checks that
// the output does not show it. docs/adr/003-vault.md lists it in the manual
// checks for macOS and Linux.
func TestTerminalPassphraseOnARealTerminal(t *testing.T) {
	if os.Getenv("VAULT_TEST_REAL_TTY") == "" {
		t.Skip("set VAULT_TEST_REAL_TTY and run inside a pty (see the comment above)")
	}
	got, err := TerminalPassphrase().Passphrase(true)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != testPassphrase {
		t.Errorf("got %d bytes that are not the expected passphrase", len(got))
	}
}

func TestUnwrapRefusesAKeyFileThatAsksForTooMuchWork(t *testing.T) {
	maker, _ := newTestPassphraseWrapper(testPassphrase)
	blob, err := maker.Wrap([]byte("a key worth keeping"))
	if err != nil {
		t.Fatal(err)
	}
	// Rewrite the work factor in the header, as a planted file would. The
	// check comes before any scrypt, so this returns at once; with a cap of 22
	// it would try to allocate 4 GiB first.
	planted := bytes.Replace(blob, []byte(" 10\n"), []byte(" 21\n"), 1)
	if bytes.Equal(planted, blob) {
		t.Fatal("test could not find the work factor in the header")
	}
	w, _ := newTestPassphraseWrapper(testPassphrase)
	start := time.Now()
	if out, err := w.Unwrap(planted); !errors.Is(err, errTooMuchWork) || out != nil {
		t.Errorf("got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("took %s: scrypt ran", time.Since(start))
	}
	if maxUnwrapWorkFactor > 20 || maxUnwrapWorkFactor < passphraseWorkFactor {
		t.Errorf("cap %d must be between what is written (%d) and 20", maxUnwrapWorkFactor, passphraseWorkFactor)
	}
}

func TestMinimumPassphraseIsSixteen(t *testing.T) {
	if minPassphraseChars != 16 {
		t.Errorf("minimum is %d", minPassphraseChars)
	}
}

func TestInterruptSignalsCoverTheWaysAPromptEnds(t *testing.T) {
	have := map[os.Signal]bool{}
	for _, s := range interruptSignals {
		have[s] = true
	}
	for _, want := range []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT} {
		if !have[want] {
			t.Errorf("%v does not end a prompt", want)
		}
	}
}

func TestOpenPassphraseFDStdinKinds(t *testing.T) {
	old := os.Stdin
	t.Cleanup(func() { os.Stdin = old })

	// A pipe on descriptor 0: accepted.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	os.Stdin = r
	s, err := FDPassphrase(0)
	if err != nil {
		t.Fatalf("a pipe on descriptor 0: %v", err)
	}
	go func() { io.WriteString(w, testPassphrase+"\n"); w.Close() }()
	if got, err := s.Passphrase(false); err != nil || string(got) != testPassphrase {
		t.Errorf("got %q, %v", got, err)
	}

	// A regular file on descriptor 0 (< file): accepted.
	f, err := os.CreateTemp(t.TempDir(), "pass")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	io.WriteString(f, testPassphrase+"\n")
	f.Seek(0, io.SeekStart)
	os.Stdin = f
	s, err = FDPassphrase(0)
	if err != nil {
		t.Fatalf("a file on descriptor 0: %v", err)
	}
	if got, err := s.Passphrase(false); err != nil || string(got) != testPassphrase {
		t.Errorf("got %q, %v", got, err)
	}

	// A device that is not a terminal: refused.
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	os.Stdin = null
	if _, err := FDPassphrase(0); err == nil || !strings.Contains(err.Error(), "not a pipe") {
		t.Errorf("%s on descriptor 0: %v", os.DevNull, err)
	}
}

func TestIsTerminalIsFalseForAFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTerminal(f) {
		t.Error("a regular file is a terminal")
	}
}
