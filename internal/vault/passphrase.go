package vault

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"unicode/utf8"

	"filippo.io/age"
)

// PassphraseName is the [KeyWrapper.Name] of the passphrase wrapper.
const PassphraseName = "age-passphrase"

const (
	// minPassphraseChars is a floor, not a strength test. It stops a one-word
	// passphrase; it cannot tell a good twelve characters from a bad one.
	minPassphraseChars = 12
	// maxPassphraseBytes bounds what is read from a terminal or a pipe.
	maxPassphraseBytes = 1024
	// passphraseWorkFactor is the scrypt cost as a power of two (age's own
	// default: about one second on a current laptop).
	passphraseWorkFactor = 18
	// maxUnwrapWorkFactor caps the cost a blob may ask for on unwrap, so a
	// damaged or planted file cannot make chapd spend minutes in scrypt.
	maxUnwrapWorkFactor = 22
	// maxWrappedBlob bounds an age-passphrase blob. The vault wraps two keys
	// of well under 300 bytes each.
	maxWrappedBlob = 4 << 10
)

// PassphraseSource asks a person (or a pipe) for the passphrase. It is the
// only way the passphrase enters the process: never a flag, never an
// environment variable.
type PassphraseSource interface {
	// Passphrase returns a fresh copy the caller zeroes. confirm is true when
	// the passphrase is being chosen, not entered: an interactive source asks
	// twice and refuses a mismatch.
	Passphrase(confirm bool) ([]byte, error)
}

// forgetter is implemented by a source or wrapper that holds a secret in
// memory between calls.
type forgetter interface{ Forget() }

// forgetSecrets drops what a wrapper kept in memory. The vault calls it when
// an operation that needed the wrapper is over (see [Open], [Init]).
func forgetSecrets(w KeyWrapper) {
	if f, ok := w.(forgetter); ok {
		f.Forget()
	}
}

// passphraseWrapper protects the vault's keys with an age file encrypted to
// one scrypt recipient. The blob is a plain age file: `age -d` with the same
// passphrase reads it.
//
// It keeps the passphrase in memory from the first successful use until
// Forget, so the many Wrap and Unwrap calls of one operation ask once. A
// passphrase that failed is never kept.
type passphraseWrapper struct {
	src        PassphraseSource
	workFactor int

	mu   sync.Mutex
	pass []byte
}

func newPassphraseWrapper(src PassphraseSource, workFactor int) *passphraseWrapper {
	return &passphraseWrapper{src: src, workFactor: workFactor}
}

func (*passphraseWrapper) Name() string { return PassphraseName }

// use runs fn with the passphrase: the cached one, or one asked from the
// source. A fresh passphrase is cached only if fn succeeds.
func (w *passphraseWrapper) use(confirm bool, fn func(pass []byte) error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	pass, fresh := w.pass, false
	if pass == nil {
		p, err := w.src.Passphrase(confirm)
		if err != nil {
			return fmt.Errorf("vault: %s: %w", PassphraseName, err)
		}
		if len(p) == 0 {
			return fmt.Errorf("vault: %s: the passphrase is empty", PassphraseName)
		}
		pass, fresh = p, true
	}
	if err := fn(pass); err != nil {
		if fresh {
			clear(pass)
		}
		return err
	}
	if fresh {
		w.pass = pass
	}
	return nil
}

func (w *passphraseWrapper) Wrap(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("vault: %s: nothing to wrap", PassphraseName)
	}
	var out []byte
	err := w.use(true, func(pass []byte) error {
		if utf8.RuneCount(pass) < minPassphraseChars {
			return fmt.Errorf("vault: %s: the passphrase needs at least %d characters", PassphraseName, minPassphraseChars)
		}
		rcp, err := age.NewScryptRecipient(string(pass))
		if err != nil {
			return fmt.Errorf("vault: %s: %w", PassphraseName, err)
		}
		rcp.SetWorkFactor(w.workFactor)
		var buf bytes.Buffer
		aw, err := age.Encrypt(&buf, rcp)
		if err != nil {
			return fmt.Errorf("vault: %s: encrypt: %w", PassphraseName, err)
		}
		if _, err := aw.Write(plaintext); err != nil {
			return fmt.Errorf("vault: %s: encrypt: %w", PassphraseName, err)
		}
		if err := aw.Close(); err != nil {
			return fmt.Errorf("vault: %s: encrypt: %w", PassphraseName, err)
		}
		out = buf.Bytes()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// errWrongPassphrase is deliberately vague: a wrong passphrase and a damaged
// file look the same to age, and the text names neither.
var errWrongPassphrase = fmt.Errorf("vault: %s: the passphrase is wrong, or the key file is damaged", PassphraseName)

func (w *passphraseWrapper) Unwrap(wrapped []byte) ([]byte, error) {
	if len(wrapped) == 0 || len(wrapped) > maxWrappedBlob {
		return nil, fmt.Errorf("vault: %s: the key file is empty or too large", PassphraseName)
	}
	var out []byte
	err := w.use(false, func(pass []byte) error {
		id, err := age.NewScryptIdentity(string(pass))
		if err != nil {
			return fmt.Errorf("vault: %s: %w", PassphraseName, err)
		}
		id.SetMaxWorkFactor(maxUnwrapWorkFactor)
		r, err := age.Decrypt(bytes.NewReader(wrapped), id)
		if err != nil {
			return errWrongPassphrase
		}
		plain, err := io.ReadAll(io.LimitReader(r, maxWrappedBlob))
		if err != nil || len(plain) == 0 {
			clear(plain)
			return errWrongPassphrase
		}
		out = plain
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Forget zeroes the cached passphrase (and the source's, if it keeps one).
// The next use asks again.
func (w *passphraseWrapper) Forget() {
	w.mu.Lock()
	defer w.mu.Unlock()
	clear(w.pass)
	w.pass = nil
	if f, ok := w.src.(forgetter); ok {
		f.Forget()
	}
}

// fdPassphrase reads one line from a file descriptor: the first line of a
// pipe or a file the caller opened (for example `systemd-creds decrypt ... |
// chapd run -vault-passphrase-fd 0`). It reads at most once and keeps the line
// until Forget, because a second ask would find the pipe empty.
type fdPassphrase struct {
	r     io.Reader
	close func() error

	mu   sync.Mutex
	pass []byte
	err  error
	read bool
}

// FDPassphrase returns a [PassphraseSource] that reads the first line of the
// open file descriptor fd. Descriptors 1 and 2 are refused. Off Unix-like
// systems only descriptor 0 (standard input) is available.
func FDPassphrase(fd int) (PassphraseSource, error) {
	f, err := openPassphraseFD(fd)
	if err != nil {
		return nil, err
	}
	s := &fdPassphrase{r: f}
	if fd != 0 {
		s.close = f.Close
	}
	return s, nil
}

func openPassphraseFD(fd int) (*os.File, error) {
	switch {
	case fd < 0 || fd == 1 || fd == 2:
		return nil, fmt.Errorf("vault: passphrase descriptor %d is not allowed", fd)
	case fd == 0:
		return os.Stdin, nil
	case runtime.GOOS == "windows":
		return nil, errors.New("vault: on Windows the passphrase can only come from standard input (descriptor 0)")
	}
	f := os.NewFile(uintptr(fd), "passphrase")
	if f == nil {
		return nil, fmt.Errorf("vault: passphrase descriptor %d is not open", fd)
	}
	if _, err := f.Stat(); err != nil {
		return nil, fmt.Errorf("vault: passphrase descriptor %d is not open", fd)
	}
	return f, nil
}

func (s *fdPassphrase) Passphrase(bool) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.read {
		s.read = true
		s.pass, s.err = readLine(s.r)
		if s.close != nil {
			_ = s.close()
		}
	}
	if s.err != nil {
		return nil, s.err
	}
	if s.pass == nil {
		return nil, errors.New("the passphrase was already used and forgotten; start the command again")
	}
	return bytes.Clone(s.pass), nil
}

func (s *fdPassphrase) Forget() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.pass)
	s.pass = nil
}

// readLine reads one line, one byte at a time so nothing past the newline is
// consumed and no buffer holds a copy. A trailing "\r" is dropped; no other
// white space is touched, because it may be part of the passphrase.
func readLine(r io.Reader) ([]byte, error) {
	line := make([]byte, 0, maxPassphraseBytes)
	var b [1]byte
	for {
		n, err := r.Read(b[:])
		if n == 1 {
			if b[0] == '\n' {
				break
			}
			if len(line) == maxPassphraseBytes {
				clear(line)
				return nil, fmt.Errorf("the passphrase is longer than %d bytes", maxPassphraseBytes)
			}
			line = append(line, b[0])
		}
		if err != nil {
			if err == io.EOF && len(line) > 0 {
				break
			}
			clear(line)
			if err == io.EOF {
				return nil, errors.New("no passphrase was given: the descriptor is empty")
			}
			return nil, fmt.Errorf("read the passphrase: %w", err)
		}
	}
	line = bytes.TrimSuffix(line, []byte{'\r'})
	if len(line) == 0 {
		return nil, errors.New("the passphrase line is empty")
	}
	return line, nil
}

// terminal is the person's keyboard and screen.
type terminal interface {
	io.Reader
	io.Writer
	// disableEcho stops the terminal showing what is typed and returns the
	// function that puts it back.
	disableEcho() (restore func(), err error)
	Close() error
}

// openTerminal opens the controlling terminal (/dev/tty, or the console on
// Windows) rather than standard input, so standard input stays free for
// other data (`chapd vault recover` reads the recovery identity from it).
// Each operating system's file sets it; a test replaces it.
var openTerminal = func() (terminal, error) { return nil, errNoTerminal }

var errNoTerminal = errors.New("there is no terminal to ask for the passphrase on; give it on a descriptor instead (-vault-passphrase-fd)")

var errInterrupted = errors.New("interrupted")

// terminalPassphrase prompts on the controlling terminal with echo off.
type terminalPassphrase struct{}

// TerminalPassphrase returns the [PassphraseSource] that asks on the
// controlling terminal without echo. It keeps nothing.
func TerminalPassphrase() PassphraseSource { return terminalPassphrase{} }

func (terminalPassphrase) Passphrase(confirm bool) ([]byte, error) {
	t, err := openTerminal()
	if err != nil {
		return nil, err
	}
	defer t.Close()
	intr := make(chan os.Signal, 1)
	signal.Notify(intr, os.Interrupt)
	defer signal.Stop(intr)
	return promptOn(t, confirm, intr)
}

type lineResult struct {
	line []byte
	err  error
}

// promptOn asks on t with echo off. A signal on intr ends the prompt with the
// terminal restored; the goroutine blocked in the read is left to die with
// the process, which is about to stop.
func promptOn(t terminal, confirm bool, intr <-chan os.Signal) ([]byte, error) {
	restore, err := t.disableEcho()
	if err != nil {
		return nil, fmt.Errorf("could not turn off echo, so the passphrase was not asked: %w", err)
	}
	restored := false
	undo := func() {
		if !restored {
			restored = true
			restore()
		}
	}
	defer undo()

	ask := func(prompt string) ([]byte, error) {
		if _, err := io.WriteString(t, prompt); err != nil {
			return nil, err
		}
		done := make(chan lineResult, 1)
		go func() {
			l, err := readLine(t)
			done <- lineResult{l, err}
		}()
		select {
		case r := <-done:
			_, _ = io.WriteString(t, "\n")
			return r.line, r.err
		case <-intr:
			undo()
			_, _ = io.WriteString(t, "\n")
			return nil, errInterrupted
		}
	}

	if !confirm {
		return ask("Vault passphrase (not shown): ")
	}
	first, err := ask(fmt.Sprintf("New vault passphrase, at least %d characters (not shown): ", minPassphraseChars))
	if err != nil {
		return nil, err
	}
	second, err := ask("Type it again: ")
	if err != nil {
		clear(first)
		return nil, err
	}
	defer clear(second)
	if !bytes.Equal(first, second) {
		clear(first)
		return nil, errors.New("the two passphrases differ")
	}
	return first, nil
}
