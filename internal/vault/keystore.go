package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
)

// Names of the wrappers that keep the key in the operating system's own
// secret store.
const (
	KeychainName      = "keychain-macos"
	SecretServiceName = "secret-service"
)

// maxStoredKey bounds what these wrappers hold. The vault wraps two keys of
// well under 300 bytes. The limit keeps the hex line under the 4096 bytes
// that `security -i` reads per command.
const maxStoredKey = 1024

// secretStore is a place where an operating system keeps small secrets for
// the current user: the macOS login keychain, or a Secret Service keyring.
// Values are lower-case hex, so no store has to cope with binary data or
// quoting. An implementation passes the value to its tool on standard input
// and reads it from standard output, and never puts it in an argument or an
// environment variable.
type secretStore interface {
	// put stores value under id. The caller zeroes value afterwards.
	put(ctx context.Context, id string, value []byte) error
	// get returns the stored value. The caller zeroes it.
	get(ctx context.Context, id string) ([]byte, error)
	// remove deletes id; used to undo a put that could not be verified.
	remove(ctx context.Context, id string) error
}

// storeWrapper is a [KeyWrapper] whose blob holds no key material. Wrap
// stores the key in the secret store under a fresh random id and returns a
// small reference to it; Unwrap follows the reference. There is no encryption
// layer of our own: the protection is the store's.
//
// A copy of the vault's key folder without the user's keychain is therefore
// useless, and so is the keychain without the key folder; recovery is the
// offline recovery identity ([Recover]).
type storeWrapper struct {
	name  string
	store secretStore
}

const refMagic = "chaperone-key-reference v1"

// idLen is the length of a reference id in hex digits. The id reaches a
// command line, so [parseRef] accepts nothing but this exact shape.
const idLen = 32

func (w storeWrapper) Name() string { return w.name }

func (w storeWrapper) fail(format string, args ...any) error {
	return fmt.Errorf("vault: %s: %s", w.name, fmt.Sprintf(format, args...))
}

func (w storeWrapper) Wrap(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, w.fail("nothing to wrap")
	}
	if len(plaintext) > maxStoredKey {
		return nil, w.fail("key is longer than %d bytes", maxStoredKey)
	}
	raw := make([]byte, idLen/2)
	if _, err := rand.Read(raw); err != nil {
		return nil, w.fail("random id: %v", err)
	}
	id := hex.EncodeToString(raw)
	value := make([]byte, hex.EncodedLen(len(plaintext)))
	hex.Encode(value, plaintext)
	defer clear(value)

	ctx := context.Background()
	if err := w.store.put(ctx, id, value); err != nil {
		return nil, err
	}
	// Read it back before the vault relies on it: some tools report success
	// without having stored anything.
	back, err := w.store.get(ctx, id)
	defer clear(back)
	if err != nil || subtle.ConstantTimeCompare(bytes.TrimRight(back, "\r\n"), value) != 1 {
		_ = w.store.remove(ctx, id)
		if err != nil {
			return nil, err
		}
		return nil, w.fail("the key was stored but did not read back the same; nothing was kept")
	}
	return []byte(refMagic + "\n" + w.name + "\n" + id + "\n"), nil
}

func (w storeWrapper) Unwrap(wrapped []byte) ([]byte, error) {
	id, err := w.parseRef(wrapped)
	if err != nil {
		return nil, err
	}
	got, err := w.store.get(context.Background(), id)
	defer clear(got)
	if err != nil {
		return nil, err
	}
	got = bytes.TrimRight(got, "\r\n")
	plain := make([]byte, hex.DecodedLen(len(got)))
	n, err := hex.Decode(plain, got)
	if err != nil || n == 0 || n > maxStoredKey {
		clear(plain)
		return nil, w.fail("the stored key is damaged")
	}
	return plain[:n], nil
}

// parseRef returns the id in a reference made by Wrap, and nothing else: the
// magic line, this wrapper's name and 32 lower-case hex digits, each on its
// own line, in that order.
func (w storeWrapper) parseRef(b []byte) (string, error) {
	parts := bytes.Split(b, []byte("\n"))
	if len(parts) != 4 || len(parts[3]) != 0 ||
		string(parts[0]) != refMagic || string(parts[1]) != w.name || !isHexID(parts[2]) {
		return "", w.fail("the key file is not a reference made by this wrapper")
	}
	return string(parts[2]), nil
}

func isHexID(b []byte) bool {
	if len(b) != idLen {
		return false
	}
	for _, c := range b {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// toolError builds the error for a tool that ran and failed. stderr is shown
// (bounded, one line) unless it contains any of secrets, in which case it is
// withheld: a tool that echoes its input must not put a key in an error text.
func toolError(w, tool, what string, res cmdResult, hint string, secrets ...[]byte) error {
	msg := string(bytes.TrimSpace(res.stderr))
	for _, s := range secrets {
		if len(s) > 0 && bytes.Contains(res.stderr, s) {
			msg = "(output withheld: it contained the key)"
		}
	}
	if len(msg) > 200 {
		msg = msg[:200] + "..."
	}
	msg = singleLine(msg)
	e := fmt.Sprintf("vault: %s: %s failed (%s, exit %d)", w, tool, what, res.exit)
	if msg != "" {
		e += ": " + msg
	}
	if hint != "" {
		e += ". " + hint
	}
	return errors.New(e)
}

// singleLine replaces anything that is not printable ASCII, so a tool cannot
// put control characters in a terminal or a log through an error text.
func singleLine(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			b[i] = ' '
		}
	}
	return string(b)
}
