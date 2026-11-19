package main

import (
	"errors"
	"flag"
	"strconv"

	"github.com/joshua-noel/chaperone/internal/vault"
)

// wrapperChoice is what the operator says about the vault's key wrapper
// (ADR-003, amendment 6): which one, and for the passphrase wrapper where the
// passphrase comes from. Every command that opens the vault takes the same two
// flags. The zero value means the system's own wrapper.
type wrapperChoice struct {
	name  string // "" means the system's own
	fd    int    // descriptor to read the passphrase from; valid when fdSet
	fdSet bool   // false means ask on the terminal
}

func (c *wrapperChoice) register(fs *flag.FlagSet) {
	fs.StringVar(&c.name, "vault-wrapper", "", "what protects the vault's keys: dpapi-user (Windows), keychain-macos, secret-service (Linux) or age-passphrase (any system). Default: the system's own. A vault must be opened with the wrapper that made it")
	fs.Func("vault-passphrase-fd", "with -vault-wrapper age-passphrase: read the passphrase's first line from this open file descriptor (0 is standard input) instead of asking on the terminal; never give a passphrase in a flag or an environment variable", func(v string) error {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return errors.New("want a file descriptor number")
		}
		c.fd, c.fdSet = n, true
		return nil
	})
}

// newWrapper replaces the key wrapper in tests (DPAPI does not exist on
// Linux CI and the others need a real keychain). Nil in the real program.
var newWrapper func() vault.KeyWrapper

// build returns the key wrapper the flags select, or an error that says how
// to choose one. It never falls back to another wrapper.
func (c wrapperChoice) build() (vault.KeyWrapper, error) {
	if newWrapper != nil {
		return newWrapper(), nil
	}
	var opts vault.WrapperOptions
	if c.fdSet {
		if c.name != vault.PassphraseName {
			return nil, errors.New("-vault-passphrase-fd needs -vault-wrapper " + vault.PassphraseName)
		}
		src, err := vault.FDPassphrase(c.fd)
		if err != nil {
			return nil, err
		}
		opts.Passphrase = src
	}
	return vault.NewWrapper(c.name, opts)
}
