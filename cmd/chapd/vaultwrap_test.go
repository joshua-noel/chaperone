package main

import (
	"flag"
	"io"
	"runtime"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/vault"
)

func parseWrapperFlags(t *testing.T, args ...string) (wrapperChoice, error) {
	t.Helper()
	var c wrapperChoice
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	c.register(fs)
	return c, fs.Parse(args)
}

func TestWrapperFlags(t *testing.T) {
	c, err := parseWrapperFlags(t)
	if err != nil || c.name != "" || c.fdSet {
		t.Errorf("defaults: %+v, %v", c, err)
	}
	c, err = parseWrapperFlags(t, "-vault-wrapper", "age-passphrase", "-vault-passphrase-fd", "0")
	if err != nil || c.name != "age-passphrase" || !c.fdSet || c.fd != 0 {
		t.Errorf("parsed: %+v, %v", c, err)
	}
	for _, bad := range []string{"-1", "x", ""} {
		if _, err := parseWrapperFlags(t, "-vault-passphrase-fd", bad); err == nil {
			t.Errorf("-vault-passphrase-fd %q accepted", bad)
		}
	}
}

func TestPassphraseDescriptorNeedsThePassphraseWrapper(t *testing.T) {
	for _, name := range []string{"", "keychain-macos", "dpapi-user"} {
		_, err := wrapperChoice{name: name, fd: 0, fdSet: true}.build()
		if err == nil || !strings.Contains(err.Error(), "-vault-wrapper age-passphrase") {
			t.Errorf("%q: %v", name, err)
		}
	}
}

func TestBuildChoosesWithoutFallingBack(t *testing.T) {
	w, err := wrapperChoice{name: "age-passphrase"}.build()
	if err != nil || w.Name() != "age-passphrase" {
		t.Fatalf("%v, %v", w, err)
	}
	if _, err := (wrapperChoice{name: "nonsense"}).build(); err == nil || !strings.Contains(err.Error(), "age-passphrase") {
		t.Errorf("unknown name: %v", err)
	}
	// The wrapper of another system is an error, not a different wrapper.
	other := vault.KeychainName
	if runtime.GOOS == "darwin" {
		other = vault.DPAPIName
	}
	if w, err := (wrapperChoice{name: other}).build(); err == nil || w != nil {
		t.Errorf("%s on %s: %v, %v", other, runtime.GOOS, w, err)
	}
}

func TestBuildHonoursTheTestSeam(t *testing.T) {
	useTestWrapper(t)
	w, err := wrapperChoice{name: "nonsense"}.build()
	if err != nil || w == nil {
		t.Errorf("%v, %v", w, err)
	}
}

func TestChapdRunTakesTheWrapperFlags(t *testing.T) {
	cfg, code := parseRunFlags("run", []string{"-vault-dir", "v", "-vault-wrapper", "age-passphrase", "-vault-passphrase-fd", "3"}, io.Discard, false)
	if code != 0 || cfg.VaultWrap.name != "age-passphrase" || !cfg.VaultWrap.fdSet || cfg.VaultWrap.fd != 3 {
		t.Errorf("%d %+v", code, cfg.VaultWrap)
	}
}
