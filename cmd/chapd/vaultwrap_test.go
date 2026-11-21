package main

import (
	"flag"
	"io"
	"os"
	"runtime"
	"strconv"
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

// pipeAsStdin makes a pipe standard input for the test, so descriptor 0 is a
// valid passphrase source.
func pipeAsStdin(t *testing.T) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old; r.Close(); w.Close() })
}

func TestWrapperFlags(t *testing.T) {
	c, err := parseWrapperFlags(t)
	if err != nil || c.name != "" || c.fdSet || c.src != nil {
		t.Errorf("defaults: %+v, %v", c, err)
	}
	pipeAsStdin(t)
	c, err = parseWrapperFlags(t, "-vault-wrapper", "age-passphrase", "-vault-passphrase-fd", "0")
	if err != nil || c.name != "age-passphrase" || !c.fdSet || c.fd != 0 || c.src == nil {
		t.Errorf("parsed: %+v, %v", c, err)
	}
	for _, bad := range []string{"-1", "x", "", "1", "2"} {
		if _, err := parseWrapperFlags(t, "-vault-passphrase-fd", bad); err == nil {
			t.Errorf("-vault-passphrase-fd %q accepted", bad)
		}
	}
}

// The descriptor is checked while the flags are parsed, before the program
// opens a log file or the database that could take the number.
func TestPassphraseDescriptorIsCheckedAtParseTime(t *testing.T) {
	// A regular file as standard input is allowed (< file); a device is not.
	old := os.Stdin
	t.Cleanup(func() { os.Stdin = old })
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	os.Stdin = null
	if _, err := parseWrapperFlags(t, "-vault-passphrase-fd", "0"); err == nil || !strings.Contains(err.Error(), "not a pipe") {
		t.Errorf("a device on descriptor 0: %v", err)
	}
	if runtime.GOOS != "windows" {
		// A descriptor that is not open is refused at once, not at the first read.
		if _, err := parseWrapperFlags(t, "-vault-passphrase-fd", "987654"); err == nil || !strings.Contains(err.Error(), "not open") {
			t.Errorf("a closed descriptor: %v", err)
		}
		// A file the program has open is not a passphrase source.
		f, err := os.CreateTemp(t.TempDir(), "log")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if fd := int(f.Fd()); fd >= 3 {
			if _, err := parseWrapperFlags(t, "-vault-passphrase-fd", strconv.Itoa(fd)); err == nil || !strings.Contains(err.Error(), "not a pipe or FIFO") {
				t.Errorf("a regular file on descriptor %d: %v", fd, err)
			}
			if _, err := f.WriteString("x"); err != nil {
				t.Errorf("the file was closed by the refusal: %v", err)
			}
		}
	}
}

func TestPassphraseDescriptorNeedsThePassphraseWrapper(t *testing.T) {
	pipeAsStdin(t)
	for _, name := range []string{"", "keychain-macos", "dpapi-user"} {
		c, err := parseWrapperFlags(t, "-vault-wrapper", name, "-vault-passphrase-fd", "0")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.build(); err == nil || !strings.Contains(err.Error(), "-vault-wrapper age-passphrase") {
			t.Errorf("%q: %v", name, err)
		}
	}
}

func TestBuildUsesTheSourceFromTheFlag(t *testing.T) {
	pipeAsStdin(t)
	c, err := parseWrapperFlags(t, "-vault-wrapper", "age-passphrase", "-vault-passphrase-fd", "0")
	if err != nil {
		t.Fatal(err)
	}
	w, err := c.build()
	if err != nil || w.Name() != vault.PassphraseName {
		t.Fatalf("%v, %v", w, err)
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
	pipeAsStdin(t)
	cfg, code := parseRunFlags("run", []string{"-vault-dir", "v", "-vault-wrapper", "age-passphrase", "-vault-passphrase-fd", "0"}, io.Discard, false)
	if code != 0 || cfg.VaultWrap.name != "age-passphrase" || !cfg.VaultWrap.fdSet || cfg.VaultWrap.src == nil {
		t.Errorf("%d %+v", code, cfg.VaultWrap)
	}
}

// recover reads the recovery identity from standard input, so the passphrase
// cannot also come from descriptor 0.
func TestVaultRecoverRefusesPassphraseOnDescriptorZero(t *testing.T) {
	pipeAsStdin(t)
	dir := t.TempDir()
	var out, errb strings.Builder
	code := run([]string{"vault", "recover", "-db", dir + "/state.db", "-vault-wrapper", "age-passphrase", "-vault-passphrase-fd", "0"}, &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "recovery identity") || !strings.Contains(errb.String(), "standard input") {
		t.Errorf("exit %d, stderr %q", code, errb.String())
	}
	if _, err := os.Stat(dir + "/state.db"); err == nil {
		t.Error("the database was opened before the refusal")
	}
}
