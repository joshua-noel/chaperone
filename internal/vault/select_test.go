package vault

import (
	"errors"
	"strings"
	"testing"
)

func fakePlatform(goos string, found ...string) (platform, *fakeTool) {
	f := &fakeTool{kind: "security", items: map[string]string{}}
	have := map[string]bool{}
	for _, n := range found {
		have[n] = true
	}
	return platform{
		goos: goos,
		run:  f,
		find: func(name string, dirs []string) (string, error) {
			if have[name] {
				return dirs[0] + "/" + name, nil
			}
			return "", errors.New(name + " not found in " + strings.Join(dirs, ","))
		},
	}, f
}

func TestDefaultWrapperPerSystem(t *testing.T) {
	for _, c := range []struct {
		goos  string
		found []string
		want  string
	}{
		{"windows", nil, DPAPIName},
		{"darwin", []string{"security"}, KeychainName},
		{"linux", []string{"secret-tool"}, SecretServiceName},
	} {
		p, _ := fakePlatform(c.goos, c.found...)
		w, err := p.wrapper("", WrapperOptions{})
		if err != nil {
			t.Errorf("%s: %v", c.goos, err)
			continue
		}
		if w.Name() != c.want {
			t.Errorf("%s: default %q, want %q", c.goos, w.Name(), c.want)
		}
	}
}

func TestNoDefaultFallsBackToNothing(t *testing.T) {
	// A default that cannot work is an error that names the way out. It is
	// never replaced by another wrapper, and never by a plain file.
	p, f := fakePlatform("linux") // secret-tool missing
	w, err := p.wrapper("", WrapperOptions{})
	if err == nil || w != nil {
		t.Fatalf("got %v, %v", w, err)
	}
	for _, want := range []string{"secret-tool", "libsecret", PassphraseName, "default on linux"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	if len(f.calls) != 0 {
		t.Error("ran a tool while selecting")
	}
	p, _ = fakePlatform("freebsd")
	if w, err := p.wrapper("", WrapperOptions{}); err == nil || w != nil || !strings.Contains(err.Error(), PassphraseName) {
		t.Errorf("freebsd: %v, %v", w, err)
	}
	p, _ = fakePlatform("darwin") // security missing
	if _, err := p.wrapper("", WrapperOptions{}); err == nil {
		t.Error("macOS without security gave a wrapper")
	}
}

func TestExplicitChoice(t *testing.T) {
	p, _ := fakePlatform("linux", "secret-tool")
	w, err := p.wrapper(PassphraseName, WrapperOptions{Passphrase: &staticPassphrase{pass: testPassphrase}})
	if err != nil || w.Name() != PassphraseName {
		t.Fatalf("%v, %v", w, err)
	}
	if _, ok := w.(*passphraseWrapper); !ok {
		t.Errorf("%T", w)
	}
	// With no source, the terminal is the source.
	w, err = p.wrapper(PassphraseName, WrapperOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := w.(*passphraseWrapper).src.(terminalPassphrase); !ok {
		t.Errorf("default source %T", w.(*passphraseWrapper).src)
	}
}

func TestChoiceThatDoesNotFitTheSystem(t *testing.T) {
	for _, c := range []struct{ goos, name string }{
		{"linux", DPAPIName}, {"darwin", DPAPIName}, {"windows", KeychainName},
		{"linux", KeychainName}, {"darwin", SecretServiceName}, {"windows", SecretServiceName},
	} {
		p, _ := fakePlatform(c.goos, "security", "secret-tool")
		w, err := p.wrapper(c.name, WrapperOptions{})
		if !errors.Is(err, ErrUnsupported) || w != nil {
			t.Errorf("%s on %s: %v, %v", c.name, c.goos, w, err)
		}
	}
	p, _ := fakePlatform("linux")
	if _, err := p.wrapper(SecretServiceName, WrapperOptions{}); err == nil || !strings.Contains(err.Error(), "libsecret") {
		t.Errorf("explicit choice with the tool missing: %v", err)
	}
	if _, err := p.wrapper("nonsense", WrapperOptions{}); err == nil || !strings.Contains(err.Error(), PassphraseName) {
		t.Errorf("unknown name: %v", err)
	}
}

func TestWrapperNamesAreTheOnesTheCodeKnows(t *testing.T) {
	p, _ := fakePlatform("linux", "security", "secret-tool")
	seen := map[string]bool{}
	for _, n := range WrapperNames() {
		if seen[n] {
			t.Errorf("duplicate %q", n)
		}
		seen[n] = true
		if _, err := p.build(n, WrapperOptions{}); err != nil && !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s: %v", n, err)
		}
	}
	for _, n := range []string{"dpapi-user", "keychain-macos", "secret-service", "age-passphrase"} {
		if !seen[n] {
			t.Errorf("%q is missing: renaming a wrapper breaks every vault made with it", n)
		}
	}
}
