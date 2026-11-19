package vault

import (
	"fmt"
	"runtime"
	"strings"
)

// WrapperOptions are the inputs of [NewWrapper] that depend on the wrapper.
type WrapperOptions struct {
	// Passphrase asks for the passphrase of the "age-passphrase" wrapper. Nil
	// means [TerminalPassphrase]. Other wrappers ignore it.
	Passphrase PassphraseSource
}

// WrapperNames lists every key wrapper name, whether or not it works on this
// system.
func WrapperNames() []string {
	return []string{DPAPIName, KeychainName, SecretServiceName, PassphraseName}
}

// platform is what NewWrapper needs from the system. Tests replace it.
type platform struct {
	goos string
	run  commandRunner
	find func(name string, dirs []string) (string, error)
}

var thisPlatform = platform{goos: runtime.GOOS, run: execRunner{}, find: findTool}

// NewWrapper returns the key wrapper called name. An empty name selects the
// system's own: Windows DPAPI on Windows, the login keychain on macOS, the
// Secret Service on Linux. Nothing is chosen for another system, and there is
// never a fall back from one wrapper to another: the vault records the name
// of the wrapper that made its keys, and a vault is opened only with that
// one.
//
// A wrapper that cannot work here (its tool is missing, or it belongs to
// another operating system) is an error now, with a message that says what to
// do, rather than at the first key.
func NewWrapper(name string, opts WrapperOptions) (KeyWrapper, error) {
	return thisPlatform.wrapper(name, opts)
}

func (p platform) defaultName() string {
	switch p.goos {
	case "windows":
		return DPAPIName
	case "darwin":
		return KeychainName
	case "linux":
		return SecretServiceName
	}
	return ""
}

func (p platform) wrapper(name string, opts WrapperOptions) (KeyWrapper, error) {
	explicit := name != ""
	if !explicit {
		if name = p.defaultName(); name == "" {
			return nil, fmt.Errorf("vault: there is no system key store for %s; choose the %s key wrapper", p.goos, PassphraseName)
		}
	}
	w, err := p.build(name, opts)
	if err != nil && !explicit {
		return nil, fmt.Errorf("%w (this is the default on %s; nothing else was tried; the %s key wrapper works on every system)", err, p.goos, PassphraseName)
	}
	return w, err
}

func (p platform) build(name string, opts WrapperOptions) (KeyWrapper, error) {
	switch name {
	case DPAPIName:
		if p.goos != "windows" {
			return nil, fmt.Errorf("vault: key wrapper %q needs Windows: %w", name, ErrUnsupported)
		}
		return NewDPAPI(), nil
	case KeychainName:
		if p.goos != "darwin" {
			return nil, fmt.Errorf("vault: key wrapper %q needs macOS: %w", name, ErrUnsupported)
		}
		tool, err := p.find("security", keychainDirs)
		if err != nil {
			return nil, fmt.Errorf("vault: key wrapper %q: %w", name, err)
		}
		return storeWrapper{name: name, store: keychainStore{run: p.run, tool: tool}}, nil
	case SecretServiceName:
		if p.goos != "linux" {
			return nil, fmt.Errorf("vault: key wrapper %q needs Linux: %w", name, ErrUnsupported)
		}
		tool, err := p.find("secret-tool", secretToolDirs)
		if err != nil {
			return nil, fmt.Errorf("vault: key wrapper %q: %w; install libsecret-tools (Debian, Ubuntu) or libsecret (Fedora, Arch)", name, err)
		}
		return storeWrapper{name: name, store: secretServiceStore{run: p.run, tool: tool}}, nil
	case PassphraseName:
		src := opts.Passphrase
		if src == nil {
			src = TerminalPassphrase()
		}
		return newPassphraseWrapper(src, passphraseWorkFactor), nil
	}
	return nil, fmt.Errorf("vault: unknown key wrapper %q; the choices are %s", name, strings.Join(WrapperNames(), ", "))
}
