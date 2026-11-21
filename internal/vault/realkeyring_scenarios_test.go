package vault

import (
	"runtime"
	"testing"
)

// The scenarios in realkeyring_integration_test.go are code too. Run them on
// the fake tools, in every normal test run, so a mistake in a scenario shows
// here and not on a CI runner that was started to find a mistake somewhere
// else. They need `ps`, so not on Windows.
func TestRealKeyringScenariosOnFakeTools(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the process-list check needs ps")
	}
	for name, f := range map[string]*fakeTool{"security": newFakeSecurity(), "secret-tool": newFakeSecretTool()} {
		t.Run(name, func(t *testing.T) {
			var st secretStore = keychainStore{run: f, tool: "/usr/bin/security"}
			w := storeWrapper{name: KeychainName, store: st}
			if name == "secret-tool" {
				st = secretServiceStore{run: f, tool: "/usr/bin/secret-tool"}
				w = storeWrapper{name: SecretServiceName, store: st}
			}
			rec := &recordingRunner{inner: f}
			switch s := st.(type) {
			case keychainStore:
				s.run = rec
				st, w.store = s, s
			case secretServiceStore:
				s.run = rec
				st, w.store = s, s
			}
			realWrapRoundTrip(t, w, st, rec)
			realVaultRoundTrip(t, w, st)
			rec.logCalls(t)
		})
	}
}
