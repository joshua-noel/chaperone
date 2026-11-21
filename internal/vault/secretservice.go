package vault

import (
	"context"
	"fmt"
)

// secretServiceService is the value of the "service" attribute on Chaperone's
// items; the "id" attribute is the reference id.
const secretServiceService = "chaperone-vault"

// secretToolDirs are the only places secret-tool is looked for: not PATH, so
// a program another process planted on PATH cannot receive a key.
var secretToolDirs = []string{"/usr/bin", "/bin", "/usr/local/bin", "/run/current-system/sw/bin"}

const secretServiceHint = "Needs a desktop session with an unlocked Secret Service keyring (GNOME Keyring, KWallet) and secret-tool (package libsecret-tools or libsecret). On a server or in an SSH session use the age-passphrase key wrapper"

// secretServiceStore keeps values in a Secret Service keyring through
// `secret-tool`, without cgo.
//
//   - `secret-tool store` reads the secret from standard input (up to 8192
//     bytes, until end of input), so it is never in the argument list.
//   - `secret-tool lookup` writes the secret to standard output.
//   - Only the attribute names, the fixed service name and the random id are
//     arguments.
//
// What it does not do: any program that runs as this user and can reach the
// session bus can ask the Secret Service for the item while the keyring is
// unlocked, which includes every agent that runs as this user. See ADR-003,
// amendment 6.
type secretServiceStore struct {
	run  commandRunner
	tool string // absolute path of secret-tool
}

func (s secretServiceStore) attrs(id string) []string {
	return []string{"service", secretServiceService, "id", id}
}

func (s secretServiceStore) put(ctx context.Context, id string, value []byte) error {
	args := append([]string{"store", "--label=chaperone-vault-key"}, s.attrs(id)...)
	res, err := s.run.Run(ctx, s.tool, args, value)
	if err != nil {
		return fmt.Errorf("vault: %s: %w. %s", SecretServiceName, err, secretServiceHint)
	}
	defer res.wipe()
	if res.exit != 0 {
		return toolError(SecretServiceName, "secret-tool", "store", res, secretServiceHint, value)
	}
	return nil
}

func (s secretServiceStore) get(ctx context.Context, id string) ([]byte, error) {
	res, err := s.run.Run(ctx, s.tool, append([]string{"lookup"}, s.attrs(id)...), nil)
	if err != nil {
		return nil, fmt.Errorf("vault: %s: %w. %s", SecretServiceName, err, secretServiceHint)
	}
	if res.exit != 0 || len(res.stdout) == 0 {
		defer res.wipe()
		// secret-tool exits 1 both for "no such item" and for a bus or
		// keyring error; its standard error tells them apart.
		return nil, toolError(SecretServiceName, "secret-tool", "read", res,
			"The key may belong to another user or machine, or the keyring is locked or unavailable. "+secretServiceHint)
	}
	clear(res.stderr)
	return res.stdout, nil
}

func (s secretServiceStore) remove(ctx context.Context, id string) error {
	res, err := s.run.Run(ctx, s.tool, append([]string{"clear"}, s.attrs(id)...), nil)
	if err != nil {
		return fmt.Errorf("vault: %s: %w", SecretServiceName, err)
	}
	defer res.wipe()
	if res.exit != 0 {
		return toolError(SecretServiceName, "secret-tool", "delete", res, "")
	}
	return nil
}
