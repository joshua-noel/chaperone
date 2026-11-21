package vault

import (
	"context"
	"fmt"
)

// keychainService is the service name of Chaperone's items in the login
// keychain; the account name is the reference id.
const keychainService = "chaperone-vault"

// keychainDirs is where macOS keeps `security`. It is a fixed path, not a PATH
// lookup.
var keychainDirs = []string{"/usr/bin"}

const keychainHint = "Unlock the login keychain (it must be unlocked for chapd to start), or use the age-passphrase key wrapper"

// keychainStore keeps values in the macOS login keychain through the system
// `security` tool, without cgo.
//
// How the secret travels, and why:
//
//   - Reading uses `security find-generic-password -w`, which prints only the
//     value on standard output.
//   - Writing uses `security -i`, which reads its commands from standard input.
//     The value is in that input and so never in the argument list that `ps`
//     shows to other processes. The alternative, `add-generic-password -w
//     VALUE`, puts it in the argument list; the tool's own manual calls that
//     insecure and this code never does it. The other safe form of that
//     command, `-w` as the last option with no value, prompts on the terminal
//     and cannot be driven from a program.
//
// The value is lower-case hex, which `security -i`'s line parser (white space,
// quotes and backslashes only) passes through unchanged.
//
// What it does not do: the item is readable by any program that runs as this
// user and calls `security find-generic-password` while the keychain is
// unlocked, which includes every agent that runs as this user. See ADR-003,
// amendment 6.
type keychainStore struct {
	run  commandRunner
	tool string // absolute path of `security`
}

func (s keychainStore) put(ctx context.Context, id string, value []byte) error {
	cmd := make([]byte, 0, len(value)+160)
	cmd = append(cmd, "add-generic-password -s "+keychainService+" -a "+id+" -l chaperone-vault-key -w "...)
	cmd = append(cmd, value...)
	cmd = append(cmd, '\n')
	defer clear(cmd)
	res, err := s.run.Run(ctx, s.tool, []string{"-i"}, cmd)
	if err != nil {
		return fmt.Errorf("vault: %s: %w. %s", KeychainName, err, keychainHint)
	}
	defer res.wipe()
	if res.exit != 0 {
		return toolError(KeychainName, "security", "store", res, keychainHint, value, cmd)
	}
	return nil
}

func (s keychainStore) get(ctx context.Context, id string) ([]byte, error) {
	res, err := s.run.Run(ctx, s.tool, []string{"find-generic-password", "-s", keychainService, "-a", id, "-w"}, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: %s: %w. %s", KeychainName, err, keychainHint)
	}
	if res.exit != 0 {
		defer res.wipe()
		hint := keychainHint
		if res.exit == 44 { // errSecItemNotFound
			hint = "The key is not in this user's keychain: the vault was made by another user or on another Mac, or the item was deleted. Recover with the offline recovery identity (chapd vault recover)"
		}
		return nil, toolError(KeychainName, "security", "read", res, hint)
	}
	clear(res.stderr)
	return res.stdout, nil
}

func (s keychainStore) remove(ctx context.Context, id string) error {
	res, err := s.run.Run(ctx, s.tool, []string{"delete-generic-password", "-s", keychainService, "-a", id}, nil)
	if err != nil {
		return fmt.Errorf("vault: %s: %w", KeychainName, err)
	}
	defer res.wipe()
	if res.exit != 0 {
		return toolError(KeychainName, "security", "delete", res, "")
	}
	return nil
}
