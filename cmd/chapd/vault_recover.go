package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/joshua-noel/chaperone/internal/vault"
)

// vaultStdin is where `chapd vault recover` reads the recovery identity. Tests
// replace it.
var vaultStdin io.Reader = os.Stdin

// vaultRecover is `chapd vault recover`: the offline recovery identity comes in
// on standard input (never as a flag, so it is not in a process list or a shell
// history), and only counts and recipients go out.
func vaultRecover(ctx context.Context, cfg vault.Config, in io.Reader, stdout, stderr io.Writer) int {
	fmt.Fprintln(stderr, "chapd: reading the recovery identity (AGE-SECRET-KEY-1...) from standard input")
	identity, err := readIdentityLine(in)
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	n, err := vault.Recover(ctx, cfg, identity)
	if err != nil {
		switch {
		case errors.Is(err, vault.ErrWrongRecoveryIdentity), errors.Is(err, vault.ErrRecoveryNotNeeded), errors.Is(err, vault.ErrNotInitialized):
			fmt.Fprintf(stderr, "chapd: %v\n", err)
		default:
			fmt.Fprintf(stderr, "chapd: recover failed, nothing was marked recovered: %v\n", err)
		}
		return 1
	}
	fmt.Fprintf(stdout, "recovered: %d secrets re-keyed to a new service identity (the recovery identity is unchanged)\nstart chapd again, then run: chapd vault list\n", n)
	return 0
}

// readIdentityLine returns the first non-empty line of in.
func readIdentityLine(in io.Reader) (string, error) {
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			return line, nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", errors.New("no recovery identity on standard input")
}
