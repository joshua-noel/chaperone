package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/joshua-noel/chaperone/internal/runtoken"
)

const hostUsage = `usage: chapd host keygen --seed-out PATH --token-out PATH

Makes the two things chap-host needs from chapd (ticket L1-15):

  * a new Ed25519 grant-signing key. The seed is written to --seed-out; import it
    into the vault and delete the file:
        chapd vault import --name grant-key --kind ed25519-seed --file PATH --delete
    The public key is printed; put it in chap-host.json as "chapd_public_key".
  * a host token, written to --token-out (readable by the operator and by the
    account that runs chapd, nobody else; chap-host sends it as its bearer).

Neither path may exist yet: keygen never overwrites a key or a token.`

// hostCmd is `chapd host`.
func hostCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "keygen" {
		fmt.Fprintln(stderr, hostUsage)
		return 2
	}
	fs := flag.NewFlagSet("chapd host keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprintln(stderr, hostUsage) }
	seedOut := fs.String("seed-out", "", "where to write the new key's seed")
	tokenOut := fs.String("token-out", "", "where to write the new host token")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *seedOut == "" || *tokenOut == "" {
		fs.Usage()
		return 2
	}
	pub, err := hostKeygen(*seedOut, *tokenOut)
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "chapd_public_key: %s\nseed written to %s: import it into the vault, then delete it\nhost token written to %s\n", pub, *seedOut, *tokenOut)
	return 0
}

func hostKeygen(seedOut, tokenOut string) (public string, err error) {
	seed, public, err := runtoken.GenerateKeyPair()
	if err != nil {
		return "", err
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	clear(raw[:])
	// No newline in the seed file: the vault secret must be exactly the seed text.
	if err := writeNew(seedOut, seed); err != nil {
		return "", err
	}
	if err := writeNew(tokenOut, token+"\n"); err != nil {
		_ = os.Remove(seedOut) // keep the pair together: no seed without its token
		return "", err
	}
	return public, nil
}

// writeNew creates path with the content and the operator-only ACL. It refuses
// an existing file.
func writeNew(path, content string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists; keygen never overwrites", path)
		}
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	if err := restrictToCurrentUser(path); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("restrict %s: %w", path, err)
	}
	return nil
}
