package main

import (
	"crypto/rand"
	"math/big"
	"net"

	"github.com/joshua-noel/chaperone/internal/loopback"
)

// The quickstart holds both loopback addresses (see listen.go). A failure to
// take the IPv4 one most likely means another quickstart is running.

// bindQuickstart listens on addr (127.0.0.1:PORT) and on [::1]:PORT.
func bindQuickstart(addr string, listen loopback.ListenFunc) ([]net.Listener, error) {
	return loopback.Bind(addr, listen, "\nIs chapd quickstart already running in another terminal? Stop it first, or use --addr with another port")
}

// newPlaygroundFake is the playground's fake GitHub. Commit SHAs differ from
// run to run, and its request log is bounded: any local process can call its
// loopback port, so it must not grow without limit.
func newPlaygroundFake() (*fakeGitHub, error) {
	skip, err := rand.Int(rand.Reader, big.NewInt(1<<31))
	if err != nil {
		return nil, err
	}
	return newFakeGitHub(fakeGitHubOptions{
		Owner: playgroundOwner, Repo: playgroundRepo, Base: playgroundBase, PRs: playgroundPRs,
		SkipIDs: skip.Int64(), BoundLog: true,
	})
}
