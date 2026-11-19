package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/joshua-noel/chaperone/internal/version"
)

// The browser is sent to http://localhost:PORT, and `localhost` may resolve to
// ::1 as well as 127.0.0.1 (Chromium tries ::1 first). A program that listens
// on [::1]:PORT would then receive the navigation, and with it the one-time
// passkey address and every cookie of every localhost console. So the
// quickstart holds both loopback addresses itself, and refuses to start when
// [::1]:PORT is taken by somebody else.

// listenFunc is net.Listen; tests replace it.
type listenFunc func(network, address string) (net.Listener, error)

// bindQuickstart listens on addr (127.0.0.1:PORT) and on [::1]:PORT. The only
// bind failure it tolerates is "this machine has no IPv6 loopback", found by
// a probe on a free port; a failure to take the real port while IPv6 works is
// an error, because another program is there.
func bindQuickstart(addr string, listen listenFunc) ([]net.Listener, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	v4, err := listen("tcp4", addr)
	if err != nil {
		return nil, fmt.Errorf("cannot listen on %s: %w\nIs chapd quickstart already running in another terminal? Stop it first, or use --addr with another port", addr, err)
	}
	probe, perr := listen("tcp6", "[::1]:0")
	if perr != nil {
		return []net.Listener{v4}, nil // no IPv6 here: nothing can be reached through ::1
	}
	_ = probe.Close()
	addr6 := net.JoinHostPort("::1", port)
	v6, err := listen("tcp6", addr6)
	if err != nil {
		_ = v4.Close()
		return nil, fmt.Errorf("cannot listen on %s: %w\n"+
			"Another program is listening there. A browser may send \"localhost\" to it instead of to Chaperone, "+
			"and it would see your passkey address. Stop that program, or use --addr with another port", addr6, err)
	}
	return []net.Listener{v4, v6}, nil
}

func closeAll(lns []net.Listener) {
	for _, l := range lns {
		_ = l.Close()
	}
}

// serveQuickstart serves a's handler on every listener until ctx ends: the same
// handler, so the Host and Origin checks are the same on both addresses (the
// console answers only Host localhost:PORT, the API also 127.0.0.1:PORT).
func serveQuickstart(ctx context.Context, a *App, lns []net.Listener) error {
	srv := &http.Server{
		Handler: a.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 2 * time.Minute,
		WriteTimeout: 2 * time.Minute, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 32 << 10,
	}
	done := make(chan error, len(lns))
	for _, ln := range lns {
		go func() { done <- srv.Serve(ln) }()
		a.log.Info("chapd listening", "addr", ln.Addr().String(), "version", version.Version)
	}
	select {
	case err := <-done:
		_ = srv.Close()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		return nil
	}
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
