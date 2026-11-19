package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/joshua-noel/chaperone/internal/version"
)

// serveListeners serves a's handler on every listener until ctx ends: the same
// handler, so the Host and Origin checks are the same on both loopback
// addresses (internal/loopback; the console answers only Host localhost:PORT,
// the API also 127.0.0.1:PORT).
func serveListeners(ctx context.Context, a *App, lns []net.Listener) error {
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
