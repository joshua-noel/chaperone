package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/loopback"
)

// startServe builds a chapd on addr and serves it with listen, as `chapd run`
// does. done closes when Serve returns on its own or after stop; stop ends it,
// closes chapd and reports what Serve returned.
func startServe(t *testing.T, addr string, listen loopback.ListenFunc) (log *syncBuf, stop func() error, done <-chan struct{}) {
	t.Helper()
	dir := t.TempDir()
	log = &syncBuf{}
	ctx, cancel := context.WithCancel(context.Background())
	app, err := Build(ctx, Config{
		DBPath: filepath.Join(dir, "state.db"), KeysPath: writeKeys(t, dir), Instance: "test",
		Addr: addr, Log: slog.New(slog.NewTextHandler(log, nil)),
	})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var serr error
	fin := make(chan struct{})
	go func() {
		lns, err := app.listenWith(listen)
		if err == nil {
			err = app.Serve(ctx, lns)
		}
		serr = err
		close(fin)
	}()
	var once sync.Once
	stop = func() error {
		once.Do(func() {
			cancel()
			select {
			case <-fin:
			case <-time.After(30 * time.Second):
				t.Error("serve did not stop")
			}
			app.Close()
		})
		return serr
	}
	t.Cleanup(func() { _ = stop() })
	return log, stop, fin
}

// waitServing waits until the address answers (any status).
func waitServing(t *testing.T, network, addr string) {
	t.Helper()
	for range 500 {
		if c, err := net.Dial(network, addr); err == nil {
			c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s never answered", addr)
}

func status(t *testing.T, addr, host, path string) int {
	t.Helper()
	req, _ := http.NewRequest("GET", "http://"+addr+path, nil)
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", addr, err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// The real service holds 127.0.0.1:PORT and [::1]:PORT, and one handler answers
// on both: the Host checks give the same answer on either address, and they
// accept what they accepted before (the console only localhost:PORT, the API
// 127.0.0.1:PORT and localhost:PORT, nobody [::1]:PORT).
func TestServeHoldsBothLoopbackAddresses(t *testing.T) {
	if !ipv6Loopback() {
		t.Skip("no IPv6 loopback on this machine")
	}
	port := freeBothPort(t)
	_, stop, _ := startServe(t, "127.0.0.1:"+port, net.Listen)
	waitServing(t, "tcp4", "127.0.0.1:"+port)
	waitServing(t, "tcp6", "[::1]:"+port)

	// Both are held: nobody else can take either.
	for _, a := range []struct{ network, addr string }{{"tcp4", "127.0.0.1:" + port}, {"tcp6", "[::1]:" + port}} {
		if l, err := net.Listen(a.network, a.addr); err == nil {
			l.Close()
			t.Errorf("%s was free while chapd held it", a.addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:" + port, "[::1]:" + port} {
		// Console routes.
		if c := status(t, addr, "localhost:"+port, "/enroll"); c != 200 {
			t.Errorf("%s console, Host localhost: %d, want 200", addr, c)
		}
		for _, host := range []string{"[::1]:" + port, "127.0.0.1:" + port, "localhost", "evil.example"} {
			if c := status(t, addr, host, "/enroll"); c != 403 {
				t.Errorf("%s console, Host %s: %d, want 403", addr, host, c)
			}
		}
		// API routes: 401 is "reached the API, no token"; 421 is the Host refusal.
		for _, host := range []string{"127.0.0.1:" + port, "localhost:" + port} {
			if c := status(t, addr, host, "/v0/ledger"); c != 401 {
				t.Errorf("%s API, Host %s: %d, want 401", addr, host, c)
			}
		}
		for _, host := range []string{"[::1]:" + port, "localhost", "evil.example"} {
			if c := status(t, addr, host, "/v0/ledger"); c != 421 {
				t.Errorf("%s API, Host %s: %d, want 421", addr, host, c)
			}
		}
	}
	if err := stop(); err != nil {
		t.Errorf("serve: %v", err)
	}
	// Stopped: both addresses are given back.
	for _, a := range []struct{ network, addr string }{{"tcp4", "127.0.0.1:" + port}, {"tcp6", "[::1]:" + port}} {
		l, err := net.Listen(a.network, a.addr)
		if err != nil {
			t.Errorf("%s not given back: %v", a.addr, err)
			continue
		}
		l.Close()
	}
}

// Another program on [::1]:PORT: chapd refuses to start, with a message that
// says why, and gives the IPv4 port back.
func TestServeRefusesATakenIPv6Port(t *testing.T) {
	if !ipv6Loopback() {
		t.Skip("no IPv6 loopback on this machine")
	}
	port := freeBothPort(t)
	squatter, err := net.Listen("tcp6", "[::1]:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer squatter.Close()
	_, stop, done := startServe(t, "127.0.0.1:"+port, net.Listen)
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("chapd kept running with another program on [::1]")
	}
	serr := stop()
	if serr == nil || !strings.Contains(serr.Error(), "[::1]:"+port) || !strings.Contains(serr.Error(), "Another program") {
		t.Errorf("unclear refusal: %v", serr)
	}
	l, err := net.Listen("tcp4", "127.0.0.1:"+port)
	if err != nil {
		t.Errorf("the IPv4 port was not given back: %v", err)
	} else {
		l.Close()
	}
}

// No IPv6 loopback on the machine: chapd serves on IPv4 alone and says so once.
func TestServeToleratesNoIPv6(t *testing.T) {
	no6 := func(network, addr string) (net.Listener, error) {
		if network == "tcp6" {
			return nil, &net.OpError{Op: "listen", Net: "tcp6", Err: os.NewSyscallError("bind", syscall.EAFNOSUPPORT)}
		}
		return net.Listen(network, addr)
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := fmt.Sprint(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	log, stop, _ := startServe(t, "127.0.0.1:"+port, no6)
	waitServing(t, "tcp4", "127.0.0.1:"+port)
	if c := status(t, "127.0.0.1:"+port, "localhost:"+port, "/enroll"); c != 200 {
		t.Errorf("console: %d, want 200", c)
	}
	if err := stop(); err != nil {
		t.Errorf("serve: %v", err)
	}
	if n := strings.Count(log.String(), "no IPv6 loopback"); n != 1 {
		t.Errorf("the log says it %d times, want once:\n%s", n, log.String())
	}
}

// runDaemon takes the console's port before it starts anything: with another program on [::1]:PORT it stops with the
// error and runs neither the "listening" hook nor the after-start hook; with the port free the port is held first.
func TestRunDaemonTakesThePortBeforeStart(t *testing.T) {
	if !ipv6Loopback() {
		t.Skip("no IPv6 loopback on this machine")
	}
	port := freeBothPort(t)
	squatter, err := net.Listen("tcp6", "[::1]:"+port)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var events []string
	cfg := Config{
		DBPath: filepath.Join(dir, "state.db"), KeysPath: writeKeys(t, dir), Instance: "test", Addr: "127.0.0.1:" + port,
		Log:         slog.New(slog.NewTextHandler(&syncBuf{}, nil)),
		onListening: func() { events = append(events, "listening") },
		afterBuild: func(context.Context, *App) error {
			events = append(events, "started")
			return nil
		},
	}
	if err := runDaemon(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "[::1]:"+port) {
		t.Fatalf("runDaemon with another program on [::1]: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("it went on: %v", events)
	}
	squatter.Close()

	// Free: the port is held before start-up, and nothing is accepted until the start-up has finished.
	ctx, cancel := context.WithCancel(context.Background())
	cfg.DBPath = filepath.Join(dir, "state2.db")
	cfg.afterBuild = func(context.Context, *App) error {
		events = append(events, "started")
		if l, err := net.Listen("tcp4", "127.0.0.1:"+port); err == nil {
			l.Close()
			t.Error("the port was not held when start-up finished")
		}
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- runDaemon(ctx, cfg) }()
	waitServing(t, "tcp6", "[::1]:"+port)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("runDaemon: %v", err)
	}
	if strings.Join(events, ",") != "listening,started" {
		t.Fatalf("order: %v", events)
	}
}
