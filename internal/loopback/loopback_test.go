package loopback

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
)

func ipv6Loopback() bool {
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		return false
	}
	l.Close()
	return true
}

// freeBothPort is a port that is free on 127.0.0.1 and on [::1].
func freeBothPort(t *testing.T) string {
	t.Helper()
	for range 50 {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := fmt.Sprint(l.Addr().(*net.TCPAddr).Port)
		l.Close()
		if l6, err := net.Listen("tcp6", "[::1]:"+port); err == nil {
			l6.Close()
			return port
		}
	}
	t.Fatal("no port free on both stacks")
	return ""
}

func TestBindHoldsBothAddresses(t *testing.T) {
	if !ipv6Loopback() {
		t.Skip("no IPv6 loopback on this machine")
	}
	// Either loopback address in addr gives the same two listeners.
	for _, host := range []string{"127.0.0.1", "[::1]"} {
		port := freeBothPort(t)
		lns, err := Bind(host+":"+port, net.Listen, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(lns) != 2 || lns[0].Addr().String() != "127.0.0.1:"+port || lns[1].Addr().String() != "[::1]:"+port {
			t.Errorf("addr %s:%s: %v", host, port, lns)
		}
		CloseAll(lns)
	}
}

// Port 0 is a port the system picks; both addresses get the same one.
func TestBindPortZeroUsesOnePort(t *testing.T) {
	if !ipv6Loopback() {
		t.Skip("no IPv6 loopback on this machine")
	}
	for range 20 {
		lns, err := Bind("127.0.0.1:0", net.Listen, "")
		if err != nil {
			continue // the port the system picked was taken on IPv6
		}
		defer CloseAll(lns)
		_, p4, _ := net.SplitHostPort(lns[0].Addr().String())
		_, p6, _ := net.SplitHostPort(lns[1].Addr().String())
		if p4 != p6 {
			t.Errorf("ports differ: %s and %s", lns[0].Addr(), lns[1].Addr())
		}
		return
	}
	t.Skip("the system picked a port taken on IPv6 every time")
}

// With fake listeners, so it holds on any machine.
func TestBindIPv6Rules(t *testing.T) {
	stub := func(failOn string) ListenFunc {
		return func(network, addr string) (net.Listener, error) {
			if strings.HasPrefix(failOn, network+" ") && strings.HasSuffix(failOn, addr) || failOn == network {
				return nil, errors.New("refused")
			}
			return net.Listen("tcp4", "127.0.0.1:0") // a real listener to close
		}
	}
	// No IPv6 at all: the probe fails, the IPv4 listener alone is fine.
	lns, err := Bind("127.0.0.1:55999", stub("tcp6"), "")
	if err != nil || len(lns) != 1 {
		t.Fatalf("no IPv6: %d listeners, %v", len(lns), err)
	}
	CloseAll(lns)
	// IPv6 works (the probe succeeds) but the real port is taken: an error, and no listener is left.
	lns, err = Bind("127.0.0.1:55999", stub("tcp6 [::1]:55999"), "")
	if err == nil || !strings.Contains(err.Error(), "[::1]:55999") || lns != nil {
		t.Fatalf("taken IPv6 port tolerated: %v (%d listeners)", err, len(lns))
	}
	// The IPv4 port itself taken: an error that carries the caller's hint.
	_, err = Bind("127.0.0.1:55999", stub("tcp4"), "\nHINT")
	if err == nil || !strings.HasSuffix(err.Error(), "\nHINT") {
		t.Fatalf("taken IPv4 port: %v", err)
	}
	// Not a host:port.
	if _, err = Bind("55999", stub(""), ""); err == nil {
		t.Fatal("a bad address was accepted")
	}
}
