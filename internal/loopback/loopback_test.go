package loopback

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
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

// opErr is how the system reports a failed listen: an OpError around a SyscallError around an errno.
func opErr(en syscall.Errno) error {
	return &net.OpError{Op: "listen", Net: "tcp6", Err: os.NewSyscallError("bind", en)}
}

// With fake listeners, so it holds on any machine. stub fails the listen of one network with err.
func stub(network string, err error) ListenFunc {
	return func(n, addr string) (net.Listener, error) {
		if n == network {
			return nil, err
		}
		return net.Listen("tcp4", "127.0.0.1:0") // a real listener to close
	}
}

// Only "this machine has no IPv6 loopback" lets chapd serve on IPv4 alone: address not available, address family not
// supported, and the Windows numbers of the same two (which Go does not map).
func TestBindToleratesOnlyAMissingIPv6(t *testing.T) {
	for name, err := range map[string]error{
		"EADDRNOTAVAIL":      opErr(syscall.EADDRNOTAVAIL),
		"EAFNOSUPPORT":       opErr(syscall.EAFNOSUPPORT),
		"WSAEADDRNOTAVAIL":   opErr(syscall.Errno(10049)),
		"WSAEAFNOSUPPORT":    opErr(syscall.Errno(10047)),
		"wrapped in a error": fmt.Errorf("listen: %w", opErr(syscall.EADDRNOTAVAIL)),
	} {
		lns, berr := Bind("127.0.0.1:55999", stub("tcp6", err), "")
		if berr != nil || len(lns) != 1 {
			t.Errorf("%s: %d listeners, %v", name, len(lns), berr)
		}
		CloseAll(lns)
	}
}

// Anything else on the IPv6 side is fatal, and the IPv4 listener is given back: a program that holds [::1]:PORT, or
// that uses up what a probe would need, must not get chapd to serve on IPv4 alone.
func TestBindRefusesEveryOtherIPv6Failure(t *testing.T) {
	for name, err := range map[string]error{
		"address in use":    opErr(syscall.EADDRINUSE),
		"WSAEADDRINUSE":     opErr(syscall.Errno(10048)),
		"no buffer space":   opErr(syscall.ENOBUFS),
		"WSAENOBUFS":        opErr(syscall.Errno(10055)),
		"too many files":    opErr(syscall.EMFILE),
		"permission denied": opErr(syscall.EACCES),
		"not an errno":      errors.New("refused"),
	} {
		var v4 net.Listener
		listen := func(n, addr string) (net.Listener, error) {
			if n == "tcp6" {
				return nil, err
			}
			l, e := net.Listen("tcp4", "127.0.0.1:0")
			v4 = l
			return l, e
		}
		lns, berr := Bind("127.0.0.1:55999", listen, "")
		if berr == nil || lns != nil || !strings.Contains(berr.Error(), "[::1]:55999") || !strings.Contains(berr.Error(), "Another program") {
			t.Errorf("%s: tolerated or unclear: %d listeners, %v", name, len(lns), berr)
		}
		if v4 != nil {
			if _, e := v4.Accept(); e == nil {
				t.Errorf("%s: the IPv4 listener was not closed", name)
			}
		}
	}
}

func TestBindIPv4Failure(t *testing.T) {
	_, err := Bind("127.0.0.1:55999", stub("tcp4", errors.New("refused")), "\nHINT")
	if err == nil || !strings.HasSuffix(err.Error(), "\nHINT") {
		t.Fatalf("taken IPv4 port: %v", err)
	}
	if _, err = Bind("55999", stub("", nil), ""); err == nil {
		t.Fatal("a bad address was accepted")
	}
}

// Whatever host addr names, both loopback addresses are held: -addr 127.0.0.2:PORT must not leave 127.0.0.1:PORT free.
func TestBindIgnoresTheHostOfAddr(t *testing.T) {
	var got []string
	listen := func(n, addr string) (net.Listener, error) {
		got = append(got, n+" "+addr)
		return net.Listen("tcp4", "127.0.0.1:0")
	}
	for _, addr := range []string{"127.0.0.2:55999", "[::1]:55999", "127.0.0.1:55999"} {
		got = nil
		lns, err := Bind(addr, listen, "")
		if err != nil {
			t.Fatal(err)
		}
		CloseAll(lns)
		if strings.Join(got, ",") != "tcp4 127.0.0.1:55999,tcp6 [::1]:55999" {
			t.Errorf("%s binds %v", addr, got)
		}
	}
}
