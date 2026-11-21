// Package loopback holds both loopback addresses of a local port.
//
// The browser is sent to http://localhost:PORT, and `localhost` may resolve to
// ::1 as well as 127.0.0.1 (Chromium tries ::1 first). A program that listens
// on [::1]:PORT would then receive the navigation, and with it the one-time
// passkey address and every cookie of the console. So everything that serves
// the console (`chapd run`, the Windows service, `chapd enroll`, the
// quickstart) holds both addresses itself, and refuses to start when
// [::1]:PORT is taken by somebody else.
package loopback

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
)

// ListenFunc is net.Listen; tests replace it.
type ListenFunc func(network, address string) (net.Listener, error)

// noIPv6 reports whether err says this machine has no IPv6 loopback address:
// "address not available" or "address family not supported". Windows reports
// them as WSAEADDRNOTAVAIL (10049) and WSAEAFNOSUPPORT (10047), which Go's
// errno matching does not map, so those are compared by number. Nothing else
// counts: "address in use", "no buffer space", "too many open files" and every
// other failure mean something is wrong, not that IPv6 is missing.
func noIPv6(err error) bool {
	var en syscall.Errno
	if !errors.As(err, &en) {
		return false
	}
	switch en {
	case syscall.EADDRNOTAVAIL, syscall.EAFNOSUPPORT, 10049, 10047:
		return true
	}
	return false
}

// Bind listens on 127.0.0.1:PORT and on [::1]:PORT, in that order, where PORT
// is the port of addr. Only the port of addr matters: another host in addr
// (127.0.0.2, or ::1 itself) does not change what is held, so no loopback
// address the browser can reach is ever left to somebody else. v4Hint is added
// to the error when the IPv4 address cannot be taken.
//
// The one failure it tolerates is on the IPv6 side: the machine has no IPv6
// loopback (see [noIPv6]). It then returns the IPv4 listener alone, and the
// caller says so in its log. Any other failure to take [::1]:PORT is an error,
// because another program may be there (or something is wrong that a program
// there could have caused), and the IPv4 listener is given back.
func Bind(addr string, listen ListenFunc, v4Hint string) ([]net.Listener, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	addr4 := net.JoinHostPort("127.0.0.1", port)
	v4, err := listen("tcp4", addr4)
	if err != nil {
		return nil, fmt.Errorf("cannot listen on %s: %w%s", addr4, err, v4Hint)
	}
	if port == "0" { // a port chosen by the system: the same number on both
		_, port, _ = net.SplitHostPort(v4.Addr().String())
	}
	addr6 := net.JoinHostPort("::1", port)
	v6, err := listen("tcp6", addr6)
	if err != nil {
		if noIPv6(err) {
			return []net.Listener{v4}, nil // no IPv6 here: nothing can be reached through ::1
		}
		_ = v4.Close()
		return nil, fmt.Errorf("cannot listen on %s: %w\n"+
			"Another program may be listening there. A browser may send \"localhost\" to it instead of to Chaperone, "+
			"and it would see your passkey address. Stop that program, or use --addr with another port", addr6, err)
	}
	return []net.Listener{v4, v6}, nil
}

// Listen is net.Listen for a console port. On Windows the socket is exclusive:
// another process of the same user cannot take the address with SO_REUSEADDR
// (the default lets it). Elsewhere it is net.Listen.
func Listen(network, address string) (net.Listener, error) {
	lc := net.ListenConfig{Control: exclusive}
	return lc.Listen(context.Background(), network, address)
}

// CloseAll closes every listener.
func CloseAll(lns []net.Listener) {
	for _, l := range lns {
		_ = l.Close()
	}
}
