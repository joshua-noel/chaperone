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
	"fmt"
	"net"
)

// ListenFunc is net.Listen; tests replace it.
type ListenFunc func(network, address string) (net.Listener, error)

// Bind listens on addr (a loopback IP and a port) and on the other loopback
// address, on the same port: 127.0.0.1:PORT first, then [::1]:PORT. Only the
// port of addr matters; an addr of [::1]:PORT holds both as well. v4Hint is
// added to the error when the IPv4 address cannot be taken.
//
// The one bind failure it tolerates is "this machine has no IPv6 loopback",
// found by a probe on a free port: it then returns the IPv4 listener alone, and
// the caller says so in its log. A failure to take the real port while IPv6
// works is an error, because another program is there.
func Bind(addr string, listen ListenFunc, v4Hint string) ([]net.Listener, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	addr4 := addr
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		addr4 = net.JoinHostPort("127.0.0.1", port)
	}
	v4, err := listen("tcp4", addr4)
	if err != nil {
		return nil, fmt.Errorf("cannot listen on %s: %w%s", addr4, err, v4Hint)
	}
	probe, perr := listen("tcp6", "[::1]:0")
	if perr != nil {
		return []net.Listener{v4}, nil // no IPv6 here: nothing can be reached through ::1
	}
	_ = probe.Close()
	if port == "0" { // a port chosen by the system: the same number on both
		_, port, _ = net.SplitHostPort(v4.Addr().String())
	}
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

// CloseAll closes every listener.
func CloseAll(lns []net.Listener) {
	for _, l := range lns {
		_ = l.Close()
	}
}
