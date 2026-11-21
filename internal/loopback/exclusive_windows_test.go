//go:build windows

package loopback

import (
	"context"
	"net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// On Windows another process of the same user can normally take an address that is in use by setting SO_REUSEADDR.
// Listen is exclusive, so it cannot.
func TestListenIsExclusiveOnWindows(t *testing.T) {
	l, err := Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	addr := l.Addr().String()
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
		}); err != nil {
			return err
		}
		return serr
	}}
	if s, err := lc.Listen(context.Background(), "tcp4", addr); err == nil {
		s.Close()
		t.Fatalf("another socket took %s with SO_REUSEADDR", addr)
	}
}

// Restarting chapd must not wait for the old connections to go away: the address can be taken again at once, even with
// a connection that was open when the old listener closed.
func TestListenCanBeTakenAgainAtOnce(t *testing.T) {
	l, err := Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	done := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); done <- c }()
	cl, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := <-done
	srv.Write([]byte("x"))
	srv.Close() // the server side closes first: it is the side that will sit in TIME_WAIT
	cl.Close()
	l.Close()
	time.Sleep(50 * time.Millisecond)
	l2, err := Listen("tcp4", addr)
	if err != nil {
		t.Fatalf("the address was not free after a restart: %v", err)
	}
	l2.Close()
}

// This Windows build already refuses a same-user SO_REUSEADDR bind on a plain listener, so the test above would pass
// without the fix. This one reads the option back from the socket: SO_EXCLUSIVEADDRUSE is 1 on a Listen listener, and
// 0 on a plain net.Listen one (the control).
func TestListenSetsExclusiveAddrUse(t *testing.T) {
	read := func(l net.Listener) int {
		t.Helper()
		rc, err := l.(*net.TCPListener).SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var v int
		var gerr error
		if err := rc.Control(func(fd uintptr) {
			v, gerr = windows.GetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, soExclusiveAddrUse)
		}); err != nil || gerr != nil {
			t.Fatalf("getsockopt: %v %v", err, gerr)
		}
		return v
	}
	l, err := Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if v := read(l); v != 1 {
		t.Fatalf("SO_EXCLUSIVEADDRUSE is %d on a Listen listener, want 1", v)
	}
	plain, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if v := read(plain); v != 0 {
		t.Fatalf("the control listener has SO_EXCLUSIVEADDRUSE %d: the test cannot tell the fix from the default", v)
	}
}
