package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// ipv6Loopback reports whether this machine can listen on [::1].
func ipv6Loopback() bool {
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		return false
	}
	l.Close()
	return true
}

// freeBothPort is a port that is free on 127.0.0.1 and, where there is IPv6, on [::1].
func freeBothPort(t *testing.T) string {
	t.Helper()
	for range 50 {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := fmt.Sprint(l.Addr().(*net.TCPAddr).Port)
		l.Close()
		if !ipv6Loopback() {
			return port
		}
		if l6, err := net.Listen("tcp6", "[::1]:"+port); err == nil {
			l6.Close()
			return port
		}
	}
	t.Fatal("no port free on both stacks")
	return ""
}

func TestBindQuickstartHoldsBothLoopbackAddresses(t *testing.T) {
	if !ipv6Loopback() {
		t.Skip("no IPv6 loopback on this machine")
	}
	port := freeBothPort(t)
	lns, err := bindQuickstart("127.0.0.1:"+port, net.Listen)
	if err != nil {
		t.Fatal(err)
	}
	if len(lns) != 2 {
		t.Fatalf("%d listeners, want 2", len(lns))
	}
	got := []string{lns[0].Addr().String(), lns[1].Addr().String()}
	if got[0] != "127.0.0.1:"+port || got[1] != "[::1]:"+port {
		t.Errorf("listening on %v", got)
	}
	// Both are held: nobody else can take either.
	for _, a := range []struct{ network, addr string }{{"tcp4", "127.0.0.1:" + port}, {"tcp6", "[::1]:" + port}} {
		if l, err := net.Listen(a.network, a.addr); err == nil {
			l.Close()
			t.Errorf("%s was free while the quickstart held it", a.addr)
		}
	}
	closeAll(lns)
}

// Somebody already on [::1]:PORT: refuse to start, and give the IPv4 port back.
func TestBindQuickstartRefusesATakenIPv6Port(t *testing.T) {
	if !ipv6Loopback() {
		t.Skip("no IPv6 loopback on this machine")
	}
	port := freeBothPort(t)
	squatter, err := net.Listen("tcp6", "[::1]:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer squatter.Close()
	lns, err := bindQuickstart("127.0.0.1:"+port, net.Listen)
	if err == nil {
		closeAll(lns)
		t.Fatal("started with another program on [::1]")
	}
	if !strings.Contains(err.Error(), "[::1]:"+port) || !strings.Contains(err.Error(), "Another program") {
		t.Errorf("unclear message: %v", err)
	}
	l, err := net.Listen("tcp4", "127.0.0.1:"+port)
	if err != nil {
		t.Errorf("the IPv4 port was not given back: %v", err)
	} else {
		l.Close()
	}

	// The whole command refuses too, before it makes a folder.
	dir := filepath.Join(t.TempDir(), "qs")
	if err := runQuickstart(t.Context(), quickstartOptions{Dir: dir, Addr: "127.0.0.1:" + port, Playground: true}, io.Discard); err == nil {
		t.Error("runQuickstart started with another program on [::1]")
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("a folder was made before the refusal")
	}
}

// With fake listeners, so it holds on any machine.
func TestBindQuickstartIPv6Rules(t *testing.T) {
	stub := func(failOn string) listenFunc {
		return func(network, addr string) (net.Listener, error) {
			if strings.HasPrefix(failOn, network+" ") && strings.HasSuffix(failOn, addr) || failOn == network {
				return nil, errors.New("refused")
			}
			return net.Listen("tcp4", "127.0.0.1:0") // a real listener to close
		}
	}
	// No IPv6 at all: the probe fails, the IPv4 listener alone is fine.
	lns, err := bindQuickstart("127.0.0.1:55999", stub("tcp6"))
	if err != nil || len(lns) != 1 {
		t.Fatalf("no IPv6: %d listeners, %v", len(lns), err)
	}
	closeAll(lns)
	// IPv6 works (the probe succeeds) but the real port is taken: an error, and the IPv4 listener is closed.
	lns, err = bindQuickstart("127.0.0.1:55999", stub("tcp6 [::1]:55999"))
	if err == nil || !strings.Contains(err.Error(), "[::1]:55999") {
		t.Fatalf("taken IPv6 port tolerated: %v (%d listeners)", err, len(lns))
	}
	// The IPv4 port itself taken: an error that names the likely cause.
	lns, err = bindQuickstart("127.0.0.1:55999", stub("tcp4"))
	if err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("taken IPv4 port: %v", err)
	}
	_ = lns
}

// A real quickstart answers on both addresses, to Host localhost:PORT only.
func TestQuickstartAnswersOnBothLoopbackAddresses(t *testing.T) {
	if !ipv6Loopback() {
		t.Skip("no IPv6 loopback on this machine")
	}
	port := freeBothPort(t)
	r := startQuickstart(t, quickstartOptions{Dir: filepath.Join(t.TempDir(), "qs"), Addr: "127.0.0.1:" + port})
	r.ready()
	get := func(addr, host string) int {
		req, _ := http.NewRequest("GET", "http://"+addr+"/enroll", nil)
		req.Host = host
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for _, addr := range []string{"127.0.0.1:" + port, "[::1]:" + port} {
		if code := get(addr, "localhost:"+port); code != 200 {
			t.Errorf("%s with Host localhost:%s: %d, want 200", addr, port, code)
		}
		for _, host := range []string{"[::1]:" + port, "127.0.0.1:" + port, "localhost", "evil.example"} {
			if code := get(addr, host); code != 403 {
				t.Errorf("%s with Host %s: %d, want 403", addr, host, code)
			}
		}
	}
}

// ---- a link or junction into the real install ----

func makeLink(t *testing.T, link, target string) {
	t.Helper()
	if err := os.Symlink(target, link); err == nil {
		return
	} else if runtime.GOOS != "windows" {
		t.Skipf("no symlinks here: %v", err)
	}
	// Windows without the symlink privilege: a junction needs none.
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("no symlinks or junctions here: %v %s", err, out)
	}
}

// Go's EvalSymlinks does not follow Windows junctions, so the real install is found by file identity: a path whose
// ancestor IS the install folder is refused whatever its text says, and so is a folder above it.
func TestQuickstartRefusesALinkIntoTheRealInstall(t *testing.T) {
	real := filepath.Join(t.TempDir(), "install")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	old := realInstallDir
	realInstallDir = func() string { return real }
	defer func() { realInstallDir = old }()

	link := filepath.Join(t.TempDir(), "link")
	makeLink(t, link, real)

	for _, d := range []string{real, filepath.Join(real, "sub"), link, filepath.Join(link, "new"), filepath.Join(link, "profiles", "x"), filepath.Dir(real)} {
		if _, _, err := checkQuickstartDir(d); err == nil || !strings.Contains(err.Error(), "real Chaperone install") {
			t.Errorf("%s was not refused as the real install: %v", d, err)
		}
	}
	// A folder elsewhere is fine.
	if _, _, err := checkQuickstartDir(filepath.Join(t.TempDir(), "elsewhere")); err != nil {
		t.Errorf("an unrelated folder: %v", err)
	}
	// A link to somewhere else is fine too.
	other := t.TempDir()
	link2 := filepath.Join(t.TempDir(), "link2")
	makeLink(t, link2, other)
	if _, _, err := checkQuickstartDir(filepath.Join(link2, "new")); err != nil {
		t.Errorf("a link to an unrelated folder: %v", err)
	}
}

// ---- the playground's fake GitHub ----

func TestPlaygroundFakeKeepsABoundedLog(t *testing.T) {
	f, err := newPlaygroundFake()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	big := strings.NewReader(strings.Repeat("x", 100_000))
	for range 650 {
		big.Seek(0, io.SeekStart)
		resp, err := http.Post(f.srv.URL()+"/nope", "text/plain", big)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	reqs := f.srv.Requests()
	if len(reqs) > 500 {
		t.Errorf("the log holds %d requests", len(reqs))
	}
	for _, r := range reqs {
		if len(r.Body) > 4<<10 {
			t.Fatalf("a logged body of %d bytes", len(r.Body))
		}
	}
}
