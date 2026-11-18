package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const doctorManifestPath = `C:\ProgramData\Chaperone\install.json`

func goodManifest() installManifest {
	return installManifest{
		Version: 1, BinDir: `C:\Program Files\Chaperone`, Root: `D:\Storefront\chaperone`,
		DB: `D:\Storefront\chaperone\state.db`, VaultDir: `D:\Storefront\chaperone\vault`,
		VaultKeyDir: `D:\Storefront\chaperone\vault-keys`, LogDir: `D:\Storefront\chaperone\logs`,
		DumpDir: `D:\Storefront\chaperone\dumps`, ExportDir: `D:\Storefront\ledger\chaperone`,
		AgentWork: `D:\Storefront\agent-work`, Service: "chapd",
		ServiceAccount: `.\svc-chaperone`, AgentAccount: `.\chap-agent`,
		AgentPasswordFile: `C:\ProgramData\Chaperone\agent-account.dpapi`,
		HostTask:          `\Chaperone\ChapHost`, Port: 55398, WithVault: true,
	}
}

// goodEnv is an install that is exactly as the runbook says.
func goodEnv(m installManifest) *doctorEnv {
	prot := map[string]bool{}
	for _, p := range []string{m.Root, m.DB, m.VaultDir, m.VaultKeyDir, m.DumpDir, m.LogDir} {
		prot[strings.ToLower(p)] = true
	}
	return &doctorEnv{
		elevated: func() bool { return false },
		service: func(string) (svcInfo, error) {
			return svcInfo{Exists: true, State: "running", StartType: "auto-delayed", Account: `.\svc-chaperone`,
				ImagePath: `"C:\Program Files\Chaperone\chapd.exe" svc -db D:\Storefront\chaperone\state.db`,
				Restarts:  3, ResetSeconds: 86400, NonCrash: true}, nil
		},
		access: func(_ *installManifest, asAgent bool, path string) (accessInfo, error) {
			low := strings.ToLower(path)
			switch {
			case prot[low]:
				return accessInfo{Exists: true}, nil
			case low == strings.ToLower(m.ExportDir):
				return accessInfo{Exists: true, Read: !asAgent}, nil
			case low == strings.ToLower(m.AgentWork):
				return accessInfo{Exists: true, Read: true, Write: true}, nil
			case low == strings.ToLower(m.BinDir):
				return accessInfo{Exists: true, Read: true}, nil
			}
			return accessInfo{}, nil // the orchestrator token file does not exist yet
		},
		freeBytes: func(string) (uint64, error) { return 200 << 30, nil },
		registry: func(subkey, value string) (string, bool) {
			switch {
			case strings.HasSuffix(subkey, `\ExcludedApplications`) && value == "chapd.exe":
				return "1", true
			case strings.HasSuffix(subkey, `\LocalDumps\chapd.exe`) && value == "DumpFolder":
				return m.DumpDir, true
			}
			return "", false
		},
		runCmd: func(string, ...string) (string, error) {
			return `<Task><Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>` +
				`<Principals><Principal id="A"><UserId>S-1-5-21-1-2-3-1001</UserId><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>` +
				`<Actions><Exec><Command>"C:\Program Files\Chaperone\chap-host.exe"</Command></Exec></Actions></Task>`, nil
		},
		userNames: func() []string { return []string{`PC\user`, "S-1-5-21-1-2-3-1001"} },
		ifaceAddrs: func() ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.20"), Mask: net.CIDRMask(24, 32)}}, nil
		},
		dial: func(network, addr string, _ time.Duration) (net.Conn, error) {
			if network == "udp" {
				return sntpConn(time.Now()), nil
			}
			if strings.HasPrefix(addr, "127.0.0.1:") {
				a, b := net.Pipe()
				b.Close()
				return a, nil
			}
			return nil, errors.New("connection refused")
		},
		now:  time.Now,
		sntp: "time.example:123",
	}
}

// sntpConn answers one SNTP request with the given server time.
func sntpConn(server time.Time) net.Conn {
	c, s := net.Pipe()
	go func() {
		defer s.Close()
		buf := make([]byte, 48)
		if _, err := s.Read(buf); err != nil {
			return
		}
		resp := make([]byte, 48)
		resp[0] = 0x1c
		secs := uint32(server.Unix() + 2208988800)
		binary.BigEndian.PutUint32(resp[40:], secs)
		s.Write(resp)
	}()
	return c
}

// doctorChapd is a chapd that answers the three doctor calls.
func doctorChapd(t *testing.T, creds int, chainOK, vaultInit bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /v0/status":
			json.NewEncoder(w).Encode(map[string]any{"version": "0.9.0", "approver_credentials": creds})
		case "POST /v0/ledger/verify":
			json.NewEncoder(w).Encode(map[string]any{"ok": chainOK, "chain": "x", "head_seq": 42, "head_hash": "sha256:00", "checked_export": false, "problems": []string{"seq 7 prev hash mismatch"}})
		case "GET /v0/vault/status":
			json.NewEncoder(w).Encode(map[string]any{"initialized": vaultInit, "secret_count": 2, "names": []string{}})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func doctorApp(t *testing.T, m installManifest, chapdURL string) *testApp {
	t.Helper()
	data, _ := json.Marshal(m)
	ta := newTestApp(t, env{token: "orch", fs: map[string]string{doctorManifestPath: string(data)}, extra: map[string]string{
		"CHAP_INSTALL_MANIFEST": doctorManifestPath, "CHAP_URL": chapdURL}})
	return ta
}

func find(t *testing.T, fnd []finding, name string) finding {
	t.Helper()
	for _, f := range fnd {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("no finding %q in %+v", name, fnd)
	return finding{}
}

func TestDoctorAllGood(t *testing.T) {
	m := goodManifest()
	ta := doctorApp(t, m, doctorChapd(t, 1, true, true).URL)
	for _, f := range runDoctor(ta.app, goodEnv(m)) {
		if f.lv != lvOK {
			t.Errorf("%s is %s: %s", f.Name, f.Level, f.Detail)
		}
	}
}

// Each deliberately broken setting must be loud.
func TestDoctorBreakages(t *testing.T) {
	m := goodManifest()
	cases := []struct {
		name  string
		check string
		want  level
		tweak func(e *doctorEnv)
		chapd [3]any // creds, chainOK, vaultInit
	}{
		{"elevated", "token", lvFail, func(e *doctorEnv) { e.elevated = func() bool { return true } }, [3]any{1, true, true}},
		{"service stopped", "service", lvFail, func(e *doctorEnv) {
			e.service = func(string) (svcInfo, error) {
				s, _ := goodEnv(m).service("")
				s.State = "stopped"
				return s, nil
			}
		}, [3]any{1, true, true}},
		{"service missing", "service", lvFail, func(e *doctorEnv) { e.service = func(string) (svcInfo, error) { return svcInfo{}, nil } }, [3]any{1, true, true}},
		{"service as LocalSystem", "service", lvFail, func(e *doctorEnv) {
			e.service = func(string) (svcInfo, error) {
				s, _ := goodEnv(m).service("")
				s.Account = "LocalSystem"
				return s, nil
			}
		}, [3]any{1, true, true}},
		{"service image outside bin dir", "service", lvFail, func(e *doctorEnv) {
			e.service = func(string) (svcInfo, error) {
				s, _ := goodEnv(m).service("")
				s.ImagePath = `D:\agent-work\chapd.exe svc`
				return s, nil
			}
		}, [3]any{1, true, true}},
		{"no recovery", "service", lvFail, func(e *doctorEnv) {
			e.service = func(string) (svcInfo, error) {
				s, _ := goodEnv(m).service("")
				s.Restarts = 0
				return s, nil
			}
		}, [3]any{1, true, true}},
		{"operator can read the vault", "acl-operator", lvFail, func(e *doctorEnv) {
			ok := e.access
			e.access = func(mm *installManifest, ag bool, p string) (accessInfo, error) {
				if !ag && p == m.VaultDir {
					return accessInfo{Exists: true, Read: true}, nil
				}
				return ok(mm, ag, p)
			}
		}, [3]any{1, true, true}},
		{"agent can read state.db", "acl-agent", lvFail, func(e *doctorEnv) {
			ok := e.access
			e.access = func(mm *installManifest, ag bool, p string) (accessInfo, error) {
				if ag && p == m.DB {
					return accessInfo{Exists: true, Read: true}, nil
				}
				return ok(mm, ag, p)
			}
		}, [3]any{1, true, true}},
		{"agent can read the orchestrator token", "acl-agent", lvFail, func(e *doctorEnv) {
			ok := e.access
			e.access = func(mm *installManifest, ag bool, p string) (accessInfo, error) {
				if ag && strings.HasSuffix(p, "orchestrator.token") {
					return accessInfo{Exists: true, Read: true}, nil
				}
				return ok(mm, ag, p)
			}
		}, [3]any{1, true, true}},
		{"agent can write the bin dir", "acl-agent", lvFail, func(e *doctorEnv) {
			ok := e.access
			e.access = func(mm *installManifest, ag bool, p string) (accessInfo, error) {
				if ag && p == m.BinDir {
					return accessInfo{Exists: true, Read: true, Write: true}, nil
				}
				return ok(mm, ag, p)
			}
		}, [3]any{1, true, true}},
		{"agent work dir not writable", "acl-agent", lvFail, func(e *doctorEnv) {
			ok := e.access
			e.access = func(mm *installManifest, ag bool, p string) (accessInfo, error) {
				if ag && p == m.AgentWork {
					return accessInfo{Exists: true, Read: true}, nil
				}
				return ok(mm, ag, p)
			}
		}, [3]any{1, true, true}},
		{"agent probe impossible", "acl-agent", lvWarn, func(e *doctorEnv) {
			ok := e.access
			e.access = func(mm *installManifest, ag bool, p string) (accessInfo, error) {
				if ag {
					return accessInfo{}, errors.New("logon failed")
				}
				return ok(mm, ag, p)
			}
		}, [3]any{1, true, true}},
		{"port open on the LAN", "listener", lvFail, func(e *doctorEnv) {
			ok := e.dial
			e.dial = func(n, a string, d time.Duration) (net.Conn, error) {
				if n == "tcp" && strings.HasPrefix(a, "192.0.2.20:") {
					c, s := net.Pipe()
					s.Close()
					return c, nil
				}
				return ok(n, a, d)
			}
		}, [3]any{1, true, true}},
		{"nothing listens", "listener", lvFail, func(e *doctorEnv) {
			e.dial = func(string, string, time.Duration) (net.Conn, error) { return nil, errors.New("refused") }
		}, [3]any{1, true, true}},
		{"clock 10 minutes fast", "clock", lvFail, func(e *doctorEnv) {
			e.dial = func(n, a string, d time.Duration) (net.Conn, error) {
				if n == "udp" {
					return sntpConn(time.Now().Add(-10 * time.Minute)), nil
				}
				return goodEnv(m).dial(n, a, d)
			}
		}, [3]any{1, true, true}},
		{"clock 2 minutes off", "clock", lvWarn, func(e *doctorEnv) {
			e.dial = func(n, a string, d time.Duration) (net.Conn, error) {
				if n == "udp" {
					return sntpConn(time.Now().Add(2 * time.Minute)), nil
				}
				return goodEnv(m).dial(n, a, d)
			}
		}, [3]any{1, true, true}},
		{"offline", "clock", lvWarn, func(e *doctorEnv) {
			ok := e.dial
			e.dial = func(n, a string, d time.Duration) (net.Conn, error) {
				if n == "udp" {
					return nil, errors.New("no route")
				}
				return ok(n, a, d)
			}
		}, [3]any{1, true, true}},
		{"disk 1 GiB", "disk", lvFail, func(e *doctorEnv) { e.freeBytes = func(string) (uint64, error) { return 1 << 30, nil } }, [3]any{1, true, true}},
		{"disk 5 GiB", "disk", lvWarn, func(e *doctorEnv) { e.freeBytes = func(string) (uint64, error) { return 5 << 30, nil } }, [3]any{1, true, true}},
		{"dumps not excluded", "crash-dumps", lvWarn, func(e *doctorEnv) { e.registry = func(string, string) (string, bool) { return "", false } }, [3]any{1, true, true}},
		{"host task elevated", "chap-host", lvWarn, func(e *doctorEnv) {
			e.runCmd = func(string, ...string) (string, error) {
				x, _ := goodEnv(m).runCmd("")
				return strings.Replace(x, "LeastPrivilege", "HighestAvailable", 1), nil
			}
		}, [3]any{1, true, true}},
		{"host task missing", "chap-host", lvWarn, func(e *doctorEnv) {
			e.runCmd = func(string, ...string) (string, error) { return "", errors.New("not found") }
		}, [3]any{1, true, true}},
		{"no Hello credential", "hello", lvWarn, func(*doctorEnv) {}, [3]any{0, true, true}},
		{"broken chain", "ledger", lvFail, func(*doctorEnv) {}, [3]any{1, false, true}},
		{"vault not initialized", "vault", lvFail, func(*doctorEnv) {}, [3]any{1, true, false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := goodEnv(m)
			tc.tweak(e)
			ta := doctorApp(t, m, doctorChapd(t, tc.chapd[0].(int), tc.chapd[1].(bool), tc.chapd[2].(bool)).URL)
			f := find(t, runDoctor(ta.app, e), tc.check)
			if f.lv != tc.want {
				t.Fatalf("%s is %s (%s), want %s", f.Name, f.Level, f.Detail, tc.want)
			}
		})
	}
}

func TestDoctorManifest(t *testing.T) {
	m := goodManifest()
	ta := newTestApp(t, env{token: "orch", extra: map[string]string{"CHAP_INSTALL_MANIFEST": doctorManifestPath}})
	if f := find(t, runDoctor(ta.app, goodEnv(m)), "manifest"); f.lv != lvFail || !strings.Contains(f.Detail, "install.ps1") {
		t.Fatalf("missing manifest: %+v", f)
	}
	ta = newTestApp(t, env{token: "orch", fs: map[string]string{doctorManifestPath: `{"version":1}`}, extra: map[string]string{"CHAP_INSTALL_MANIFEST": doctorManifestPath}})
	if f := find(t, runDoctor(ta.app, goodEnv(m)), "manifest"); f.lv != lvFail {
		t.Fatalf("incomplete manifest: %+v", f)
	}
	ta = newTestApp(t, env{token: "orch", fs: map[string]string{doctorManifestPath: `not json`}, extra: map[string]string{"CHAP_INSTALL_MANIFEST": doctorManifestPath}})
	if f := find(t, runDoctor(ta.app, goodEnv(m)), "manifest"); f.lv != lvFail {
		t.Fatalf("bad manifest: %+v", f)
	}
}

func TestDoctorChapdUnreachable(t *testing.T) {
	m := goodManifest()
	srv := doctorChapd(t, 1, true, true)
	url := srv.URL
	srv.Close()
	ta := doctorApp(t, m, url)
	if f := find(t, runDoctor(ta.app, goodEnv(m)), "chapd"); f.lv != lvFail {
		t.Fatalf("unreachable chapd: %+v", f)
	}
}

func TestCmdDoctorExitAndOutput(t *testing.T) {
	m := goodManifest()
	old := doctorEnvFor
	t.Cleanup(func() { doctorEnvFor = old })
	doctorEnvFor = func(*app) *doctorEnv { return goodEnv(m) }

	ta := doctorApp(t, m, doctorChapd(t, 1, true, true).URL)
	if code := ta.app.run([]string{"doctor"}); code != exitOK {
		t.Fatalf("good install: exit %d\n%s%s", code, ta.out, ta.errb)
	}
	if !strings.Contains(ta.out.String(), "0 warn, 0 FAIL") {
		t.Fatalf("summary line missing:\n%s", ta.out)
	}

	ta = doctorApp(t, m, doctorChapd(t, 1, false, true).URL)
	if code := ta.app.run([]string{"doctor", "--json"}); code != exitNotOK {
		t.Fatalf("broken chain: exit %d", code)
	}
	var got struct {
		OK     bool      `json:"ok"`
		Checks []finding `json:"checks"`
	}
	if err := json.Unmarshal(ta.out.Bytes(), &got); err != nil || got.OK {
		t.Fatalf("json: %v ok=%v\n%s", err, got.OK, ta.out)
	}

	doctorEnvFor = func(*app) *doctorEnv { return nil }
	ta = doctorApp(t, m, "http://127.0.0.1:1")
	if code := ta.app.run([]string{"doctor"}); code != exitUsage {
		t.Fatalf("unsupported system: exit %d", code)
	}
}

// The doctor must never print a token or a password: the app's scrubber is
// the only writer, and the findings carry paths and counts only.
func TestDoctorOutputHasNoToken(t *testing.T) {
	m := goodManifest()
	old := doctorEnvFor
	t.Cleanup(func() { doctorEnvFor = old })
	doctorEnvFor = func(*app) *doctorEnv { return goodEnv(m) }
	ta := doctorApp(t, m, doctorChapd(t, 1, true, true).URL)
	ta.app.run([]string{"doctor"})
	if strings.Contains(ta.out.String()+ta.errb.String(), testOrchToken) {
		t.Fatal("the orchestrator token was printed")
	}
}

func TestSplitImagePath(t *testing.T) {
	for in, want := range map[string][2]string{
		`"C:\Program Files\x\chapd.exe" svc -db D:\a b`: {`C:\Program Files\x\chapd.exe`, `svc -db D:\a b`},
		`C:\x\chapd.exe svc`:                            {`C:\x\chapd.exe`, `svc`},
		`"C:\x\chapd.exe"`:                              {`C:\x\chapd.exe`, ``},
	} {
		exe, args := splitImagePath(in)
		if exe != want[0] || args != want[1] {
			t.Errorf("%q -> %q, %q", in, exe, args)
		}
	}
}

func TestSameAccountAndPath(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{`.\svc-chaperone`, `svc-chaperone`, true}, {`PC\SVC-Chaperone`, `.\svc-chaperone`, true}, {`LocalSystem`, `.\svc-chaperone`, false}, {``, `svc-chaperone`, false}} {
		if sameAccount(c.a, c.b) != c.want {
			t.Errorf("sameAccount(%q, %q)", c.a, c.b)
		}
	}
	if !samePath(`C:\Program Files\X\`, `c:/program files/x`) || samePath(`C:\a`, `C:\b`) {
		t.Error("samePath")
	}
}

func TestSntpSkewSignAndGarbage(t *testing.T) {
	dial := func(string, string, time.Duration) (net.Conn, error) {
		return sntpConn(time.Now().Add(90 * time.Second)), nil
	}
	d, err := sntpSkew("x:123", dial, time.Now)
	if err != nil || d < 85*time.Second || d > 95*time.Second {
		t.Fatalf("skew %v err %v", d, err)
	}
	// An all-zero reply carries no time.
	zero := func(string, string, time.Duration) (net.Conn, error) {
		c, s := net.Pipe()
		go func() { s.Read(make([]byte, 48)); s.Write(make([]byte, 48)); s.Close() }()
		return c, nil
	}
	if _, err := sntpSkew("x:123", zero, time.Now); err == nil {
		t.Fatal("a reply with no time must be an error")
	}
}

func TestProbeAccessLeavesNothingBehind(t *testing.T) {
	dir := t.TempDir()
	got := probeAccess(dir)
	if !got.Exists || !got.Read || !got.Write {
		t.Fatalf("own temp dir: %+v", got)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("the probe left %d files behind", len(ents))
	}
	f := filepath.Join(dir, "a.db")
	if err := os.WriteFile(f, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := probeAccess(f); !got.Read || !got.Write {
		t.Fatalf("file: %+v", got)
	}
	if b, _ := os.ReadFile(f); string(b) != "keep" {
		t.Fatal("the probe changed the file")
	}
	if got := probeAccess(filepath.Join(dir, "none")); got.Exists {
		t.Fatal("missing path reported as existing")
	}
}
