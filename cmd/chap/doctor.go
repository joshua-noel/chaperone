package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// `chap doctor` is the install's self-check (ticket L1-17). It answers one
// question for the operator: "is the server set up the way the install runbook
// says, and is it still?" It reads the install manifest the installer wrote,
// then probes the real thing: the service, the folder ACLs (as the operator
// and, through a network logon, as the agent account), the port, the clock,
// the disk and the crash-dump settings. It never changes anything.
//
// The logic here is platform-neutral and runs against a doctorEnv of probes;
// doctor_windows.go supplies the real ones and the tests supply fakes.

// level is how bad a finding is. A FAIL makes the exit code non-zero.
type level int

const (
	lvOK level = iota
	lvWarn
	lvFail
)

func (l level) String() string {
	switch l {
	case lvWarn:
		return "warn"
	case lvFail:
		return "FAIL"
	}
	return "ok"
}

type finding struct {
	Name   string `json:"name"`
	Level  string `json:"level"`
	Detail string `json:"detail"`
	lv     level
}

// installManifest is C:\ProgramData\Chaperone\install.json, written by
// scripts/windows/install.ps1. Admin-write, users read; it holds no secret.
type installManifest struct {
	Version           int    `json:"version"`
	BinDir            string `json:"bin_dir"`
	Root              string `json:"root"`
	DB                string `json:"db"`
	VaultDir          string `json:"vault_dir"`
	VaultKeyDir       string `json:"vault_key_dir"`
	LogDir            string `json:"log_dir"`
	DumpDir           string `json:"dump_dir"`
	ExportDir         string `json:"export_dir"`
	AgentWork         string `json:"agent_work"`
	Service           string `json:"service"`
	ServiceAccount    string `json:"service_account"`
	AgentAccount      string `json:"agent_account"`
	AgentPasswordFile string `json:"agent_password_file"`
	HostTask          string `json:"host_task"`
	HostConfig        string `json:"host_config"`
	Port              int    `json:"port"`
	WithVault         bool   `json:"with_vault"`
}

func (m *installManifest) validate() error {
	if m.Version != 1 {
		return fmt.Errorf("manifest version %d is not 1", m.Version)
	}
	for name, v := range map[string]string{
		"bin_dir": m.BinDir, "root": m.Root, "db": m.DB, "vault_dir": m.VaultDir, "vault_key_dir": m.VaultKeyDir,
		"log_dir": m.LogDir, "dump_dir": m.DumpDir, "export_dir": m.ExportDir, "agent_work": m.AgentWork,
		"service": m.Service, "service_account": m.ServiceAccount, "agent_account": m.AgentAccount,
	} {
		if v == "" {
			return fmt.Errorf("manifest has no %s", name)
		}
	}
	if m.Port == 0 {
		m.Port = 55398
	}
	return nil
}

// svcInfo is what the service manager says about a service.
type svcInfo struct {
	Exists       bool
	State        string // "running", "stopped", ...
	StartType    string // "auto", "auto-delayed", "manual", "disabled"
	Account      string // the logon account as configured, e.g. ".\svc-chaperone"
	ImagePath    string // BinaryPathName, with its arguments
	Restarts     int    // leading restart actions of the failure policy
	ResetSeconds int    // failure counter reset period
	NonCrash     bool   // failure actions also on non-crash failures (failureflag)
}

// accessInfo is what a probe found out about one path.
type accessInfo struct {
	Exists bool
	Read   bool
	Write  bool
}

// doctorEnv is every probe the doctor uses. A nil member is a programming
// error; the Windows implementation fills all of them.
type doctorEnv struct {
	elevated func() bool
	service  func(name string) (svcInfo, error)
	// access probes path as the current (normal-token) user, or, when
	// asAgent, as the agent account via a network logon with the password the
	// installer stored (DPAPI, operator only).
	access     func(m *installManifest, asAgent bool, path string) (accessInfo, error)
	freeBytes  func(path string) (uint64, error)
	registry   func(subkey, value string) (string, bool) // HKLM string value
	runCmd     func(name string, args ...string) (string, error)
	userNames  func() []string // current user's DOMAIN\name and SID, for the task check
	ifaceAddrs func() ([]net.Addr, error)
	dial       func(network, addr string, timeout time.Duration) (net.Conn, error)
	now        func() time.Time
	sntp       string // host:port of the time server
}

const minFreeFail, minFreeWarn = 2 << 30, 10 << 30

// manifestPath is where the installer wrote the manifest.
func (a *app) manifestPath() string {
	if p := strings.TrimSpace(a.getenv("CHAP_INSTALL_MANIFEST")); p != "" {
		return p
	}
	pd := a.getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "Chaperone", "install.json")
}

func cmdDoctor(a *app, c *command, args []string) int {
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	asJSON := jsonOnly(fs)
	if _, code, done := a.parse(c, fs, args, 0, 0); done {
		return code
	}
	env := doctorEnvFor(a)
	if env == nil {
		return a.fail(exitUsage, "doctor checks the Windows install and is not available on this system")
	}
	fnd := runDoctor(a, env)
	nWarn, nFail := 0, 0
	for _, f := range fnd {
		switch f.lv {
		case lvWarn:
			nWarn++
		case lvFail:
			nFail++
		}
	}
	if *asJSON {
		b, _ := json.MarshalIndent(map[string]any{"ok": nFail == 0, "checks": fnd}, "", "  ")
		a.out(string(b) + "\n")
	} else {
		var b strings.Builder
		for _, f := range fnd {
			fmt.Fprintf(&b, "%-4s  %-18s %s\n", f.Level, f.Name, clean(f.Detail))
		}
		fmt.Fprintf(&b, "\n%d checks: %d ok, %d warn, %d FAIL\n", len(fnd), len(fnd)-nWarn-nFail, nWarn, nFail)
		a.out(b.String())
	}
	if nFail > 0 {
		return exitNotOK
	}
	return exitOK
}

// runDoctor runs every check and returns the findings in a fixed order.
func runDoctor(a *app, env *doctorEnv) []finding {
	var out []finding
	add := func(name string, lv level, format string, args ...any) {
		out = append(out, finding{Name: name, Level: lv.String(), Detail: fmt.Sprintf(format, args...), lv: lv})
	}

	// An elevated token is a member of Administrators, which the install's
	// ACLs let in: every "denied" probe would pass for the wrong reason.
	if env.elevated() {
		add("token", lvFail, "this terminal is elevated; open a normal one (the probes only mean something with the filtered token)")
		return out
	}
	add("token", lvOK, "normal (not elevated)")

	mp := a.manifestPath()
	data, err := a.readFile(mp)
	if err != nil {
		add("manifest", lvFail, "cannot read %s: %v (run scripts\\windows\\install.ps1 as administrator)", mp, err)
		return out
	}
	var m installManifest
	if err := json.Unmarshal(data, &m); err != nil {
		add("manifest", lvFail, "%s is not valid JSON: %v", mp, err)
		return out
	}
	if err := m.validate(); err != nil {
		add("manifest", lvFail, "%s: %v", mp, err)
		return out
	}
	add("manifest", lvOK, "%s", mp)

	checkService(env, &m, add)
	checkACLs(a, env, &m, add)
	checkListener(env, &m, add)
	checkClock(env, add)
	checkDisk(env, &m, add)
	checkCrashDumps(env, &m, add)
	checkHostTask(env, &m, add)
	checkChapd(a, &m, add)
	return out
}

type adder func(name string, lv level, format string, args ...any)

func checkService(env *doctorEnv, m *installManifest, add adder) {
	s, err := env.service(m.Service)
	switch {
	case err != nil:
		add("service", lvFail, "cannot query service %s: %v", m.Service, err)
		return
	case !s.Exists:
		add("service", lvFail, "service %s is not installed", m.Service)
		return
	}
	var bad []string
	if s.State != "running" {
		bad = append(bad, "state is "+s.State+", want running")
	}
	if s.StartType != "auto" && s.StartType != "auto-delayed" {
		bad = append(bad, "start type is "+s.StartType+", want auto")
	}
	if !sameAccount(s.Account, m.ServiceAccount) {
		bad = append(bad, fmt.Sprintf("runs as %q, want %s", s.Account, m.ServiceAccount))
	}
	exe, args := splitImagePath(s.ImagePath)
	if !samePath(winDir(exe), m.BinDir) || !strings.EqualFold(winBase(exe), "chapd.exe") {
		bad = append(bad, fmt.Sprintf("image is %q, want chapd.exe inside %s", exe, m.BinDir))
	}
	if !strings.Contains(" "+args+" ", " svc ") {
		bad = append(bad, "image arguments do not start `chapd svc`")
	}
	if s.Restarts < 3 || s.ResetSeconds != 86400 || !s.NonCrash {
		bad = append(bad, fmt.Sprintf("recovery is %d restarts, reset %ds, non-crash %v; want 3 restarts, 86400s, true", s.Restarts, s.ResetSeconds, s.NonCrash))
	}
	if len(bad) > 0 {
		add("service", lvFail, "%s: %s", m.Service, strings.Join(bad, "; "))
		return
	}
	add("service", lvOK, "%s running as %s from %s, restarts on failure", m.Service, m.ServiceAccount, m.BinDir)
}

// expect is one path with the access a given account should have.
type expect struct {
	path        string
	read, write bool
	note        string
}

func checkACLs(a *app, env *doctorEnv, m *installManifest, add adder) {
	protected := []string{m.Root, m.DB, m.VaultDir, m.VaultKeyDir, m.DumpDir, m.LogDir}
	var me, agent []expect
	for _, p := range protected {
		me = append(me, expect{path: p})
		agent = append(agent, expect{path: p})
	}
	// The operator reads the ledger export but cannot change it; the agent
	// sees neither the export nor the operator's orchestrator token.
	me = append(me,
		expect{path: m.ExportDir, read: true},
		expect{path: m.AgentWork, read: true, write: true},
		expect{path: m.BinDir, read: true})
	agent = append(agent,
		expect{path: m.ExportDir},
		expect{path: m.AgentWork, read: true, write: true},
		expect{path: m.BinDir, read: true},
		expect{path: a.tokenFilePath(), note: "orchestrator token"})

	run := func(name string, asAgent bool, list []expect) {
		var bad []string
		skipped := 0
		for _, e := range list {
			got, err := env.access(m, asAgent, e.path)
			if err != nil {
				add(name, lvWarn, "cannot probe as this account: %v", err)
				return
			}
			if !got.Exists {
				if e.note != "" || e.path == m.DB || e.path == m.DumpDir || e.path == m.ExportDir {
					skipped++ // not created yet (chapd never ran, no token issued)
					continue
				}
				bad = append(bad, e.path+" does not exist")
				continue
			}
			if got.Read != e.read {
				bad = append(bad, fmt.Sprintf("%s: read is %v, want %v", e.path, got.Read, e.read))
			}
			if got.Write != e.write {
				bad = append(bad, fmt.Sprintf("%s: write is %v, want %v", e.path, got.Write, e.write))
			}
		}
		switch {
		case len(bad) > 0:
			add(name, lvFail, "%s", strings.Join(bad, "; "))
		default:
			d := fmt.Sprintf("%d paths have exactly the intended access", len(list)-skipped)
			if skipped > 0 {
				d += fmt.Sprintf(" (%d not created yet)", skipped)
			}
			add(name, lvOK, "%s", d)
		}
	}
	run("acl-operator", false, me)
	run("acl-agent", true, agent)
}

func checkListener(env *doctorEnv, m *installManifest, add adder) {
	port := strconv.Itoa(m.Port)
	conn, err := env.dial("tcp", net.JoinHostPort("127.0.0.1", port), 2*time.Second)
	if err != nil {
		add("listener", lvFail, "nothing answers on 127.0.0.1:%s: %v", port, err)
		return
	}
	conn.Close()
	addrs, err := env.ifaceAddrs()
	if err != nil {
		add("listener", lvWarn, "listens on loopback, but the interface list is unreadable: %v", err)
		return
	}
	var open []string
	for _, ad := range addrs {
		ipn, ok := ad.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() || ipn.IP.IsUnspecified() || ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		if c, err := env.dial("tcp", net.JoinHostPort(ipn.IP.String(), port), time.Second); err == nil {
			c.Close()
			open = append(open, ipn.IP.String())
		}
	}
	if len(open) > 0 {
		add("listener", lvFail, "port %s also answers on %s; chapd must listen on loopback only", port, strings.Join(open, ", "))
		return
	}
	add("listener", lvOK, "127.0.0.1:%s answers; no other local address does", port)
}

func checkClock(env *doctorEnv, add adder) {
	skew, err := sntpSkew(env.sntp, env.dial, env.now)
	if err != nil {
		add("clock", lvWarn, "cannot reach the time server %s (offline?): %v", env.sntp, err)
		return
	}
	abs := skew
	if abs < 0 {
		abs = -abs
	}
	switch {
	case abs > 5*time.Minute:
		add("clock", lvFail, "the clock is %s off the time server; tokens and the ledger depend on it", skew.Round(time.Second))
	case abs > 30*time.Second:
		add("clock", lvWarn, "the clock is %s off the time server", skew.Round(time.Second))
	default:
		add("clock", lvOK, "within 30s of %s (skew %s)", env.sntp, skew.Round(time.Second))
	}
}

// sntpSkew returns server time minus local time using one SNTP exchange.
func sntpSkew(addr string, dial func(network, addr string, timeout time.Duration) (net.Conn, error), now func() time.Time) (time.Duration, error) {
	conn, err := dial("udp", addr, 3*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(now().Add(3 * time.Second))
	req := make([]byte, 48)
	req[0] = 0x1b // LI 0, version 3, mode 3 (client)
	t0 := now()
	if _, err := conn.Write(req); err != nil {
		return 0, err
	}
	resp := make([]byte, 48)
	n, err := io.ReadFull(conn, resp)
	if err != nil {
		return 0, fmt.Errorf("short reply (%d bytes): %w", n, err)
	}
	t1 := now()
	secs := uint64(resp[40])<<24 | uint64(resp[41])<<16 | uint64(resp[42])<<8 | uint64(resp[43])
	frac := uint64(resp[44])<<24 | uint64(resp[45])<<16 | uint64(resp[46])<<8 | uint64(resp[47])
	if secs == 0 {
		return 0, errors.New("the server sent no time")
	}
	const ntpToUnix = 2208988800
	server := time.Unix(int64(secs)-ntpToUnix, int64(frac*1e9>>32))
	mid := t0.Add(t1.Sub(t0) / 2)
	return server.Sub(mid), nil
}

func checkDisk(env *doctorEnv, m *installManifest, add adder) {
	free, err := env.freeBytes(m.Root)
	if err != nil {
		add("disk", lvWarn, "cannot read the free space of %s: %v", m.Root, err)
		return
	}
	gib := float64(free) / (1 << 30)
	switch {
	case free < minFreeFail:
		add("disk", lvFail, "%.1f GiB free on the drive of %s; chapd needs room for the database, ledger and logs", gib, m.Root)
	case free < minFreeWarn:
		add("disk", lvWarn, "%.1f GiB free on the drive of %s", gib, m.Root)
	default:
		add("disk", lvOK, "%.0f GiB free on the drive of %s", gib, m.Root)
	}
}

const werKey = `SOFTWARE\Microsoft\Windows\Windows Error Reporting`

func checkCrashDumps(env *doctorEnv, m *installManifest, add adder) {
	var bad []string
	if _, ok := env.registry(werKey+`\ExcludedApplications`, "chapd.exe"); !ok {
		bad = append(bad, "chapd.exe is not excluded from Windows Error Reporting")
	}
	folder, ok := env.registry(werKey+`\LocalDumps\chapd.exe`, "DumpFolder")
	if !ok || !samePath(folder, m.DumpDir) {
		bad = append(bad, fmt.Sprintf("LocalDumps\\chapd.exe DumpFolder is %q, want %s", folder, m.DumpDir))
	}
	if len(bad) > 0 {
		add("crash-dumps", lvWarn, "%s (a chapd crash dump would hold the vault's keys in memory)", strings.Join(bad, "; "))
		return
	}
	add("crash-dumps", lvOK, "chapd.exe is excluded from WER and any local dump goes to the locked folder")
}

var (
	taskRunLevelRE = regexp.MustCompile(`(?s)<RunLevel>\s*(.*?)\s*</RunLevel>`)
	taskUserRE     = regexp.MustCompile(`(?s)<Principal\b.*?<UserId>\s*(.*?)\s*</UserId>`)
	taskCommandRE  = regexp.MustCompile(`(?s)<Command>\s*(.*?)\s*</Command>`)
)

func checkHostTask(env *doctorEnv, m *installManifest, add adder) {
	if m.HostTask == "" {
		add("chap-host", lvOK, "not installed (no -WithHost)")
		return
	}
	xml, err := env.runCmd("schtasks.exe", "/Query", "/TN", m.HostTask, "/XML")
	if err != nil {
		add("chap-host", lvWarn, "scheduled task %s cannot be read: %v", m.HostTask, err)
		return
	}
	var bad []string
	if g := taskRunLevelRE.FindStringSubmatch(xml); g == nil || g[1] != "LeastPrivilege" {
		bad = append(bad, "the task does not run with least privilege")
	}
	if !strings.Contains(xml, "<LogonTrigger>") {
		bad = append(bad, "the task has no at-logon trigger")
	}
	if strings.Contains(xml, "<Enabled>false</Enabled>") {
		bad = append(bad, "the task is disabled")
	}
	if g := taskCommandRE.FindStringSubmatch(xml); g == nil || !samePath(winDir(strings.Trim(g[1], `"`)), m.BinDir) {
		bad = append(bad, "the task does not run chap-host.exe from "+m.BinDir)
	}
	g := taskUserRE.FindStringSubmatch(xml)
	okUser := false
	if g != nil {
		for _, n := range env.userNames() {
			if strings.EqualFold(n, g[1]) {
				okUser = true
			}
		}
	}
	if !okUser {
		bad = append(bad, "the task is not set to run as the operator")
	}
	if len(bad) > 0 {
		add("chap-host", lvWarn, "%s", strings.Join(bad, "; "))
		return
	}
	add("chap-host", lvOK, "%s runs chap-host at logon as the operator, not elevated", m.HostTask)
}

// checkChapd asks chapd itself: the credential count (Windows Hello), the
// ledger chain and the vault. A refusal or an unreachable chapd is reported,
// not retried.
func checkChapd(a *app, m *installManifest, add adder) {
	r, err := a.call("GET", "/v0/status", nil, nil)
	if err != nil {
		add("chapd", lvFail, "%s", errText(err))
		return
	}
	if r.status != 200 {
		add("chapd", lvFail, "GET /v0/status answered %d (is the orchestrator token current? `chapd orch issue`)", r.status)
		return
	}
	var st struct {
		Version     string `json:"version"`
		Credentials *int   `json:"approver_credentials"`
	}
	if err := json.Unmarshal(r.body, &st); err != nil {
		add("chapd", lvFail, "unreadable status reply: %v", err)
		return
	}
	add("chapd", lvOK, "answers as %s", clean(st.Version))
	switch {
	case st.Credentials == nil:
		add("hello", lvWarn, "chapd did not report the approver credentials (is the token an orchestrator token?)")
	case *st.Credentials == 0:
		add("hello", lvWarn, "no Windows Hello credential is enrolled: no approval can be given (chapd enroll)")
	default:
		add("hello", lvOK, "%d approver credential(s) enrolled", *st.Credentials)
	}

	r, err = a.call("POST", "/v0/ledger/verify", nil, map[string]any{"against_export": false})
	switch {
	case err != nil:
		add("ledger", lvFail, "%s", errText(err))
	case r.status != 200:
		add("ledger", lvFail, "ledger verify answered %d", r.status)
	default:
		var v struct {
			OK       bool     `json:"ok"`
			HeadSeq  int64    `json:"head_seq"`
			Problems []string `json:"problems"`
		}
		if json.Unmarshal(r.body, &v) != nil {
			add("ledger", lvFail, "unreadable ledger verify reply")
		} else if !v.OK {
			add("ledger", lvFail, "the hash chain does not verify: %s", clean(strings.Join(v.Problems, "; ")))
		} else {
			add("ledger", lvOK, "hash chain verifies, head seq %d", v.HeadSeq)
		}
	}

	if !m.WithVault {
		add("vault", lvOK, "not installed (no -WithVault)")
		return
	}
	r, err = a.call("GET", "/v0/vault/status", nil, nil)
	switch {
	case err != nil:
		add("vault", lvFail, "%s", errText(err))
	case r.status != 200:
		add("vault", lvFail, "vault status answered %d", r.status)
	default:
		var v struct {
			Initialized bool `json:"initialized"`
			SecretCount int  `json:"secret_count"`
		}
		if json.Unmarshal(r.body, &v) != nil || !v.Initialized {
			add("vault", lvFail, "the vault is not initialized (chapd vault init, as %s)", m.ServiceAccount)
		} else {
			add("vault", lvOK, "initialized, %d secrets", v.SecretCount)
		}
	}
}

func errText(err error) string {
	var ce *cliError
	if errors.As(err, &ce) {
		return ce.msg
	}
	return err.Error()
}

// probeAccess opens path for reading and writing as the calling thread's
// identity and reports what worked. It leaves nothing behind: a directory is
// probed with a temp file that is removed at once, a file is opened without
// truncation.
func probeAccess(path string) accessInfo {
	fi, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return accessInfo{}
		}
		// Exists, but the caller may not even look at it.
		return accessInfo{Exists: true}
	}
	out := accessInfo{Exists: true}
	if fi.IsDir() {
		if d, err := os.Open(path); err == nil {
			_, rerr := d.Readdirnames(1)
			out.Read = rerr == nil || errors.Is(rerr, io.EOF)
			d.Close()
		}
		if f, err := os.CreateTemp(path, ".chap-doctor-*"); err == nil {
			out.Write = true
			name := f.Name()
			f.Close()
			os.Remove(name)
		}
		return out
	}
	if f, err := os.OpenFile(path, os.O_RDONLY, 0); err == nil {
		out.Read = true
		f.Close()
	}
	if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		out.Write = true
		f.Close()
	}
	return out
}

func sameAccount(have, want string) bool {
	norm := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.TrimPrefix(s, `.\`)
		if i := strings.LastIndex(s, `\`); i >= 0 {
			s = s[i+1:]
		}
		return s
	}
	return norm(have) == norm(want)
}

func samePath(a, b string) bool {
	norm := func(s string) string { return strings.ToLower(strings.TrimRight(strings.ReplaceAll(s, "/", `\`), `\`)) }
	return norm(a) == norm(b)
}

// splitImagePath separates the executable from its arguments in a service's
// BinaryPathName: `"C:\Program Files\x\chapd.exe" svc -db ...`.
func splitImagePath(p string) (exe, args string) {
	p = strings.TrimSpace(p)
	if strings.HasPrefix(p, `"`) {
		if i := strings.Index(p[1:], `"`); i >= 0 {
			return p[1 : 1+i], strings.TrimSpace(p[i+2:])
		}
		return strings.Trim(p, `"`), ""
	}
	if i := strings.IndexByte(p, ' '); i >= 0 {
		return p[:i], strings.TrimSpace(p[i+1:])
	}
	return p, ""
}

// doctorEnvFor builds the probes; tests replace it.
var doctorEnvFor = newDoctorEnv

// winDir and winBase split a Windows path whatever system the tests run on.
func winDir(p string) string {
	p = strings.ReplaceAll(p, "/", `\`)
	if i := strings.LastIndex(p, `\`); i >= 0 {
		return p[:i]
	}
	return ""
}

func winBase(p string) string {
	p = strings.ReplaceAll(p, "/", `\`)
	return p[strings.LastIndex(p, `\`)+1:]
}
