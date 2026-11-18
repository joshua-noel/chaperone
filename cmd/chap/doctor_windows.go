//go:build windows

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// newDoctorEnv returns the real probes. None of them changes anything.
func newDoctorEnv(*app) *doctorEnv {
	return &doctorEnv{
		elevated:   func() bool { return windows.GetCurrentProcessToken().IsElevated() },
		service:    queryService,
		access:     accessProbe,
		freeBytes:  freeBytes,
		registry:   hklmValue,
		runCmd:     runCmd,
		userNames:  userNames,
		ifaceAddrs: net.InterfaceAddrs,
		dial: func(network, addr string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout(network, addr, timeout)
		},
		now:  time.Now,
		sntp: "time.windows.com:123",
	}
}

// queryService reads a service's configuration through the service manager
// with query-only access, which any signed-in user has by default.
func queryService(name string) (svcInfo, error) {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return svcInfo{}, fmt.Errorf("open the service manager: %w", err)
	}
	defer windows.CloseServiceHandle(m)
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return svcInfo{}, err
	}
	s, err := windows.OpenService(m, n, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return svcInfo{}, nil
		}
		return svcInfo{}, fmt.Errorf("open service %s: %w", name, err)
	}
	defer windows.CloseServiceHandle(s)

	info := svcInfo{Exists: true}

	cfgBuf, err := queryBuf(func(buf *byte, size uint32, need *uint32) error {
		return windows.QueryServiceConfig(s, (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(buf)), size, need)
	})
	if err != nil {
		return svcInfo{}, fmt.Errorf("read the service config: %w", err)
	}
	cfg := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&cfgBuf[0]))
	info.Account = windows.UTF16PtrToString(cfg.ServiceStartName)
	info.ImagePath = windows.UTF16PtrToString(cfg.BinaryPathName)
	switch cfg.StartType {
	case windows.SERVICE_AUTO_START:
		info.StartType = "auto"
	case windows.SERVICE_DEMAND_START:
		info.StartType = "manual"
	case 4:
		info.StartType = "disabled"
	default:
		info.StartType = fmt.Sprintf("type-%d", cfg.StartType)
	}
	if info.StartType == "auto" {
		if b, err := queryBuf(func(buf *byte, size uint32, need *uint32) error {
			return windows.QueryServiceConfig2(s, windows.SERVICE_CONFIG_DELAYED_AUTO_START_INFO, buf, size, need)
		}); err == nil && (*windows.SERVICE_DELAYED_AUTO_START_INFO)(unsafe.Pointer(&b[0])).IsDelayedAutoStartUp != 0 {
			info.StartType = "auto-delayed"
		}
	}

	fb, err := queryBuf(func(buf *byte, size uint32, need *uint32) error {
		return windows.QueryServiceConfig2(s, windows.SERVICE_CONFIG_FAILURE_ACTIONS, buf, size, need)
	})
	if err != nil {
		return svcInfo{}, fmt.Errorf("read the failure actions: %w", err)
	}
	fa := (*windows.SERVICE_FAILURE_ACTIONS)(unsafe.Pointer(&fb[0]))
	info.ResetSeconds = int(fa.ResetPeriod)
	if fa.ActionsCount > 0 && fa.Actions != nil {
		acts := unsafe.Slice(fa.Actions, fa.ActionsCount)
		const scActionRestart = 1
		for _, a := range acts {
			if a.Type != scActionRestart {
				break
			}
			info.Restarts++
		}
	}
	if b, err := queryBuf(func(buf *byte, size uint32, need *uint32) error {
		return windows.QueryServiceConfig2(s, windows.SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, buf, size, need)
	}); err == nil {
		info.NonCrash = (*windows.SERVICE_FAILURE_ACTIONS_FLAG)(unsafe.Pointer(&b[0])).FailureActionsOnNonCrashFailures != 0
	}

	var st windows.SERVICE_STATUS_PROCESS
	var need uint32
	if err := windows.QueryServiceStatusEx(s, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&st)), uint32(unsafe.Sizeof(st)), &need); err != nil {
		return svcInfo{}, fmt.Errorf("read the service state: %w", err)
	}
	switch st.CurrentState {
	case windows.SERVICE_RUNNING:
		info.State = "running"
	case 1:
		info.State = "stopped"
	case 2:
		info.State = "start-pending"
	case 3:
		info.State = "stop-pending"
	default:
		info.State = fmt.Sprintf("state-%d", st.CurrentState)
	}
	return info, nil
}

// queryBuf runs the two-call size-then-fill pattern of the service manager's
// query functions and returns the filled buffer.
func queryBuf(call func(buf *byte, size uint32, need *uint32) error) ([]byte, error) {
	var need uint32
	err := call(nil, 0, &need)
	if err == nil {
		need = 1
	} else if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, err
	}
	buf := make([]byte, need)
	if err := call(&buf[0], need, &need); err != nil {
		return nil, err
	}
	return buf, nil
}

func freeBytes(path string) (uint64, error) {
	vol := filepath.VolumeName(path)
	if vol == "" {
		return 0, fmt.Errorf("%q has no drive", path)
	}
	p, err := windows.UTF16PtrFromString(vol + `\`)
	if err != nil {
		return 0, err
	}
	var free, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &free, &total, &totalFree); err != nil {
		return 0, err
	}
	return free, nil
}

// hklmValue reads one value under HKLM (64-bit view). A DWORD comes back as
// its decimal text. ok is false when the key or value does not exist.
func hklmValue(subkey, value string) (string, bool) {
	sk, err := windows.UTF16PtrFromString(subkey)
	if err != nil {
		return "", false
	}
	var h windows.Handle
	if err := windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE, sk, 0, windows.KEY_READ|windows.KEY_WOW64_64KEY, &h); err != nil {
		return "", false
	}
	defer windows.RegCloseKey(h)
	vn, err := windows.UTF16PtrFromString(value)
	if err != nil {
		return "", false
	}
	var typ, n uint32
	if err := windows.RegQueryValueEx(h, vn, nil, &typ, nil, &n); err != nil {
		return "", false
	}
	buf := make([]byte, n+2)
	n = uint32(len(buf))
	if err := windows.RegQueryValueEx(h, vn, nil, &typ, &buf[0], &n); err != nil {
		return "", false
	}
	switch typ {
	case windows.REG_SZ, windows.REG_EXPAND_SZ:
		return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(&buf[0]))), true
	case windows.REG_DWORD:
		if n >= 4 {
			return fmt.Sprint(*(*uint32)(unsafe.Pointer(&buf[0]))), true
		}
	}
	return "", true
}

func runCmd(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

func userNames() []string {
	u, err := user.Current()
	if err != nil {
		return nil
	}
	return []string{u.Username, u.Uid}
}

// accessProbe probes path as the operator's own (normal) token, or as the
// agent account through a network logon: the password the installer stored
// for the launcher is unwrapped with the operator's DPAPI scope, used for one
// LogonUser(NETWORK), and dropped. The probe thread impersonates the agent
// only while it touches the paths.
func accessProbe(m *installManifest, asAgent bool, path string) (accessInfo, error) {
	if !asAgent {
		return probeAccess(path), nil
	}
	if m.AgentPasswordFile == "" {
		return accessInfo{}, errors.New("the manifest names no agent password file")
	}
	tok, err := agentToken(m)
	if err != nil {
		return accessInfo{}, err
	}
	defer tok.Close()
	runtime.LockOSThread()
	if err := impersonate(tok); err != nil {
		runtime.UnlockOSThread()
		return accessInfo{}, fmt.Errorf("impersonate %s: %w", m.AgentAccount, err)
	}
	got := probeAccess(path)
	if err := windows.RevertToSelf(); err != nil {
		// Never hand a thread that still carries the agent's identity back
		// to the scheduler: leave it locked so the runtime ends it with
		// the goroutine.
		return accessInfo{}, fmt.Errorf("revert to self: %w", err)
	}
	runtime.UnlockOSThread()
	return got, nil
}

var (
	advapi32                = windows.NewLazySystemDLL("advapi32.dll")
	procLogonUser           = advapi32.NewProc("LogonUserW")
	procImpersonateLoggedOn = advapi32.NewProc("ImpersonateLoggedOnUser")
)

const (
	logon32LogonNetwork    = 3
	logon32ProviderDefault = 0
)

// agentToken logs the agent account on over the network logon type and
// returns the token. The password lives in memory for this call only.
func agentToken(m *installManifest) (windows.Token, error) {
	raw, err := os.ReadFile(m.AgentPasswordFile)
	if err != nil {
		return 0, fmt.Errorf("read the agent password file: %w", err)
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return 0, errors.New("the agent password file is not base64 (re-run install.ps1)")
	}
	if len(blob) == 0 {
		return 0, errors.New("the agent password file is empty")
	}
	in := windows.DataBlob{Size: uint32(len(blob)), Data: &blob[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, 0x1 /* CRYPTPROTECT_UI_FORBIDDEN */, &out); err != nil {
		return 0, fmt.Errorf("unwrap the agent password (only the operator's profile can): %w", err)
	}
	pw := unsafe.Slice(out.Data, out.Size)
	defer func() {
		for i := range pw {
			pw[i] = 0
		}
		windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	}()
	pw16, err := windows.UTF16FromString(string(pw))
	if err != nil {
		return 0, errors.New("the agent password is not valid text")
	}
	defer func() {
		for i := range pw16 {
			pw16[i] = 0
		}
	}()
	name := m.AgentAccount
	domain := "."
	if i := strings.LastIndex(name, `\`); i >= 0 {
		domain, name = name[:i], name[i+1:]
	}
	n16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	d16, err := windows.UTF16PtrFromString(domain)
	if err != nil {
		return 0, err
	}
	var tok windows.Token
	r, _, e := procLogonUser.Call(uintptr(unsafe.Pointer(n16)), uintptr(unsafe.Pointer(d16)), uintptr(unsafe.Pointer(&pw16[0])),
		logon32LogonNetwork, logon32ProviderDefault, uintptr(unsafe.Pointer(&tok)))
	if r == 0 {
		return 0, fmt.Errorf("log %s on (network): %w", m.AgentAccount, errnoOr(e))
	}
	return tok, nil
}

func impersonate(tok windows.Token) error {
	r, _, e := procImpersonateLoggedOn.Call(uintptr(tok))
	if r == 0 {
		return errnoOr(e)
	}
	return nil
}

func errnoOr(e error) error {
	if e == nil || errors.Is(e, syscall.Errno(0)) {
		return errors.New("unknown error")
	}
	return e
}
