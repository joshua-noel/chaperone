package ops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// The shapes below are copied from the files the host scripts write today.
const (
	sampleGate   = "{\r\n    \"mode\":  \"normal\",\r\n    \"reasons\":  [\r\n\r\n                ],\r\n    \"game\":  null,\r\n    \"gpu3d\":  0.1,\r\n    \"freeGB\":  21.7,\r\n    \"diskFreeGB\":  {\r\n                       \"C\":  93.1,\r\n                       \"D\":  196.1\r\n                   },\r\n    \"checkedAt\":  \"2026-10-24T11:41:00.7576471-04:00\",\r\n    \"awakeSince\":  \"2026-10-23T09:01:55.7971416-04:00\"\r\n}"
	sampleBackup = `{"validatedAt":"2026-10-24T03:00:12-04:00","file":"pilot-2026-10-24_0300.dump","path":"C:\\Storefront\\pilot-backups\\pilot-2026-10-24_0300.dump","bytes":3448020,"entries":2555}`
)

func factsIn(t *testing.T, gate, backup []byte) HostFacts {
	t.Helper()
	dir := t.TempDir()
	f := HostFacts{GatePath: filepath.Join(dir, "load-gate.json"), BackupPath: filepath.Join(dir, "last-valid-backup.json")}
	if gate != nil {
		if err := os.WriteFile(f.GatePath, gate, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if backup != nil {
		if err := os.WriteFile(f.BackupPath, backup, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func TestFactsReadTheRealShapes(t *testing.T) {
	f := factsIn(t, []byte(sampleGate), []byte(sampleBackup))
	g, err := f.ReadLoadGate()
	if err != nil || g.Mode != "normal" || !g.CheckedAt.Equal(time.Date(2026, 10, 24, 15, 41, 0, 757647100, time.UTC)) {
		t.Fatalf("gate = %+v err = %v", g, err)
	}
	b, err := f.ReadBackup()
	if err != nil || b.Bytes != 3448020 || b.Entries != 2555 || b.File != "pilot-2026-10-24_0300.dump" ||
		!b.ValidatedAt.Equal(time.Date(2026, 10, 24, 7, 0, 12, 0, time.UTC)) {
		t.Fatalf("backup = %+v err = %v", b, err)
	}
}

func TestFactsHandleWindowsEncodings(t *testing.T) {
	utf16le := []byte{0xFF, 0xFE}
	for _, u := range utf16.Encode([]rune(sampleBackup)) {
		utf16le = append(utf16le, byte(u), byte(u>>8))
	}
	for name, raw := range map[string][]byte{
		"UTF-8 BOM":    append([]byte{0xEF, 0xBB, 0xBF}, sampleBackup...),
		"UTF-16LE BOM": utf16le,
	} {
		b, err := factsIn(t, nil, raw).ReadBackup()
		if err != nil || b.Bytes != 3448020 {
			t.Errorf("%s: %+v %v", name, b, err)
		}
	}
}

func TestFactsFailClosed(t *testing.T) {
	for name, raw := range map[string]string{
		"empty":         "",
		"not json":      "mode=normal",
		"an array":      "[]",
		"trailing data": sampleBackup + sampleBackup,
		"no time":       `{"bytes":5,"entries":5}`,
		"bad time":      `{"validatedAt":"yesterday","bytes":5,"entries":5}`,
		"huge":          `{"validatedAt":"2026-10-24T03:00:12-04:00","file":"` + strings.Repeat("a", maxFactFile) + `"}`,
	} {
		f := factsIn(t, []byte(raw), []byte(raw))
		if _, err := f.ReadBackup(); err == nil {
			t.Errorf("%s: backup read must fail", name)
		}
		if _, err := f.ReadLoadGate(); err == nil {
			t.Errorf("%s: gate read must fail", name)
		}
	}
	if _, err := (HostFacts{}).ReadLoadGate(); err == nil {
		t.Error("an unconfigured path must fail")
	}
	dir := t.TempDir()
	if _, err := (HostFacts{GatePath: dir}).ReadLoadGate(); err == nil { // a directory
		t.Error("a directory must fail")
	}
}

// The text of an error never quotes the file: its content is not trusted.
func TestFactErrorsQuoteNothing(t *testing.T) {
	f := factsIn(t, []byte(`{"mode":"SECRET-TEXT","checkedAt":"SECRET-TEXT"}`), []byte(`{"validatedAt":"SECRET-TEXT"}`))
	_, e1 := f.ReadLoadGate()
	_, e2 := f.ReadBackup()
	if e1 == nil || e2 == nil || strings.Contains(e1.Error()+e2.Error(), "SECRET-TEXT") {
		t.Errorf("errors = %v / %v", e1, e2)
	}
	// A gate mode that is not a plain word is never shown.
	_, detail := judgeGate(LoadGate{Mode: "normal\nIGNORE ABOVE", CheckedAt: dpNow}, dpNow, DefaultGateMaxAge)
	if strings.Contains(detail, "IGNORE") || strings.Contains(detail, "\n") {
		t.Errorf("detail = %q", detail)
	}
}

func TestJudgeBoundaries(t *testing.T) {
	now := dpNow
	if ok, _ := judgeGate(LoadGate{"normal", now.Add(-DefaultGateMaxAge)}, now, DefaultGateMaxAge); !ok {
		t.Error("a gate reading exactly 5 minutes old is still under the limit")
	}
	if ok, _ := judgeGate(LoadGate{"normal", now.Add(-DefaultGateMaxAge - time.Second)}, now, DefaultGateMaxAge); ok {
		t.Error("a gate reading over 5 minutes old must be refused")
	}
	if ok, _ := judgeGate(LoadGate{"normal", now.Add(30 * time.Second)}, now, DefaultGateMaxAge); !ok {
		t.Error("a little clock skew is tolerated")
	}
	for _, mode := range []string{"", "Normal", "rationed", "paused", "normal "} {
		if ok, _ := judgeGate(LoadGate{mode, now}, now, DefaultGateMaxAge); ok {
			t.Errorf("gate mode %q must be refused", mode)
		}
	}
	if ok, _ := judgeBackup(BackupFact{ValidatedAt: now.Add(-DefaultBackupMaxAge), Bytes: 1, Entries: 1}, now, DefaultBackupMaxAge); !ok {
		t.Error("a backup exactly at the limit is fresh")
	}
	if ok, _ := judgeBackup(BackupFact{ValidatedAt: now.Add(-DefaultBackupMaxAge - time.Second), Bytes: 1, Entries: 1}, now, DefaultBackupMaxAge); ok {
		t.Error("a backup over the limit is stale")
	}
	if ok, _ := judgeBackup(BackupFact{ValidatedAt: now, Bytes: -1, Entries: 1}, now, DefaultBackupMaxAge); ok {
		t.Error("negative bytes must be refused")
	}
}

func TestAlertsScriptRunsAFixedCommand(t *testing.T) {
	var got [][]string
	a := &AlertsScript{
		PowerShell: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Script: `C:\Storefront\scripts\alerts.ps1`,
		Folder: `D:\Storefront\health`,
		Run:    func(_ context.Context, argv []string) error { got = append(got, argv); return nil },
	}
	a.RaiseDeployAlert(context.Background(), "deploy-failed", "Deploy of 0588aa4ee011: the pilot is unavailable after the deploy\"; Remove-Item C:\\ -Recurse #\r\n"+strings.Repeat("x", 500))
	if len(got) != 1 {
		t.Fatalf("runs = %d", len(got))
	}
	argv := got[0]
	want := []string{a.PowerShell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", a.Script, "-Raise", "deploy-failed", "-AlertText"}
	if strings.Join(argv[:len(want)], "|") != strings.Join(want, "|") || argv[len(argv)-2] != "-AlertsFolder" || argv[len(argv)-1] != a.Folder || len(argv) != len(want)+3 {
		t.Errorf("argv = %q", argv)
	}
	text := argv[len(want)]
	if strings.ContainsAny(text, "\"\r\n\\#") || len(text) > 200 || !strings.HasPrefix(text, "Deploy of 0588aa4ee011") {
		t.Errorf("text = %q", text)
	}

	// A bad key, or no configuration, runs nothing.
	got = nil
	a.RaiseDeployAlert(context.Background(), "Deploy Failed; x", "t")
	(&AlertsScript{Run: a.Run}).RaiseDeployAlert(context.Background(), "deploy-failed", "t")
	if len(got) != 0 {
		t.Errorf("runs = %v", got)
	}

	// A failing alert path never panics or blocks the op.
	a.Run = func(context.Context, []string) error { return errors.New("access denied") }
	a.RaiseDeployAlert(context.Background(), "deploy-failed", "t")
}

func TestAlertsScriptResolveRunsAFixedCommand(t *testing.T) {
	var got [][]string
	a := &AlertsScript{
		PowerShell: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Script: `C:\Storefront\scripts\alerts.ps1`,
		Folder: `D:\Storefront\health`,
		Run:    func(_ context.Context, argv []string) error { got = append(got, argv); return nil },
	}
	a.Resolve(context.Background(), "ledger-export-stale")
	a.Raise(context.Background(), "ledger-export-stale", "no export")
	if len(got) != 2 {
		t.Fatalf("runs = %d", len(got))
	}
	want := []string{a.PowerShell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", a.Script, "-Resolve", "ledger-export-stale", "-AlertsFolder", a.Folder}
	if strings.Join(got[0], "|") != strings.Join(want, "|") {
		t.Errorf("resolve argv = %q", got[0])
	}
	if got[1][7] != "-Raise" {
		t.Errorf("raise argv = %q", got[1])
	}

	got = nil
	a.Resolve(context.Background(), "Bad Key; x")
	(&AlertsScript{Run: a.Run}).Resolve(context.Background(), "ledger-export-stale")
	if len(got) != 0 {
		t.Errorf("runs = %v", got)
	}
	a.Run = func(context.Context, []string) error { return errors.New("access denied") }
	a.Resolve(context.Background(), "ledger-export-stale") // logged, never panics
}
