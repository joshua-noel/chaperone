package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The embedded script must parse in Windows PowerShell 5.1. This only parses;
// it shows nothing.
func TestToastScriptParsesInPowerShell51(t *testing.T) {
	exe := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	cmd := exec.Command(exe, "-NoProfile", "-NonInteractive", "-Command",
		"$e = $null; [void][System.Management.Automation.Language.Parser]::ParseInput($env:CHAP_HOST_SCRIPT, [ref]$null, [ref]$e); if ($e.Count) { $e | ForEach-Object { $_.Message }; exit 1 }; 'parsed ' + $PSVersionTable.PSVersion")
	cmd.Env = append(os.Environ(), "CHAP_HOST_SCRIPT="+toastScript)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(string(out), "parsed 5.1") {
		t.Fatalf("not Windows PowerShell 5.1: %s", out)
	}
}
