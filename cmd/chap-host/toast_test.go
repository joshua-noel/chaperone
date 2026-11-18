package main

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestToastTextGolden(t *testing.T) {
	for n, want := range map[int]string{1: "1 approval waiting", 2: "2 approvals waiting", 10: "10 approvals waiting"} {
		if got := toastText(n); got != want {
			t.Errorf("toastText(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestToastRange(t *testing.T) {
	for _, n := range []int{-1, 0, 10000} {
		if err := (PowerShellToaster{}).Show(context.Background(), n); err == nil {
			t.Errorf("Show(%d) accepted", n)
		}
	}
}

func TestEncodePowerShell(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString(encodePowerShell("Write-Output 'é'"))
	if err != nil || len(raw)%2 != 0 {
		t.Fatal(err)
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	if got := string(utf16.Decode(u)); got != "Write-Output 'é'" {
		t.Fatalf("got %q", got)
	}
}

// The toast carries no parameter: the script has no place for one, and the
// only text that reaches it is the environment variable built by toastText.
func TestToastScriptTakesNoParameters(t *testing.T) {
	for _, bad := range []string{"param(", "$args", "Invoke-Expression", "iex ", "Start-Process", "activationType=\"protocol\"", "launch="} {
		if strings.Contains(toastScript, bad) {
			t.Errorf("toast script contains %q", bad)
		}
	}
	if strings.Count(toastScript, "$env:") != 3 {
		t.Errorf("toast script reads an unexpected number of environment values")
	}
}
