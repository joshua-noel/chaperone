package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
	"unicode/utf16"
)

// Toaster shows and removes the one "approvals waiting" toast.
type Toaster interface {
	Show(ctx context.Context, pending int) error
	Clear(ctx context.Context) error
}

// toastText is the whole toast: a count and a fixed phrase. No op, project,
// parameter or link ever goes in it; the operator opens the console himself.
func toastText(pending int) string {
	if pending == 1 {
		return "1 approval waiting"
	}
	return strconv.Itoa(pending) + " approvals waiting"
}

// toastScript uses the built-in WinRT ToastNotification API from Windows
// PowerShell 5.1, the same method as scripts/pilot-host/alerts.ps1 in the
// Storefront repo (Show-Toast, Remove-Toast). It is a constant: the toast
// text and the mode reach it only through two environment variables, and the
// text is XML-escaped.
const toastScript = `
$ErrorActionPreference = 'Stop'
$appId = 'Chaperone.Host'
$tag = 'chaperone-approvals'
$group = 'chaperone'
[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
[void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
if ($env:CHAP_HOST_TOAST_MODE -eq 'clear') {
  [Windows.UI.Notifications.ToastNotificationManager]::History.Remove($tag, $group, $appId)
  exit 0
}
if ($env:CHAP_HOST_TOAST_MODE -ne 'show') { throw 'bad mode' }
$registry = "HKCU:\Software\Classes\AppUserModelId\$appId"
if (-not (Test-Path $registry)) {
  New-Item -Path $registry -Force | Out-Null
  New-ItemProperty -Path $registry -Name DisplayName -Value 'Chaperone' -PropertyType String | Out-Null
}
$body = [Security.SecurityElement]::Escape($env:CHAP_HOST_TOAST_TEXT)
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml('<toast scenario="reminder"><visual><binding template="ToastGeneric"><text>Chaperone</text><text>' + $body + '</text></binding></visual><actions><action content="Dismiss" arguments="dismiss" activationType="system"/></actions></toast>')
$toast = New-Object Windows.UI.Notifications.ToastNotification $xml
$toast.Tag = $tag
$toast.Group = $group
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)
`

const toastTimeout = 20 * time.Second

// PowerShellToaster shows toasts through Windows PowerShell 5.1. It must run
// in the operator's interactive session; a service in session 0 cannot show
// one (that is why this helper exists).
type PowerShellToaster struct{}

func (PowerShellToaster) Show(ctx context.Context, pending int) error {
	if pending < 1 || pending > 9999 {
		return fmt.Errorf("toast: count %d out of range", pending)
	}
	return runToast(ctx, "show", toastText(pending))
}

func (PowerShellToaster) Clear(ctx context.Context) error { return runToast(ctx, "clear", "") }

func runToast(ctx context.Context, mode, text string) error {
	root := os.Getenv("SystemRoot")
	if root == "" {
		return errors.New("toast: needs Windows")
	}
	exe := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	ctx, cancel := context.WithTimeout(ctx, toastTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", encodePowerShell(toastScript))
	cmd.Env = childEnv([]string{"CHAP_HOST_TOAST_MODE=" + mode, "CHAP_HOST_TOAST_TEXT=" + text})
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("toast: %w: %.300s", err, out)
	}
	return nil
}

// encodePowerShell is the -EncodedCommand form: base64 of UTF-16LE.
func encodePowerShell(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 0, 2*len(u))
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return base64.StdEncoding.EncodeToString(b)
}
