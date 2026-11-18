package ops

import (
	"context"
	"log/slog"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// AlertsScript raises a deploy alert through the Storefront host's own
// alert path: `alerts.ps1 -Raise <key> -AlertText "..."` in Windows PowerShell
// 5.1 (scripts/pilot-host/alerts.ps1). The script writes the alert to
// `alerts-state.json` and its log, which the heartbeat and the ops dashboard
// read, and shows the operator a toast when it runs in his session.
//
// [INFERENCE: not run on the server] chapd runs as svc-chaperone in session 0, where a
// toast cannot show; the state file and the log are written either way, and
// the helper (chap-host) is the user-session surface for approvals.
//
// The command line is fixed: the program, the script and the folder come from
// configuration, the key must match [alertKeyRE], and the text is cut to a safe
// character set, so nothing an agent wrote reaches a shell (there is none: the
// arguments are an argv).
type AlertsScript struct {
	// PowerShell is the absolute path of powershell.exe (Windows PowerShell 5.1).
	PowerShell string
	// Script is the absolute path of the stable copy of alerts.ps1.
	Script string
	// Folder is the health folder alerts.ps1 keeps its state in (-AlertsFolder).
	Folder string
	Log    *slog.Logger
	// Run starts the program. Nil runs it with os/exec under a 30 second limit.
	Run func(ctx context.Context, argv []string) error
}

var (
	_             DeployAlerter = (*AlertsScript)(nil)
	alertKeyRE                  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)
	alertUnsafeRE               = regexp.MustCompile(`[^A-Za-z0-9 .,:;()/_+=-]`)
)

// RaiseDeployAlert implements [DeployAlerter]. It never fails the op: an alert
// that cannot be raised is logged.
func (a *AlertsScript) RaiseDeployAlert(ctx context.Context, key, text string) {
	log := a.Log
	if log == nil {
		log = slog.Default()
	}
	if !alertKeyRE.MatchString(key) || a.PowerShell == "" || a.Script == "" || a.Folder == "" {
		log.Error("ops: deploy alert not raised: the alert path is not configured")
		return
	}
	text = strings.TrimSpace(alertUnsafeRE.ReplaceAllString(clip(text, 200), "?"))
	argv := []string{
		a.PowerShell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-File", a.Script, "-Raise", key, "-AlertText", text, "-AlertsFolder", a.Folder,
	}
	run := a.Run
	if run == nil {
		run = runArgv
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := run(rctx, argv); err != nil {
		log.Error("ops: deploy alert not raised", "key", key, "err", clip(err.Error(), 200))
	}
}

// Raise raises alert key through the same script, for alerts that are not about
// a deploy (the ledger export and anchor alerts, L1-21). It satisfies
// ledger.Alerter together with [AlertsScript.Resolve].
func (a *AlertsScript) Raise(ctx context.Context, key, text string) {
	a.RaiseDeployAlert(ctx, key, text)
}

// Resolve clears alert key: `alerts.ps1 -Resolve <key>`. Like a raise it never
// fails the caller; a failure is logged.
func (a *AlertsScript) Resolve(ctx context.Context, key string) {
	log := a.Log
	if log == nil {
		log = slog.Default()
	}
	if !alertKeyRE.MatchString(key) || a.PowerShell == "" || a.Script == "" || a.Folder == "" {
		log.Error("ops: alert not resolved: the alert path is not configured")
		return
	}
	argv := []string{
		a.PowerShell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-File", a.Script, "-Resolve", key, "-AlertsFolder", a.Folder,
	}
	run := a.Run
	if run == nil {
		run = runArgv
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := run(rctx, argv); err != nil {
		log.Error("ops: alert not resolved", "key", key, "err", clip(err.Error(), 200))
	}
}

func runArgv(ctx context.Context, argv []string) error {
	return exec.CommandContext(ctx, argv[0], argv[1:]...).Run()
}
