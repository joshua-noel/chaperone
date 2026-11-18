package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/ops"
)

// An op the operator approved and that was then refused at release raises its own alert, through the same script as
// the critical-op alerts, with a key per request (the script keeps one alert per key for 30 minutes).
func TestApprovedNotRunAlertReachesTheAlertScript(t *testing.T) {
	var mu sync.Mutex
	var argvs [][]string
	script := &ops.AlertsScript{PowerShell: `C:\ps.exe`, Script: `C:\alerts.ps1`, Folder: `C:\health`,
		Run: func(_ context.Context, argv []string) error {
			mu.Lock()
			argvs = append(argvs, argv)
			mu.Unlock()
			return nil
		}}
	var logs bytes.Buffer
	a := &alerter{log: slog.New(slog.NewTextHandler(&logs, nil)), script: script}

	a.Alert(context.Background(), ops.Alert{Kind: ops.AlertApprovedNotRun, Op: "pr.merge", Project: "storefront", RequestID: "q-0a1b2c",
		Requester: "orchestrator:main", Detail: "CI_STALE: the head is 1 commit behind main"})

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(argvs)
		mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no alert raised; log: %s", logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	got := strings.Join(argvs[0], " ")
	for _, want := range []string{"-Raise chaperone-no-run-q-0a1b2c", "You approved pr.merge in storefront but it did not run", "CI_STALE: the head is 1 commit behind main"} {
		if !strings.Contains(got, want) {
			t.Errorf("argv lacks %q: %s", want, got)
		}
	}
	if !strings.Contains(logs.String(), "APPROVED OP DID NOT RUN") {
		t.Errorf("no log line: %s", logs.String())
	}
}
