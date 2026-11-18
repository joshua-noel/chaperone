//go:build windows

package main

import (
	"context"
	"fmt"
	"io"

	"golang.org/x/sys/windows/svc"
)

const serviceName = "chapd"

// svcCmd is `chapd svc`: chapd under the Windows service manager (installed by
// the L1-17 script with recovery actions, running as svc-chaperone). The flags
// are those of `chapd run`. Stop and shutdown end the context, which stops the
// listener, the reaper and the sweeper, then closes the ledger and database.
func svcCmd(args []string, stdout, stderr io.Writer) int {
	cfg, code := parseRunFlags("chapd svc", args, stderr, false)
	if code != 0 {
		return code
	}
	is, err := svc.IsWindowsService()
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	if !is {
		fmt.Fprintln(stderr, "chapd svc: not started by the service manager; use `chapd run` in a console")
		return 2
	}
	logger, closeLog, err := newLogger(cfg.LogDir, io.Discard)
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	defer closeLog()
	cfg.Log = logger
	if err := svc.Run(serviceName, &service{cfg: cfg}); err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	return 0
}

type service struct{ cfg Config }

func (s *service) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runDaemon(ctx, s.cfg) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			// chapd stopped by itself (bad config, listen failure): report a
			// service-specific failure so the recovery action restarts it.
			if err != nil {
				s.cfg.Log.Error("chapd stopped", "err", err)
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		}
	}
}
