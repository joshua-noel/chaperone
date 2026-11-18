package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Routes, as agreed with the L1-07 contract (api/openapi.yaml owns them):
//
//	GET  /v0/host/events                 text/event-stream
//	       event: approvals.pending   data: {"count": N}
//	       event: grant               data: {"grant": "lg1....", "op_id": "<id>"}
//	POST /v0/host/runs/{op_id}/output    application/octet-stream, redacted chunk
//	POST /v0/host/runs/{op_id}/result    {"exit_code", "outcome", "code"?}
//
// Every request carries Authorization: Bearer <host token>, read from the
// token file on each call so a rotated token takes effect without a restart.
const (
	eventsPath  = "/v0/host/events"
	maxSSELine  = 64 << 10
	postTimeout = 15 * time.Second
)

var opIDRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,80}$`)

// HTTPChapd talks to chapd over loopback HTTP. It presents the host token so
// that chapd can refuse to hand grants to any other local process; the grant
// itself proves nothing to chapd and everything to us, by its signature.
type HTTPChapd struct {
	base      string
	tokenFile string
	client    *http.Client
	body      io.Closer
	sc        *bufio.Scanner
}

// NewHTTPChapd returns a client for the chapd at base ("http://127.0.0.1:55398"),
// authenticating with the token in tokenFile. A nil client means a default client with no overall timeout (the event
// stream is long-lived; calls carry their own deadlines).
func NewHTTPChapd(base, tokenFile string, client *http.Client) *HTTPChapd {
	if client == nil {
		client = &http.Client{}
	}
	return &HTTPChapd{base: strings.TrimRight(base, "/"), tokenFile: tokenFile, client: client}
}

// Next implements Chapd.
func (h *HTTPChapd) Next(ctx context.Context) (Event, error) {
	if h.sc == nil {
		if err := h.connect(ctx); err != nil {
			return Event{}, err
		}
	}
	ev, err := h.read()
	if err != nil {
		h.drop()
		return Event{}, err
	}
	return ev, nil
}

func (h *HTTPChapd) connect(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.base+eventsPath, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	if err := h.authorize(req); err != nil {
		return err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return fmt.Errorf("chapd events: %s", resp.Status)
	}
	h.body = resp.Body
	h.sc = bufio.NewScanner(resp.Body)
	h.sc.Buffer(make([]byte, 0, 4096), maxSSELine)
	return nil
}

func (h *HTTPChapd) authorize(req *http.Request) error {
	raw, err := os.ReadFile(h.tokenFile)
	if err != nil {
		return fmt.Errorf("host token: %w", err)
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		return errors.New("host token file is empty")
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	return nil
}

func (h *HTTPChapd) drop() {
	if h.body != nil {
		h.body.Close()
	}
	h.body, h.sc = nil, nil
}

// read returns the next complete, understood event. Unknown event names and
// comment lines (keep-alives) are skipped.
func (h *HTTPChapd) read() (Event, error) {
	var name string
	var data []string
	for h.sc.Scan() {
		line := h.sc.Text()
		switch {
		case line == "":
			if ev, ok, err := decodeEvent(name, strings.Join(data, "\n")); err != nil || ok {
				return ev, err
			}
			name, data = "", nil
		case strings.HasPrefix(line, ":"):
		case strings.HasPrefix(line, "event:"):
			name = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if err := h.sc.Err(); err != nil {
		return Event{}, err
	}
	return Event{}, io.EOF
}

func decodeEvent(name, data string) (Event, bool, error) {
	switch name {
	case EventApprovals:
		var p struct {
			Count *int `json:"count"`
		}
		if err := strictJSON(data, &p); err != nil || p.Count == nil || *p.Count < 0 || *p.Count > 1_000_000 {
			return Event{}, false, errors.New("chapd sent a bad approvals event")
		}
		return Event{Kind: EventApprovals, Pending: *p.Count}, true, nil
	case EventGrant:
		var p struct {
			Grant string `json:"grant"`
			OpID  string `json:"op_id"`
		}
		if err := strictJSON(data, &p); err != nil || !opIDRe.MatchString(p.OpID) || p.Grant == "" {
			return Event{}, false, errors.New("chapd sent a bad grant event")
		}
		return Event{Kind: EventGrant, OpID: p.OpID, Grant: p.Grant}, true, nil
	}
	return Event{}, false, nil
}

func strictJSON(data string, v any) error {
	dec := json.NewDecoder(strings.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

// Output implements Chapd.
func (h *HTTPChapd) Output(ctx context.Context, opID string, chunk []byte) error {
	return h.post(ctx, opID, "output", "application/octet-stream", chunk)
}

// Done implements Chapd.
func (h *HTTPChapd) Done(ctx context.Context, opID string, r Result) error {
	body, err := json.Marshal(struct {
		ExitCode int    `json:"exit_code"`
		Outcome  string `json:"outcome"`
		Code     string `json:"code,omitempty"`
	}{r.ExitCode, r.Status, r.Code})
	if err != nil {
		return err
	}
	return h.post(ctx, opID, "result", "application/json", body)
}

func (h *HTTPChapd) post(ctx context.Context, opID, leaf, ctype string, body []byte) error {
	if !opIDRe.MatchString(opID) {
		return errors.New("bad op id")
	}
	ctx, cancel := context.WithTimeout(ctx, postTimeout)
	defer cancel()
	u := h.base + "/v0/host/runs/" + url.PathEscape(opID) + "/" + leaf
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", ctype)
	if err := h.authorize(req); err != nil {
		return err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("chapd %s: %s", leaf, resp.Status)
	}
	return nil
}
