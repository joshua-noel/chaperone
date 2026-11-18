// Package mcpfront is the local MCP front end (ADR-009): `chap mcp` serves
// Chaperone's op catalog to an MCP client on the same machine over stdio.
//
// What it is: a translator. A tools/call becomes one request to chapd (POST
// /v0/ops, POST /v0/approvals or GET /v0/ops/{id}) with the caller's own
// credential, and chapd's answer becomes the tool result. Policy, approvals and
// the ledger all stay in chapd; this package decides nothing.
//
// What it is not, and the code has no path for:
//
//   - A listener. The package imports no net or net/http (a test checks the
//     import list), so it cannot serve anything; stdin and stdout are the
//     whole transport.
//   - A card renderer. A call that needs a human returns the op id, the
//     approval id, the class and the time left, and nothing else; the card text
//     is shown only by the console (the no-card rule). The package
//     imports nothing from the approvals or console packages.
//   - A way to approve, deny or edit an approval. No tool calls such a route;
//     chapd has none either.
//
// Protocol: newline-delimited JSON-RPC 2.0, tools only. Both eras of MCP are
// served (see protocol.go): the stateless 2026-07-28 revision, where every
// request carries its version in _meta, and the earlier initialize handshake.
package mcpfront

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Reply is chapd's answer to one request.
type Reply struct {
	Status     int
	RetryAfter string // the Retry-After header, as sent
	Body       []byte
}

// ErrKind says why a call never produced a Reply.
type ErrKind int

const (
	ErrOther       ErrKind = iota
	ErrAuth                // no usable credential
	ErrUnavailable         // chapd is not reachable; nothing ran
)

// CallError is a failed call: no answer from chapd.
type CallError struct {
	Kind    ErrKind
	Message string
}

func (e *CallError) Error() string { return e.Message }

// Backend sends one request to chapd with the caller's credential. The
// implementation owns credential loading, the loopback rule and redirects; it
// is the same code `chap` uses. It must honour ctx (cancellation, shutdown).
type Backend interface {
	Call(ctx context.Context, method, path string, query url.Values, body any) (*Reply, error)
}

// Target is an op's usual target, for an op whose target is always the same.
type Target struct {
	Adapter string `json:"adapter"`
	Ref     string `json:"ref"`
}

// Config is everything the server needs from its host.
type Config struct {
	Backend Backend
	// Project is the project slug sent with every call (CHAP_PROJECT). An
	// orchestrator must name one; a run's is its token's.
	Project string
	// Version is the build version, reported to the client.
	Version string
	// DefaultTargets lets a call omit the target of an op that has one usual
	// target (health, logs, deploy).
	DefaultTargets map[string]Target
	// RenderDenial words a denial body, so a refusal reads as it does in `chap`.
	// Nil falls back to the cause and the reason.
	RenderDenial func(body []byte) string
	// Scrub masks every secret the host knows of, and anything shaped like
	// one, in text bound for the client. Nil leaves text as it is.
	Scrub func(string) string
	// Log receives diagnostics (stderr). Never a request, an argument or a
	// result. Nil discards.
	Log io.Writer
	// Now is the clock for "time left"; nil is time.Now.
	Now func() time.Time
}

// maxLine bounds one incoming message.
const maxLine = 8 << 20

// maxInFlight bounds the requests served at once. Each holds a goroutine and
// may hold a call to chapd for up to 55 s, so the count is fixed and small: a
// request over the limit gets an error at once, nothing queues.
const maxInFlight = 8

type server struct {
	cfg Config
	out io.Writer
	wmu sync.Mutex // one message per write, never interleaved

	mu       sync.Mutex
	inflight map[string]*running
	wg       sync.WaitGroup
}

// running is one request being served.
type running struct {
	cancel    context.CancelFunc
	cancelled bool // the client asked to stop: send nothing more for it
}

// Serve reads messages from in and answers on out until in ends or ctx is
// done. It returns nil on a clean end of input and nil when ctx is done: a
// stop asked for by a signal is not a failure. A done ctx returns even while
// in stays open; calls in flight are cancelled and get no reply.
//
// in is read by a goroutine of its own, because a read of a pipe or terminal
// cannot be interrupted. After a done ctx that goroutine stays blocked in its
// read until in is closed or the process exits.
func Serve(ctx context.Context, cfg Config, in io.Reader, out io.Writer) error {
	if cfg.Backend == nil {
		return errors.New("mcpfront: no backend")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Scrub == nil {
		cfg.Scrub = func(s string) string { return s }
	}
	s := &server{cfg: cfg, out: out, inflight: map[string]*running{}}
	ctx, stop := context.WithCancel(ctx)
	// On the end of input, answer what is in flight first (a one-shot pipe
	// would lose its reply otherwise); a done ctx cancels those calls.
	defer stop()
	defer s.wg.Wait()

	quit := make(chan struct{})
	defer close(quit)
	lines := make(chan input)
	go readInput(in, lines, quit)

	for {
		if ctx.Err() != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case msg, ok := <-lines:
			if !ok {
				return nil
			}
			if msg.tooLong {
				s.reply(nil, nil, &rpcError{codeInvalidRequest, fmt.Sprintf("the message is larger than the %d MiB limit and was skipped", maxLine>>20), nil})
			} else if len(bytes.TrimSpace(msg.line)) > 0 {
				s.dispatch(ctx, msg.line)
			}
			if msg.err != nil {
				if errors.Is(msg.err, io.EOF) {
					return nil
				}
				s.logf("input stopped: %v", msg.err)
				return msg.err
			}
		}
	}
}

// input is one read from stdin: a line, a line that was too long (skipped), or
// the error that ended the input. err is set on the last item only.
type input struct {
	line    []byte
	tooLong bool
	err     error
}

// readInput reads lines from r until it fails or quit closes.
func readInput(r io.Reader, out chan<- input, quit <-chan struct{}) {
	defer close(out)
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, tooLong, err := readLine(br)
		select {
		case out <- input{line: line, tooLong: tooLong, err: err}:
		case <-quit:
			return
		}
		if err != nil {
			return
		}
	}
}

// readLine reads one line, at most maxLine bytes. A longer line is read to its
// end and dropped (tooLong), so the next call starts at the next message.
func readLine(r *bufio.Reader) (line []byte, tooLong bool, err error) {
	var buf []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if !tooLong {
			buf = append(buf, chunk...)
			if len(buf) > maxLine {
				tooLong, buf = true, nil
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return buf, tooLong, err
	}
}

func (s *server) logf(format string, args ...any) {
	if s.cfg.Log == nil {
		return
	}
	fmt.Fprintln(s.cfg.Log, "chap mcp: "+s.cfg.Scrub(fmt.Sprintf(format, args...)))
}

// rpcMessage is one incoming message. An id marks a request; none marks a
// notification.
type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *rpcError) Error() string { return e.Message }

// JSON-RPC and MCP error codes.
const (
	codeParse          = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternal       = -32603
	codeBusy           = -32001 // implementation-defined server error: the in-flight limit
	codeUnsupportedVer = -32022
)

func (s *server) dispatch(ctx context.Context, line []byte) {
	trimmed := bytes.TrimSpace(line)
	if trimmed[0] == '[' {
		s.reply(nil, nil, &rpcError{codeInvalidRequest, "batches are not supported", nil})
		return
	}
	// Valid JSON that is not an object (123, "x", null) is an invalid
	// request, not a parse error.
	if !json.Valid(trimmed) {
		s.reply(nil, nil, &rpcError{codeParse, "the message is not valid JSON", nil})
		return
	}
	var m rpcMessage
	if trimmed[0] != '{' || json.Unmarshal(trimmed, &m) != nil {
		s.reply(nil, nil, &rpcError{codeInvalidRequest, "the message is not a JSON-RPC request object", nil})
		return
	}
	hasID := len(m.ID) > 0 && string(m.ID) != "null"
	if m.Method == "" {
		if len(m.Result) > 0 || len(m.Error) > 0 {
			// A response from the client: this server sends no requests,
			// so there is nothing it could answer.
			return
		}
		s.reply(m.ID, nil, &rpcError{codeInvalidRequest, "the message has no method, result or error", nil})
		return
	}
	if !hasID {
		s.notification(m)
		return
	}
	key := string(m.ID)
	cctx, cancel := context.WithCancel(ctx)
	c := &running{cancel: cancel}
	s.mu.Lock()
	_, reused := s.inflight[key]
	full := len(s.inflight) >= maxInFlight
	if !reused && !full {
		s.inflight[key] = c
	}
	s.mu.Unlock()
	switch {
	case reused:
		cancel()
		s.reply(m.ID, nil, &rpcError{codeInvalidRequest, "this request id is already in use by a request that has not finished", nil})
		return
	case full:
		cancel()
		s.reply(m.ID, nil, &rpcError{codeBusy, fmt.Sprintf("too many requests in flight (limit %d); wait for one to finish", maxInFlight), nil})
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer cancel()
		result, rerr := s.handle(cctx, m)
		s.mu.Lock()
		delete(s.inflight, key)
		stopped := c.cancelled
		s.mu.Unlock()
		if stopped || ctx.Err() != nil {
			return // cancelled: no further message for this request
		}
		s.reply(m.ID, result, rerr)
	}()
}

// notification handles a message that wants no answer.
func (s *server) notification(m rpcMessage) {
	if m.Method != "notifications/cancelled" {
		return // initialized, progress, roots changes: nothing to do
	}
	var p struct {
		RequestID json.RawMessage `json:"requestId"`
	}
	if json.Unmarshal(m.Params, &p) != nil || len(p.RequestID) == 0 {
		return
	}
	s.mu.Lock()
	c := s.inflight[string(p.RequestID)]
	if c != nil {
		c.cancelled = true
	}
	s.mu.Unlock()
	if c != nil {
		c.cancel()
	}
}

// reply writes one response. It scrubs the whole line as a last defence: the
// text of each result was already scrubbed value by value.
func (s *server) reply(id json.RawMessage, result any, rerr *rpcError) {
	msg := map[string]any{"jsonrpc": "2.0"}
	if len(id) == 0 {
		msg["id"] = nil
	} else {
		msg["id"] = id
	}
	if rerr != nil {
		msg["error"] = rerr
	} else {
		msg["result"] = result
	}
	b, err := json.Marshal(msg)
	if err != nil {
		b, _ = json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id,
			"error": &rpcError{codeInternal, "the reply could not be encoded", nil}})
	}
	line := s.cfg.Scrub(string(b))
	if !json.Valid([]byte(line)) {
		// A mask that broke the framing: send the unmasked line's error
		// instead of a line the client cannot parse.
		b, _ = json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id,
			"error": &rpcError{codeInternal, "the reply was withheld", nil}})
		line = string(b)
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	io.WriteString(s.out, line+"\n")
}

// protocolVersionOf reads the protocol version the modern revision puts in
// params._meta; empty when the request carries none.
func protocolVersionOf(params json.RawMessage) string {
	var p struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if json.Unmarshal(params, &p) != nil {
		return ""
	}
	raw := p.Meta[metaProtocolVersion]
	var v string
	if json.Unmarshal(raw, &v) != nil {
		return ""
	}
	return strings.TrimSpace(v)
}
