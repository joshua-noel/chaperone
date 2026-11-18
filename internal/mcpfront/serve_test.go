package mcpfront

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuf is an output the test can read while the server still writes.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// waitFor polls until cond holds, or fails the test.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func errCode(m map[string]any) float64 {
	e, _ := m["error"].(map[string]any)
	c, _ := e["code"].(float64)
	return c
}

// Ctrl+C and SIGTERM cancel the context `chap mcp` serves under; a client that
// has not closed stdin must not keep the process alive.
func TestServeReturnsWhenContextIsDoneWhileInputIsOpen(t *testing.T) {
	t.Run("idle", func(t *testing.T) {
		pr, pw := ioPipe()
		t.Cleanup(func() { pw.Close() })
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- Serve(ctx, testConfig(okBackend(nil)), pr, &syncBuf{}) }()
		time.Sleep(20 * time.Millisecond) // let it block in its read
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Serve = %v, want nil on a stop asked for by a signal", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Serve did not return after its context was done (stdin still open)")
		}
	})
	t.Run("call in flight", func(t *testing.T) {
		started := make(chan struct{})
		be := okBackend(func(r recorded, ctx context.Context) (*Reply, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		})
		pr, pw := ioPipe()
		t.Cleanup(func() { pw.Close() })
		ctx, cancel := context.WithCancel(context.Background())
		var out syncBuf
		done := make(chan error, 1)
		go func() { done <- Serve(ctx, testConfig(be), pr, &out) }()
		pw.WriteString(call(1, "pr_view", `{"target":{"adapter":"github","ref":"a/b#1"}}`) + "\n")
		<-started
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Serve = %v, want nil", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Serve did not return after its context was done (call in flight, stdin open)")
		}
		if strings.TrimSpace(out.String()) != "" {
			t.Errorf("a cancelled call was answered: %s", out.String())
		}
	})
}

// Valid JSON that is not an object, and an id with nothing to answer, are
// invalid requests (-32600), not parse errors and not silence.
func TestInvalidRequestsGetInvalidRequest(t *testing.T) {
	msgs := exchange(t, testConfig(okBackend(nil)),
		`123`, `"x"`, `null`, `true`,
		`{"jsonrpc":"2.0","id":7}`,
		`{"jsonrpc":"2.0","id":"s-8"}`,
		`{"jsonrpc":"2.0","method":5,"id":9}`,
		// Responses from a client: this server asked nothing, and says nothing.
		`{"jsonrpc":"2.0","id":10,"result":{}}`,
		`{"jsonrpc":"2.0","id":11,"error":{"code":1,"message":"x"}}`,
	)
	if len(msgs) != 7 {
		t.Fatalf("got %d replies, want 7 (4 non-objects, 2 ids with no method, 1 bad method type; no reply to the 2 responses): %v", len(msgs), msgs)
	}
	for i := range 4 {
		if errCode(msgs[i]) != codeInvalidRequest || msgs[i]["id"] != nil {
			t.Errorf("non-object #%d = %v, want -32600 with a null id", i, msgs[i])
		}
	}
	if errCode(msgs[4]) != codeInvalidRequest || msgs[4]["id"] != float64(7) {
		t.Errorf("id with no method = %v, want -32600 for id 7", msgs[4])
	}
	if errCode(msgs[5]) != codeInvalidRequest || msgs[5]["id"] != "s-8" {
		t.Errorf("string id with no method = %v, want -32600 for id s-8", msgs[5])
	}
	if errCode(msgs[6]) != codeInvalidRequest {
		t.Errorf("method of the wrong type = %v, want -32600", msgs[6])
	}
}

func TestMalformedJSONStaysAParseError(t *testing.T) {
	msgs := exchange(t, testConfig(okBackend(nil)), `{not json`, `{"a":`)
	if len(msgs) != 2 || errCode(msgs[0]) != codeParse || errCode(msgs[1]) != codeParse {
		t.Fatalf("replies = %v, want two -32700", msgs)
	}
}

// One message over the limit is answered with an error and skipped to its
// newline; the server keeps serving the next message.
func TestOversizedLineIsSkippedAndServingContinues(t *testing.T) {
	big := `{"jsonrpc":"2.0","id":1,"method":"ping","pad":"` + strings.Repeat("a", maxLine+10) + `"}`
	msgs := exchange(t, testConfig(okBackend(nil)), big, `{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	if len(msgs) != 2 {
		t.Fatalf("got %d replies, want the error and the ping: %v", len(msgs), msgs)
	}
	if errCode(msgs[0]) != codeInvalidRequest || msgs[0]["id"] != nil {
		t.Errorf("oversized line = %v, want -32600 with a null id", msgs[0])
	}
	if _, ok := byID(t, msgs, 2)["result"]; !ok {
		t.Errorf("the next message was not served: %v", msgs)
	}

	// The same when the oversized message is the last and has no newline.
	var out bytes.Buffer
	in := strings.NewReader(`{"jsonrpc":"2.0","id":3,"method":"ping"}` + "\n" + big)
	if err := Serve(context.Background(), testConfig(okBackend(nil)), in, &out); err != nil {
		t.Fatalf("Serve = %v, want nil at the end of input", err)
	}
	got := parseLines(t, out.String())
	if len(got) != 2 || errCode(got[1]) != codeInvalidRequest {
		t.Errorf("unterminated oversized line: %v", got)
	}
}

// At most maxInFlight requests run at once; one more is refused at once, and a
// reused id never replaces the request in flight.
func TestInFlightCapAndReusedID(t *testing.T) {
	release := make(chan struct{})
	be := okBackend(func(r recorded, ctx context.Context) (*Reply, error) {
		select {
		case <-release:
			return jsonReply(200, `{"id":"q-abc123","state":"succeeded","op":"pr.view","class":"routine"}`), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	pr, pw := ioPipe()
	t.Cleanup(func() { pw.Close() })
	var out syncBuf
	done := make(chan error, 1)
	go func() { done <- Serve(context.Background(), testConfig(be), pr, &out) }()

	args := `{"target":{"adapter":"github","ref":"a/b#1"}}`
	for id := 1; id <= maxInFlight; id++ {
		pw.WriteString(call(id, "pr_view", args) + "\n")
	}
	pw.WriteString(call(3, "pr_view", args) + "\n")             // id still in flight
	pw.WriteString(call(maxInFlight+1, "pr_view", args) + "\n") // over the cap
	waitFor(t, "the two refusals", func() bool { return strings.Count(out.String(), `"error"`) >= 2 })

	got := parseLines(t, out.String())
	if len(got) != 2 {
		t.Fatalf("before any call finished, replies = %v, want only the two refusals", got)
	}
	if got[0]["id"] != float64(3) || errCode(got[0]) != codeInvalidRequest {
		t.Errorf("reused id = %v, want -32600 for id 3", got[0])
	}
	if got[1]["id"] != float64(maxInFlight+1) || errCode(got[1]) != codeBusy {
		t.Errorf("over the cap = %v, want %d for id %d", got[1], codeBusy, maxInFlight+1)
	}

	// The reused id did not overwrite the first: cancelling id 3 still stops it.
	pw.WriteString(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":3}}` + "\n")
	time.Sleep(50 * time.Millisecond)
	close(release)
	pw.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return at the end of input")
	}
	msgs := parseLines(t, out.String())
	for id := 1; id <= maxInFlight; id++ {
		has := false
		for _, m := range msgs {
			if m["id"] == float64(id) {
				if _, ok := m["result"]; ok {
					has = true
				}
			}
		}
		if id == 3 && has {
			t.Error("id 3 was cancelled and must get no result")
		}
		if id != 3 && !has {
			t.Errorf("id %d got no result: %v", id, msgs)
		}
	}
}

// The notice is a fixed field of structuredContent too, for a client that
// hands the model only that part.
func TestUntrustedNoticeIsAlsoInStructuredContent(t *testing.T) {
	be := okBackend(func(r recorded, ctx context.Context) (*Reply, error) {
		return jsonReply(200, `{"id":"q-abc123","state":"succeeded","op":"pr.view","class":"routine","result":{"body":"hi"}}`), nil
	})
	msgs := exchange(t, testConfig(be), call(1, "pr_view", `{"target":{"adapter":"github","ref":"a/b#1"}}`))
	res := resultOf(t, byID(t, msgs, 1))
	sc := res["structuredContent"].(map[string]any)
	if sc["untrusted_notice"] != UntrustedNotice {
		t.Errorf("structuredContent notice = %v, want the fixed notice", sc["untrusted_notice"])
	}
	if n := strings.Count(text(t, res), UntrustedNotice); n != 1 {
		t.Errorf("the text carries the notice %d times, want once", n)
	}

	// No outside text, no notice.
	be2 := okBackend(func(r recorded, ctx context.Context) (*Reply, error) {
		return jsonReply(200, `{"id":"q-abc123","state":"succeeded","op":"pr.view","class":"routine"}`), nil
	})
	msgs = exchange(t, testConfig(be2), call(1, "pr_view", `{"target":{"adapter":"github","ref":"a/b#1"}}`))
	if _, has := resultOf(t, byID(t, msgs, 1))["structuredContent"].(map[string]any)["untrusted_notice"]; has {
		t.Error("a result with no outside text carries the notice")
	}
}

// The advertised schema is guidance; the description says Chaperone validates.
func TestToolDescriptionsSayChapdValidates(t *testing.T) {
	msgs := exchange(t, testConfig(okBackend(nil)), `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	for _, name := range []string{"pr_view", "deploy", "health", "pr_merge"} {
		d := listedTools(t, msgs, 1)[name]["description"].(string)
		if !strings.Contains(d, "Chaperone validates every call") {
			t.Errorf("%s description does not say Chaperone validates the call: %s", name, d)
		}
	}
}
