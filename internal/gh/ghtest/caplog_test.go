package ghtest

import (
	"net/http"
	"runtime"
	"strings"
	"testing"
)

func TestCapLogBoundsTheRequestLog(t *testing.T) {
	s := New(t)
	post := func(i int) {
		resp, err := http.Post(s.URL()+"/x"+strings.Repeat("y", i), "text/plain", strings.NewReader(strings.Repeat("b", 5000)))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	// Without a cap everything is kept, whole.
	post(0)
	if got := s.Requests(); len(got) != 1 || len(got[0].Body) != 5000 {
		t.Fatalf("uncapped log: %d entries", len(got))
	}
	s.CapLog(3, 10)
	for i := 1; i <= 20; i++ {
		post(i)
	}
	got := s.Requests()
	if len(got) != 3 {
		t.Fatalf("log has %d entries, want 3", len(got))
	}
	for _, r := range got {
		if len(r.Body) != 10 {
			t.Errorf("body of %d bytes, want 10", len(r.Body))
		}
	}
	// The newest are kept.
	if want := "/x" + strings.Repeat("y", 20); got[2].Path != want {
		t.Errorf("newest entry %q, want %q", got[2].Path, want)
	}
}

// A capped log must not keep the request bodies alive: 200 posts of 1 MiB must not leave 200 MiB on the heap.
func TestCapLogDoesNotRetainWholeBodies(t *testing.T) {
	s := New(t)
	s.CapLog(500, 4<<10)
	body := strings.Repeat("b", 1<<20)
	for range 200 {
		resp, err := http.Post(s.URL()+"/x", "text/plain", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	got := s.Requests()
	if len(got) != 200 || len(got[0].Body) != 4<<10 {
		t.Fatalf("%d entries, first body %d bytes", len(got), len(got[0].Body))
	}
	var m runtime.MemStats
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&m)
	if m.HeapInuse > 64<<20 { // the bug held about 200 MiB
		t.Errorf("heap in use after 200 capped 1 MiB posts: %d MiB", m.HeapInuse>>20)
	}
	runtime.KeepAlive(got)
}
