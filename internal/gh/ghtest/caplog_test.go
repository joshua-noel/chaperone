package ghtest

import (
	"net/http"
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
