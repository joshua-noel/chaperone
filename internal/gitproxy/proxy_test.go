package gitproxy

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

const (
	zero = "0000000000000000000000000000000000000000"
	one  = "1111111111111111111111111111111111111111"
)

func pkt(s string) string {
	const hexd = "0123456789abcdef"
	n := len(s) + 4
	return string([]byte{hexd[n>>12&15], hexd[n>>8&15], hexd[n>>4&15], hexd[n&15]}) + s
}

func TestReadPushHeadPlainAndGzip(t *testing.T) {
	cmd := pkt(zero+" "+one+" refs/heads/agent/x\x00report-status side-band-64k agent=git/2\n") + "0000"
	pack := "PACK" + strings.Repeat("z", 5000)

	var zb bytes.Buffer
	zw := gzip.NewWriter(&zb)
	_, _ = zw.Write([]byte(cmd + pack))
	_ = zw.Close()

	for name, tc := range map[string]struct {
		body []byte
		enc  string
	}{
		"plain": {[]byte(cmd + pack), ""},
		"gzip":  {zb.Bytes(), "gzip"},
	} {
		t.Run(name, func(t *testing.T) {
			r := bytes.NewReader(tc.body)
			head, p := readPushHead(r, tc.enc)
			if p.Malformed != "" || len(p.Updates) != 1 || p.More || p.PushCert {
				t.Fatalf("parsed %+v", p)
			}
			if u := p.Updates[0]; u.Old != zero || u.New != one || u.Ref != "refs/heads/agent/x" {
				t.Errorf("update %+v", u)
			}
			// What was consumed plus what is left is the whole body, untouched.
			rest := make([]byte, r.Len())
			_, _ = r.Read(rest)
			if got := append(append([]byte(nil), head...), rest...); !bytes.Equal(got, tc.body) {
				t.Errorf("head+rest differ from the body (%d vs %d bytes)", len(got), len(tc.body))
			}
		})
	}
}

func TestParseCommands(t *testing.T) {
	ref := func(n string) string { return pkt(zero + " " + one + " " + n + "\n") }
	for name, tc := range map[string]struct {
		in        string
		updates   int
		more      bool
		cert      bool
		malformed bool
	}{
		"one":             {pkt(zero+" "+one+" refs/heads/a\x00caps\n") + "0000", 1, false, false, false},
		"shallow first":   {pkt("shallow "+one+"\n") + ref("refs/heads/a") + "0000", 1, false, false, false},
		"two":             {ref("refs/heads/a") + ref("refs/heads/b") + "0000", 2, true, false, false},
		"cert":            {pkt("push-cert\x00caps\n") + "0000", 0, false, true, false},
		"caps later":      {ref("refs/heads/a") + pkt(zero+" "+one+" refs/heads/b\x00x\n") + "0000", 1, false, false, true},
		"short sha":       {pkt("abc "+one+" refs/heads/a\n") + "0000", 0, false, false, true},
		"upper sha":       {pkt(strings.Repeat("A", 40)+" "+one+" refs/heads/a\n") + "0000", 0, false, false, true},
		"extra field":     {pkt(zero+" "+one+" refs/heads/a b\n") + "0000", 0, false, false, true},
		"empty":           {"", 0, false, false, true},
		"cut in a packet": {"00ff" + zero, 0, false, false, true},
		"delim packet":    {"0001", 0, false, false, true},
		"not hex":         {"zzzz", 0, false, false, true},
		"too long":        {pkt(strings.Repeat("a", 60000)) + pkt(strings.Repeat("a", 60000)) + pkt(strings.Repeat("a", 60000)) + "0000", 0, false, false, true},
	} {
		t.Run(name, func(t *testing.T) {
			p := parseCommands(strings.NewReader(tc.in))
			if (p.Malformed != "") != tc.malformed {
				t.Fatalf("malformed %q, want %v", p.Malformed, tc.malformed)
			}
			if tc.malformed {
				return
			}
			if len(p.Updates) != tc.updates || p.More != tc.more || p.PushCert != tc.cert {
				t.Errorf("got %+v", p)
			}
		})
	}
}

func TestParseReport(t *testing.T) {
	band := func(b byte, s string) string { return pkt(string([]byte{b}) + s) }
	okInner := pkt("unpack ok\n") + pkt("ok refs/heads/a\n") + "0000"
	for name, tc := range map[string]struct {
		in     string
		unpack string
		refs   map[string]string
		bad    bool
	}{
		"plain ok":      {okInner, "ok", map[string]string{"refs/heads/a": "ok"}, false},
		"sideband ok":   {band(2, "remote: hi\n") + band(1, okInner) + "0000", "ok", map[string]string{"refs/heads/a": "ok"}, false},
		"ng":            {pkt("unpack ok\n") + pkt("ng refs/heads/a stale info\n") + "0000", "ok", map[string]string{"refs/heads/a": "stale info"}, false},
		"unpack failed": {pkt("unpack index-pack abnormal exit\n") + "0000", "index-pack abnormal exit", map[string]string{}, false},
		"fatal band":    {band(3, "denied by hook\n"), "", nil, true},
		"ERR line":      {pkt("ERR repository not found\n"), "", nil, true},
		"empty":         {"", "", map[string]string{}, false},
	} {
		t.Run(name, func(t *testing.T) {
			unpack, refs, bad := parseReport([]byte(tc.in))
			if (bad != "") != tc.bad {
				t.Fatalf("bad %q", bad)
			}
			if unpack != tc.unpack || len(refs) != len(tc.refs) {
				t.Fatalf("unpack %q refs %v", unpack, refs)
			}
			for k, v := range tc.refs {
				if refs[k] != v {
					t.Errorf("ref %s: %q, want %q", k, refs[k], v)
				}
			}
		})
	}
}
