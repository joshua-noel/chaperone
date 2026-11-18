package runtoken

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/joshua-noel/chaperone/internal/spec"
)

// maxProfileBytes bounds one profile file: a generic profile is a few KiB.
const maxProfileBytes = 256 << 10

var digestRe = regexp.MustCompile(`^sha256:([0-9a-f]{64})$`)

// ProfileDir is the profile source of chapd: a folder of generic
// profiles, one JSON file per profile, named <64 hex>.json where the hex is
// the SHA-256 of the profile's JCS form (the token's profile.digest without
// "sha256:"; section 3 of the spec: sha256 of the JCS form of the profile).
//
// A file is admitted only when it is strict I-JSON, valid against
// profile.schema.json as a generic profile with a branch_prefix, and hashes to
// its own file name. The folder is Chaperone's allowlist: whoever can write to it
// can admit a profile, so it belongs next to state.db with the same ACL (ADR-003).
// Signature checking of the OCI artifact is phase 4 of the spec; the spec
// defines no signature format for a file, so none is checked here.
//
// Lookup reads the file on every call, so a tampered file is refused on the
// next request and a new profile needs no restart.
type ProfileDir struct {
	dir string
	log *slog.Logger
}

// OpenProfileDir opens dir and loads every *.json in it once, so a malformed or
// tampered file stops chapd at start instead of surfacing as a refused token
// later. log may be nil.
func OpenProfileDir(dir string, log *slog.Logger) (*ProfileDir, int, error) {
	if dir == "" {
		return nil, 0, errors.New("runtoken: profiles: no folder given")
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, fmt.Errorf("runtoken: profiles: read %s: %w", dir, err)
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	p := &ProfileDir{dir: dir, log: log}
	n := 0
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.EqualFold(filepath.Ext(name), ".json") {
			continue
		}
		hex, ok := strings.CutSuffix(name, ".json")
		if !ok || !digestRe.MatchString("sha256:"+hex) {
			return nil, 0, fmt.Errorf("runtoken: profiles: %s: the file name must be <64 lowercase hex>.json (the profile's digest)", filepath.Join(dir, name))
		}
		if _, err := p.load("sha256:" + hex); err != nil {
			return nil, 0, err
		}
		n++
	}
	return p, n, nil
}

// Lookup is the ProfileFunc of the source. A digest that is not a file, or a
// file that no longer verifies, is not admitted; the reason is logged, not
// returned (a token sender learns only TOKEN_INVALID).
func (p *ProfileDir) Lookup(digest string) (*spec.GenericProfile, bool) {
	gp, err := p.load(digest)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			p.log.Warn("profile refused", "digest", digest, "err", err)
		}
		return nil, false
	}
	return gp, true
}

// load reads and verifies <dir>/<hex>.json for digest.
func (p *ProfileDir) load(digest string) (*spec.GenericProfile, error) {
	m := digestRe.FindStringSubmatch(digest)
	if m == nil {
		return nil, fmt.Errorf("runtoken: profiles: %q is not a sha256 digest", digest)
	}
	path := filepath.Join(p.dir, m[1]+".json")
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxProfileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("runtoken: profiles: read %s: %w", path, err)
	}
	got, gp, err := ParseProfile(data)
	if err != nil {
		return nil, fmt.Errorf("runtoken: profiles: %s: %w", path, err)
	}
	if got != digest {
		return nil, fmt.Errorf("runtoken: profiles: %s: the file hashes to %s, not to the digest in its name (tampered or misnamed)", path, got)
	}
	return gp, nil
}

// ParseProfile verifies one profile document and returns its digest and the
// part run-token checks read. It accepts only a generic profile that is valid
// against profile.schema.json and names a branch_prefix.
func ParseProfile(data []byte) (digest string, gp *spec.GenericProfile, err error) {
	if len(data) > maxProfileBytes {
		return "", nil, fmt.Errorf("profile is larger than %d bytes", maxProfileBytes)
	}
	tree, err := spec.LoadTree(spec.SchemaProfile, data)
	if err != nil {
		return "", nil, fmt.Errorf("not a valid profile: %w", err)
	}
	if m, _ := tree.(map[string]any); m["layer"] != "generic" {
		return "", nil, errors.New("not a generic profile (an overlay is not a profile source)")
	}
	var g spec.GenericProfile
	if err := json.Unmarshal(data, &g); err != nil { // unknown members are the rest of the profile
		return "", nil, fmt.Errorf("profile does not decode: %w", err)
	}
	if g.BranchPrefix == "" {
		return "", nil, errors.New("a profile needs a branch_prefix: without one any branch is pushable")
	}
	canon, err := spec.JCS(tree)
	if err != nil {
		return "", nil, fmt.Errorf("profile has no canonical form: %w", err)
	}
	return spec.SHA256Tagged(canon), &g, nil
}

// AdmitProfile verifies data and writes it to dir as <hex>.json, creating dir
// when it is missing. It returns the digest. A file of the same digest is
// replaced, so admitting again repairs a tampered copy.
func AdmitProfile(dir string, data []byte) (string, error) {
	digest, _, err := ParseProfile(data)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("runtoken: profiles: %w", err)
	}
	path := filepath.Join(dir, strings.TrimPrefix(digest, "sha256:")+".json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("runtoken: profiles: %w", err)
	}
	return digest, nil
}
