package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The quickstart's folder rules, in one place. Making an ARBITRARY folder private against other local users
// kept producing holes (a handle opened on it before the lock, a parent that lets others rename it away, a
// file planted before the lock), so the folder is not arbitrary:
//
//   - it lies inside the current user's home folder;
//   - a first run CREATES it, private from the instant it exists, and refuses a folder that already exists;
//   - every ancestor between home and it is checked, so nobody else can rename it away;
//   - a later run reuses only a folder with the marker, a known list of entries, each owned by the user and
//     closed to others;
//   - the folder's identity is recorded and checked again before serving.
//
// What none of this defends against: another program running as the same user, an administrator, or someone
// you gave rights inside your own profile.

// prepareGapHook runs in prepareQuickstartFolder between the ancestor check and the folder being made. Only tests set it.
var prepareGapHook func()

// quickstartTestRoots are extra folders that count as "inside home". Only tests set it (a test asserts that no
// non-test file does, and that there is no flag or environment variable for it).
var quickstartTestRoots []string

// defaultQuickstartDir is the folder under the user's own profile. On Windows
// it is under %LOCALAPPDATA% (not the roaming %APPDATA%: a database must not
// follow a profile around); elsewhere it is under the user's config folder. If
// that is not inside the home folder (a redirected config or profile folder) it
// is a folder directly in home. Never the real install's folders.
func defaultQuickstartDir(goos string, cacheDir, configDir, homeDir func() (string, error)) (string, error) {
	home, herr := homeDir()
	var base string
	var err error
	if goos == "windows" {
		base, err = cacheDir()
	} else {
		base, err = configDir()
	}
	if err == nil && herr == nil && within(base, home) && !samePath(base, home) {
		return filepath.Join(base, "chaperone-quickstart"), nil
	}
	if herr != nil {
		return "", fmt.Errorf("cannot find your home folder (pass --dir inside it): %w", errors.Join(err, herr))
	}
	return filepath.Join(home, ".chaperone-quickstart"), nil
}

// resolveExisting makes p absolute and resolves links in the part that exists,
// so a link into a real install is seen for what it is.
func resolveExisting(p string) (string, error) {
	p, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	rest := ""
	for cur := p; ; cur = filepath.Dir(cur) {
		if real, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(real, rest), nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p, nil
		}
		rest = filepath.Join(filepath.Base(cur), rest)
	}
}

func samePath(a, b string) bool {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// within reports whether p is dir or inside it.
func within(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		rel = strings.ToLower(rel)
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel))
}

// allowedRoots are the folders the quickstart folder may lie in: the user's home folder (and, for tests only,
// quickstartTestRoots).
func allowedRoots() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("cannot find your home folder: %w", err)
	}
	return append([]string{home}, quickstartTestRoots...), nil
}

// resolveFolderPath is THE resolution of a folder path, shared by checkQuickstartDir and prepareQuickstartFolder so that
// they cannot drift: the path made absolute, and every link in the part that exists resolved once. The rule for a link in a
// path the caller gives: it is followed up front, and the RESOLVED path must lie inside an allowed root and must itself
// go through no link (checkAncestors refuses one). Everything after this step uses the resolved path, never the given one.
func resolveFolderPath(dir string) (given, resolved string, err error) {
	if given, err = filepath.Abs(dir); err != nil {
		return "", "", err
	}
	resolved, err = resolveExisting(given)
	return given, resolved, err
}

// checkAncestors decides whether dir may be made or used, as far as WHERE it is goes. It
// must lie strictly inside an allowed root, by path text and by file identity (walking its ancestors with
// os.SameFile until one is the root). Every ancestor from the root down to dir's parent that exists must be a
// real folder (no link or junction below the root) and must pass ancestorSafe: nobody else may be able to
// rename a folder out of it or into it. Folders that do not exist yet are made by this program, private.
func checkAncestors(dir string) error {
	// It judges exactly the path it is given and resolves nothing: a link below the root in that path is refused as a
	// link. Callers resolve once, with resolveFolderPath, and pass the result.
	roots, err := allowedRoots()
	if err != nil {
		return err
	}
	for _, r := range roots {
		res, err := resolveExisting(r)
		if err != nil {
			continue
		}
		rootSt, err := os.Stat(res)
		if err != nil || !within(dir, res) || samePath(dir, res) {
			continue
		}
		var chain []string // dir's parent first, up to the root
		found := false
		for cur := filepath.Dir(dir); ; cur = filepath.Dir(cur) {
			chain = append(chain, cur)
			// The root counts as found only when the TEXT reaches it and the folder there IS the root. A junction below
			// the root that leads back to it must not stand in for it: it is walked past and refused as a link.
			if samePath(cur, res) {
				if st, err := os.Stat(cur); err == nil && os.SameFile(st, rootSt) {
					found = true
				}
				break
			}
			if filepath.Dir(cur) == cur {
				break
			}
		}
		if !found {
			continue
		}
		slices.Reverse(chain) // root first
		for i, p := range chain {
			st, err := os.Lstat(p)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			if i > 0 && (!st.IsDir() || st.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0) {
				return fmt.Errorf("%s is a link or junction, not a plain folder. Use a folder that does not go through one", p)
			}
			if err := ancestorSafe(p); err != nil {
				return fmt.Errorf("%s: %w", dir, err)
			}
		}
		return nil
	}
	return fmt.Errorf("%s is outside your home folder (%s). The quickstart keeps its folder inside your home folder, "+
		"where it can make it private to you. Use a folder inside it, or leave out --dir", dir, roots[0])
}

// realInstallDir is the real install's database folder where this system has a
// known one (the Windows default of ADR-006), else "". A variable so tests can
// point it at a scratch folder.
var realInstallDir = func() string {
	if filepath.IsAbs(defaultDB) {
		return filepath.Dir(defaultDB)
	}
	return ""
}

// hasAncestorSameFile reports whether p, or a folder above it, is the very same
// folder as target. It compares file identity (os.SameFile), not path text, so a
// junction or link that leads into target is found: Go's EvalSymlinks does not
// follow Windows junctions.
func hasAncestorSameFile(p string, target os.FileInfo) bool {
	for cur := p; ; {
		if st, err := os.Stat(cur); err == nil && os.SameFile(st, target) {
			return true
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return false
		}
		cur = parent
	}
}

// overlapsRealInstall reports whether any of the paths is, holds or lies inside the
// known real install folder, by path text after resolving links and by file identity.
// It is a second line of defence: the quickstart folder must lie in the home folder and
// must not exist yet, which already keeps a real install out.
func overlapsRealInstall(paths ...string) bool {
	real := realInstallDir()
	if real == "" {
		return false
	}
	realAbs, err := filepath.Abs(real)
	if err != nil {
		return false
	}
	realRes, _ := resolveExisting(realAbs)
	realSt, realErr := os.Stat(realAbs)
	for _, p := range paths {
		for _, r := range []string{realAbs, realRes} {
			if r != "" && (within(p, r) || within(r, p)) {
				return true
			}
		}
		if realErr == nil && hasAncestorSameFile(p, realSt) {
			return true
		}
		if st, err := os.Stat(p); err == nil && hasAncestorSameFile(realAbs, st) {
			return true
		}
	}
	return false
}

// checkQuickstartDir decides whether dir may be used and returns it resolved. The marker is returned when it
// is a folder of an earlier run (reuse); nil means it does not exist yet and a first run will make it. It
// refuses a folder outside home, one with an unsafe ancestor, the known real install folder, a file, and ANY
// existing folder without the marker, even an empty one: a first run makes its own folder, so that nobody
// can have put anything in it, or held it open, first.
func checkQuickstartDir(dir string) (string, *quickstartState, error) {
	given, dir, err := resolveFolderPath(dir)
	if err != nil {
		return "", nil, err
	}
	if overlapsRealInstall(given, dir) {
		return "", nil, fmt.Errorf("%s is, or holds, the real Chaperone install's folder. The quickstart never touches it", dir)
	}
	if err := checkAncestors(dir); err != nil {
		return "", nil, err
	}
	st, err := os.Lstat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return dir, nil, nil
	case err != nil:
		return "", nil, err
	case !st.IsDir() || st.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0:
		return "", nil, fmt.Errorf("%s is not a plain folder", dir)
	}
	state, err := readQuickstartState(dir)
	if err == nil {
		return dir, state, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", nil, fmt.Errorf("%s: %w", dir, err)
	}
	return "", nil, fmt.Errorf("%s already exists and was not made by chapd quickstart (it has no %s). "+
		"The quickstart makes its own folder and never uses one that exists, so that nothing can have been put in it first, "+
		"and a real install is never touched. Use a path that does not exist yet, or leave out --dir", dir, quickstartMarker)
}

func readQuickstartState(dir string) (*quickstartState, error) {
	b, err := os.ReadFile(filepath.Join(dir, quickstartMarker))
	if err != nil {
		return nil, err
	}
	var s quickstartState
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s is damaged: %w", quickstartMarker, err)
	}
	if s.Kind != quickstartKind || s.Version != 1 {
		return nil, fmt.Errorf("%s is not a quickstart marker this version understands", quickstartMarker)
	}
	if err := checkQuickstartAddr(s.Addr); err != nil {
		return nil, fmt.Errorf("%s names a bad address: %w", quickstartMarker, err)
	}
	return &s, nil
}

// quickstartFolder is a prepared folder.
type quickstartFolder struct {
	Dir, DB, Keys, PolicyDir, TokenFile, LogDir string
	Addr                                        string
	Fresh                                       bool
	identity                                    os.FileInfo // the folder as it was when it was prepared
}

// folderIdentity is the folder's identity read from an OPEN HANDLE. On Windows os.Stat keeps only the path and reads
// the file ID lazily, when os.SameFile is called, so two Stat results would both describe whatever is at the path
// at that moment; a handle fixes the ID at the time it is read.
func folderIdentity(dir string) (os.FileInfo, error) {
	h, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer h.Close()
	return h.Stat()
}

// stillTheSameFolder fails unless the path still leads to the folder that was prepared. Run after chapd has
// opened its files and before anything is served: a folder renamed away and replaced in between is refused.
func (f *quickstartFolder) stillTheSameFolder() error {
	st, err := folderIdentity(f.Dir)
	if err != nil {
		return err
	}
	if !os.SameFile(st, f.identity) {
		return fmt.Errorf("%s is no longer the folder that was prepared: it was replaced while the quickstart was starting. Nothing is served", f.Dir)
	}
	return nil
}

// knownTopLevel are the only entries a quickstart folder holds. state.db-journal is here because SQLite
// opens a rollback journal it finds next to the database and writes its pages into the database.
var knownTopLevel = []string{quickstartMarker, "run-keys.json", "state.db", "state.db-wal", "state.db-shm", "state.db-journal",
	quickstartTokenFile, "policy", "logs"}

// isKnownEntry: a known name, or the temporary file `writePrivate` leaves if it is interrupted.
func isKnownEntry(name string) bool {
	if slices.Contains(knownTopLevel, name) {
		return true
	}
	ok, _ := filepath.Match(".orch-*.tmp", name)
	return ok
}

// prepareQuickstartFolder makes (state == nil) or re-opens (state != nil) the folder. dir is already resolved.
//
// A first run CREATES the folder, private from the instant it exists (createPrivateDir), together with any
// missing parent inside the allowed root, and every file in it exclusively. A path that exists is an error.
// A later run verifies the folder is private and owned by the user, lists it, refuses any entry that is not on
// the known list, and checks each known entry (owner; closed to others) before anything is trusted.
func prepareQuickstartFolder(dir string, state *quickstartState, wantAddr string, now time.Time) (*quickstartFolder, error) {
	// One path from here on: the resolved one. It is what is checked, created, locked, recorded, derived into file paths,
	// returned and printed.
	_, dir, err := resolveFolderPath(dir)
	if err != nil {
		return nil, err
	}
	f := &quickstartFolder{
		Dir: dir, DB: filepath.Join(dir, "state.db"), Keys: filepath.Join(dir, "run-keys.json"),
		PolicyDir: filepath.Join(dir, "policy"), TokenFile: filepath.Join(dir, quickstartTokenFile), LogDir: filepath.Join(dir, "logs"),
		Fresh: state == nil,
	}
	switch {
	case state == nil:
		f.Addr = wantAddr
		if f.Addr == "" {
			f.Addr = net.JoinHostPort(quickstartHost, strconv.Itoa(quickstartPort))
		}
	case wantAddr != "" && wantAddr != state.Addr:
		return nil, fmt.Errorf("this folder was set up for %s, and its passkey is bound to that address. "+
			"Use --addr %s, or a new --dir", state.Addr, state.Addr)
	default:
		f.Addr = state.Addr
	}
	if err := checkAncestors(dir); err != nil {
		return nil, err
	}
	if prepareGapHook != nil {
		prepareGapHook()
	}
	if state == nil {
		created, err := makePrivateTree(dir)
		if err != nil {
			return nil, err
		}
		// What was made must be what was checked: the path still resolves to itself, no ancestor is a link or open to others
		// (a parent made or swapped in the gap), and it is the same folder by identity. If not, take back what was made.
		if err := confirmCreated(dir); err != nil {
			removeCreated(created)
			return nil, err
		}
		if err := firstRunFiles(f, now); err != nil {
			return nil, err
		}
	} else {
		if err := verifyPrivateDir(dir); err != nil {
			return nil, fmt.Errorf("%s is not private to you (%w). Only a folder this version of the quickstart made is reused; use a new --dir", dir, err)
		}
		if err := reuseFiles(f, state); err != nil {
			return nil, err
		}
	}
	st, err := folderIdentity(dir)
	if err != nil {
		return nil, err
	}
	f.identity = st
	return f, nil
}

// makePrivateTree creates dir and any parent that does not exist, each with createPrivateDir. dir must not
// exist: if it does (it was made after the check) that is an error.
func makePrivateTree(dir string) ([]string, error) {
	if _, err := os.Lstat(dir); err == nil {
		return nil, fmt.Errorf("%s already exists; the quickstart makes its own folder and never uses one that exists", dir)
	}
	var missing []string
	for cur := dir; ; cur = filepath.Dir(cur) {
		if _, err := os.Lstat(cur); err == nil {
			break
		}
		missing = append(missing, cur)
		if filepath.Dir(cur) == cur {
			break
		}
	}
	slices.Reverse(missing)
	var created []string
	for _, d := range missing {
		if err := createPrivateDir(d); err != nil {
			removeCreated(created)
			return nil, fmt.Errorf("cannot create %s as a private folder: %w (it must not exist yet)", d, err)
		}
		created = append(created, d)
	}
	return created, nil
}

// removeCreated takes back the folders a first run made, the innermost first. They are empty; Remove refuses a folder that is not.
func removeCreated(created []string) {
	for i := len(created) - 1; i >= 0; i-- {
		_ = os.Remove(created[i])
	}
}

// confirmCreated checks that the folder that now exists is the one that was checked. The path must still resolve to
// itself (no ancestor has become a link since it was resolved), every ancestor must still pass checkAncestors (a parent
// somebody else made, or replaced by a link or junction, in the gap is refused), and the folder reached by the path must
// be the same object, by identity from an open handle, as the one reached by the resolved path.
func confirmCreated(dir string) error {
	again, err := resolveExisting(dir)
	if err != nil {
		return err
	}
	if !samePath(again, dir) {
		return fmt.Errorf("%s now leads to %s: a folder above it was replaced by a link while the quickstart was starting. Nothing was used", dir, again)
	}
	if err := checkAncestors(dir); err != nil {
		return err
	}
	a, err := folderIdentity(dir)
	if err != nil {
		return err
	}
	b, err := folderIdentity(again)
	if err != nil {
		return err
	}
	if !os.SameFile(a, b) {
		return fmt.Errorf("%s is not the folder that was made", dir)
	}
	return nil
}

// firstRunFiles fills the folder this run just made. Nothing may exist; everything is made exclusively.
func firstRunFiles(f *quickstartFolder, now time.Time) error {
	entries, err := os.ReadDir(f.Dir)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("%s was just made and is not empty (it holds %q). Nothing was used", f.Dir, entries[0].Name())
	}
	b, _ := json.MarshalIndent(quickstartState{Kind: quickstartKind, Version: 1, Addr: f.Addr, Playground: true, Created: now.UTC().Format(time.RFC3339)}, "", "  ")
	if err := createExclusive(filepath.Join(f.Dir, quickstartMarker), append(b, '\n')); err != nil {
		return err
	}
	for _, d := range []string{f.PolicyDir, f.LogDir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			return err
		}
	}
	keys, err := newQuickstartKeySet()
	if err != nil {
		return err
	}
	for _, c := range []struct {
		path string
		data []byte
	}{
		{filepath.Join(f.PolicyDir, quickstartProject+".yaml"), quickstartPolicy},
		{f.Keys, keys},
		{f.DB, nil}, // an empty file is an empty database; made here so nobody else can make it first
	} {
		if err := createExclusive(c.path, c.data); err != nil {
			return err
		}
	}
	return nil
}

// reuseFiles checks a folder of an earlier run before anything in it is trusted, then
// makes what is missing, exclusively.
func reuseFiles(f *quickstartFolder, state *quickstartState) error {
	if again, err := readQuickstartState(f.Dir); err != nil || *again != *state {
		return fmt.Errorf("%s changed while the quickstart was starting (%v). Nothing was used", filepath.Join(f.Dir, quickstartMarker), err)
	}
	entries, err := os.ReadDir(f.Dir)
	if err != nil {
		return err
	}
	var trust []string
	for _, e := range entries {
		if !isKnownEntry(e.Name()) {
			return fmt.Errorf("%s holds %q, which the quickstart did not make. It could be somebody else's (a leftover SQLite journal would be replayed into the database). "+
				"Nothing was used; use a new --dir", f.Dir, e.Name())
		}
		trust = append(trust, filepath.Join(f.Dir, e.Name()))
	}
	for _, d := range []string{f.PolicyDir, f.LogDir} {
		if es, err := os.ReadDir(d); err == nil {
			for _, e := range es {
				trust = append(trust, filepath.Join(d, e.Name()))
			}
		}
	}
	existed := map[string]bool{}
	for _, p := range trust {
		if err := checkTrusted(p); err != nil {
			return fmt.Errorf("will not use %s: %w. If you did not put it there, somebody else may have; use a new --dir", p, err)
		}
		existed[p] = true
	}
	// What was missing at the check is made now, exclusively: a file that has appeared since was not checked and is refused.
	policy := filepath.Join(f.PolicyDir, quickstartProject+".yaml")
	keys, err := newQuickstartKeySet()
	if err != nil {
		return err
	}
	for _, c := range []struct {
		path  string
		isDir bool
		data  []byte
	}{
		{f.PolicyDir, true, nil}, {f.LogDir, true, nil},
		{policy, false, quickstartPolicy}, {f.Keys, false, keys},
		{f.DB, false, nil}, // so nobody can make the database first
	} {
		if existed[c.path] {
			continue
		}
		var err error
		if c.isDir {
			err = os.Mkdir(c.path, 0o700)
		} else {
			err = createExclusive(c.path, c.data)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// createExclusive writes data to a NEW file with mode 0600 and fails if the file exists.
func createExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}
