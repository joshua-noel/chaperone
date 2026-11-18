package main

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var identityRE = regexp.MustCompile(`AGE-SECRET-KEY-1[A-Z0-9]+`)

func TestVaultRecoverCommand(t *testing.T) {
	useTestWrapper(t) // the account before the reset
	dir := t.TempDir()
	db := filepath.Join(dir, "state.db")
	code, out, e := runVault(t, "init", "-db", db)
	if code != 0 {
		t.Fatalf("init: exit %d: %s", code, e)
	}
	identity := identityRE.FindString(out)
	if identity == "" {
		t.Fatalf("init printed no recovery identity: %q", out)
	}
	pemPath, _, _ := writePEM(t, dir)
	if code, _, e := runVault(t, "import", "--name", "github-app-key", "--file", pemPath, "-db", db); code != 0 {
		t.Fatalf("import: exit %d: %s", code, e)
	}

	useTestWrapper(t) // a new account: the old wrapped keys no longer unwrap
	if code, _, _ := runVault(t, "list", "-db", db); code == 0 {
		t.Fatal("the new account listed the old vault")
	}

	setStdin := func(s string) {
		old := vaultStdin
		vaultStdin = strings.NewReader(s)
		t.Cleanup(func() { vaultStdin = old })
	}

	setStdin("")
	if code, _, e := runVault(t, "recover", "-db", db); code != 1 || !strings.Contains(e, "no recovery identity") {
		t.Errorf("empty stdin: exit %d, %q", code, e)
	}
	setStdin("AGE-SECRET-KEY-1RQSGSN568R4M3ZHQ8FN7Z4T5MFQVDXYV6NPFJ0WML5QPSTL2Q9AS9QDNFYQ\n")
	if code, _, e := runVault(t, "recover", "-db", db); code != 1 || !strings.Contains(e, "not this vault's recovery identity") {
		t.Errorf("wrong identity: exit %d, %q", code, e)
	}

	setStdin("\n  " + identity + "  \n")
	code, out, e = runVault(t, "recover", "-db", db)
	if code != 0 || !strings.Contains(out, "recovered: 1 secrets re-keyed") {
		t.Fatalf("recover: exit %d, stdout %q, stderr %q", code, out, e)
	}
	if strings.Contains(out+e, identity) {
		t.Error("recover printed the recovery identity")
	}
	code, out, _ = runVault(t, "list", "-db", db)
	if code != 0 || !strings.Contains(out, "github-app-key") {
		t.Fatalf("list after recover: exit %d, %q", code, out)
	}

	setStdin(identity + "\n")
	if code, _, e := runVault(t, "recover", "-db", db); code != 1 || !strings.Contains(e, "nothing to recover") {
		t.Errorf("second recover: exit %d, %q", code, e)
	}
}
