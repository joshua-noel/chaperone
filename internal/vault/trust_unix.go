//go:build unix

package vault

import (
	"os"
	"syscall"
)

// toolTrusted is the rule for a program that is about to be handed a key: the
// file and the folder it is in are owned by root, and neither can be written by
// the group or by others. A user-owned or group-writable folder (a
// /usr/local/bin that an admin group can write to, a Homebrew prefix) lets
// another account, or anything running as that user, swap the tool.
//
// It checks the final file and its folder, not every folder above it, and it
// follows symlinks (NixOS links its tools into the store). It is a check of the
// state at this moment, not a lock.
func toolTrusted(file, dir os.FileInfo) bool {
	return rootOwnedNotWritable(file) && rootOwnedNotWritable(dir)
}

func rootOwnedNotWritable(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0 && fi.Mode().Perm()&0o022 == 0
}
