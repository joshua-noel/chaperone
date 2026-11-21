// Package privfile creates files that only the current user can open, and holds the one piece of Windows
// access-control code that chapd and chap share.
//
// A mode of 0600 means nothing on Windows: a new file takes the access list of its folder, so a key file written to
// a repository or to the temp folder is readable by whoever can read that folder. [Create] gives the file its own
// protected access list at the moment it is created, so there is no instant at which it is looser. On Unix it is
// mode 0600.
//
// Create makes a NEW file and never follows or replaces a link at the final path. On Unix, O_CREATE|O_EXCL fails when
// anything is there, a symbolic link (a dangling one too) included, and O_NOFOLLOW is added. On Windows, CREATE_NEW
// alone would follow a symbolic link whose target does not exist and create the target (found by a CI run on a real
// Windows runner), so the file is opened with FILE_FLAG_OPEN_REPARSE_POINT as well: a link or a junction at the path
// is then opened as itself, which exists, and the call fails; and what was opened is read back from the handle and
// must be a plain file.
//
// A link in an earlier component of the path (a folder that is a link) is followed, on Unix and on Windows alike: the
// folder is the caller's choice, and Create guards only the file it makes.
package privfile
