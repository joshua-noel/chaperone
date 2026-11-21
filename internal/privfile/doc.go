// Package privfile creates files that only the current user can open, and holds the one piece of Windows
// access-control code that chapd and chap share.
//
// A mode of 0600 means nothing on Windows: a new file takes the access list of its folder, so a key file written to
// a repository or to the temp folder is readable by whoever can read that folder. [Create] gives the file its own
// protected access list at the moment it is created, so there is no instant at which it is looser. On Unix it is
// mode 0600, and an existing file, or a link of any kind, at the path is refused.
package privfile
