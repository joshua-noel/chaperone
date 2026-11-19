//go:build !unix

package store

// File modes mean nothing on Windows: access to the folder is set by its ACL
// (the install script gives it to the service account only). There is nothing
// to do here.
func prepareDBFile(string) error    { return nil }
func restrictSidecars(string) error { return nil }
