//go:build !windows

package main

// newDoctorEnv is nil where the install does not exist: `chap doctor` says so.
func newDoctorEnv(*app) *doctorEnv { return nil }
