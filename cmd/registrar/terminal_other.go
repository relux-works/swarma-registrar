//go:build !linux

package main

import "io"

// Production interactive confirmation is supported only on Linux.
func openTerminal() (io.ReadCloser, error) { return nil, registryFailure() }
