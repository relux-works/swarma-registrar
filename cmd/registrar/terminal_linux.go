//go:build linux

package main

import (
	"io"
	"os"
	"syscall"
	"unsafe"
)

// openTerminal rejects redirected stdin and then reads the controlling terminal,
// not an injectable flag/environment digest. TCGETS establishes a real terminal.
func openTerminal() (io.ReadCloser, error) {
	var state syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, os.Stdin.Fd(), syscall.TCGETS, uintptr(unsafe.Pointer(&state)))
	if errno != 0 {
		return nil, registryFailure()
	}
	f, err := os.OpenFile("/dev/tty", os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, registryFailure()
	}
	return f, nil
}
