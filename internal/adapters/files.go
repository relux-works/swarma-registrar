// Package adapters supplies offline registry and local service adapters.
// Admission/HTTP wiring is deferred. No production clock evidence source or
// authenticated remote audit sink is provided: their absence fails closed.
package adapters

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/relux-works/swarma-registrar/internal/refusal"
)

const serviceUnavailable refusal.Code = "service_unavailable"
const auditUnavailable refusal.Code = "audit_unavailable"
const configurationInvalid refusal.Code = "configuration_invalid"

func failure(code refusal.Code) error { return refusal.New(code) }
func privateDirectory(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}
func nofollow(path string, flags int, mode uint32) (*os.File, error) {
	// Nonblocking open lets fstat reject FIFOs without waiting for a writer.
	fd, err := syscall.Open(path, flags|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, mode)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "local file"), nil
}
func protected(info os.FileInfo, serviceUID int) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && stat.Uid == 0 && serviceUID != 0 && info.Mode().Perm()&0022 == 0
}
func readProtectedWith(path string, limit int64, guard func(os.FileInfo, int) bool) ([]byte, error) {
	f, err := nofollow(path, syscall.O_RDONLY, 0)
	if err != nil {
		return nil, failure(configurationInvalid)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !guard(info, os.Geteuid()) {
		return nil, failure(configurationInvalid)
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, failure(configurationInvalid)
	}
	return raw, nil
}
func privateFile(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && info.Mode().Perm() == 0600 && int(stat.Uid) == os.Geteuid()
}
func absolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && strings.IndexByte(path, 0) < 0
}
