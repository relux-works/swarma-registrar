package adapters

import (
	"crypto/tls"
	"io"
	"path/filepath"
	"syscall"
)

// LoadTLS loads service-owned 0600 certificate/key files from private directories.
// No underlying parser, key bytes or configured paths escape through errors.
func LoadTLS(certificate, key string) (tls.Certificate, error) {
	read := func(path string) ([]byte, error) {
		if !absolute(path) || !privateDirectory(filepath.Dir(path)) {
			return nil, failure(serviceUnavailable)
		}
		f, err := nofollow(path, syscall.O_RDONLY, 0)
		if err != nil {
			return nil, failure(serviceUnavailable)
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !privateFile(info) {
			return nil, failure(serviceUnavailable)
		}
		raw, err := io.ReadAll(io.LimitReader(f, 65537))
		if err != nil || len(raw) > 65536 {
			return nil, failure(serviceUnavailable)
		}
		return raw, nil
	}
	cert, err := read(certificate)
	if err != nil {
		return tls.Certificate{}, err
	}
	secret, err := read(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	pair, err := tls.X509KeyPair(cert, secret)
	if err != nil {
		return tls.Certificate{}, failure(serviceUnavailable)
	}
	return pair, nil
}
