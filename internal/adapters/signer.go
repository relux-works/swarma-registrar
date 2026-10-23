package adapters

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"io"
	"path/filepath"
	"syscall"
)

// Signer holds one immutable generation. Loading/rotation never logs or returns
// a configured path, key bytes or underlying filesystem/parser diagnostics.
type Signer struct{ key ed25519.PrivateKey }

func LoadSigner(path string) (*Signer, error) {
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
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(raw) > 16384 {
		return nil, failure(serviceUnavailable)
	}
	if !singlePrivatePEM(raw) {
		return nil, failure(serviceUnavailable)
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, failure(serviceUnavailable)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, failure(serviceUnavailable)
	}
	private, ok := key.(ed25519.PrivateKey)
	if !ok || len(private) != ed25519.PrivateKeySize {
		return nil, failure(serviceUnavailable)
	}
	return &Signer{key: append(ed25519.PrivateKey(nil), private...)}, nil
}

// Bind pem.Decode to the first complete block: its parser otherwise skips
// malformed leading blocks and can return a later valid key.
func singlePrivatePEM(raw []byte) bool {
	raw = bytes.TrimSpace(raw)
	return bytes.HasPrefix(raw, []byte("-----BEGIN PRIVATE KEY-----")) &&
		bytes.HasSuffix(raw, []byte("-----END PRIVATE KEY-----")) &&
		bytes.Count(raw, []byte("-----BEGIN")) == 1 &&
		bytes.Count(raw, []byte("-----END")) == 1
}

func (s *Signer) PublicKey() ed25519.PublicKey {
	if s == nil || len(s.key) != ed25519.PrivateKeySize {
		return nil
	}
	return append(ed25519.PublicKey(nil), s.key.Public().(ed25519.PublicKey)...)
}
func (s *Signer) Sign(ctx context.Context, message []byte) ([]byte, error) {
	if ctx.Err() != nil || s == nil || len(s.key) != ed25519.PrivateKeySize {
		return nil, failure(serviceUnavailable)
	}
	signed := ed25519.Sign(s.key, message)
	if ctx.Err() != nil {
		return nil, failure(serviceUnavailable)
	}
	return signed, nil
}
