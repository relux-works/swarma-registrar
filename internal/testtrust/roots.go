// Package testtrust scopes TLS fixture roots to Go test binaries only.
package testtrust

import (
	"context"
	"crypto/x509"
	"testing"
)

type rootsKey struct{}

// WithRoots is an internal test hook. Ordinary binaries cannot enable it.
func WithRoots(ctx context.Context, roots *x509.CertPool) context.Context {
	if !testing.Testing() {
		panic("test trust unavailable")
	}
	return context.WithValue(ctx, rootsKey{}, roots.Clone())
}

// Roots returns nil in every non-test binary, retaining system TLS trust.
func Roots(ctx context.Context) *x509.CertPool {
	if !testing.Testing() {
		return nil
	}
	roots, _ := ctx.Value(rootsKey{}).(*x509.CertPool)
	return roots
}
