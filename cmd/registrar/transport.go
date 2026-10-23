package main

import (
	"crypto/tls"
	"errors"
	"net/netip"

	"github.com/relux-works/swarma-registrar/internal/adapters"
)

func transport(c adapters.Config, plain bool) (*tls.Config, error) {
	address, err := netip.ParseAddrPort(c.Listen)
	if err != nil || address.Addr().Zone() != "" {
		return nil, errors.New("invalid listener")
	}
	if plain {
		if !address.Addr().Unmap().IsLoopback() {
			return nil, errors.New("test HTTP requires loopback")
		}
		return nil, nil
	}
	if c.TLSCertificate == "" || c.TLSKey == "" {
		return nil, errors.New("TLS required")
	}
	pair, err := adapters.LoadTLS(c.TLSCertificate, c.TLSKey)
	if err != nil {
		return nil, errors.New("TLS unavailable")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}, nil
}
