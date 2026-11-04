package main

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/relux-works/swarma-registrar/internal/testtrust"
)

// A normal binary must keep system roots and reject the internal test hook.
func main() {
	ctx := context.Background()
	if testtrust.Roots(ctx) != nil {
		panic("custom roots in production")
	}
	defer func() {
		if recovered := recover(); recovered == "test trust unavailable" {
			fmt.Println("system roots only")
		} else {
			panic("test hook was not rejected")
		}
	}()
	testtrust.WithRoots(ctx, x509.NewCertPool())
}
