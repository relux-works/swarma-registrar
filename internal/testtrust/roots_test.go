package testtrust

import (
	"context"
	"crypto/x509"
	"os/exec"
	"path/filepath"
	"testing"
)

// Isolated roots work only in tests; a separately built ordinary binary rejects
// injection, establishing the production guard rather than assuming test mode.
func TestProductionTrustGuard(t *testing.T) {
	roots := x509.NewCertPool()
	ctx := WithRoots(context.Background(), roots)
	if Roots(ctx) == nil || Roots(context.Background()) != nil {
		t.Fatal("test trust was missing or escaped its context")
	}
	binary := filepath.Join(t.TempDir(), "trust-check")
	if out, err := exec.Command("go", "build", "-o", binary, "./testdata/production").CombinedOutput(); err != nil {
		t.Fatalf("production fixture build failed: %v: %s", err, out)
	}
	out, err := exec.Command(binary).CombinedOutput()
	if err != nil || string(out) != "system roots only\n" {
		t.Fatalf("production trust guard failed: %v: %s", err, out)
	}
}
