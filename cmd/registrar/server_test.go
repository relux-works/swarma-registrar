package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-registrar/internal/adapters"
	"github.com/relux-works/swarma-registrar/internal/admission"
)

type exactRemote struct{}

func (exactRemote) Commit(ctx context.Context, line []byte) ([32]byte, error) {
	return sha256.Sum256(line), ctx.Err()
}

func testDependencies(t *testing.T, f *fixtureData, noClock, noRemote bool) dependencies {
	t.Helper()
	return dependencies{
		loadConfig: func(string) (adapters.Config, error) { return f.config, nil },
		terminal:   func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(f.initialDigest + "\n")), nil },
		open: func(ctx context.Context, c adapters.Config, start time.Time, confirm bool, terminal terminalOpener, out io.Writer) (*runtime, error) {
			var remote adapters.Remote = exactRemote{}
			if noRemote {
				remote = nil
			}
			audit, err := adapters.NewAudit(ctx, c.AuditFile, remote)
			if err != nil {
				return nil, err
			}
			snapshot, err := startRegistry(ctx, c, f.source, f.store, confirm, terminal, out)
			if err != nil {
				snapshot = nil
			}
			var clock admission.Clock = testClock{}
			startup := healthyStartup()
			if noClock {
				realClock := adapters.NewClock(start, nil)
				clock = clockBridge{realClock}
				s := realClock.Startup()
				startup = admission.Startup{Reading: admission.Reading{UTC: s.Reading.UTC, Healthy: s.Reading.Healthy, Faulted: s.Reading.Faulted}, Ordered: s.Ordered}
			}
			head := audit.Head()
			handler, err := wire(c, snapshot, clock, startup, f.signer, auditBridge{audit}, admission.AuditHead{Sequence: head.Sequence, Hash: head.Hash})
			if err != nil {
				_ = audit.Close()
				return nil, err
			}
			return &runtime{handler: handler, close: audit.Close}, nil
		},
	}
}
func startTestServer(t *testing.T, d dependencies, plain, confirm bool) (string, *http.Client) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	address := make(chan net.Addr, 1)
	d.listening = func(a net.Addr) { address <- a }
	args := []string{"serve", "--config", "fixture"}
	if plain {
		args = append(args, "--loopback-test-http")
	}
	if confirm {
		args = append(args, "--reconcile")
	}
	ended := make(chan error, 1)
	go func() { ended <- run(ctx, args, io.Discard, io.Discard, time.Now(), d) }()
	var addr net.Addr
	select {
	case addr = <-address:
	case err := <-ended:
		t.Fatalf("serve refused: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("serve startup timeout")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-ended:
			if err != nil {
				t.Errorf("serve shutdown: %v", err)
			}
		case <-time.After(6 * time.Second):
			t.Error("shutdown timeout")
		}
	})
	scheme := "https"
	if plain {
		scheme = "http"
	}
	return scheme + "://" + addr.String(), &http.Client{Timeout: 5 * time.Second}
}

// On a real loopback listener, registry/clock/audit fences suppress JWTs, while
// confirmed authority with healthy fake evidence and exact remote ack signs one.
// Git/config ownership trust is represented by bounded test adapters here.
func TestLoopbackAdmissionFences(t *testing.T) {
	cases := []struct {
		name                       string
		confirm, noClock, noRemote bool
		status                     int
		code                       string
	}{
		{"no-registry-confirmation", false, false, false, 503, "registry_unavailable"},
		{"no-clock-evidence", true, true, false, 400, "clock_skew"},
		{"no-remote-audit", true, false, true, 503, "audit_unavailable"},
		{"healthy-control", true, false, false, 200, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := fixture(t)
			url, client := startTestServer(t, testDependencies(t, f, tc.noClock, tc.noRemote), true, tc.confirm)
			ready, err := client.Get(url + "/readyz")
			if err != nil {
				t.Fatal(err)
			}
			ready.Body.Close()
			if (!tc.confirm || tc.noClock) && ready.StatusCode != 503 {
				t.Fatal("fenced readiness opened")
			}
			if tc.confirm && !tc.noClock && ready.StatusCode != 200 {
				t.Fatal("confirmed healthy readiness closed")
			}
			response, err := client.Post(url+"/v1/registration", "application/json", bytes.NewReader(proof(t)))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			var result struct{ JWT, Code string }
			if err = json.Unmarshal(raw, &result); err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != tc.status || result.Code != tc.code {
				t.Fatalf("status/code %d/%s, want %d/%s", response.StatusCode, result.Code, tc.status, tc.code)
			}
			if tc.status != 200 {
				if result.JWT != "" {
					t.Fatal("fenced JWT escaped")
				}
				return
			}
			parts := strings.Split(result.JWT, ".")
			if len(parts) != 3 {
				t.Fatal("missing JWT")
			}
			signature, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil || !ed25519.Verify(private(9).Public().(ed25519.PublicKey), []byte(parts[0]+"."+parts[1]), signature) {
				t.Fatal("JWT signature")
			}
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				t.Fatal(err)
			}
			var claims map[string]any
			if json.Unmarshal(payload, &claims) != nil || claims["iss"] != "swarma-registrar" || claims["sub"] != "host-a_project_role" || claims["exp"] != float64(epoch+220) {
				t.Fatalf("JWT claims: %s", payload)
			}
		})
	}
}

// Plain HTTP requires both an explicit flag and a literal loopback address;
// default mode requires usable private TLS material and validates a TLS handshake.
func TestTransportRequiresTLSOrExplicitLoopback(t *testing.T) {
	f := fixture(t)
	if _, err := transport(f.config, false); err == nil {
		t.Fatal("implicit plaintext")
	}
	for _, listen := range []string{"0.0.0.0:0", "[::]:0", "192.0.2.1:0", "localhost:0", "[fe80::1%lo]:0"} {
		c := f.config
		c.Listen = listen
		if _, err := transport(c, true); err == nil {
			t.Fatalf("plaintext accepted %s", listen)
		}
	}
	for _, listen := range []string{"127.0.0.1:0", "[::1]:0"} {
		c := f.config
		c.Listen = listen
		if _, err := transport(c, true); err != nil {
			t.Fatal("loopback control")
		}
	}
	certificate, key := tlsFixture(t)
	f.config.TLSCertificate = certificate
	f.config.TLSKey = key
	if err := os.Chmod(key, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := transport(f.config, false); err == nil {
		t.Fatal("unsafe TLS key")
	}
	if err := os.Chmod(key, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(key), "key-link")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	unsafe := f.config
	unsafe.TLSKey = link
	if _, err := transport(unsafe, false); err == nil {
		t.Fatal("TLS key symlink accepted")
	}
	badCertificate := filepath.Join(filepath.Dir(key), "invalid-certificate")
	if err := os.WriteFile(badCertificate, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	unsafe = f.config
	unsafe.TLSCertificate = badCertificate
	if _, err := transport(unsafe, false); err == nil || strings.Contains(err.Error(), badCertificate) {
		t.Fatal("TLS parsing refusal/path boundary")
	}
	url, client := startTestServer(t, testDependencies(t, f, false, false), false, true)
	certPEM, err := os.ReadFile(certificate)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("certificate fixture")
	}
	client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	t.Cleanup(client.CloseIdleConnections)
	response, err := client.Get(url + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("HTTPS readiness")
	}
}
func tlsFixture(t *testing.T) (string, string) {
	t.Helper()
	dir := privateDir(t)
	certPath, keyPath := filepath.Join(dir, "certificate"), filepath.Join(dir, "key")
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Unix(1577836800, 0), NotAfter: time.Unix(2208988800, 0), IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(bytes.NewReader(bytes.Repeat([]byte{1}, 4096)), cert, cert, private(8).Public(), private(8))
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private(8))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// Wrong, EOF and redirected confirmation leave the running HTTP process fenced;
// a fresh exact confirmation is covered by the adjacent healthy issuance control.
func TestLoopbackWrongConfirmationStaysFenced(t *testing.T) {
	for _, answer := range []string{"wrong\n", "", "not-terminal"} {
		t.Run(answer, func(t *testing.T) {
			f := fixture(t)
			d := testDependencies(t, f, false, false)
			d.terminal = func() (io.ReadCloser, error) {
				if answer == "not-terminal" {
					return nil, registryFailure()
				}
				return io.NopCloser(strings.NewReader(answer)), nil
			}
			url, client := startTestServer(t, d, true, true)
			response, err := client.Get(url + "/readyz")
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != 503 {
				t.Fatal("unconfirmed readiness opened")
			}
			response, err = client.Post(url+"/v1/registration", "application/json", bytes.NewReader(proof(t)))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			var result struct{ JWT, Code string }
			if json.NewDecoder(response.Body).Decode(&result) != nil || response.StatusCode != 503 || result.Code != "registry_unavailable" || result.JWT != "" {
				t.Fatal("unconfirmed authority escaped")
			}
			if digest(t, f.store) != f.initialDigest {
				t.Fatal("unconfirmed state changed")
			}
		})
	}
}
