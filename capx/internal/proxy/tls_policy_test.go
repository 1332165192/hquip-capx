package proxy

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Trust only the loopback fixture's certificate for the duration of this test.
// No operating-system trust settings or production verification are changed.
func trustFixtureCA(t *testing.T) {
	t.Helper()
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cert := fixture.Certificate()
	fixture.Close()
	path := filepath.Join(t.TempDir(), "fixture-ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CAPX_UPSTREAM_CA_FILE", path)
}

func TestUpstreamTLSRejectsUntrustedAndAcceptsExplicitCA(t *testing.T) {
	t.Setenv("CAPX_UPSTREAM_CA_FILE", "")
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer fixture.Close()
	tr := newUpstreamTransport(false)
	tr.TLSClientConfig.RootCAs = x509.NewCertPool()
	defer tr.CloseIdleConnections()
	if _, err := (&http.Client{Transport: tr}).Get(fixture.URL); err == nil {
		t.Fatal("accepted an untrusted origin")
	}
	trustFixtureCA(t)
	trusted := newUpstreamTransport(false)
	defer trusted.CloseIdleConnections()
	response, err := (&http.Client{Transport: trusted}).Get(fixture.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatal(response.StatusCode)
	}
	// Changing the expected name must still reject a trusted certificate.
	config, err := upstreamTLSConfig("wrong.example")
	if err != nil {
		t.Fatal(err)
	}
	if config.InsecureSkipVerify {
		t.Fatal("verification disabled")
	}
	if _, err := fixture.Certificate().Verify(x509.VerifyOptions{Roots: config.RootCAs, DNSName: config.ServerName}); err == nil {
		t.Fatal("accepted a hostname mismatch")
	}
}

func TestInvalidConfiguredCAFailsClosed(t *testing.T) {
	t.Setenv("CAPX_UPSTREAM_CA_FILE", filepath.Join(t.TempDir(), "missing.pem"))
	if _, err := upstreamTLSConfig(""); err == nil {
		t.Fatal("accepted missing configured CA")
	}
}
