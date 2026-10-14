// Package proxy implements capx's L7 MITM proxy: a self-signed CA that signs
// per-host leaf certificates on the fly so HTTPS traffic can be decrypted,
// plus an HTTP/HTTPS interception engine that records transactions into the
// store (Burp-style HTTP history) and supports request interception.
//
// This is the "M4" milestone: it is what fills the Proxy / HTTP history /
// HTTPS history panels with real traffic. It is pure Go (crypto/tls,
// net/http) so it stays in the default build with no native dependencies.
package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CA is capx's certificate authority. It holds the root cert/key and an
// in-memory cache of generated leaf certificates keyed by host.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte // root cert, PEM-encoded (for the user to install/trust)

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// dataDir returns the directory where capx persists the CA (~/.capx).
func dataDir() (string, error) {
	if dir := strings.TrimSpace(os.Getenv("CAPX_DATA_DIR")); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".capx")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// LoadOrCreateCA loads the persisted CA from ~/.capx, generating and saving a
// new one the first time. The PEM-encoded root cert is exposed so the console
// can offer it for download/installation into the system trust store.
func LoadOrCreateCA() (*CA, error) {
	dir, err := dataDir()
	if err != nil {
		return nil, err
	}
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")

	if cb, err := os.ReadFile(certPath); err == nil {
		if kb, err := os.ReadFile(keyPath); err == nil {
			if ca, err := parseCA(cb, kb); err == nil {
				return ca, nil
			}
		}
	}

	ca, err := generateCA()
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(ca.key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, ca.certPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	return ca, nil
}

func parseCA(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, fmt.Errorf("ca: bad pem")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, certPEM: certPEM, cache: map[string]*tls.Certificate{}}, nil
}

func generateCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "capx Root CA",
			Organization: []string{"capx"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &CA{cert: cert, key: key, certPEM: certPEM, cache: map[string]*tls.Certificate{}}, nil
}

// CertPEM returns the PEM-encoded root certificate.
func (ca *CA) CertPEM() []byte { return ca.certPEM }

// LeafFor returns (creating + caching as needed) a TLS certificate for host,
// signed by the CA. host may include a port, which is stripped.
func (ca *CA) LeafFor(host string) (*tls.Certificate, error) {
	host = stripPort(host)
	ca.mu.Lock()
	if c, ok := ca.cache[host]; ok {
		ca.mu.Unlock()
		return c, nil
	}
	ca.mu.Unlock()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	// Deterministic-ish serial from host so re-issues are stable per run.
	sum := sha256.Sum256([]byte(host))
	serial := new(big.Int).SetBytes(sum[:16])
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{"capx MITM"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := parseIP(host); ip != nil {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	} else {
		tmpl.DNSNames = append(tmpl.DNSNames, host)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &leafKey.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	leaf := &tls.Certificate{
		Certificate: [][]byte{der, ca.cert.Raw},
		PrivateKey:  leafKey,
	}
	ca.mu.Lock()
	ca.cache[host] = leaf
	ca.mu.Unlock()
	return leaf, nil
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func parseIP(host string) net.IP { return net.ParseIP(strings.TrimSpace(host)) }
