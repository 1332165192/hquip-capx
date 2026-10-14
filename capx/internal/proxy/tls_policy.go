package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
)

// A custom test/enterprise CA is explicit; verification is never disabled.
func upstreamTLSConfig(host string, protocols ...string) (*tls.Config, error) {
	config := &tls.Config{ServerName: stripPort(host), MinVersion: tls.VersionTLS12, NextProtos: protocols}
	if path := strings.TrimSpace(os.Getenv("CAPX_UPSTREAM_CA_FILE")); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read configured upstream CA: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("configured upstream CA contains no PEM certificates")
		}
		config.RootCAs = pool
	}
	return config, nil
}
