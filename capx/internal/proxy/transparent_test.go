package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"
)

func TestTransparentReportsRejectedCertificate(t *testing.T) {
	p := newBridgeProxy(t)
	if err := p.StartTransparent("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer p.StopTransparent()
	_, addr := p.TransparentStatus()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName: "capx-validation.invalid", RootCAs: x509.NewCertPool(),
	})
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("client must reject the test CA")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		for _, event := range p.st.Recent() {
			if event.Kind != "transparent_tls_error" {
				continue
			}
			data, ok := event.Data.(map[string]string)
			if !ok || data["host"] != "capx-validation.invalid" || data["stage"] != "client_tls" || data["error"] == "" {
				t.Fatalf("missing handshake metadata: %#v", event.Data)
			}
			if tx := p.st.ListHTTPTx(""); len(tx) != 0 {
				t.Fatal("rejected handshake must not count as a decrypted transaction")
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("missing certificate rejection diagnostic")
}
