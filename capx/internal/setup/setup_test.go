package setup

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestCertThumbprint(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "capx-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	tp, subj, err := certThumbprint(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(tp) != 40 {
		t.Fatalf("thumbprint len = %d, want 40 hex chars", len(tp))
	}
	if subj == "" {
		t.Fatal("empty subject")
	}
	st := Snapshot(pemBytes, "")
	if st.OS == "" {
		t.Fatal("empty OS")
	}
}

func TestCertThumbprintRejectsGarbage(t *testing.T) {
	if _, _, err := certThumbprint([]byte("not a cert")); err == nil {
		t.Fatal("expected error")
	}
}

func TestCertSPKIHash(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "capx-spki"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	h := certSPKIHash(pemBytes)
	if h == "" {
		t.Fatal("empty SPKI hash")
	}
	if certSPKIHash([]byte("nope")) != "" {
		t.Fatal("garbage should not hash")
	}
}
