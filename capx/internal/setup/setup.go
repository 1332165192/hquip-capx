package setup

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/hquip/capx/internal/backgroundprocess"
)

// Status is a point-in-time view of the local capture setup.
type Status struct {
	OS              string `json:"os"`
	Admin           bool   `json:"admin"`
	CAInstalled     bool   `json:"ca_installed"`
	CAThumbprint    string `json:"ca_thumbprint,omitempty"`
	CASubject       string `json:"ca_subject,omitempty"`
	ProxySet        bool   `json:"proxy_set"`
	ProxyOwned      bool   `json:"proxy_owned"`
	ProxyServer     string `json:"proxy_server,omitempty"`
	ProxyOverride   string `json:"proxy_override,omitempty"`
	HTTP3Disabled   bool   `json:"http3_disabled"`
	ChromeProfile   string `json:"chrome_profile,omitempty"`
	ChromeAvailable bool   `json:"chrome_available"`
	ProxyBackup     bool   `json:"proxy_backup"`
	Hint            string `json:"hint,omitempty"`
}

type proxySnapshot struct {
	Enable        uint32
	Server        string
	Override      string
	AutoConfigURL string
	// Native Unix settings are kept separately: HTTPS/PAC need not equal HTTP.
	Mode         string `json:",omitempty"`
	SecureEnable uint32 `json:",omitempty"`
	SecureServer string `json:",omitempty"`
	PACEnable    uint32 `json:",omitempty"`
	SameProxy    string `json:",omitempty"`
}

func certThumbprint(pemBytes []byte) (string, string, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", "", fmt.Errorf("ca: not a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", err
	}
	sum := sha1.Sum(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:])), cert.Subject.String(), nil
}

func certSPKIHash(pemBytes []byte) string {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func run(name string, args ...string) (string, error) {
	cmd := backgroundprocess.Command(name, args...)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func unsupported(feature string) error {
	return fmt.Errorf("%s is not implemented on %s", feature, runtime.GOOS)
}

func splitLastColon(addr string) (string, string, error) {
	i := strings.LastIndex(addr, ":")
	if i <= 0 || i == len(addr)-1 {
		return "", "", fmt.Errorf("invalid host:port %q", addr)
	}
	return strings.Trim(addr[:i], "[]"), addr[i+1:], nil
}
