package wxhook

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRedirectAgentMockIPv4IPv6AndExplicitProtocol(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node is required for the isolated Frida JS fixture")
	}
	script, err := renderRedirectAgentWithOptions(CaptureOptions{Port: 18443, ExplicitPort: 18444, UpstreamProxy: "http://127.0.0.1:7897"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "redirect.js")
	if err := os.WriteFile(path, script, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, "redirect_mock.cjs", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated agent fixture: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

func TestCaptureOptionsRequireVerifiedHTTPIPv4LoopbackShape(t *testing.T) {
	for _, upstream := range []string{"https://127.0.0.1:7897", "socks5://127.0.0.1:7897", "http://localhost:7897", "http://203.0.113.4:7897", "http://[::1]:7897", "http://user:password@127.0.0.1:7897", "http://127.0.0.1:7897/path", "http://127.0.0.1:7897?x=y", "http://127.0.0.1:18443", "http://127.0.0.1:18444"} {
		t.Run(upstream, func(t *testing.T) {
			if _, err := renderRedirectAgentWithOptions(CaptureOptions{Port: 18443, ExplicitPort: 18444, UpstreamProxy: upstream}); err == nil {
				t.Fatal("unsupported/ambiguous upstream accepted")
			}
		})
	}
	if _, err := renderRedirectAgentWithOptions(CaptureOptions{Port: 18443, ExplicitPort: 18444}); err == nil {
		t.Fatal("explicit bridge without upstream accepted")
	}
	if _, err := renderRedirectAgentWithOptions(CaptureOptions{Port: 18443, UpstreamProxy: "http://127.0.0.1:7897"}); err == nil {
		t.Fatal("upstream without separate explicit bridge accepted")
	}
}
