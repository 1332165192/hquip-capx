package mobile

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"howett.net/plist"
	"software.sslmate.com/src/go-pkcs12"
)

func setupFixtureEnvironment(t *testing.T) {
	t.Helper()
	tool, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CAPX_IOS_TOOL", tool)
	for _, name := range []string{"CAPX_WDA_IPA", "CAPX_WDA_P12", "CAPX_WDA_PROFILE", "CAPX_WDA_BUNDLE_ID", "CAPX_WDA_P12_PASSWORD"} {
		t.Setenv(name, "")
	}
}

func fixtureProvision(t *testing.T, expiry time.Time) []byte {
	data, _ := fixtureSigning(t, expiry)
	return data
}
func fixtureSigning(t *testing.T, expiry time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "capx synthetic signing fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	data, err := plist.Marshal(map[string]any{"ExpirationDate": expiry, "ProvisionedDevices": []string{"fixture-phone"}, "DeveloperCertificates": [][]byte{der}, "Entitlements": map[string]any{"get-task-allow": true, "application-identifier": "FIXTURETEAM.com.example.wda.xctrunner"}}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	p12, err := pkcs12.Legacy.Encode(key, parsed, nil, "fixture-only-secret")
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte("fixture CMS metadata; not an Apple signature\x00"), data...), p12
}

func fixtureIPA(t *testing.T, path string, profile []byte, unsafe bool) {
	t.Helper()
	var buffer bytes.Buffer
	z := zip.NewWriter(&buffer)
	info, err := plist.Marshal(map[string]string{"CFBundleIdentifier": "com.example.wda.xctrunner"}, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string][]byte{"Payload/WDA.app/Info.plist": info, "Payload/WDA.app/PlugIns/WebDriverAgentRunner.xctest/Info.plist": info}
	if profile != nil {
		entries["Payload/WDA.app/embedded.mobileprovision"] = profile
	}
	if unsafe {
		entries["../outside"] = []byte("not extracted")
	}
	for name, data := range entries {
		w, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
}

func unusedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitPrepare(t *testing.T, p *IOSPrepare, want string) IOSPrepareStatus {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		status := p.Status()
		if !status.Running {
			if status.State != want {
				t.Fatalf("prepare state %s: %s %s", status.State, status.Code, status.Message)
			}
			return status
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("prepare never completed")
	return IOSPrepareStatus{}
}

func TestWDAIPAMetadataAndPathBounds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wda.ipa")
	profile := fixtureProvision(t, time.Now().Add(time.Hour))
	fixtureIPA(t, path, profile, false)
	meta, err := inspectWDAIPA(path)
	if err != nil || meta.BundleID != "com.example.wda.xctrunner" || meta.XCTest != "WebDriverAgentRunner.xctest" {
		t.Fatal(meta, err)
	}
	if err := profileAllows(meta.Profile, "fixture-phone", meta.BundleID); err != nil {
		t.Fatal(err)
	}
	if err := profileAllows(meta.Profile, "another-phone", meta.BundleID); err == nil {
		t.Fatal("profile accepted another device")
	}
	fixtureIPA(t, path, profile, true)
	if _, err := inspectWDAIPA(path); err == nil {
		t.Fatal("unsafe package accepted")
	}
	fixtureIPA(t, path, fixtureProvision(t, time.Now().Add(-time.Hour)), false)
	meta, err = inspectWDAIPA(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := profileAllows(meta.Profile, "fixture-phone", meta.BundleID); err == nil {
		t.Fatal("expired profile accepted")
	}
}

func TestPrepareDoesNotGuessMissingOrMultipleDevices(t *testing.T) {
	setupFixtureEnvironment(t)
	for _, tc := range []struct{ devices, code string }{{`[]`, "device_missing"}, {`["first-phone","second-phone"]`, "select_device"}} {
		t.Run(tc.code, func(t *testing.T) {
			p := NewIOSPrepare(NewIOS())
			defer p.Close()
			p.run = func(ctx context.Context, tool string, args ...string) ([]byte, error) {
				if len(args) != 1 || args[0] != "list" {
					t.Error("unexpected device mutation")
				}
				return []byte(`{"deviceList":` + tc.devices + `}`), nil
			}
			p.start = func(context.Context, string, ...string) (<-chan error, error) {
				t.Error("started a helper without a selected phone")
				return nil, errors.New("not allowed")
			}
			if _, err := p.Begin(IOSPrepareRequest{Port: unusedPort(t)}); err != nil {
				t.Fatal(err)
			}
			if job := waitPrepare(t, p, "failed"); job.Code != tc.code {
				t.Fatal(job)
			}
		})
	}
}

func TestPrepareRejectsExpiredPackageBeforeInstall(t *testing.T) {
	setupFixtureEnvironment(t)
	ipa := filepath.Join(t.TempDir(), "expired.ipa")
	fixtureIPA(t, ipa, fixtureProvision(t, time.Now().Add(-time.Hour)), false)
	p := NewIOSPrepare(NewIOS())
	defer p.Close()
	p.run = func(ctx context.Context, tool string, args ...string) ([]byte, error) {
		if args[0] != "list" {
			t.Error("expired package reached an installation command")
		}
		return []byte(`{"deviceList":["fixture-phone"]}`), nil
	}
	if _, err := p.Begin(IOSPrepareRequest{IPA: ipa, Port: unusedPort(t)}); err != nil {
		t.Fatal(err)
	}
	job := waitPrepare(t, p, "failed")
	if job.Code != "signing_required" || !strings.Contains(job.Message, "过期") {
		t.Fatal(job)
	}
}

func TestPrepareNeverBorrowsOrStopsAnotherWDAPort(t *testing.T) {
	setupFixtureEnvironment(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"value":{"ready":true}}`)) }))
	defer server.Close()
	_, portText, _ := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	port, _ := strconv.Atoi(portText)
	p := NewIOSPrepare(NewIOS())
	defer p.Close()
	p.run = func(context.Context, string, ...string) ([]byte, error) {
		return []byte(`{"deviceList":["fixture-phone"]}`), nil
	}
	p.start = func(context.Context, string, ...string) (<-chan error, error) {
		t.Error("attempted to start on an occupied port")
		return nil, errors.New("not allowed")
	}
	if _, err := p.Begin(IOSPrepareRequest{Port: port}); err != nil {
		t.Fatal(err)
	}
	if job := waitPrepare(t, p, "failed"); job.Code != "port_in_use" {
		t.Fatal(job)
	}
	p.Stop()
	response, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatal("borrowed service was stopped", err)
	}
	response.Body.Close()
}

type prepareRoundTripper func(*http.Request) (*http.Response, error)

func (f prepareRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPrepareSignsInstallsStartsAndStopsOnlyOwnedHelpers(t *testing.T) {
	for _, download := range []bool{false, true} {
		t.Run(strconv.FormatBool(download), func(t *testing.T) { testPrepareSigningWorkflow(t, download) })
	}
}
func testPrepareSigningWorkflow(t *testing.T, download bool) {
	setupFixtureEnvironment(t)
	dir := t.TempDir()
	unsigned := filepath.Join(dir, "unsigned.ipa")
	fixtureIPA(t, unsigned, nil, false)
	profile, p12Data := fixtureSigning(t, time.Now().Add(time.Hour))
	profilePath := filepath.Join(dir, "development.mobileprovision")
	os.WriteFile(profilePath, profile, 0600)
	p12 := filepath.Join(dir, "identity.p12")
	os.WriteFile(p12, p12Data, 0600)
	t.Setenv("CAPX_WDA_P12_PASSWORD", "fixture-only-secret")
	var online, tunnel, signs, installs, starts atomic.Int32
	c := NewIOS()
	c.client = &http.Client{Transport: prepareRoundTripper(func(r *http.Request) (*http.Response, error) {
		var value any
		switch r.URL.Path {
		case "/status":
			value = map[string]any{"ready": online.Load() == 1}
		case "/session":
			value = map[string]any{"sessionId": "managed"}
		case "/session/managed/window/size":
			value = map[string]any{"width": 414, "height": 896}
		case "/session/managed/appium/settings":
		default:
			t.Errorf("unexpected WDA request %s", r.URL.Path)
		}
		data, _ := json.Marshal(map[string]any{"value": value})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), Header: make(http.Header)}, nil
	})}
	p := NewIOSPrepare(c)
	defer p.Close()
	var children sync.WaitGroup
	p.run = func(ctx context.Context, tool string, args ...string) ([]byte, error) {
		switch args[0] {
		case "list":
			return []byte(`{"deviceList":["fixture-phone"]}`), nil
		case "sign", "ui":
			if args[0] == "ui" {
				installs.Add(1)
			}
			for _, arg := range args {
				if strings.Contains(arg, "fixture-only-secret") || strings.Contains(arg, "p12password") {
					t.Error("signing password was passed on the command line")
				}
			}
			signs.Add(1)
			output := ""
			for _, arg := range args {
				if strings.HasPrefix(arg, "--output=") {
					output = strings.TrimPrefix(arg, "--output=")
				}
			}
			fixtureIPA(t, output, profile, false)
			return []byte(`{}`), nil
		case "install":
			installs.Add(1)
			return []byte(`{}`), nil
		case "lockdown":
			return []byte(`{"ProductVersion":"18.3"}`), nil
		case "tunnel":
			if tunnel.Load() == 1 {
				return []byte(`[{"udid":"fixture-phone"}]`), nil
			}
			return []byte(`[]`), nil
		case "image":
			return []byte(`{}`), nil
		default:
			return nil, errors.New("unexpected helper command")
		}
	}
	p.start = func(ctx context.Context, tool string, args ...string) (<-chan error, error) {
		starts.Add(1)
		switch args[0] {
		case "tunnel":
			tunnel.Store(1)
		case "runwda":
			online.Store(1)
		case "forward":
		default:
			t.Errorf("unexpected process %s", args[0])
		}
		done := make(chan error, 1)
		children.Add(1)
		go func() { defer children.Done(); <-ctx.Done(); done <- ctx.Err(); close(done) }()
		return done, nil
	}
	if download {
		unsigned = ""
	}
	job, err := p.Begin(IOSPrepareRequest{IPA: unsigned, P12: p12, Profile: profilePath, Port: unusedPort(t)})
	if err != nil || !job.Running {
		t.Fatal(job, err)
	}
	if _, err := p.Begin(IOSPrepareRequest{}); err == nil {
		t.Fatal("overlapping prepare accepted")
	}
	job = waitPrepare(t, p, "ready")
	if job.Endpoint == "" || signs.Load() != 1 || installs.Load() != 1 || starts.Load() != 3 {
		t.Fatal(job, signs.Load(), installs.Load(), starts.Load())
	}
	if strings.Contains(job.Message, "fixture-only-secret") {
		t.Fatal("signing secret leaked")
	}
	p.Stop()
	finished := make(chan struct{})
	go func() { children.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("owned helper leaked after stop")
	}
	if _, err := c.Status(); err == nil {
		t.Fatal("stopped managed endpoint remained selected")
	}
}

func TestToolFailureAndChecksumDoNotExposeOrExecuteInputs(t *testing.T) {
	code, message := toolFailure([]byte("pkcs12 password fixture-only-secret: failed"))
	if code != "signing_password" || strings.Contains(message, "fixture-only-secret") {
		t.Fatal(code, message)
	}
	if _, err := installIOSToolArchive([]byte("corrupt release archive"), strings.Repeat("0", 64)); err == nil {
		t.Fatal("tool checksum mismatch accepted")
	}
}
