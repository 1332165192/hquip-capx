package mobile

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"encoding/json"
	"howett.net/plist"
	"software.sslmate.com/src/go-pkcs12"
)

// IOSPrepare owns only the helper processes it starts. Borrowed WDA services,
// tunnels, pairing records and applications are never stopped by cleanup.
type IOSPrepare struct {
	mu         sync.Mutex
	controller *IOSController
	job        IOSPrepareStatus
	cancel     context.CancelFunc
	run        func(context.Context, string, ...string) ([]byte, error)
	start      func(context.Context, string, ...string) (<-chan error, error)
}

type IOSPrepareRequest struct {
	UDID        string `json:"udid"`
	IPA         string `json:"ipa_path"`
	BundleID    string `json:"bundle_id"`
	P12         string `json:"p12_path"`
	Profile     string `json:"profile_path"`
	PasswordEnv string `json:"password_env"`
	Port        int    `json:"port"`
	TunnelPort  int    `json:"tunnel_port"`
}

type IOSPrepareStatus struct {
	Generation uint64 `json:"generation"`
	State      string `json:"state"`
	Phase      string `json:"phase"`
	Message    string `json:"message"`
	Code       string `json:"code,omitempty"`
	Endpoint   string `json:"endpoint,omitempty"`
	Running    bool   `json:"running"`
}

type IOSUSBDevice struct {
	UDID string `json:"udid"`
}

type IOSPrepareInspection struct {
	ToolAvailable  bool             `json:"tool_available"`
	Devices        []IOSUSBDevice   `json:"devices"`
	Job            IOSPrepareStatus `json:"job"`
	HasIPA         bool             `json:"has_ipa"`
	CanSign        bool             `json:"can_sign"`
	ProfileExpiry  *time.Time       `json:"profile_expiry,omitempty"`
	ProfileExpired bool             `json:"profile_expired"`
	Code           string           `json:"code,omitempty"`
	Message        string           `json:"message,omitempty"`
}

func NewIOSPrepare(c *IOSController) *IOSPrepare {
	p := &IOSPrepare{controller: c, job: IOSPrepareStatus{State: "idle", Phase: "idle", Message: "准备 iOS 环境后可自动安装并连接 WDA"}}
	p.run = runIOSTool
	p.start = startIOSTool
	return p
}

func iosToolPath() string {
	if name := strings.TrimSpace(os.Getenv("CAPX_IOS_TOOL")); name != "" {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
		return ""
	}
	for _, name := range []string{"ios", "go-ios"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	name := "ios"
	if os.PathSeparator == '\\' {
		name += ".exe"
	}
	cache, _ := os.UserCacheDir()
	for _, path := range []string{filepath.Join(cache, "capx", "tools", "go-ios", name), filepath.Join(os.TempDir(), "capx-mobile-device-tools", name)} {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return path
		}
	}
	return ""
}

// Bounded output never becomes a public error/log; tools can print UDIDs or
// signing configuration. Errors are mapped to actionable codes below.
type limitedToolOutput struct {
	mu   sync.Mutex
	data []byte
}

func (b *limitedToolOutput) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(data)
	if room := (1 << 20) - len(b.data); room > 0 {
		if len(data) > room {
			data = data[:room]
		}
		b.data = append(b.data, data...)
	}
	return n, nil
}

func iosWorkDir() (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(cache, "capx", "ios")
	return dir, os.MkdirAll(dir, 0700)
}

func iosCommand(ctx context.Context, tool string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, tool, args...)
	cmd.SysProcAttr = hiddenSysProcAttr()
	cmd.WaitDelay = time.Second
	cmd.Dir = os.TempDir()
	return cmd
}

func runIOSTool(ctx context.Context, tool string, args ...string) ([]byte, error) {
	cmd := iosCommand(ctx, tool, args...)
	out := &limitedToolOutput{}
	stderr := &limitedToolOutput{}
	cmd.Stdout = out
	cmd.Stderr = stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return out.data, ctx.Err()
	}
	if err != nil {
		return append(out.data, stderr.data...), err
	}
	return out.data, err
}

func startIOSTool(ctx context.Context, tool string, args ...string) (<-chan error, error) {
	cmd := iosCommand(ctx, tool, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait(); close(done) }()
	return done, nil
}

func (p *IOSPrepare) Status() IOSPrepareStatus { p.mu.Lock(); defer p.mu.Unlock(); return p.job }

func (p *IOSPrepare) command(ctx context.Context, tool string, args ...string) ([]byte, error) {
	step, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	return p.run(step, tool, args...)
}

func parseIOSDevices(data []byte) ([]IOSUSBDevice, error) {
	var envelope struct {
		Devices []json.RawMessage `json:"deviceList"`
	}
	if json.Unmarshal(data, &envelope) != nil || envelope.Devices == nil {
		return nil, errors.New("go-ios returned invalid device JSON")
	}
	devices := []IOSUSBDevice{}
	for _, raw := range envelope.Devices {
		var id string
		if json.Unmarshal(raw, &id) != nil {
			var obj struct {
				UDID       string `json:"udid"`
				Serial     string `json:"SerialNumber"`
				Properties struct {
					Serial string `json:"SerialNumber"`
				} `json:"Properties"`
			}
			if json.Unmarshal(raw, &obj) != nil {
				continue
			}
			id = obj.UDID
			if id == "" {
				id = obj.Serial
			}
			if id == "" {
				id = obj.Properties.Serial
			}
		}
		if wdaSessionRE.MatchString(id) {
			devices = append(devices, IOSUSBDevice{UDID: id})
		}
	}
	return devices, nil
}

type provisionInfo struct {
	Expiration   time.Time `plist:"ExpirationDate"`
	Devices      []string  `plist:"ProvisionedDevices"`
	AllDevices   bool      `plist:"ProvisionsAllDevices"`
	Certificates [][]byte  `plist:"DeveloperCertificates"`
	Entitlements struct {
		AppID string `plist:"application-identifier"`
		Debug bool   `plist:"get-task-allow"`
	} `plist:"Entitlements"`
}

// Read metadata from the CMS container; actual signature/trust is checked by
// Apple's installation service. Metadata inspection alone is not signature proof.
func parseProvision(data []byte) (provisionInfo, error) {
	var info provisionInfo
	if len(data) > 8<<20 {
		return info, errors.New("provisioning profile exceeds limit")
	}
	start := bytes.Index(data, []byte("<?xml"))
	if start < 0 {
		start = bytes.Index(data, []byte("<plist"))
	}
	end := bytes.LastIndex(data, []byte("</plist>"))
	if start < 0 || end < start {
		return info, errors.New("invalid provisioning metadata")
	}
	if _, err := plist.Unmarshal(data[start:end+8], &info); err != nil || info.Expiration.IsZero() {
		return info, errors.New("invalid provisioning metadata")
	}
	return info, nil
}

func readSmallFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("file exceeds limit")
	}
	return data, nil
}

type ipaMetadata struct {
	BundleID string
	Profile  *provisionInfo
	XCTest   string
}

func inspectWDAIPA(filename string) (ipaMetadata, error) {
	var meta ipaMetadata
	z, err := zip.OpenReader(filename)
	if err != nil {
		return meta, errors.New("无法读取 WDA IPA")
	}
	defer z.Close()
	if len(z.File) > 30000 {
		return meta, errors.New("IPA 文件数量过多")
	}
	root := ""
	var total uint64
	for _, file := range z.File {
		name := strings.TrimSuffix(file.Name, "/")
		if name == "" || strings.ContainsAny(name, "\\:\x00") || path.IsAbs(name) || path.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") || file.Mode()&os.ModeSymlink != 0 || file.UncompressedSize64 > 256<<20 || file.UncompressedSize64 > (1<<30)-total {
			return meta, errors.New("IPA 包含不安全路径或过大的成员")
		}
		total += file.UncompressedSize64
		parts := strings.Split(file.Name, "/")
		if len(parts) == 3 && parts[0] == "Payload" && strings.HasSuffix(parts[1], ".app") && parts[2] == "Info.plist" {
			if root != "" {
				return meta, errors.New("IPA 必须只包含一个顶层 App")
			}
			root = "Payload/" + parts[1] + "/"
			data, err := readZipEntry(file)
			if err != nil {
				return meta, err
			}
			var info struct {
				BundleID string `plist:"CFBundleIdentifier"`
			}
			if _, err := plist.Unmarshal(data, &info); err != nil || !iosBundleRE.MatchString(info.BundleID) {
				return meta, errors.New("IPA bundle ID 无效")
			}
			meta.BundleID = info.BundleID
		}
	}
	if root == "" {
		return meta, errors.New("IPA 缺少 App Info.plist")
	}
	for _, file := range z.File {
		if file.Name == root+"embedded.mobileprovision" {
			data, err := readZipEntry(file)
			if err != nil {
				return meta, err
			}
			profile, err := parseProvision(data)
			if err != nil {
				return meta, err
			}
			meta.Profile = &profile
		}
		if strings.HasPrefix(file.Name, root+"PlugIns/") && strings.HasSuffix(file.Name, ".xctest/Info.plist") {
			parts := strings.Split(file.Name, "/")
			meta.XCTest = parts[len(parts)-2]
		}
	}
	if meta.XCTest == "" {
		return meta, errors.New("IPA 没有 XCTest 测试模块，不能作为 WDA 启动")
	}
	return meta, nil
}

func readZipEntry(file *zip.File) ([]byte, error) {
	if file.UncompressedSize64 > 8<<20 {
		return nil, errors.New("IPA metadata exceeds limit")
	}
	r, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, (8<<20)+1))
	if len(data) > 8<<20 {
		return nil, errors.New("IPA metadata exceeds limit")
	}
	return data, err
}

func (r IOSPrepareRequest) defaults() IOSPrepareRequest {
	for _, pair := range []struct {
		dst *string
		env string
	}{{&r.IPA, "CAPX_WDA_IPA"}, {&r.P12, "CAPX_WDA_P12"}, {&r.Profile, "CAPX_WDA_PROFILE"}, {&r.BundleID, "CAPX_WDA_BUNDLE_ID"}} {
		*pair.dst = strings.TrimSpace(*pair.dst)
		if *pair.dst == "" {
			*pair.dst = strings.TrimSpace(os.Getenv(pair.env))
		}
	}
	if r.PasswordEnv == "" {
		r.PasswordEnv = "CAPX_WDA_P12_PASSWORD"
	}
	if r.Port == 0 {
		r.Port = 8100
	}
	if r.TunnelPort == 0 {
		r.TunnelPort = 28100
	}
	for _, value := range []*string{&r.IPA, &r.P12, &r.Profile} {
		if *value != "" {
			if absolute, err := filepath.Abs(*value); err == nil {
				*value = absolute
			}
		}
	}
	return r
}

func installedWDABundles(data []byte) ([]string, error) {
	var value any
	if json.Unmarshal(data, &value) != nil {
		return nil, errors.New("invalid installed app list")
	}
	found := map[string]bool{}
	out := []string{}
	var visit func(any, int)
	visit = func(value any, depth int) {
		if depth > 32 || len(out) > 4096 {
			return
		}
		switch node := value.(type) {
		case map[string]any:
			id, _ := node["CFBundleIdentifier"].(string)
			if id == "" {
				id, _ = node["bundleIdentifier"].(string)
			}
			name := ""
			for _, key := range []string{"CFBundleName", "CFBundleDisplayName", "CFBundleExecutable"} {
				if text, ok := node[key].(string); ok {
					name += " " + text
				}
			}
			if iosBundleRE.MatchString(id) && strings.HasSuffix(strings.ToLower(id), ".xctrunner") && strings.Contains(strings.ToLower(id+name), "webdriveragent") && !found[id] {
				found[id] = true
				out = append(out, id)
			}
			for _, child := range node {
				visit(child, depth+1)
			}
		case []any:
			for _, child := range node {
				visit(child, depth+1)
			}
		}
	}
	visit(value, 0)
	return out, nil
}

func profileBundleID(profile *provisionInfo, current string) string {
	app := profile.Entitlements.AppID
	if dot := strings.IndexByte(app, '.'); dot >= 0 {
		app = app[dot+1:]
	}
	if app != "" && !strings.Contains(app, "*") {
		return app
	}
	if strings.HasSuffix(app, "*") && !strings.HasPrefix(current, strings.TrimSuffix(app, "*")) {
		return strings.TrimSuffix(app, "*") + "WebDriverAgentRunner.xctrunner"
	}
	if current == "" {
		return "com.facebook.WebDriverAgentRunner.xctrunner"
	}
	return current
}

func (p *IOSPrepare) Inspect(ctx context.Context) IOSPrepareInspection {
	req := IOSPrepareRequest{}.defaults()
	info := IOSPrepareInspection{Job: p.Status(), Devices: []IOSUSBDevice{}, HasIPA: req.IPA != "", CanSign: req.P12 != "" && req.Profile != ""}
	tool := iosToolPath()
	info.ToolAvailable = tool != ""
	if tool == "" {
		info.Code = "tool_missing"
		info.Message = "请安装 go-ios 并设置 CAPX_IOS_TOOL，或将 ios 加入 PATH"
		return info
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	data, err := p.run(ctx, tool, "list")
	if err == nil {
		info.Devices, err = parseIOSDevices(data)
	}
	if err != nil {
		info.Code = "device_list_failed"
		info.Message = "读取 iPhone 失败，请检查 Apple USB 驱动与配对"
	} else if len(info.Devices) == 0 {
		info.Code = "device_missing"
		info.Message = "当前未识别到 iPhone；请连接 USB、解锁并信任电脑"
	}
	var profile *provisionInfo
	if req.Profile != "" {
		if data, err := readSmallFile(req.Profile, 8<<20); err == nil {
			if parsed, err := parseProvision(data); err == nil {
				profile = &parsed
			}
		}
	} else if req.IPA != "" {
		if meta, err := inspectWDAIPA(req.IPA); err == nil {
			profile = meta.Profile
		}
	}
	if profile != nil {
		info.ProfileExpiry = &profile.Expiration
		info.ProfileExpired = !time.Now().Before(profile.Expiration)
	}
	return info
}

var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (p *IOSPrepare) Begin(req IOSPrepareRequest) (IOSPrepareStatus, error) {
	req = req.defaults()
	if req.Port == req.TunnelPort || req.Port < 1 || req.Port > 65535 || req.TunnelPort < 1 || req.TunnelPort > 65535 || !envNameRE.MatchString(req.PasswordEnv) || (req.BundleID != "" && !iosBundleRE.MatchString(req.BundleID)) || (req.UDID != "" && !wdaSessionRE.MatchString(req.UDID)) {
		return p.Status(), errors.New("无效的端口、设备、bundle ID 或环境变量名")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.job.Running || p.cancel != nil {
		return p.job, errors.New("准备流程或自有 WDA 正在运行，请先停止后再切换")
	}
	p.job = IOSPrepareStatus{Generation: p.job.Generation + 1, State: "running", Phase: "checking", Message: "正在检查设备与 WDA 环境", Running: true}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	go p.prepare(ctx, p.job.Generation, req)
	return p.job, nil
}

func (p *IOSPrepare) phase(generation uint64, phase, message string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.job.Generation == generation && p.job.Running {
		p.job.Phase = phase
		p.job.Message = message
	}
}

func (p *IOSPrepare) fail(generation uint64, code, message string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.job.Generation != generation {
		return
	}
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}
	p.job.State = "failed"
	p.job.Running = false
	p.job.Code = code
	p.job.Message = message
}

func toolFailure(data []byte) (string, string) {
	text := strings.ToLower(string(data))
	switch {
	case strings.Contains(text, "password"), strings.Contains(text, "pkcs12"):
		return "signing_password", "签名证书无法解锁，请检查本地 P12 及签名口令环境变量"
	case strings.Contains(text, "expired"), strings.Contains(text, "signature"), strings.Contains(text, "codesign"):
		return "signature_invalid", "WDA 签名无效或过期，请提供有效的开发证书和描述文件后重新准备"
	case strings.Contains(text, "access is denied"), strings.Contains(text, "administrator"), strings.Contains(text, "permission denied"):
		return "admin_required", "iOS 隧道需要当前工具具备管理员权限；请以管理员身份运行后重试"
	case strings.Contains(text, "certificate"), strings.Contains(text, "x509"):
		return "apple_tls_trust", "Apple 服务证书链验证失败，请更新工具的根证书环境后重试"
	default:
		return "tool_failed", "iOS 工具执行失败，请检查 USB、开发者模式、开发者镜像和签名；未自动确认手机系统授权"
	}
}

func profileAllows(profile *provisionInfo, udid, bundle string) error {
	if profile == nil {
		return errors.New("WDA 缺少开发描述文件，请提供签名证书和描述文件")
	}
	if !time.Now().Before(profile.Expiration) {
		return errors.New("WDA 描述文件已过期，请重新签名")
	}
	if !profile.Entitlements.Debug {
		return errors.New("WDA XCTest 需要允许调试的开发描述文件")
	}
	if len(profile.Certificates) == 0 {
		return errors.New("开发描述文件缺少签名证书")
	}
	if !profile.AllDevices {
		found := false
		for _, id := range profile.Devices {
			found = found || strings.EqualFold(id, udid)
		}
		if !found {
			return errors.New("描述文件未包含所选 iPhone，请重新配置开发描述文件")
		}
	}
	if app := profile.Entitlements.AppID; app != "" {
		if dot := strings.IndexByte(app, '.'); dot >= 0 {
			app = app[dot+1:]
		}
		if app != bundle && !(strings.HasSuffix(app, "*") && strings.HasPrefix(bundle, strings.TrimSuffix(app, "*"))) {
			return errors.New("描述文件与 WDA bundle ID 不匹配")
		}
	}
	for _, der := range profile.Certificates {
		cert, err := x509.ParseCertificate(der)
		if err != nil || time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
			return errors.New("描述文件中的开发证书无效或过期")
		}
	}
	return nil
}

// Rewrap password-protected P12 data inside a private, short-lived file. The
// original password never appears in an HTTP body, command line or tool output.
func privateSigningP12(req IOSPrepareRequest, profile *provisionInfo, dir string) (string, func(), error) {
	data, err := readSmallFile(req.P12, 8<<20)
	if err != nil {
		return "", nil, errors.New("无法读取 P12 签名证书")
	}
	key, cert, chain, err := pkcs12.DecodeChain(data, os.Getenv(req.PasswordEnv))
	if err != nil || cert == nil {
		return "", nil, errors.New("P12 口令或证书格式无效，请检查本地签名口令环境变量")
	}
	match := false
	for _, der := range profile.Certificates {
		match = match || bytes.Equal(der, cert.Raw)
	}
	if !match {
		return "", nil, errors.New("P12 的开发证书与描述文件不匹配")
	}
	if time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
		return "", nil, errors.New("P12 开发证书已过期或尚未生效")
	}
	repacked, err := pkcs12.Legacy.Encode(key, cert, chain, "")
	if err != nil {
		return "", nil, errors.New("无法准备临时签名身份")
	}
	f, err := os.CreateTemp(dir, "wda-identity-*.p12")
	if err != nil {
		return "", nil, errors.New("无法创建私有签名临时文件")
	}
	cleanup := func() { os.Remove(f.Name()) }
	_, err = f.Write(repacked)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		cleanup()
		return "", nil, errors.New("无法写入私有签名临时文件")
	}
	return f.Name(), cleanup, nil
}

func (p *IOSPrepare) prepare(ctx context.Context, g uint64, req IOSPrepareRequest) {
	tool := iosToolPath()
	if tool == "" {
		p.phase(g, "tool_download", "正在下载并校验官方 go-ios 工具")
		var err error
		tool, err = ensureIOSTool(ctx)
		if err != nil {
			p.fail(g, "tool_missing", "无法准备 go-ios，请设置 CAPX_IOS_TOOL 或检查官方下载网络；下载包须通过固定 SHA-256 校验")
			return
		}
	}
	data, err := p.command(ctx, tool, "list")
	if err != nil {
		code, msg := toolFailure(data)
		p.fail(g, code, msg)
		return
	}
	devices, err := parseIOSDevices(data)
	if err != nil {
		p.fail(g, "device_list_failed", "go-ios 没有返回有效的设备列表")
		return
	}
	if req.UDID == "" && len(devices) == 1 {
		req.UDID = devices[0].UDID
	}
	found := false
	for _, d := range devices {
		found = found || d.UDID == req.UDID
	}
	if !found {
		code, msg := "device_missing", "未检测到所选 iPhone，请连接并信任电脑"
		if len(devices) > 1 && req.UDID == "" {
			code, msg = "select_device", "检测到多台 iPhone，请先选择设备"
		}
		p.fail(g, code, msg)
		return
	}
	args := []string{"--udid=" + req.UDID, "--tunnel-info-port=" + strconv.Itoa(req.TunnelPort)}
	explicitBundle := req.BundleID != ""
	// A loopback WDA endpoint does not expose a trustworthy USB UDID. Do not
	// borrow a busy port when preparing a specifically selected phone.
	endpoint := "http://127.0.0.1:" + strconv.Itoa(req.Port)
	listener, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(req.Port))
	if err != nil {
		p.fail(g, "port_in_use", "WDA 端口已被占用；请使用手动连接已有 WDA，或更换端口后准备所选手机")
		return
	}
	listener.Close()
	p.controller.mu.Lock()
	configured := p.controller.endpoint != ""
	p.controller.mu.Unlock()
	if configured {
		p.fail(g, "connection_active", "当前已有 WDA 连接，请先断开后再准备所选手机")
		return
	}
	var meta ipaMetadata
	installed := false
	if req.IPA != "" {
		meta, err = inspectWDAIPA(req.IPA)
		if err != nil {
			p.fail(g, "invalid_ipa", err.Error())
			return
		}
		if req.BundleID == "" {
			req.BundleID = meta.BundleID
		}
	}
	if req.P12 != "" || req.Profile != "" {
		if req.P12 == "" || req.Profile == "" {
			p.fail(g, "signing_required", "自动签名需要本地 P12 和开发描述文件")
			return
		}
		profileData, err := readSmallFile(req.Profile, 8<<20)
		if err != nil {
			p.fail(g, "profile_unreadable", "无法读取开发描述文件")
			return
		}
		profile, err := parseProvision(profileData)
		if err != nil {
			p.fail(g, "profile_invalid", "开发描述文件格式无效")
			return
		}
		if !explicitBundle {
			req.BundleID = profileBundleID(&profile, req.BundleID)
		}
		if !iosBundleRE.MatchString(req.BundleID) {
			p.fail(g, "profile_invalid", "描述文件中的 App 标识不适用于 WDA")
			return
		}
		if err := profileAllows(&profile, req.UDID, req.BundleID); err != nil {
			p.fail(g, "profile_invalid", err.Error())
			return
		}
		if info, err := os.Stat(req.P12); err != nil || !info.Mode().IsRegular() {
			p.fail(g, "certificate_unreadable", "无法读取本地 P12 签名证书")
			return
		}
		p.phase(g, "signing", "正在使用本地开发身份签名 WDA")
		dir, err := iosWorkDir()
		if err != nil {
			p.fail(g, "cache_unavailable", "无法创建私有 WDA 工作目录")
			return
		}
		output, err := os.CreateTemp(dir, "wda-signed-*.ipa")
		if err != nil {
			p.fail(g, "cache_unavailable", "无法创建签名输出")
			return
		}
		outputPath := output.Name()
		output.Close()
		os.Remove(outputPath)
		defer os.Remove(outputPath)
		signingP12, cleanupIdentity, err := privateSigningP12(req, &profile, dir)
		if err != nil {
			p.fail(g, "signing_identity", err.Error())
			return
		}
		defer cleanupIdentity()
		var command []string
		if req.IPA == "" {
			command = []string{"ui", "install", "wda", "--p12file=" + signingP12, "--profile=" + req.Profile, "--output=" + outputPath, "--bundleid=" + req.BundleID}
			command = append(command, args...)
			installed = true
		} else {
			command = []string{"sign", "app", "--path=" + req.IPA, "--p12file=" + signingP12, "--profile=" + req.Profile, "--output=" + outputPath, "--bundleid=" + req.BundleID}
		}

		data, err = p.command(ctx, tool, command...)
		if err != nil {
			code, msg := toolFailure(data)
			p.fail(g, code, msg)
			return
		}
		meta, err = inspectWDAIPA(outputPath)
		if err != nil {
			p.fail(g, "signed_ipa_invalid", "签名工具未生成完整 WDA IPA")
			return
		}
		req.IPA = outputPath
	}
	if req.IPA != "" {
		if meta.BundleID != req.BundleID {
			p.fail(g, "bundle_mismatch", "签名包的 bundle ID 与准备目标不一致")
			return
		}
		if err := profileAllows(meta.Profile, req.UDID, req.BundleID); err != nil {
			p.fail(g, "signing_required", err.Error())
			return
		}
		if !installed {
			p.phase(g, "installing", "正在安装已检查的 WDA；手机可能要求确认开发者信任")
			data, err = p.command(ctx, tool, append([]string{"install", "--path=" + req.IPA}, args...)...)
			if err != nil {
				code, msg := toolFailure(data)
				p.fail(g, code, msg)
				return
			}
		}
	}
	if req.BundleID == "" {
		data, err = p.command(ctx, tool, append([]string{"apps", "--all"}, args...)...)
		if err != nil {
			p.fail(g, "app_list_failed", "无法读取已安装的 WDA，请检查设备连接或填写已知 WDA bundle ID")
			return
		}
		bundles, err := installedWDABundles(data)
		if err != nil {
			p.fail(g, "app_list_failed", "已安装应用列表格式无效，请填写已知 WDA bundle ID")
			return
		}
		if len(bundles) == 0 {
			p.fail(g, "wda_not_installed", "未找到已安装 WDA，请提供有效签名 IPA，或配置开发身份以自动下载安装")
			return
		}
		if len(bundles) > 1 {
			p.fail(g, "select_wda", "发现多个 WDA，请明确填写要启动的 bundle ID")
			return
		}
		req.BundleID = bundles[0]
	}
	xctest := meta.XCTest
	if xctest == "" {
		xctest = "WebDriverAgentRunner.xctest"
	}
	var tunnel <-chan error
	version, _ := p.command(ctx, tool, append([]string{"lockdown", "get", "ProductVersion"}, args...)...)
	var versionValue any
	if json.Unmarshal(version, &versionValue) != nil {
		p.fail(g, "version_unavailable", "无法读取 iOS 版本，请检查设备配对与信任")
		return
	}
	var versionString string
	switch value := versionValue.(type) {
	case string:
		versionString = value
	case map[string]any:
		versionString, _ = value["ProductVersion"].(string)
		if versionString == "" {
			versionString, _ = value["value"].(string)
		}
	}
	major, _ := strconv.Atoi(strings.Split(versionString, ".")[0])
	if major == 0 {
		p.fail(g, "version_unavailable", "go-ios 未返回有效的 iOS 版本")
		return
	}
	if major >= 17 {
		p.phase(g, "tunnel", "正在检查或启动 iOS 17+ 通信隧道")
		data, err = p.command(ctx, tool, append([]string{"tunnel", "ls"}, args...)...)
		if err != nil || !bytes.Contains(data, []byte("\""+req.UDID+"\"")) {
			dir, err := iosWorkDir()
			if err != nil {
				p.fail(g, "cache_unavailable", "无法创建私有 iOS 配对目录")
				return
			}
			pairs := filepath.Join(dir, "pairs")
			if os.MkdirAll(pairs, 0700) != nil {
				p.fail(g, "cache_unavailable", "无法创建私有 iOS 配对目录")
				return
			}
			tunnel, err = p.start(ctx, tool, append([]string{"tunnel", "start", "--userspace", "--pair-record-path=" + pairs}, args...)...)
			if err != nil {
				p.fail(g, "tunnel_failed", "无法启动 iOS 隧道，请检查管理员权限和设备信任")
				return
			}
			wait, cancel := context.WithTimeout(ctx, 30*time.Second)
			ready := false
			for !ready && wait.Err() == nil {
				select {
				case <-tunnel:
					cancel()
					p.fail(g, "tunnel_exited", "iOS 隧道已退出，请检查管理员权限、USB 和设备信任")
					return
				default:
				}
				data, err = p.command(wait, tool, append([]string{"tunnel", "ls"}, args...)...)
				ready = err == nil && bytes.Contains(data, []byte("\""+req.UDID+"\""))
				if !ready {
					select {
					case <-wait.Done():
					case <-time.After(300 * time.Millisecond):
					}
				}
			}
			cancel()
			if !ready {
				p.fail(g, "tunnel_timeout", "iOS 隧道未就绪，请检查管理员权限、Apple 驱动和手机授权")
				return
			}
		}
	}
	p.phase(g, "developer_image", "正在准备 iOS 开发者镜像")
	data, err = p.command(ctx, tool, append([]string{"image", "auto"}, args...)...)
	if err != nil {
		code, msg := toolFailure(data)
		p.fail(g, code, msg)
		return
	}
	p.phase(g, "starting", "正在启动 XCTest 与 USB 转发；请在手机上完成系统授权")
	forward, err := p.start(ctx, tool, append([]string{"forward", strconv.Itoa(req.Port), "8100"}, args...)...)
	if err != nil {
		p.fail(g, "forward_failed", "无法启动 WDA USB 转发")
		return
	}
	runner, err := p.start(ctx, tool, append([]string{"runwda", "--bundleid=" + req.BundleID, "--testrunnerbundleid=" + req.BundleID, "--xctestconfig=" + xctest}, args...)...)
	if err != nil {
		p.fail(g, "runner_failed", "无法启动 WDA XCTest")
		return
	}
	timer := time.NewTimer(75 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-forward:
			p.fail(g, "forward_exited", "WDA USB 转发已退出，请检查 USB 连接和端口")
			return
		case <-runner:
			p.fail(g, "runner_exited", "XCTest 已退出，请检查签名、开发者镜像和手机系统授权")
			return
		case <-timer.C:
			p.fail(g, "wda_timeout", "WDA 未在时限内就绪，请检查手机授权、签名及开发者模式")
			return
		case <-tunnel:
			p.fail(g, "tunnel_exited", "iOS 隧道已退出")
			return
		case <-tick.C:
			if _, err := p.controller.ConnectContext(ctx, endpoint, ""); err == nil {
				p.ready(g, endpoint)
				go p.watch(ctx, g, forward, runner, tunnel)
				return
			}
		}
	}
}

func (p *IOSPrepare) ready(g uint64, endpoint string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.job.Generation != g || !p.job.Running {
		return
	}
	p.job.State = "ready"
	p.job.Phase = "ready"
	p.job.Message = "WDA 已就绪并接入统一手机操作"
	p.job.Endpoint = endpoint
	p.job.Running = false
}
func (p *IOSPrepare) watch(ctx context.Context, g uint64, forward, runner, tunnel <-chan error) {
	select {
	case <-ctx.Done():
		return
	case <-forward:
		p.fail(g, "forward_exited", "WDA USB 转发已退出")
	case <-runner:
		p.fail(g, "runner_exited", "WDA XCTest 已退出")
	case <-tunnel:
		p.fail(g, "tunnel_exited", "iOS 隧道已退出")
	}
}

func (p *IOSPrepare) Stop() IOSPrepareStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}
	if p.job.Endpoint != "" {
		p.controller.mu.Lock()
		if p.controller.endpoint == p.job.Endpoint {
			p.controller.endpoint, p.controller.session = "", ""
		}
		p.controller.mu.Unlock()
	}
	p.job.Generation++
	p.job.State = "stopped"
	p.job.Phase = "stopped"
	p.job.Running = false
	p.job.Message = "自有准备任务和控制进程已停止"
	p.job.Code = ""
	return p.job
}

func (p *IOSPrepare) Close() { p.Stop() }
