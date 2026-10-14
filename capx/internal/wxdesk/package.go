package wxdesk

import (
	"embed"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

//go:embed scripts/*.ps1
var scriptFiles embed.FS

type Package struct {
	Root              string `json:"root"`
	Configuration     string `json:"configuration"`
	SandboxInstalled  bool   `json:"sandbox_installed"`
	Note              string `json:"note"`
	SourceMode        string `json:"source_mode"`
	InstallerVerified bool   `json:"installer_verified"`
}

type PrepareOptions struct {
	Source    string `json:"source"`
	WeChatExe string `json:"wechat_exe"`
	Installer string `json:"installer"`
}

type mapping struct {
	HostFolder    string
	SandboxFolder string
	ReadOnly      bool
}
type sandboxConfig struct {
	XMLName              xml.Name `xml:"Configuration"`
	VGpu                 string   `xml:"vGPU"`
	Networking           string
	ClipboardRedirection string
	AudioInput           string
	VideoInput           string
	PrinterRedirection   string
	MemoryInMB           int
	MappedFolders        []mapping `xml:"MappedFolders>MappedFolder"`
	LogonCommand         struct{ Command string }
}

func writePackage(root, source, backend string, sandboxInstalled bool) (Package, error) {
	return writeSourcePackage(root, source, backend, sandboxInstalled, false, nil)
}

func writeSourcePackage(root, source, backend string, sandboxInstalled, installer bool, verifyInstaller func(string) error) (Package, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return Package{}, err
	}
	source, err = filepath.Abs(source)
	if err != nil {
		return Package{}, err
	}
	name := strings.ToLower(filepath.Base(source))
	if !installer && name != "weixin.exe" && name != "wechat.exe" {
		return Package{}, fmt.Errorf("需要官方 Weixin.exe / WeChat.exe，不能单独使用 WeChatAppEx.exe")
	}
	info, err := os.Stat(source)
	if err != nil {
		return Package{}, err
	}
	if info.IsDir() {
		return Package{}, fmt.Errorf("请选择程序文件，不能选择目录")
	}
	if installer && (filepath.Ext(name) != ".exe" || info.Size() == 0 || info.Size() > 1<<30) {
		return Package{}, fmt.Errorf("安装包必须是有效的 EXE 文件，大小不超过 1 GiB")
	}
	if installer && verifyInstaller == nil {
		return Package{}, fmt.Errorf("安装包签名校验不可用")
	}
	assets := filepath.Join(root, "assets")
	channel := filepath.Join(root, "channel")
	for _, dir := range []string{assets, channel, filepath.Join(channel, "requests"), filepath.Join(channel, "responses")} {
		if err = os.MkdirAll(dir, 0700); err != nil {
			return Package{}, err
		}
	}
	if installer {
		file, err := os.CreateTemp(assets, "wechat-setup-*.exe")
		if err != nil {
			return Package{}, err
		}
		staged := file.Name()
		if err = file.Close(); err != nil {
			os.Remove(staged)
			return Package{}, err
		}
		defer os.Remove(staged)
		if err = copyFile(source, staged); err != nil {
			return Package{}, fmt.Errorf("复制微信安装包: %w", err)
		}
		// Verify the exact copied bytes, never execute the installer on the host.
		if err = verifyInstaller(staged); err != nil {
			return Package{}, err
		}
		if err = os.Rename(staged, filepath.Join(assets, "WeChatSetup.exe")); err != nil {
			return Package{}, err
		}
	}
	dest := filepath.Join(assets, "capx-captured.exe")
	if err = copyFile(backend, dest); err != nil {
		return Package{}, fmt.Errorf("复制隔离后台: %w", err)
	}
	for _, name := range []string{"Start-Environment.ps1", "Relay.ps1"} {
		data, err := scriptFiles.ReadFile("scripts/" + name)
		if err != nil {
			return Package{}, err
		}
		// Windows PowerShell 5.1 recognizes Unicode scripts reliably with BOM.
		if err = os.WriteFile(filepath.Join(assets, name), append([]byte{0xef, 0xbb, 0xbf}, data...), 0600); err != nil {
			return Package{}, err
		}
	}
	mode := "client"
	details := map[string]any{"source_mode": mode, "wechat_filename": filepath.Base(source)}
	if installer {
		mode = "installer"
		details = map[string]any{"source_mode": mode, "installer_filename": "WeChatSetup.exe", "installer_verified": true}
	}
	configuration, _ := json.MarshalIndent(details, "", "  ")
	if err = os.WriteFile(filepath.Join(assets, "environment.json"), configuration, 0600); err != nil {
		return Package{}, err
	}
	config := sandboxConfig{VGpu: "Enable", Networking: "Enable", ClipboardRedirection: "Disable", AudioInput: "Disable", VideoInput: "Disable", PrinterRedirection: "Disable", MemoryInMB: 6144,
		MappedFolders: []mapping{{assets, `C:\CapxTools`, true}, {channel, `C:\CapxChannel`, false}}}
	if !installer {
		config.MappedFolders = []mapping{{assets, `C:\CapxTools`, true}, {filepath.Dir(source), `C:\WeChatSource`, true}, {channel, `C:\CapxChannel`, false}}
	}
	config.LogonCommand.Command = `powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\CapxTools\Start-Environment.ps1`
	data, err := xml.MarshalIndent(config, "", "  ")
	if err != nil {
		return Package{}, err
	}
	path := filepath.Join(root, "WeChat-Test.wsb")
	if err = os.WriteFile(path, append([]byte(xml.Header), data...), 0600); err != nil {
		return Package{}, err
	}
	note := "隔离包已生成。沙箱内需重新登录小号；关闭沙箱会清除微信账号环境，抓包记录保留在专用 channel 目录"
	if installer {
		note = "官方微信安装包已内置并通过腾讯签名校验。启动沙箱后先完成安装，再登录小号；宿主电脑无需安装微信"
	}
	return Package{Root: root, Configuration: path, SandboxInstalled: sandboxInstalled, SourceMode: mode, InstallerVerified: installer, Note: note}, nil
}

func copyFile(source, dest string) error {
	if filepath.Clean(source) == filepath.Clean(dest) {
		return nil
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0700)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	closeErr := out.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func (c *Controller) Prepare(options PrepareOptions) (Package, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return prepareNative(options)
}
func (c *Controller) StartEnvironment() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return startNativeEnvironment()
}
