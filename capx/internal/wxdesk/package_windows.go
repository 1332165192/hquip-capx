//go:build windows

package wxdesk

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func sandboxExecutable() string {
	path := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsSandbox.exe")
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		return path
	}
	if path, err := exec.LookPath("WindowsSandbox.exe"); err == nil {
		return path
	}
	return ""
}
func prepareNative(options PrepareOptions) (Package, error) {
	if inSandbox() {
		return Package{}, fmt.Errorf("当前已在隔离环境中，无需再次生成")
	}
	root := boxRoot()
	if (&relayBackend{root: root}).Available() {
		return Package{}, fmt.Errorf("隔离环境正在运行，请关闭后再更新隔离包")
	}
	backend, err := os.Executable()
	if err != nil {
		return Package{}, err
	}
	mode := strings.TrimSpace(options.Source)
	if mode == "" {
		mode = "bundled"
		if options.WeChatExe != "" {
			mode = "client"
		}
		if options.Installer != "" {
			mode = "installer"
		}
	}
	if mode == "bundled" || mode == "installer" {
		installer := strings.TrimSpace(options.Installer)
		if mode == "bundled" {
			installer = bundledInstaller(backend)
		}
		if installer == "" {
			return Package{}, fmt.Errorf("请指定官方微信安装包，或将 WeChatSetup.exe 放到项目 runtime/wechat 目录")
		}
		return writeSourcePackage(root, installer, backend, sandboxExecutable() != "", true, verifyTencentInstaller)
	}
	if mode != "client" {
		return Package{}, fmt.Errorf("source 仅支持 bundled、installer 或 client")
	}
	source := strings.TrimSpace(options.WeChatExe)
	if source == "" {
		source = strings.TrimSpace(os.Getenv("CAPX_WECHAT_EXE"))
	}
	if source == "" {
		// Discover the executable even when the personal client is minimized or
		// has no visible window. This reads image paths, never account data.
		source = runningClientExecutable()
	}
	if source == "" {
		return Package{}, fmt.Errorf("请填写官方微信程序路径，或先打开已安装的微信以定位程序")
	}
	name := strings.ToLower(filepath.Base(source))
	if name != "weixin.exe" && name != "wechat.exe" {
		return Package{}, fmt.Errorf("请选择完整客户端 Weixin.exe / WeChat.exe，不能选 WeChatAppEx.exe")
	}
	return writePackage(root, source, backend, sandboxExecutable() != "")
}

func bundledInstaller(backend string) string {
	if path := strings.TrimSpace(os.Getenv("CAPX_WECHAT_INSTALLER")); path != "" {
		return path
	}
	path := filepath.Join(filepath.Dir(backend), "runtime", "wechat", "WeChatSetup.exe")
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		return path
	}
	return ""
}

func runningClientExecutable() string {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(snapshot)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if windows.Process32First(snapshot, &entry) != nil {
		return ""
	}
	for {
		name := windows.UTF16ToString(entry.ExeFile[:])
		if strings.EqualFold(name, "Weixin.exe") || strings.EqualFold(name, "WeChat.exe") {
			path, _, err := processIdentity(entry.ProcessID)
			if err == nil {
				return path
			}
		}
		if windows.Process32Next(snapshot, &entry) != nil {
			return ""
		}
	}
}
func startNativeEnvironment() error {
	if inSandbox() {
		return fmt.Errorf("当前已在 Windows 沙箱内")
	}
	if (&relayBackend{root: boxRoot()}).Available() {
		return fmt.Errorf("独立微信环境已运行")
	}
	exe := sandboxExecutable()
	if exe == "" {
		return fmt.Errorf("未检测到 Windows 沙箱，请先在 Windows 功能中启用 Windows Sandbox 并按系统提示重启")
	}
	configuration := filepath.Join(boxRoot(), "WeChat-Test.wsb")
	if _, err := os.Stat(configuration); err != nil {
		return fmt.Errorf("请先生成隔离包")
	}
	cmd := exec.Command(exe, configuration)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait()
	return nil
}
