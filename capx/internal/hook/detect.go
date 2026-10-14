package hook

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/hquip/capx/internal/backgroundprocess"
)

func exeDir() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	p, err = filepath.EvalSymlinks(p)
	if err != nil {
		return filepath.Dir(os.Args[0])
	}
	return filepath.Dir(p)
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func lookFile(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if fileExists(p) {
		return p
	}
	if lp, err := exec.LookPath(p); err == nil {
		return lp
	}
	return ""
}

func bundledFridaDir() string {
	dir := exeDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "runtime", "frida")
}

func detectFridaCLI() string {
	if p := lookFile(os.Getenv("CAPX_FRIDA")); p != "" {
		return p
	}
	dir := bundledFridaDir()
	if dir != "" {
		names := []string{"frida.exe", "frida"}
		if runtime.GOOS != "windows" {
			names = []string{"frida", "frida-inject"}
		}
		for _, n := range names {
			cand := filepath.Join(dir, n)
			if fileExists(cand) {
				return cand
			}
		}
	}
	for _, n := range []string{"frida", "frida.exe"} {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

// detectPython 返回一个装有 frida 绑定的 python 的真实可执行路径。
// 必须解析 sys.executable:PATH 里的版本管理器 shim(如 vsm/uv/pyenv)
// 会再包一层子进程,导致 capx 取消时杀不死真正的驱动进程、会话泄漏。
func detectPython() string {
	if p := lookFile(os.Getenv("CAPX_PYTHON")); p != "" {
		if real := resolvePythonExe(p); real != "" {
			return real
		}
		return p
	}
	for _, c := range []string{"python3", "python"} {
		p, err := exec.LookPath(c)
		if err != nil {
			continue
		}
		if real := resolvePythonExe(p); real != "" {
			return real
		}
	}
	return ""
}

// resolvePythonExe 验证 frida 绑定可用,并返回解释器真实路径;失败返回空。
func resolvePythonExe(p string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := backgroundprocess.CommandContext(ctx, p, "-c", "import frida, sys; print(sys.executable)").Output()
	if err != nil {
		return ""
	}
	real := strings.TrimSpace(string(out))
	if fileExists(real) {
		return real
	}
	return ""
}

func readBundledVersion() string {
	dir := bundledFridaDir()
	if dir == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(dir, "VERSION"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
