//go:build !windows || !native_hook

package api

import (
	"net/http"
	"runtime"
)

// hookNativeAttach/Status stubs: the Go-native DLL-injection hook is Windows-only.

func (s *Server) hookNativeAttach(w http.ResponseWriter, r *http.Request) {
	writeErr(w, http.StatusNotImplemented, "原生注入 Hook 需要 Windows native_hook 构建及自行编译的 DLL；默认构建请用 Frida")
}

func (s *Server) hookNativeStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"os": runtime.GOOS, "listening": false, "available": false})
}
