//go:build windows && native_hook

package api

// Go-native (no Frida/Python) TLS plaintext hook for Windows. capx injects a
// pure-C hook DLL (capx_hook.dll, MinHook inline hooks on SSL_write/SSL_read)
// into a target process via remote-thread LoadLibraryW; the DLL streams the
// plaintext back over a local TCP channel which we turn into HookEvents — so the
// existing /api/hook/events surface (and Hook tab) shows native captures too.

import (
	"bufio"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/hquip/capx/internal/model"
	"golang.org/x/sys/windows"
)

//go:embed native/capx_hook.dll
var capxHookDLL []byte

const nhPort = 19092

var (
	nhMu        sync.Mutex
	nhListening bool
	nhDLLPath   string
	nhSessions  = map[uint32]string{}
)

// nhEnsureListener starts the TCP receiver for injected DLLs (once).
func (s *Server) nhEnsureListener() error {
	nhMu.Lock()
	defer nhMu.Unlock()
	if nhListening {
		return nil
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", nhPort))
	if err != nil {
		return fmt.Errorf("监听 127.0.0.1:%d 失败: %w", nhPort, err)
	}
	nhListening = true
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.nhHandleConn(c)
		}
	}()
	return nil
}

// nhHandleConn parses framed plaintext from one injected DLL and records events.
func (s *Server) nhHandleConn(c net.Conn) {
	defer c.Close()
	br := bufio.NewReaderSize(c, 64<<10)
	hdr := make([]byte, 5)
	var pid uint32
	for {
		if _, err := io.ReadFull(br, hdr); err != nil {
			return
		}
		typ := hdr[0]
		n := binary.LittleEndian.Uint32(hdr[1:5])
		if n > 16<<20 {
			return
		}
		payload := make([]byte, n)
		if n > 0 {
			if _, err := io.ReadFull(br, payload); err != nil {
				return
			}
		}
		switch typ {
		case 'H':
			parts := strings.SplitN(string(payload), "\t", 2)
			if len(parts) >= 1 {
				if v, err := strconv.Atoi(strings.TrimSpace(parts[0])); err == nil {
					pid = uint32(v)
				}
			}
			name := ""
			if len(parts) > 1 {
				name = parts[1]
			}
			nhMu.Lock()
			nhSessions[pid] = name
			nhMu.Unlock()
		case 'W', 'R':
			dir, fn := "send", "SSL_write"
			if typ == 'R' {
				dir, fn = "recv", "SSL_read"
			}
			s.st.AddHookEvent(&model.HookEvent{
				PID: pid, TS: time.Now(), Func: fn, Dir: dir,
				Len: int(n), Data: nhPreview(payload),
			})
		}
	}
}

func nhPreview(b []byte) string {
	const max = 16384
	if len(b) > max {
		b = b[:max]
	}
	if utf8.Valid(b) {
		return string(b)
	}
	return hex.EncodeToString(b)
}

// nhInject writes the embedded DLL to disk (once) and LoadLibrary-injects it
// into the target pid via a remote thread.
func (s *Server) nhInject(pid uint32) error {
	nhMu.Lock()
	if nhDLLPath == "" {
		p := filepath.Join(os.TempDir(), "capx_hook.dll")
		if err := os.WriteFile(p, capxHookDLL, 0o644); err != nil {
			nhMu.Unlock()
			return fmt.Errorf("写出 DLL 失败: %w", err)
		}
		nhDLLPath = p
	}
	dll := nhDLLPath
	nhMu.Unlock()

	h, err := windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d) 失败: %w（需管理员且与目标同架构 x64）", pid, err)
	}
	defer windows.CloseHandle(h)

	pathU16, err := windows.UTF16FromString(dll)
	if err != nil {
		return err
	}
	sz := uintptr(len(pathU16) * 2)
	k32 := windows.NewLazySystemDLL("kernel32.dll")
	virtualAllocEx := k32.NewProc("VirtualAllocEx")
	loadLib := k32.NewProc("LoadLibraryW")
	createRemoteThread := k32.NewProc("CreateRemoteThread")

	remote, _, allocErr := virtualAllocEx.Call(uintptr(h), 0, sz, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if remote == 0 {
		return fmt.Errorf("VirtualAllocEx 失败: %v", allocErr)
	}
	var written uintptr
	if err := windows.WriteProcessMemory(h, remote, (*byte)(unsafe.Pointer(&pathU16[0])), sz, &written); err != nil {
		return fmt.Errorf("WriteProcessMemory 失败: %w", err)
	}
	hThread, _, callErr := createRemoteThread.Call(uintptr(h), 0, 0, loadLib.Addr(), remote, 0, 0)
	if hThread == 0 {
		return fmt.Errorf("CreateRemoteThread 失败: %v", callErr)
	}
	th := windows.Handle(hThread)
	_, _ = windows.WaitForSingleObject(th, 10000)
	windows.CloseHandle(th)
	return nil
}

func (s *Server) hookNativeStatus(w http.ResponseWriter, r *http.Request) {
	nhMu.Lock()
	listening := nhListening
	sess := make([]map[string]any, 0, len(nhSessions))
	for pid, name := range nhSessions {
		sess = append(sess, map[string]any{"pid": pid, "name": name})
	}
	nhMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"os": "windows", "listening": listening, "port": nhPort, "sessions": sess})
}

func (s *Server) hookNativeAttach(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PID uint32 `json:"pid"`
	}
	if err := decodeBody(r, &req); err != nil || req.PID == 0 {
		writeErr(w, http.StatusBadRequest, "缺少 pid")
		return
	}
	if err := s.nhEnsureListener(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.nhInject(req.PID); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"attached": req.PID, "port": nhPort, "note": "已注入；目标用 OpenSSL/BoringSSL 时会在事件里出现明文"})
}
