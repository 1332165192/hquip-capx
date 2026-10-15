// Package api exposes capx over HTTP (REST + Server-Sent Events). It mirrors
// the gRPC surface described in capx/proto/capture.proto; SSE keeps the live
// event stream dependency-free for local clients and MCP adapters.
package api

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hquip/capx/internal/correlate"
	"github.com/hquip/capx/internal/decode"
	"github.com/hquip/capx/internal/dnslog"
	"github.com/hquip/capx/internal/hae"
	"github.com/hquip/capx/internal/hook"
	"github.com/hquip/capx/internal/inline"
	"github.com/hquip/capx/internal/memscan"
	"github.com/hquip/capx/internal/mobile"
	"github.com/hquip/capx/internal/mobilevpn"
	"github.com/hquip/capx/internal/model"
	"github.com/hquip/capx/internal/proxy"
	"github.com/hquip/capx/internal/script"
	"github.com/hquip/capx/internal/setup"
	"github.com/hquip/capx/internal/sniffer"
	"github.com/hquip/capx/internal/spoof"
	"github.com/hquip/capx/internal/store"
	"github.com/hquip/capx/internal/ui"
	"github.com/hquip/capx/internal/wxauto"
	"github.com/hquip/capx/internal/wxhook"
)

// Server is the capx HTTP API.
type Server struct {
	st         *store.Store
	snif       sniffer.Sniffer
	scanner    memscan.Scanner
	proxy      *proxy.Proxy
	hook       *hook.Manager
	inline     *inline.Manager
	corr       *correlate.Engine
	script     *script.Engine
	dnslog     *dnslog.Client
	spoof      *spoof.Manager
	wxhook     *wxhook.Manager
	wxauto     *wxauto.Automation
	wxctrl     *wxauto.Controller
	wxdesk     wxDesktop
	mobile     *mobile.Controller
	ios        *mobile.IOSController
	iosPrepare *mobile.IOSPrepare
	mobileVPN  *mobilevpn.Gateway
	hae        *hae.Engine
	guard      *guard
	oob        *oobCatcher

	mu       sync.Mutex
	captures map[string]context.CancelFunc
	sessions map[string]memscan.Session
	freezes  map[string]*memFreezer
	ext      map[string]*memExt
	addrs    *addrList
	patches  *patchStore
	seq      int

	runtimeInstanceID    string
	runtimeGeneration    string
	runtimeShutdown      func()
	shutdownOnce         sync.Once
	wxCaptureMu          sync.Mutex
	wxCaptureOwnProxy    bool
	wxCaptureOwnBridge   bool
	wxCaptureOwnRedirect bool
	wxCaptureMode        string
	wxCaptureUpstream    string
	wxCaptureEngine      wxCaptureEngine
	wxSystemProxy        func() (setup.SystemProxyConfig, error)

	ifaceCache    []sniffer.Device
	ifaceCacheAt  time.Time
	ifaceScanDone chan struct{}
	ifaceScanErr  error
}

// New builds an API server over the given store and backends. The MITM proxy
// is optional (nil disables the proxy/repeater endpoints' live behavior).
func New(st *store.Store, snif sniffer.Sniffer, scanner memscan.Scanner, px *proxy.Proxy, hk *hook.Manager, il *inline.Manager, sc *script.Engine, dl *dnslog.Client, sp *spoof.Manager) *Server {
	srv := &Server{
		st:       st,
		snif:     snif,
		scanner:  scanner,
		proxy:    px,
		hook:     hk,
		inline:   il,
		corr:     correlate.New(st),
		script:   sc,
		dnslog:   dl,
		spoof:    sp,
		hae:      hae.New(),
		guard:    newGuard(),
		oob:      newOOBCatcher(),
		captures: make(map[string]context.CancelFunc),
		sessions: make(map[string]memscan.Session),
		freezes:  make(map[string]*memFreezer),
		ext:      make(map[string]*memExt),
		addrs:    newAddrList(),
		patches:  newPatchStore(),
	}
	// Let Lua scripts drive the live memory engine via capx.mem.*.
	if sc != nil {
		sc.SetMem(srv)
	}
	// Route TLS key-log lines dumped by hook agents into the store.
	if hk != nil {
		hk.SetKeylogSink(func(line string) { st.AddKeylogLine(line) })
	}
	return srv
}

// SetWxhook wires the WeChat mini-program DevTools bridge and deterministic
// page operator used by the automation API.
func (s *Server) SetWxhook(m *wxhook.Manager) {
	s.wxhook = m
	s.wxCaptureEngine = m
	if m == nil {
		s.wxCaptureEngine = nil
		s.wxctrl, s.wxauto = nil, nil
		return
	}
	s.wxctrl = wxauto.NewController(m.CDPCall)
	s.wxauto = wxauto.NewAutomation(s.wxctrl, s.st.SnapshotHTTPTx)
}

// SetMobile wires Android capture and initializes the iOS WDA controller for
// the shared /api/mobile/* endpoints. Passing nil disables Android only.
func (s *Server) SetMobile(m *mobile.Controller) {
	s.mobile = m
	s.ios = mobile.NewIOS()
	s.iosPrepare = mobile.NewIOSPrepare(s.ios)
}

func (s *Server) SetMobileVPN(v *mobilevpn.Gateway) {
	s.mobileVPN = v
	if v != nil {
		v.SetOutboundGuard(func(network, address string) error {
			if s.proxy != nil && s.proxy.UpstreamConfig().Enabled {
				return fmt.Errorf("generic VPN %s forwarding is blocked by the selected HTTP secondary route", network)
			}
			return nil
		})
	}
}

// SetRuntimeIdentity configures the optional identity exposed by /health.
func (s *Server) SetRuntimeIdentity(instanceID, generation string) {
	s.mu.Lock()
	s.runtimeInstanceID = instanceID
	s.runtimeGeneration = generation
	s.mu.Unlock()
}

// SetRuntimeShutdown configures the graceful-shutdown callback used by the
// authenticated runtime lifecycle endpoint.
func (s *Server) SetRuntimeShutdown(shutdown func()) {
	s.mu.Lock()
	s.runtimeShutdown = shutdown
	s.mu.Unlock()
}

// Handler returns the HTTP router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("POST /api/runtime/shutdown", s.runtimeShutdownHandler)
	mux.HandleFunc("GET /api/ifaces", s.listIfaces)
	mux.HandleFunc("GET /api/captures", s.listCaptures)
	mux.HandleFunc("POST /api/captures", s.startCapture)
	mux.HandleFunc("POST /api/captures/{id}/stop", s.stopCapture)
	mux.HandleFunc("GET /api/flows", s.listFlows)
	mux.HandleFunc("GET /api/packets", s.listPackets)
	mux.HandleFunc("GET /api/export/pcap", s.exportPCAP)
	mux.HandleFunc("GET /api/http", s.listHTTP)
	mux.HandleFunc("DELETE /api/history", s.clearHistory)
	mux.HandleFunc("GET /api/http/export", s.exportHTTPHar)
	mux.HandleFunc("GET /api/http/{id}", s.getHTTP)
	mux.HandleFunc("POST /api/http/{id}/decrypt", s.httpDecrypt)
	mux.HandleFunc("GET /api/http/{id}/curl", s.exportHTTPCurl)
	mux.HandleFunc("GET /api/ws", s.listWS)
	mux.HandleFunc("GET /api/ws/page", s.wsPage)
	mux.HandleFunc("GET /api/ws/detail/{id}", s.wsDetail)
	mux.HandleFunc("GET /api/stream", s.stream)
	// L7 MITM proxy (M4): control, scope, interception, CA download.
	mux.HandleFunc("GET /api/proxy/status", s.proxyStatus)
	mux.HandleFunc("GET /api/proxy/lan", s.proxyLANStatus)
	mux.HandleFunc("POST /api/proxy/lan/start", s.proxyLANStart)
	mux.HandleFunc("POST /api/proxy/lan/stop", s.proxyLANStop)
	mux.HandleFunc("GET /api/mobile/vpn/status", s.mobileVPNStatus)
	mux.HandleFunc("POST /api/mobile/vpn/start", s.mobileVPNStart)
	mux.HandleFunc("POST /api/mobile/vpn/stop", s.mobileVPNStop)
	mux.HandleFunc("GET /api/mobile/vpn/config", s.mobileVPNConfig)
	mux.HandleFunc("GET /api/proxy/upstream", s.proxyUpstream)
	mux.HandleFunc("POST /api/proxy/upstream", s.proxyUpstream)
	mux.HandleFunc("POST /api/proxy/start", s.proxyStart)
	mux.HandleFunc("POST /api/proxy/stop", s.proxyStop)
	mux.HandleFunc("GET /api/proxy/transparent", s.proxyTransparentStatus)
	mux.HandleFunc("POST /api/proxy/transparent/start", s.proxyTransparentStart)
	mux.HandleFunc("POST /api/proxy/transparent/stop", s.proxyTransparentStop)
	mux.HandleFunc("POST /api/proxy/intercept", s.proxyInterceptToggle)
	mux.HandleFunc("POST /api/proxy/http2", s.proxyHTTP2Toggle)
	mux.HandleFunc("POST /api/proxy/body-capture", s.proxyBodyCapture)
	mux.HandleFunc("GET /api/proxy/intercept/queue", s.proxyInterceptQueue)
	mux.HandleFunc("POST /api/proxy/intercept/decide", s.proxyInterceptDecide)
	mux.HandleFunc("GET /api/proxy/intercept/rules", s.proxyInterceptRules)
	mux.HandleFunc("POST /api/proxy/intercept/rules", s.proxyInterceptRulesSet)
	mux.HandleFunc("GET /api/proxy/ws/conns", s.proxyWSConns)
	mux.HandleFunc("POST /api/proxy/ws/replay", s.proxyWSReplay)
	mux.HandleFunc("GET /api/proxy/ca", s.proxyCA)
	mux.HandleFunc("GET /capx-ca.pem", s.proxyCA)
	mux.HandleFunc("GET /api/setup", s.setupStatus)
	mux.HandleFunc("POST /api/setup/ca/install", s.setupInstallCA)
	mux.HandleFunc("POST /api/setup/ca/uninstall", s.setupUninstallCA)
	mux.HandleFunc("POST /api/setup/sysproxy/on", s.setupSysProxyOn)
	mux.HandleFunc("POST /api/setup/sysproxy/off", s.setupSysProxyOff)
	mux.HandleFunc("POST /api/setup/http3/off", s.setupDisableHTTP3)
	mux.HandleFunc("POST /api/setup/browser", s.setupLaunchBrowser)
	mux.HandleFunc("POST /api/setup/prepare", s.setupPrepare)
	mux.HandleFunc("POST /api/setup/browsers/restart", s.setupRestartBrowsers)
	mux.HandleFunc("GET /api/scope", s.getScope)
	mux.HandleFunc("POST /api/scope", s.setScope)
	mux.HandleFunc("GET /api/sitemap", s.siteMap)
	mux.HandleFunc("POST /api/repeater/send", s.repeaterSend)
	mux.HandleFunc("POST /api/intruder/run", s.intruderRun)
	mux.HandleFunc("POST /api/turbo/run", s.turboRun)
	mux.HandleFunc("POST /api/intruder/export", s.exportIntruderCSV)
	mux.HandleFunc("GET /api/session", s.sessionGet)
	mux.HandleFunc("POST /api/session", s.sessionSet)
	mux.HandleFunc("POST /api/session/run", s.sessionRunMacro)
	mux.HandleFunc("POST /api/session/ws/run", s.sessionRunWSMacro)
	mux.HandleFunc("GET /api/mem/processes", s.memProcesses)
	mux.HandleFunc("POST /api/mem/open", s.memOpen)
	mux.HandleFunc("POST /api/mem/{sid}/first", s.memFirst)
	mux.HandleFunc("POST /api/mem/{sid}/snapshot", s.memSnapshot)
	mux.HandleFunc("POST /api/mem/{sid}/next", s.memNext)
	mux.HandleFunc("POST /api/mem/{sid}/string", s.memString)
	mux.HandleFunc("POST /api/mem/{sid}/round", s.memRound)
	mux.HandleFunc("POST /api/mem/{sid}/opts", s.memOpts)
	mux.HandleFunc("POST /api/mem/{sid}/aob", s.memAOB)
	mux.HandleFunc("GET /api/mem/{sid}/results", s.memResults)
	mux.HandleFunc("POST /api/mem/{sid}/ptrscan", s.memPtrScan)
	mux.HandleFunc("GET /api/mem/{sid}/ptrpaths", s.memPtrPaths)
	mux.HandleFunc("POST /api/mem/{sid}/ptrfilter", s.memPtrFilter)
	mux.HandleFunc("GET /api/mem/{sid}/ptrmap", s.memPtrMapExport)
	mux.HandleFunc("POST /api/mem/{sid}/ptrmap/check", s.memPtrMapCheck)
	mux.HandleFunc("POST /api/mem/{sid}/write", s.memWrite)
	mux.HandleFunc("POST /api/mem/{sid}/patch", s.memPatch)
	mux.HandleFunc("POST /api/mem/{sid}/alloc", s.memAlloc)
	mux.HandleFunc("POST /api/mem/{sid}/assemble", s.memAssemble)
	mux.HandleFunc("POST /api/mem/{sid}/freeze", s.memFreeze)
	mux.HandleFunc("POST /api/mem/{sid}/unfreeze", s.memUnfreeze)
	mux.HandleFunc("GET /api/mem/{sid}/freezes", s.memFreezes)
	mux.HandleFunc("POST /api/mem/{sid}/close", s.memClose)
	mux.HandleFunc("GET /api/mem/addrlist", s.memAddrList)
	mux.HandleFunc("POST /api/mem/addrlist", s.memAddrAdd)
	mux.HandleFunc("DELETE /api/mem/addrlist/{id}", s.memAddrDel)
	mux.HandleFunc("POST /api/mem/addrlist/{id}/freeze", s.memAddrFreeze)
	mux.HandleFunc("POST /api/mem/addrlist/{id}/unfreeze", s.memAddrUnfreeze)
	mux.HandleFunc("GET /api/mem/{sid}/modules", s.memModules)
	mux.HandleFunc("POST /api/mem/{sid}/resolve", s.memResolve)
	mux.HandleFunc("GET /api/mem/{sid}/regions", s.memRegions)
	mux.HandleFunc("GET /api/mem/{sid}/view", s.memView)
	mux.HandleFunc("GET /api/mem/{sid}/disasm", s.memDisasm)
	mux.HandleFunc("POST /api/mem/{sid}/savefirst", s.memSaveFirst)
	mux.HandleFunc("POST /api/mem/{sid}/allfirst", s.memAllFirst)
	mux.HandleFunc("POST /api/mem/{sid}/groupscan", s.memGroupScan)
	mux.HandleFunc("POST /api/mem/{sid}/binscan", s.memBinScan)
	mux.HandleFunc("POST /api/mem/{sid}/undo", s.memUndo)
	mux.HandleFunc("GET /api/mem/{sid}/history", s.memHistory)
	mux.HandleFunc("POST /api/mem/{sid}/dissect", s.memDissect)
	mux.HandleFunc("GET /api/mem/table/export", s.memTableExport)
	mux.HandleFunc("POST /api/mem/table/import", s.memTableImport)
	mux.HandleFunc("POST /api/mem/{sid}/watch", s.memWatchStart)
	mux.HandleFunc("GET /api/mem/{sid}/watch", s.memWatchStatus)
	mux.HandleFunc("POST /api/mem/{sid}/unwatch", s.memWatchStop)
	mux.HandleFunc("GET /api/mem/{sid}/debug/disasm", s.memDebugDisasm)
	mux.HandleFunc("GET /api/mem/{sid}/debug/stack", s.memDebugStack)
	mux.HandleFunc("POST /api/mem/{sid}/ptrmap/save", s.memPtrMapSave)
	mux.HandleFunc("POST /api/mem/{sid}/reattach", s.memReattach)
	mux.HandleFunc("GET /api/mem/{sid}/link/http", s.memLinkHTTP)
	// In-process hooking (M5): Frida-driven TLS plaintext extraction.
	mux.HandleFunc("GET /api/hook/status", s.hookStatus)
	mux.HandleFunc("GET /api/hook/procs", s.hookProcs)
	mux.HandleFunc("GET /api/hook/sessions", s.hookSessions)
	mux.HandleFunc("POST /api/hook/attach", s.hookAttach)
	mux.HandleFunc("POST /api/hook/detach", s.hookDetach)
	mux.HandleFunc("GET /api/hook/events", s.hookEvents)
	mux.HandleFunc("POST /api/hook/native/attach", s.hookNativeAttach)
	mux.HandleFunc("GET /api/hook/native/status", s.hookNativeStatus)
	mux.HandleFunc("GET /api/hook/agents", s.hookAgentsList)
	mux.HandleFunc("POST /api/hook/agents", s.hookAgentUpload)
	mux.HandleFunc("DELETE /api/hook/agents/{name}", s.hookAgentDelete)
	// TLS key log (SSLKEYLOGFILE): collect session secrets to decrypt captured
	// TLS without MITM, and export them for Wireshark.
	mux.HandleFunc("GET /api/keylog", s.keylogStatus)
	mux.HandleFunc("POST /api/keylog", s.keylogAdd)
	mux.HandleFunc("GET /api/keylog/export", s.keylogExport)
	// Schema-less body decoders: protobuf / gRPC frames.
	mux.HandleFunc("POST /api/decode/protobuf", s.decodeProtobuf)
	mux.HandleFunc("POST /api/decode/grpc", s.decodeGRPC)
	mux.HandleFunc("POST /api/decode/packet", s.decodePacket)
	mux.HandleFunc("POST /api/decode/quic", s.decodeQUIC)
	mux.HandleFunc("POST /api/crypto/codec", s.cryptoCodec)
	mux.HandleFunc("POST /api/crypto/digest", s.cryptoDigest)
	// Passive issue detection over captured HTTP history.
	mux.HandleFunc("GET /api/scan/passive", s.scanPassive)
	mux.HandleFunc("GET /api/scan/passive/{id}", s.scanPassiveTx)
	// HaE-compatible highlight/extract ruleset (load HaE's Rules.yml).
	mux.HandleFunc("GET /api/hae", s.haeStatus)
	mux.HandleFunc("GET /api/hae/rules", s.haeRulesList)
	mux.HandleFunc("POST /api/hae/rules", s.haeRulesUpload)
	mux.HandleFunc("GET /api/hae/scan", s.haeScan)
	mux.HandleFunc("GET /api/hae/tx/{id}", s.haeTx)
	// Collaborator-lite: HTTP OOB callback catcher (SSRF/XXE/blind RCE).
	mux.HandleFunc("POST /api/oob/start", s.oobStart)
	mux.HandleFunc("POST /api/oob/stop", s.oobStop)
	mux.HandleFunc("GET /api/oob/status", s.oobStatus)
	mux.HandleFunc("GET /api/oob/hits", s.oobHits)
	mux.HandleFunc("POST /api/oob/payload", s.oobPayload)
	// WeChat mini-program (.wxapkg) unpack/decrypt.
	mux.HandleFunc("GET /api/wxapkg/scan", s.wxapkgScan)
	mux.HandleFunc("GET /api/wxapkg/rules", s.wxapkgRules)
	mux.HandleFunc("POST /api/wxapkg/unpack", s.wxapkgUnpack)
	mux.HandleFunc("GET /api/wxapkg/read", s.wxapkgRead)
	// CaA-style collector: extract params/paths/files/values into fuzz wordlists.
	mux.HandleFunc("GET /api/collect", s.collectScan)
	mux.HandleFunc("GET /api/collect/wordlist", s.collectWordlist)
	// Project bundle: save/restore the whole working state.
	mux.HandleFunc("GET /api/project/export", s.exportProject)
	mux.HandleFunc("POST /api/project/import", s.importProject)
	// ARP spoofing for LAN MITM positioning (active, needs -tags pcap + admin).
	mux.HandleFunc("GET /api/spoof/arp", s.spoofStatus)
	mux.HandleFunc("POST /api/spoof/arp/start", s.spoofStart)
	mux.HandleFunc("POST /api/spoof/arp/stop", s.spoofStop)
	// Inline Match&Replace rules (M6): rewrite/block proxied traffic.
	mux.HandleFunc("GET /api/rules", s.rulesList)
	mux.HandleFunc("POST /api/rules", s.rulesAdd)
	mux.HandleFunc("DELETE /api/rules/{id}", s.rulesDelete)
	mux.HandleFunc("GET /api/wsrules", s.wsRulesList)
	mux.HandleFunc("POST /api/wsrules", s.wsRulesAdd)
	mux.HandleFunc("DELETE /api/wsrules/{id}", s.wsRulesDelete)
	// Raw-packet inline modification (M6): WinDivert/NFQUEUE backend.
	mux.HandleFunc("GET /api/inline/status", s.inlineStatus)
	mux.HandleFunc("POST /api/inline/start", s.inlineStart)
	mux.HandleFunc("POST /api/inline/stop", s.inlineStop)
	mux.HandleFunc("POST /api/inline/send", s.inlineSend)
	mux.HandleFunc("GET /api/inline/rules", s.inlineRulesList)
	mux.HandleFunc("POST /api/inline/rules", s.inlineRulesAdd)
	mux.HandleFunc("DELETE /api/inline/rules/{id}", s.inlineRulesDelete)
	// WeChat mini-program DevTools (F12) force-open (ported from e0e1-wx/wx-hook).
	mux.HandleFunc("GET /api/wxhook/status", s.wxhookStatus)
	mux.HandleFunc("GET /api/wxhook/procs", s.wxhookProcs)
	mux.HandleFunc("POST /api/wxhook/enable", s.wxhookEnable)
	mux.HandleFunc("POST /api/wxhook/disable", s.wxhookDisable)
	mux.HandleFunc("POST /api/wxhook/capture/start", s.wxhookCaptureStart)
	mux.HandleFunc("POST /api/wxhook/capture/stop", s.wxhookCaptureStop)
	mux.HandleFunc("GET /api/wxhook/cdp/status", s.wxhookCDPStatus)
	mux.HandleFunc("GET /api/wxhook/cdp/targets", s.wxhookCDPTargets)
	mux.HandleFunc("POST /api/wxhook/cdp/start", s.wxhookCDPStart)
	mux.HandleFunc("POST /api/wxhook/cdp/stop", s.wxhookCDPStop)
	mux.HandleFunc("POST /api/wxhook/cdp/eval", s.wxhookCDPEval)
	mux.HandleFunc("POST /api/wxhook/cdp/call", s.wxhookCDPCall)
	mux.HandleFunc("GET /api/wxhook/auto/snapshot", s.wxautoSnapshot)
	mux.HandleFunc("GET /api/wxhook/auto/screenshot", s.wxautoScreenshot)
	mux.HandleFunc("POST /api/wxhook/auto/click", s.wxautoClick)
	mux.HandleFunc("POST /api/wxhook/auto/input", s.wxautoInput)
	mux.HandleFunc("POST /api/wxhook/auto/scroll", s.wxautoScroll)
	mux.HandleFunc("POST /api/wxhook/auto/back", s.wxautoBack)
	mux.HandleFunc("POST /api/wxhook/auto/start", s.wxautoStart)
	mux.HandleFunc("POST /api/wxhook/auto/stop", s.wxautoStop)
	mux.HandleFunc("GET /api/wxhook/auto/status", s.wxautoStatus)
	mux.HandleFunc("GET /api/wxdesk/windows", s.wxdeskWindows)
	mux.HandleFunc("GET /api/wxdesk/environment", s.wxdeskEnvironment)
	mux.HandleFunc("POST /api/wxdesk/prepare", s.wxdeskPrepare)
	mux.HandleFunc("POST /api/wxdesk/start-environment", s.wxdeskStartEnvironment)
	mux.HandleFunc("POST /api/wxdesk/launch", s.wxdeskLaunch)
	mux.HandleFunc("GET /api/wxdesk/screenshot", s.wxdeskScreenshot)
	mux.HandleFunc("POST /api/wxdesk/{action}", s.wxdeskAction)
	mux.HandleFunc("GET /api/mobile/devices", s.mobileDevices)
	mux.HandleFunc("POST /api/mobile/ios/connect", s.mobileIOSConnect)
	mux.HandleFunc("POST /api/mobile/ios/disconnect", s.mobileIOSDisconnect)
	mux.HandleFunc("GET /api/mobile/ios/setup", s.mobileIOSSetup)
	mux.HandleFunc("GET /api/mobile/ios/setup/status", s.mobileIOSPrepareStatus)
	mux.HandleFunc("POST /api/mobile/ios/prepare", s.mobileIOSPrepare)
	mux.HandleFunc("POST /api/mobile/ios/prepare/stop", s.mobileIOSPrepareStop)
	mux.HandleFunc("GET /api/mobile/status", s.mobileStatus)
	mux.HandleFunc("POST /api/mobile/use", s.mobileUse)
	mux.HandleFunc("POST /api/mobile/capture/start", s.mobileCaptureStart)
	mux.HandleFunc("POST /api/mobile/capture/stop", s.mobileCaptureStop)
	mux.HandleFunc("POST /api/mobile/ca", s.mobileCA)
	mux.HandleFunc("GET /api/mobile/snapshot", s.mobileSnapshot)
	mux.HandleFunc("GET /api/mobile/screenshot", s.mobileScreenshot)
	mux.HandleFunc("POST /api/mobile/tap", s.mobileTap)
	mux.HandleFunc("POST /api/mobile/input", s.mobileInput)
	mux.HandleFunc("POST /api/mobile/swipe", s.mobileSwipe)
	mux.HandleFunc("POST /api/mobile/key", s.mobileKey)
	mux.HandleFunc("POST /api/mobile/back", s.mobileBack)
	mux.HandleFunc("POST /api/mobile/home", s.mobileHome)
	mux.HandleFunc("POST /api/mobile/launch", s.mobileLaunch)
	mux.HandleFunc("GET /api/mobile/foreground", s.mobileForeground)
	// Security policy + audit: toggle active mode, inspect the audit ring.
	mux.HandleFunc("GET /api/policy", s.policyGet)
	mux.HandleFunc("POST /api/policy", s.policySet)
	mux.HandleFunc("GET /api/audit", s.auditList)
	// Cross-layer correlation (M7): flow <-> http/ws <-> hook timelines.
	mux.HandleFunc("GET /api/correlate", s.correlate)
	// Lua scripting layer (M7): event-driven plugins.
	mux.HandleFunc("GET /api/scripts", s.scriptsList)
	mux.HandleFunc("POST /api/scripts", s.scriptsAdd)
	mux.HandleFunc("DELETE /api/scripts/{id}", s.scriptsDelete)
	mux.HandleFunc("GET /api/scripts/{id}/log", s.scriptsLog)
	// DNSLog out-of-band (OOB) integration: Collaborator-style blind-vuln
	// detection via the DNSLog platform (request subdomains, poll for hits).
	mux.HandleFunc("GET /api/dnslog/status", s.dnslogStatus)
	mux.HandleFunc("GET /api/dnslog/logs", s.dnslogLogs)
	mux.HandleFunc("POST /api/dnslog/config", s.dnslogConfig)
	mux.HandleFunc("GET /api/dnslog/payloads", s.dnslogPayloads)
	mux.HandleFunc("POST /api/dnslog/payloads", s.dnslogNewPayload)
	mux.HandleFunc("DELETE /api/dnslog/payloads/{subdomain}", s.dnslogForget)
	mux.HandleFunc("GET /api/dnslog/check", s.dnslogCheck)
	mux.HandleFunc("POST /api/dnslog/poll", s.dnslogPoll)
	// Web console (Burp-like desktop UI) served at "/". Wrapped so it drops the
	// same-site auth cookie the in-browser console uses to reach /api/*.
	mux.Handle("GET /", s.guard.setAuthCookie(ui.Handler()))
	// Apply the security guard (host/origin/token checks, active-mode gating,
	// write rate limiting) to every route.
	return s.guard.wrap(mux)
}

// SetActive toggles the active-mode policy switch (used by the -allow-active
// startup flag).
func (s *Server) SetActive(on bool) { s.guard.SetActive(on, "startup") }

// AuthToken returns the API bearer token (for startup logging).
func (s *Server) AuthToken() string { return s.guard.Token() }

// AuthEnabled reports whether token auth is enforced.
func (s *Server) AuthEnabled() bool { return s.guard.AuthEnabled() }

// ActiveAllowed reports whether mutating "active" primitives are permitted.
func (s *Server) ActiveAllowed() bool { return s.guard.ActiveAllowed() }

// policyGet reports the current security policy (active mode + auth state).
func (s *Server) policyGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"active_allowed": s.guard.ActiveAllowed(),
		"auth_enabled":   s.guard.AuthEnabled(),
	})
}

// policySet toggles the active-mode switch. This is the documented explicit
// opt-in for mutating primitives; the change is audited.
func (s *Server) policySet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AllowActive bool `json:"allow_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	s.guard.SetActive(req.AllowActive, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"active_allowed": s.guard.ActiveAllowed()})
}

// auditList returns the recent security audit entries (active-op attempts and
// policy changes).
func (s *Server) auditList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.guard.recentAudit())
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	instanceID := s.runtimeInstanceID
	generation := s.runtimeGeneration
	runningCaptures := len(s.captures)
	s.mu.Unlock()

	response := map[string]any{
		"status":         "ok",
		"sniffer":        s.snif.Backend(),
		"memscan_ffi":    s.scanner.Available(),
		"memscan":        s.scanner.Available(),
		"hook":           s.hookBackend(),
		"inline":         s.inlineBackend(),
		"time":           time.Now().UTC(),
		"recent_events":  len(s.st.Recent()),
		"running_captrs": runningCaptures,
	}
	if instanceID != "" || generation != "" {
		identity := map[string]string{}
		if instanceID != "" {
			identity["instance_id"] = instanceID
		}
		if generation != "" {
			identity["generation"] = generation
		}
		response["identity"] = identity
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) runtimeShutdownHandler(w http.ResponseWriter, r *http.Request) {
	var fields map[string]json.RawMessage
	if r.Body != nil {
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		if err := decoder.Decode(&fields); err != nil && err != io.EOF {
			writeErr(w, http.StatusBadRequest, "invalid shutdown request")
			return
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			writeErr(w, http.StatusBadRequest, "unexpected data after shutdown request")
			return
		}
	}
	rawInstance, hasInstance := fields["expected_instance_id"]
	rawGeneration, hasGeneration := fields["expected_generation"]
	var instance, generation *string
	if hasInstance || hasGeneration {
		if !hasInstance || !hasGeneration || json.Unmarshal(rawInstance, &instance) != nil || json.Unmarshal(rawGeneration, &generation) != nil || instance == nil || generation == nil {
			writeErr(w, http.StatusBadRequest, "expected_instance_id and expected_generation must both be strings")
			return
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if hasInstance && (*instance != s.runtimeInstanceID || *generation != s.runtimeGeneration) {
		writeErr(w, http.StatusConflict, "runtime identity changed; refusing to stop replacement instance")
		return
	}
	shutdown := s.runtimeShutdown
	if shutdown == nil {
		writeErr(w, http.StatusServiceUnavailable, "runtime shutdown is not configured")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "shutting_down"})
	s.shutdownOnce.Do(func() { go shutdown() })
}

func (s *Server) listIfaces(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if !s.ifaceCacheAt.IsZero() && time.Since(s.ifaceCacheAt) < 30*time.Second {
		devs := append([]sniffer.Device(nil), s.ifaceCache...)
		s.mu.Unlock()
		if devs == nil {
			devs = []sniffer.Device{}
		}
		writeJSON(w, http.StatusOK, devs)
		return
	}
	if s.ifaceScanDone == nil {
		s.ifaceScanDone = make(chan struct{})
		done := s.ifaceScanDone
		go func() {
			var devs []sniffer.Device
			var err error
			func() {
				defer func() {
					if failure := recover(); failure != nil {
						err = fmt.Errorf("interface scan failed: %v", failure)
					}
				}()
				devs, err = s.snif.Interfaces()
			}()
			s.mu.Lock()
			s.ifaceScanErr = err
			if err == nil {
				s.ifaceCache = append([]sniffer.Device(nil), devs...)
				s.ifaceCacheAt = time.Now()
			}
			s.ifaceScanDone = nil
			close(done)
			s.mu.Unlock()
		}()
	}
	done := s.ifaceScanDone
	s.mu.Unlock()

	select {
	case <-done:
		s.mu.Lock()
		err := s.ifaceScanErr
		devs := append([]sniffer.Device(nil), s.ifaceCache...)
		s.mu.Unlock()
		if err != nil {
			status := http.StatusNotImplemented
			if errors.Is(err, os.ErrPermission) {
				status = http.StatusForbidden
			}
			writeErr(w, status, err.Error())
			return
		}
		if devs == nil {
			devs = []sniffer.Device{}
		}
		writeJSON(w, http.StatusOK, devs)
	case <-r.Context().Done():
		return
	case <-time.After(1500 * time.Millisecond):
		s.mu.Lock()
		devs := append([]sniffer.Device(nil), s.ifaceCache...)
		s.mu.Unlock()
		if len(devs) > 0 {
			writeJSON(w, http.StatusOK, devs)
			return
		}
		writeErr(w, http.StatusGatewayTimeout, "interface scan timed out; check Npcap/driver or choose an interface later")
	}
}

func (s *Server) listCaptures(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.st.ListCaptures())
}

type startReq struct {
	Iface  string `json:"iface"`
	Filter string `json:"filter"`
	Mode   string `json:"mode"`
	MaxRaw int    `json:"max_raw"`
}

func (s *Server) startCapture(w http.ResponseWriter, r *http.Request) {
	var req startReq
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	mode := model.ModePassive
	if model.CaptureMode(req.Mode) == model.ModeActive {
		mode = model.ModeActive
	}

	// Fail fast when this binary has no live sniffer so the UI does not sit
	// on a "running" session that immediately dies with capture_error.
	if s.snif.Backend() == "stub" {
		writeErr(w, http.StatusNotImplemented, sniffer.ErrNoPcap.Error())
		return
	}

	s.mu.Lock()
	s.seq++
	id := fmt.Sprintf("cap-%d", s.seq)
	for {
		if _, exists := s.st.GetCapture(id); !exists {
			break
		}
		s.seq++
		id = fmt.Sprintf("cap-%d", s.seq)
	}
	s.mu.Unlock()

	c := &model.Capture{
		ID: id, Iface: req.Iface, Filter: req.Filter, Mode: mode,
		Started: time.Now().UTC(), Running: true, Backend: s.snif.Backend(),
	}
	s.st.PutCapture(c)

	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.captures[id] = cancel
	s.mu.Unlock()

	go func() {
		err := s.snif.Run(ctx, id, sniffer.Config{
			Iface: req.Iface, Filter: req.Filter, MaxRaw: req.MaxRaw,
		}, s.st)
		now := time.Now().UTC()
		s.st.MarkCaptureStopped(id, now)
		kind := "capture_stopped"
		msg := ""
		if err != nil && ctx.Err() == nil {
			kind = "capture_error"
			msg = err.Error()
		}
		s.st.Publish(model.Event{Source: model.SourceSniffer, Kind: kind,
			Data: map[string]string{"capture": id, "error": msg}})
		s.mu.Lock()
		delete(s.captures, id)
		s.mu.Unlock()
	}()

	writeJSON(w, http.StatusOK, c)
}

func (s *Server) stopCapture(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	cancel, ok := s.captures[id]
	s.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, "capture not found or already stopped")
		return
	}
	cancel()
	writeJSON(w, http.StatusOK, map[string]string{"stopped": id})
}

func (s *Server) listFlows(w http.ResponseWriter, r *http.Request) {
	flows := s.st.ListFlows()
	// Most-recent first so ?limit= keeps the freshest flows (the full set can be
	// huge once payloads are attached; the desktop UI fetches a bounded slice).
	sort.Slice(flows, func(i, j int) bool { return flows[i].Updated.After(flows[j].Updated) })
	if ls := r.URL.Query().Get("limit"); ls != "" {
		if n, err := strconv.Atoi(ls); err == nil && n > 0 && n < len(flows) {
			flows = flows[:n]
		}
	}
	writeJSON(w, http.StatusOK, flows)
}

func (s *Server) listPackets(w http.ResponseWriter, r *http.Request) {
	captureID := r.URL.Query().Get("capture_id")
	flowID := r.URL.Query().Get("flow_id")
	limit := 200
	if ls := r.URL.Query().Get("limit"); ls != "" {
		if n, err := strconv.Atoi(ls); err == nil && n > 0 {
			limit = n
		}
	}
	packets := s.st.ListPackets(captureID)
	if flowID != "" {
		filtered := packets[:0]
		for _, p := range packets {
			if p.FlowID == flowID {
				filtered = append(filtered, p)
			}
		}
		packets = filtered
	}
	if len(packets) > 1 {
		sort.Slice(packets, func(i, j int) bool { return packets[i].TS.Before(packets[j].TS) })
	}
	if limit > 0 && len(packets) > limit {
		packets = packets[len(packets)-limit:]
	}
	type packetView struct {
		model.Packet
		RawHex string `json:"raw_hex,omitempty"`
	}
	out := make([]packetView, 0, len(packets))
	for _, p := range packets {
		v := packetView{Packet: p}
		if len(p.Raw) > 0 {
			raw := p.Raw
			if len(raw) > 256 {
				raw = raw[:256]
			}
			v.RawHex = hex.EncodeToString(raw)
			v.Raw = nil
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

// listHTTP backs the Burp-style HTTP/HTTPS history panels. The scheme query
// param ("http"|"https") selects which panel's data to return; empty returns
// all. Data is populated by the MITM proxy (M4); until then this is empty.
func (s *Server) listHTTP(w http.ResponseWriter, r *http.Request) {
	limit, offset := httpPage(r)
	query := store.HTTPQuery{Filter: httpFilterFromQuery(r), Limit: limit, Offset: offset, Summary: true}
	// Display expressions also apply BEFORE pagination and before computing the
	// total. Only metadata is loaded here; raw messages remain lazy details.
	expr := r.URL.Query().Get("filter")
	if expr != "" {
		query.Limit, query.Offset = 0, 0
	}
	txs, total, disk, err := s.st.QueryHTTPPage(query)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !disk {
		txs = s.st.FilterHTTPTx(query.Filter)
		sort.Slice(txs, func(i, j int) bool {
			ti, tj := txs[i].LastSeen, txs[j].LastSeen
			if ti.IsZero() {
				ti = txs[i].TS
			}
			if tj.IsZero() {
				tj = txs[j].TS
			}
			if ti.Equal(tj) {
				return txs[i].ID > txs[j].ID
			}
			return ti.After(tj)
		})
	}
	if expr != "" {
		f, err := decode.CompileFilter(expr)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad filter: "+err.Error())
			return
		}
		out := txs[:0]
		for _, tx := range txs {
			if f.Match(decode.FilterFields{Host: tx.Host, Method: tx.Method, URL: tx.URL, MIME: tx.MIME, Scheme: tx.Scheme, Status: tx.Status}) {
				out = append(out, tx)
			}
		}
		txs = out
	}
	if !disk || expr != "" {
		total = len(txs)
		if offset >= len(txs) {
			txs = nil
		} else {
			txs = txs[offset:]
		}
		if len(txs) > limit {
			txs = txs[:limit]
		}
	}
	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	writeHTTPSummaries(w, txs)
}

func httpPage(r *http.Request) (limit int, offset int) {
	limit = 500
	if ls := r.URL.Query().Get("limit"); ls != "" {
		if n, err := strconv.Atoi(ls); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 5000 {
		limit = 5000
	}
	if os := r.URL.Query().Get("offset"); os != "" {
		if n, err := strconv.Atoi(os); err == nil && n > 0 {
			offset = n
		}
	}
	return limit, offset
}

func writeHTTPSummaries(w http.ResponseWriter, txs []*model.HTTPTx) {
	out := make([]httpTxSummary, 0, len(txs))
	for _, tx := range txs {
		out = append(out, summarizeHTTP(tx))
	}
	writeJSON(w, http.StatusOK, out)
}

type httpTxSummary struct {
	ID            uint64            `json:"id"`
	FlowID        string            `json:"flow_id,omitempty"`
	TS            time.Time         `json:"ts"`
	LastSeen      time.Time         `json:"last_seen,omitempty"`
	Scheme        string            `json:"scheme"`
	Method        string            `json:"method"`
	Host          string            `json:"host"`
	Path          string            `json:"path"`
	URL           string            `json:"url"`
	Status        int               `json:"status"`
	RespLen       int               `json:"resp_len"`
	Proto         string            `json:"proto,omitempty"`
	MIME          string            `json:"mime,omitempty"`
	ReqHdr        map[string]string `json:"req_hdr,omitempty"`
	RespHdr       map[string]string `json:"resp_hdr,omitempty"`
	Decrypted     bool              `json:"decrypted"`
	RepeatCnt     int               `json:"repeat_count,omitempty"`
	ServerAddr    string            `json:"server_addr,omitempty"`
	CaptureMode   string            `json:"capture_mode,omitempty"`
	ClientAddr    string            `json:"client_addr,omitempty"`
	CapturePeer   string            `json:"capture_peer,omitempty"`
	ReqRawLen     int               `json:"req_raw_len,omitempty"`
	RespRawLen    int               `json:"resp_raw_len,omitempty"`
	HasDetail     bool              `json:"has_detail"`
	InScope       bool              `json:"in_scope"`
	BodyTruncated bool              `json:"body_truncated,omitempty"`
}

func summarizeHTTP(tx *model.HTTPTx) httpTxSummary {
	if tx == nil {
		return httpTxSummary{}
	}
	return httpTxSummary{
		ID: tx.ID, FlowID: tx.FlowID, TS: tx.TS, LastSeen: tx.LastSeen,
		Scheme: tx.Scheme, Method: tx.Method, Host: tx.Host, Path: tx.Path, URL: tx.URL,
		Status: tx.Status, RespLen: tx.RespLen, Proto: tx.Proto, MIME: tx.MIME,
		ReqHdr: tx.ReqHdr, RespHdr: tx.RespHdr, Decrypted: tx.Decrypted,
		RepeatCnt: tx.RepeatCnt, ServerAddr: tx.ServerAddr,
		CaptureMode: tx.CaptureMode, ClientAddr: tx.ClientAddr, CapturePeer: tx.CapturePeer,
		ReqRawLen: max(len(tx.ReqRaw), tx.ReqRawLen), RespRawLen: max(len(tx.RespRaw), tx.RespRawLen),
		HasDetail: tx.ReqRaw != "" || tx.RespRaw != "" || tx.ReqRawLen > 0 || tx.RespRawLen > 0,
		InScope:   !tx.OutOfScope, BodyTruncated: tx.BodyTruncated,
	}
}

func (s *Server) getHTTP(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad tx id")
		return
	}
	tx, ok := s.st.GetHTTPTx(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "transaction not found")
		return
	}
	writeJSON(w, http.StatusOK, tx)
}

func (s *Server) clearHistory(w http.ResponseWriter, r *http.Request) {
	counts, err := s.st.ClearHistoryAndNotify()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "clear history: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"cleared": counts,
	})
}

// httpFilterFromQuery builds a store.HTTPFilter from the request query string.
// Supported params: scheme, host, method (comma list), mime, status
// ("200"|"2xx"|"200-299"), q (free-text over URL + raw request/response).
func httpFilterFromQuery(r *http.Request) store.HTTPFilter {
	q := r.URL.Query()
	return store.HTTPFilter{
		Scheme: q.Get("scheme"),
		Host:   q.Get("host"),
		Method: q.Get("method"),
		MIME:   q.Get("mime"),
		Status: q.Get("status"),
		Query:  q.Get("q"),
		Scope:  q.Get("scope"),
	}
}

// listWS backs the WebSocket panel (frames captured on upgraded connections).
// Supported filter params: url, dir ("send"|"recv"), opcode ("text"|"binary"),
// q (free-text over the frame payload).
func (s *Server) listWS(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	writeJSON(w, http.StatusOK, s.st.FilterWS(store.WSFilter{
		URL:    q.Get("url"),
		Dir:    q.Get("dir"),
		Opcode: q.Get("opcode"),
		Query:  q.Get("q"),
	}))
}

// stream emits recent + live events as Server-Sent Events.
func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, unsub := s.st.Subscribe(512)
	defer unsub()

	for _, ev := range s.st.Recent() {
		ev.Replayed = true // annotate the copy; never mutate persisted events
		writeSSE(w, ev)
	}
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			ev.Replayed = false
			writeSSE(w, ev)
			flusher.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, ev model.Event) {
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Kind, b)
}

// ----------------------------- memory scan --------------------------------

func (s *Server) memOpen(w http.ResponseWriter, r *http.Request) {
	if !s.scanner.Available() {
		writeErr(w, http.StatusNotImplemented, "memscan engine is not available in this build/platform")
		return
	}
	var req struct {
		PID uint32 `json:"pid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	sess, err := s.scanner.Open(req.PID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	s.seq++
	sid := fmt.Sprintf("mem-%d", s.seq)
	s.sessions[sid] = sess
	s.ext[sid] = &memExt{pid: req.PID}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"session": sid})
}

func (s *Server) session(sid string) (memscan.Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sid]
	return sess, ok
}

// encodeValue renders a numeric value into little-endian bytes for the engine.
func encodeValue(vt memscan.ValueType, raw json.Number) ([]byte, error) {
	switch vt {
	case memscan.U8, memscan.I8:
		n, err := strconv.ParseInt(string(raw), 10, 64)
		if err != nil {
			return nil, err
		}
		return []byte{byte(n)}, nil
	case memscan.U16, memscan.I16:
		n, err := strconv.ParseInt(string(raw), 10, 64)
		if err != nil {
			return nil, err
		}
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, uint16(n))
		return b, nil
	case memscan.I32, memscan.U32:
		n, err := strconv.ParseInt(string(raw), 10, 64)
		if err != nil {
			return nil, err
		}
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(n))
		return b, nil
	case memscan.I64, memscan.U64:
		n, err := strconv.ParseInt(string(raw), 10, 64)
		if err != nil {
			return nil, err
		}
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, uint64(n))
		return b, nil
	case memscan.F32:
		f, err := strconv.ParseFloat(string(raw), 32)
		if err != nil {
			return nil, err
		}
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, math.Float32bits(float32(f)))
		return b, nil
	case memscan.F64:
		f, err := strconv.ParseFloat(string(raw), 64)
		if err != nil {
			return nil, err
		}
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, math.Float64bits(f))
		return b, nil
	}
	return nil, fmt.Errorf("unknown value type")
}

type scanReq struct {
	Type  memscan.ValueType `json:"type"`
	Op    memscan.Op        `json:"op"`
	Value json.Number       `json:"value"`
	// Value2 is the upper bound for the BETWEEN op (lower bound is Value).
	Value2 json.Number `json:"value2"`
	// ToFirst compares against the saved first-scan snapshot (savefirst)
	// instead of the previous scan (CE's 与首次扫描相比).
	ToFirst bool `json:"to_first"`
}

func (s *Server) memFirst(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.session(r.PathValue("sid"))
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	var req scanReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	val, err := encodeValue(req.Type, req.Value)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	n, err := sess.FirstScan(req.Type, val)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.extFor(r.PathValue("sid")).resetGo()
	s.recordHist(r.PathValue("sid"), scanHistEntry{
		Action: "first", Type: typeName(req.Type), Value: string(req.Value), Hits: n,
	})
	s.publishScanHits(r.PathValue("sid"), sess, typeName(req.Type), string(req.Value))
	writeJSON(w, http.StatusOK, map[string]int{"hits": n})
}

// memSnapshot captures a baseline of writable memory for an unknown-initial-
// value scan; the client then narrows with memNext using a delta op.
func (s *Server) memSnapshot(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.session(r.PathValue("sid"))
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	var req scanReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	n, err := sess.Snapshot(req.Type)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.extFor(r.PathValue("sid")).resetGo()
	writeJSON(w, http.StatusOK, map[string]int{"bytes": n})
}

func (s *Server) memNext(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	sess, ok := s.session(sid)
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	var req scanReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	// Go-layer next scan: compare-to-first, or any next once the Go side owns
	// the hit list (after a previous compare-to-first).
	e := s.extFor(sid)
	e.mu.Lock()
	goOwned := e.goHits != nil
	e.mu.Unlock()
	if req.ToFirst || goOwned {
		n, err := s.goNextScan(sid, sess, req, req.ToFirst)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.recordHist(sid, scanHistEntry{
			Action: "next", Type: typeName(req.Type), Op: opName(req.Op),
			Value: string(req.Value), Hits: n,
		})
		s.publishScanHits(sid, sess, typeName(req.Type), string(req.Value))
		writeJSON(w, http.StatusOK, map[string]int{"hits": n})
		return
	}
	var val []byte
	if req.Value != "" {
		v, err := encodeValue(req.Type, req.Value)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		val = v
	}
	// BETWEEN passes lo||hi; the engine reads two values from the buffer.
	if req.Op == memscan.OpBetween {
		if req.Value == "" || req.Value2 == "" {
			writeErr(w, http.StatusBadRequest, "between requires value and value2")
			return
		}
		hi, err := encodeValue(req.Type, req.Value2)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		val = append(val, hi...)
	}
	n, err := sess.NextScan(req.Op, val)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.recordHist(sid, scanHistEntry{
		Action: "next", Type: typeName(req.Type), Op: opName(req.Op),
		Value: string(req.Value), Hits: n,
	})
	s.publishScanHits(sid, sess, typeName(req.Type), string(req.Value))
	writeJSON(w, http.StatusOK, map[string]int{"hits": n})
}

// memString scans for an exact string (utf16=true for wide strings).
func (s *Server) memString(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.session(r.PathValue("sid"))
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	var req struct {
		Text  string `json:"text"`
		UTF16 bool   `json:"utf16"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	if req.Text == "" {
		writeErr(w, http.StatusBadRequest, "empty text")
		return
	}
	n, err := sess.StringScan(req.Text, req.UTF16)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.recordHist(r.PathValue("sid"), scanHistEntry{
		Action: "string", Type: "str", Value: req.Text, Hits: n,
	})
	s.publishScanHits(r.PathValue("sid"), sess, "str", req.Text)
	writeJSON(w, http.StatusOK, map[string]int{"hits": n})
}

// memRound sets the float comparison mode (0 exact, 1 rounded, 2 truncated).
func (s *Server) memRound(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.session(r.PathValue("sid"))
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	var req struct {
		Mode memscan.RoundMode `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	if err := sess.SetRound(req.Mode); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// memOpts sets fast-scan options: align (0 => type width / aligned fast scan,
// 1 => unaligned find-all), an optional [range_lo, range_hi) address window
// (range_hi == 0 => unbounded), and writable_only to skip non-writable regions.
// Addresses accept "0x"-prefixed hex or decimal.
func (s *Server) memOpts(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.session(r.PathValue("sid"))
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	var req struct {
		Align        uint64 `json:"align"`
		RangeLo      string `json:"range_lo"`
		RangeHi      string `json:"range_hi"`
		WritableOnly bool   `json:"writable_only"`
		Kind         string `json:"kind"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	lo, err := parseAddrDefault(req.RangeLo)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad range_lo: "+err.Error())
		return
	}
	hi, err := parseAddrDefault(req.RangeHi)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad range_hi: "+err.Error())
		return
	}
	if hi != 0 && hi <= lo {
		writeErr(w, http.StatusBadRequest, "range_hi must be greater than range_lo")
		return
	}
	if err := sess.SetOpts(req.Align, lo, hi, req.WritableOnly); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if kind := strings.TrimSpace(req.Kind); kind != "" && kind != "all" {
		e := s.extFor(r.PathValue("sid"))
		if regions, err := listRegions(e.pid); err == nil {
			var minLo, maxHi uint64
			for _, rg := range regions {
				if !regionKindOK(rg.kind(), kind) {
					continue
				}
				if minLo == 0 || rg.Start < minLo {
					minLo = rg.Start
				}
				if rg.End > maxHi {
					maxHi = rg.End
				}
			}
			if maxHi > minLo {
				if lo == 0 || minLo > lo {
					lo = minLo
				}
				if hi == 0 || maxHi < hi {
					hi = maxHi
				}
				_ = sess.SetOpts(req.Align, lo, hi, req.WritableOnly)
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "kind": req.Kind})
}

func (s *Server) memAOB(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.session(r.PathValue("sid"))
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	var req struct {
		Pattern string `json:"pattern"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	n, err := sess.AOBScan(req.Pattern)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.extFor(r.PathValue("sid")).resetGo()
	s.recordHist(r.PathValue("sid"), scanHistEntry{
		Action: "aob", Type: "aob", Value: req.Pattern, Hits: n,
	})
	s.publishScanHits(r.PathValue("sid"), sess, "aob", req.Pattern)
	writeJSON(w, http.StatusOK, map[string]int{"hits": n})
}

func (s *Server) memResults(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.session(r.PathValue("sid"))
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	max := 1000
	if q := r.URL.Query().Get("max"); q != "" {
		if v, err := strconv.Atoi(q); err == nil {
			max = v
		}
	}
	sid := r.PathValue("sid")
	addrs, err := s.currentHits(sid, sess, max)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	hexed := make([]string, len(addrs))
	for i, a := range addrs {
		hexed[i] = fmt.Sprintf("0x%X", a)
	}
	resp := map[string]any{"count": len(addrs), "addrs": hexed}
	// Include undo stack depth so the UI knows whether undo is available.
	e := s.extFor(sid)
	e.mu.Lock()
	resp["undo_depth"] = len(e.undoStack)
	var firstVals map[uint64][]byte
	if e.firstVals != nil {
		firstVals = make(map[uint64][]byte, len(e.firstVals))
		for k, v := range e.firstVals {
			cp := make([]byte, len(v))
			copy(cp, v)
			firstVals[k] = cp
		}
	}
	firstType := e.firstType
	pid := e.pid
	e.mu.Unlock()
	if r.URL.Query().Get("modules") == "1" && pid != 0 {
		if mods, err := listModules(pid); err == nil {
			labels := make([]string, len(addrs))
			for i, a := range addrs {
				labels[i] = moduleLabelFromMods(mods, a)
			}
			resp["module_labels"] = labels
		}
	}
	if firstVals != nil && firstType.Width() > 0 {
		first := make([]any, len(addrs))
		for i, a := range addrs {
			if b, ok := firstVals[a]; ok {
				first[i] = decodeValue(firstType, b)
			}
		}
		resp["first_values"] = first
		resp["first_type"] = uint32(firstType)
	}
	// Optional ?type= adds the live value of each address to the response.
	if q := r.URL.Query().Get("type"); q != "" {
		if tv, err := strconv.Atoi(q); err == nil {
			vt := memscan.ValueType(tv)
			if wd := vt.Width(); wd > 0 {
				sorted := append([]uint64(nil), addrs...)
				sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
				vals := readBatch(sess, sorted, wd)
				out := make([]any, len(addrs))
				for i, a := range addrs {
					if b, ok := vals[a]; ok {
						out[i] = decodeValue(vt, b)
					}
				}
				resp["values"] = out
			}
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// memPtrScan runs a CE-style pointer scan for a target address, finding stable
// static-base + multi-level-offset paths that resolve to it. max_offset is the
// per-level offset slack (default 0x400) and max_level the indirection depth
// (default 3). target accepts "0x"-prefixed hex or decimal.
func (s *Server) memPtrScan(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.session(r.PathValue("sid"))
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	var req struct {
		Target    string `json:"target"`
		MaxOffset string `json:"max_offset"`
		MaxLevel  uint32 `json:"max_level"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	target, err := parseAddr(req.Target)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad target: "+err.Error())
		return
	}
	maxOff, err := parseAddrDefault(req.MaxOffset)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad max_offset: "+err.Error())
		return
	}
	if maxOff == 0 {
		maxOff = 0x400
	}
	level := req.MaxLevel
	if level == 0 {
		level = 3
	}
	n, err := sess.PointerScan(target, maxOff, level)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.recordHist(r.PathValue("sid"), scanHistEntry{
		Action: "ptrscan", Type: "ptr", Value: formatHex(target), Hits: n,
	})
	writeJSON(w, http.StatusOK, map[string]any{"paths": n, "max_level": level, "max_offset": formatHex(maxOff)})
}

// memPtrPaths returns the pointer paths from the last scan, each re-resolved
// against live memory so the caller can see the current value address (and
// whether the path still holds).
func (s *Server) memPtrPaths(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.session(r.PathValue("sid"))
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	max := 200
	if q := r.URL.Query().Get("max"); q != "" {
		if v, err := strconv.Atoi(q); err == nil {
			max = v
		}
	}
	paths, err := sess.PointerPaths(max)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(paths))
	for i, p := range paths {
		offs := make([]string, len(p.Offsets))
		for j, o := range p.Offsets {
			offs[j] = fmt.Sprintf("0x%X", o)
		}
		item := map[string]any{
			"base":    fmt.Sprintf("0x%X", p.Base),
			"offsets": offs,
		}
		if addr, ok, _ := sess.PointerResolve(i); ok {
			item["resolved"] = fmt.Sprintf("0x%X", addr)
		} else {
			item["resolved"] = nil
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(out), "paths": out})
}

func (s *Server) memClose(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	sess, ok := s.session(sid)
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	s.mu.Lock()
	if f := s.freezes[sid]; f != nil {
		f.stopAll()
		delete(s.freezes, sid)
	}
	var wt memWatcher
	if e := s.ext[sid]; e != nil {
		e.mu.Lock()
		wt = e.watch
		e.watch = nil
		e.mu.Unlock()
	}
	delete(s.ext, sid)
	delete(s.sessions, sid)
	s.mu.Unlock()
	if wt != nil {
		wt.Stop()
	}
	_ = sess.Close()
	writeJSON(w, http.StatusOK, map[string]string{"closed": sid})
}
