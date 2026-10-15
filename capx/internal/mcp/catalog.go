package mcp

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type mcpRoute struct {
	Name        string
	Description string
	Method      string // GET POST DELETE
	Path        string // may contain {id} {sid} {name} {subdomain}
	Active      bool   // requires CAPX_MCP_ACTIVE
	Query       []string
	PathParams  []string
	Body        bool
	MaxLimit    int
}

func (r mcpRoute) schema() map[string]any {
	if r.Name == "capx_runtime_shutdown" {
		return runtimeShutdownSchema()
	}
	props := map[string]any{}
	required := []string{}
	for _, p := range r.PathParams {
		props[p] = map[string]any{"type": "string", "description": "path parameter " + p}
		required = append(required, p)
	}
	for _, q := range r.Query {
		props[q] = map[string]any{"type": "string"}
	}
	if r.MaxLimit > 0 {
		props["limit"] = map[string]any{"type": "integer"}
		props["offset"] = map[string]any{"type": "integer"}
	}
	if r.Body {
		props["body"] = map[string]any{"type": "object", "description": "JSON body fields for this API", "additionalProperties": true}
	}
	sch := map[string]any{"type": "object", "properties": props, "additionalProperties": r.Body}
	if len(required) > 0 {
		sch["required"] = required
	}
	return sch
}

func allRoutes() []mcpRoute {
	qHTTP := []string{"host", "method", "status", "scheme", "q", "scope", "filter"}
	return []mcpRoute{
		{Name: "capx_health", Description: "守护进程健康检查", Method: "GET", Path: "/health"},
		{Name: "capx_proxy_lan_status", Description: "手机 Wi-Fi 代理状态与电脑局域网 IP", Method: "GET", Path: "/api/proxy/lan"},
		{Name: "capx_proxy_lan_start", Description: "在指定电脑局域网 IP 和端口开启手机 Wi-Fi 代理；与当前 MITM 共享证书、上游和历史", Method: "POST", Path: "/api/proxy/lan/start", Body: true, Active: true},
		{Name: "capx_proxy_lan_stop", Description: "关闭本实例的手机 Wi-Fi 代理入口", Method: "POST", Path: "/api/proxy/lan/stop", Body: true},
		{Name: "capx_ifaces", Description: "列出网卡（需 pcap 构建）", Method: "GET", Path: "/api/ifaces"},
		{Name: "capx_captures", Description: "列出抓包会话", Method: "GET", Path: "/api/captures"},
		{Name: "capx_capture_start", Description: "启动 L3/L4 抓包", Method: "POST", Path: "/api/captures", Body: true},
		{Name: "capx_capture_stop", Description: "停止抓包会话", Method: "POST", Path: "/api/captures/{id}/stop", PathParams: []string{"id"}},
		{Name: "capx_flows", Description: "列出传输层流", Method: "GET", Path: "/api/flows", Query: []string{"limit"}},
		{Name: "capx_packets", Description: "列出已缓存原始包摘要", Method: "GET", Path: "/api/packets", Query: []string{"limit", "capture"}},
		{Name: "capx_export_pcap", Description: "导出 pcap 元数据/下载信息", Method: "GET", Path: "/api/export/pcap", Query: []string{"format", "capture"}},
		{Name: "capx_list_http", Description: "HTTP 历史摘要", Method: "GET", Path: "/api/http", Query: qHTTP, MaxLimit: 200},
		{Name: "capx_clear_history", Description: "清空 HTTP/WS 历史", Method: "DELETE", Path: "/api/history", Active: true},
		{Name: "capx_http_export", Description: "导出 HTTP HAR", Method: "GET", Path: "/api/http/export"},
		{Name: "capx_http_decrypt", Description: "解密已捕获交易的业务密文：side=request/response、json_pointer=/data/ciphertext、algorithm/mode/input_enc；支持 CAPX_APP_ 前缀的 key_env/iv_env/private_key_env。需要有效密钥，不改写原始流量，AES-GCM 会验证认证标签", Method: "POST", Path: "/api/http/{id}/decrypt", PathParams: []string{"id"}, Body: true},
		{Name: "capx_get_http", Description: "按 id 取完整 HTTP 交易", Method: "GET", Path: "/api/http/{id}", PathParams: []string{"id"}},
		{Name: "capx_http_curl", Description: "把交易导出为 curl", Method: "GET", Path: "/api/http/{id}/curl", PathParams: []string{"id"}},
		{Name: "capx_list_ws", Description: "WebSocket 帧", Method: "GET", Path: "/api/ws", Query: []string{"url", "dir", "opcode", "q"}},
		{Name: "capx_proxy_status", Description: "MITM 代理状态", Method: "GET", Path: "/api/proxy/status"},
		{Name: "capx_proxy_start", Description: "启动 MITM 代理", Method: "POST", Path: "/api/proxy/start", Body: true},
		{Name: "capx_proxy_stop", Description: "停止 MITM 代理", Method: "POST", Path: "/api/proxy/stop"},
		{Name: "capx_transparent_status", Description: "透明 MITM 状态", Method: "GET", Path: "/api/proxy/transparent"},
		{Name: "capx_transparent_start", Description: "启动透明监听（OS 重定向视 build tag）", Method: "POST", Path: "/api/proxy/transparent/start", Body: true, Active: true},
		{Name: "capx_transparent_stop", Description: "停止透明 MITM", Method: "POST", Path: "/api/proxy/transparent/stop", Active: true},
		{Name: "capx_intercept_toggle", Description: "开关请求/响应/WS 拦截", Method: "POST", Path: "/api/proxy/intercept", Body: true},
		{Name: "capx_http2_toggle", Description: "开关上游 HTTP/2", Method: "POST", Path: "/api/proxy/http2", Body: true},
		{Name: "capx_body_capture", Description: "设置历史正文捕获上限", Method: "POST", Path: "/api/proxy/body-capture", Body: true},
		{Name: "capx_intercept_queue", Description: "拦截队列", Method: "GET", Path: "/api/proxy/intercept/queue"},
		{Name: "capx_intercept_decide", Description: "放行/丢弃/改写拦截中的请求", Method: "POST", Path: "/api/proxy/intercept/decide", Body: true, Active: true},
		{Name: "capx_intercept_rules", Description: "读取拦截条件", Method: "GET", Path: "/api/proxy/intercept/rules"},
		{Name: "capx_intercept_rules_set", Description: "设置拦截条件", Method: "POST", Path: "/api/proxy/intercept/rules", Body: true},
		{Name: "capx_ws_conns", Description: "活动 WebSocket 连接", Method: "GET", Path: "/api/proxy/ws/conns"},
		{Name: "capx_ws_replay", Description: "向活动 WS 注入一帧", Method: "POST", Path: "/api/proxy/ws/replay", Body: true, Active: true},
		{Name: "capx_ca", Description: "下载 CA PEM 文本", Method: "GET", Path: "/api/proxy/ca"},
		{Name: "capx_ca_pem", Description: "下载 CA（/capx-ca.pem 别名）", Method: "GET", Path: "/capx-ca.pem"},
		{Name: "capx_stream", Description: "SSE 事件短读：读 /api/stream 前若干条后断开（stdio 不适合作长连接推流）", Method: "GET", Path: "/api/stream", Query: []string{"max"}},
		{Name: "capx_setup_status", Description: "本机 CA/代理/HTTP3 状态", Method: "GET", Path: "/api/setup"},
		{Name: "capx_ca_install", Description: "安装 capx 根证书", Method: "POST", Path: "/api/setup/ca/install", Active: true},
		{Name: "capx_ca_uninstall", Description: "卸载 capx 根证书", Method: "POST", Path: "/api/setup/ca/uninstall", Active: true},
		{Name: "capx_sysproxy_on", Description: "打开系统代理", Method: "POST", Path: "/api/setup/sysproxy/on", Active: true},
		{Name: "capx_sysproxy_off", Description: "还原系统代理", Method: "POST", Path: "/api/setup/sysproxy/off", Active: true},
		{Name: "capx_http3_off", Description: "写策略关闭浏览器 HTTP/3", Method: "POST", Path: "/api/setup/http3/off", Active: true},
		{Name: "capx_launch_browser", Description: "打开独立抓包浏览器", Method: "POST", Path: "/api/setup/browser", Body: true},
		{Name: "capx_prepare", Description: "一键准备（默认不开系统代理）", Method: "POST", Path: "/api/setup/prepare", Body: true},
		{Name: "capx_restart_browsers", Description: "重启本机 Chrome/Edge", Method: "POST", Path: "/api/setup/browsers/restart", Active: true},
		{Name: "capx_get_scope", Description: "读取 Target scope", Method: "GET", Path: "/api/scope"},
		{Name: "capx_set_scope", Description: "设置 Target scope", Method: "POST", Path: "/api/scope", Body: true},
		{Name: "capx_sitemap", Description: "站点地图", Method: "GET", Path: "/api/sitemap"},
		{Name: "capx_repeater_send", Description: "Repeater 重放原文", Method: "POST", Path: "/api/repeater/send", Body: true},
		{Name: "capx_intruder_run", Description: "Intruder 批量", Method: "POST", Path: "/api/intruder/run", Body: true, Active: true},
		{Name: "capx_turbo_run", Description: "Turbo 并发重放", Method: "POST", Path: "/api/turbo/run", Body: true, Active: true},
		{Name: "capx_intruder_export", Description: "导出 Intruder CSV", Method: "POST", Path: "/api/intruder/export", Body: true, Active: true},
		{Name: "capx_session_get", Description: "会话宏/变量", Method: "GET", Path: "/api/session"},
		{Name: "capx_session_set", Description: "设置会话宏/变量", Method: "POST", Path: "/api/session", Body: true},
		{Name: "capx_session_run", Description: "跑 HTTP 会话宏", Method: "POST", Path: "/api/session/run", Body: true, Active: true},
		{Name: "capx_session_ws_run", Description: "跑 WS 会话宏", Method: "POST", Path: "/api/session/ws/run", Body: true, Active: true},

		{Name: "capx_mem_processes", Description: "进程列表", Method: "GET", Path: "/api/mem/processes"},
		{Name: "capx_mem_open", Description: "附加进程", Method: "POST", Path: "/api/mem/open", Body: true, Active: true},
		{Name: "capx_mem_first", Description: "首次扫描", Method: "POST", Path: "/api/mem/{sid}/first", PathParams: []string{"sid"}, Body: true, Active: true},
		{Name: "capx_mem_snapshot", Description: "快照", Method: "POST", Path: "/api/mem/{sid}/snapshot", PathParams: []string{"sid"}, Active: true},
		{Name: "capx_mem_next", Description: "下一轮扫描", Method: "POST", Path: "/api/mem/{sid}/next", PathParams: []string{"sid"}, Body: true, Active: true},
		{Name: "capx_mem_string", Description: "字符串扫描", Method: "POST", Path: "/api/mem/{sid}/string", PathParams: []string{"sid"}, Body: true, Active: true},
		{Name: "capx_mem_round", Description: "扫描轮次", Method: "POST", Path: "/api/mem/{sid}/round", PathParams: []string{"sid"}, Body: true, Active: true},
		{Name: "capx_mem_opts", Description: "扫描选项", Method: "POST", Path: "/api/mem/{sid}/opts", PathParams: []string{"sid"}, Body: true, Active: true},
		{Name: "capx_mem_aob", Description: "AOB 扫描", Method: "POST", Path: "/api/mem/{sid}/aob", PathParams: []string{"sid"}, Body: true, Active: true},
		{Name: "capx_mem_results", Description: "扫描结果", Method: "GET", Path: "/api/mem/{sid}/results", PathParams: []string{"sid"}, Query: []string{"limit", "offset"}},
		{Name: "capx_mem_ptrscan", Description: "指针扫描", Method: "POST", Path: "/api/mem/{sid}/ptrscan", PathParams: []string{"sid"}, Body: true, Active: true},
		{Name: "capx_mem_ptrpaths", Description: "指针路径", Method: "GET", Path: "/api/mem/{sid}/ptrpaths", PathParams: []string{"sid"}},
		{Name: "capx_mem_ptrfilter", Description: "指针过滤", Method: "POST", Path: "/api/mem/{sid}/ptrfilter", PathParams: []string{"sid"}, Body: true, Active: true},
		{Name: "capx_mem_ptrmap", Description: "导出指针图", Method: "GET", Path: "/api/mem/{sid}/ptrmap", PathParams: []string{"sid"}},
		{Name: "capx_mem_ptrmap_check", Description: "校验指针图", Method: "POST", Path: "/api/mem/{sid}/ptrmap/check", PathParams: []string{"sid"}, Body: true, Active: true},
		{Name: "capx_mem_write", Description: "写内存", Method: "POST", Path: "/api/mem/{sid}/write", PathParams: []string{"sid"}, Body: true, Active: true},
		{Name: "capx_mem_patch", Description: "代码补丁", Method: "POST", Path: "/api/mem/{sid}/patch", PathParams: []string{"sid"}, Body: true, Active: true},
		{Name: "capx_mem_alloc", Description: "目标内分配", Method: "POST", Path: "/api/mem/{sid}/alloc", PathParams: []string{"sid"}, Body: true, Active: true},
		{Name: "capx_mem_assemble", Description: "汇编", Method: "POST", Path: "/api/mem/{sid}/assemble", PathParams: []string{"sid"}, Body: true, Active: true},
		{Name: "capx_mem_freeze", Description: "冻结地址", Method: "POST", Path: "/api/mem/{sid}/freeze", PathParams: []string{"sid"}, Body: true, Active: true},
		{Name: "capx_mem_unfreeze", Description: "解冻", Method: "POST", Path: "/api/mem/{sid}/unfreeze", PathParams: []string{"sid"}, Body: true, Active: true},
		{Name: "capx_mem_freezes", Description: "冻结列表", Method: "GET", Path: "/api/mem/{sid}/freezes", PathParams: []string{"sid"}},
		{Name: "capx_mem_close", Description: "关闭内存会话", Method: "POST", Path: "/api/mem/{sid}/close", PathParams: []string{"sid"}, Active: true},
		{Name: "capx_mem_addrlist", Description: "地址表", Method: "GET", Path: "/api/mem/addrlist"},
		{Name: "capx_mem_addr_add", Description: "加入地址表", Method: "POST", Path: "/api/mem/addrlist", Body: true, Active: true},
		{Name: "capx_mem_addr_del", Description: "删除地址表项", Method: "DELETE", Path: "/api/mem/addrlist/{id}", PathParams: []string{"id"}, Active: true},
		{Name: "capx_mem_addr_freeze", Description: "冻结地址表项", Method: "POST", Path: "/api/mem/addrlist/{id}/freeze", PathParams: []string{"id"}, Active: true},
		{Name: "capx_mem_addr_unfreeze", Description: "解冻地址表项", Method: "POST", Path: "/api/mem/addrlist/{id}/unfreeze", PathParams: []string{"id"}, Active: true},
		{Name: "capx_mem_modules", Description: "模块列表", Method: "GET", Path: "/api/mem/{sid}/modules", PathParams: []string{"sid"}},
		{Name: "capx_mem_resolve", Description: "解析地址表达式", Method: "POST", Path: "/api/mem/{sid}/resolve", PathParams: []string{"sid"}, Body: true},
		{Name: "capx_mem_regions", Description: "内存区", Method: "GET", Path: "/api/mem/{sid}/regions", PathParams: []string{"sid"}},
		{Name: "capx_mem_view", Description: "读内存视图", Method: "GET", Path: "/api/mem/{sid}/view", PathParams: []string{"sid"}, Query: []string{"addr", "len"}},
		{Name: "capx_mem_disasm", Description: "反汇编", Method: "GET", Path: "/api/mem/{sid}/disasm", PathParams: []string{"sid"}, Query: []string{"addr", "len"}},
		{Name: "capx_mem_savefirst", Description: "保存首次", Method: "POST", Path: "/api/mem/{sid}/savefirst", PathParams: []string{"sid"}, Active: true},
		{Name: "capx_mem_allfirst", Description: "全部首次", Method: "POST", Path: "/api/mem/{sid}/allfirst", PathParams: []string{"sid"}, Active: true},
		{Name: "capx_mem_groupscan", Description: "分组扫描", Method: "POST", Path: "/api/mem/{sid}/groupscan", PathParams: []string{"sid"}, Body: true, Active: true},
		{Name: "capx_mem_binscan", Description: "二进制扫描", Method: "POST", Path: "/api/mem/{sid}/binscan", PathParams: []string{"sid"}, Body: true, Active: true},
		{Name: "capx_mem_undo", Description: "撤销扫描", Method: "POST", Path: "/api/mem/{sid}/undo", PathParams: []string{"sid"}, Active: true},
		{Name: "capx_mem_history", Description: "扫描历史", Method: "GET", Path: "/api/mem/{sid}/history", PathParams: []string{"sid"}},
		{Name: "capx_mem_dissect", Description: "结构剖析", Method: "POST", Path: "/api/mem/{sid}/dissect", PathParams: []string{"sid"}, Body: true},
		{Name: "capx_mem_table_export", Description: "导出地址表", Method: "GET", Path: "/api/mem/table/export"},
		{Name: "capx_mem_table_import", Description: "导入地址表", Method: "POST", Path: "/api/mem/table/import", Body: true, Active: true},
		{Name: "capx_mem_watch", Description: "硬件断点监视", Method: "POST", Path: "/api/mem/{sid}/watch", PathParams: []string{"sid"}, Body: true, Active: true},
		{Name: "capx_mem_watch_status", Description: "监视状态", Method: "GET", Path: "/api/mem/{sid}/watch", PathParams: []string{"sid"}},
		{Name: "capx_mem_unwatch", Description: "停止监视", Method: "POST", Path: "/api/mem/{sid}/unwatch", PathParams: []string{"sid"}, Active: true},
		{Name: "capx_mem_debug_disasm", Description: "调试反汇编", Method: "GET", Path: "/api/mem/{sid}/debug/disasm", PathParams: []string{"sid"}, Query: []string{"addr"}},
		{Name: "capx_mem_debug_stack", Description: "调试栈", Method: "GET", Path: "/api/mem/{sid}/debug/stack", PathParams: []string{"sid"}},
		{Name: "capx_mem_ptrmap_save", Description: "保存指针图", Method: "POST", Path: "/api/mem/{sid}/ptrmap/save", PathParams: []string{"sid"}, Body: true, Active: true},
		{Name: "capx_mem_reattach", Description: "重新附加", Method: "POST", Path: "/api/mem/{sid}/reattach", PathParams: []string{"sid"}, Active: true},
		{Name: "capx_mem_link_http", Description: "内存命中关联 HTTP", Method: "GET", Path: "/api/mem/{sid}/link/http", PathParams: []string{"sid"}},

		{Name: "capx_hook_status", Description: "Frida/hook 后端状态", Method: "GET", Path: "/api/hook/status"},
		{Name: "capx_hook_procs", Description: "可 Hook 进程", Method: "GET", Path: "/api/hook/procs"},
		{Name: "capx_hook_sessions", Description: "Hook 会话", Method: "GET", Path: "/api/hook/sessions"},
		{Name: "capx_hook_attach", Description: "Frida attach", Method: "POST", Path: "/api/hook/attach", Body: true, Active: true},
		{Name: "capx_hook_detach", Description: "Frida detach", Method: "POST", Path: "/api/hook/detach", Body: true, Active: true},
		{Name: "capx_hook_events", Description: "Hook 事件", Method: "GET", Path: "/api/hook/events", Query: []string{"limit"}},
		{Name: "capx_hook_native_attach", Description: "原生 DLL 注入 hook", Method: "POST", Path: "/api/hook/native/attach", Body: true, Active: true},
		{Name: "capx_hook_native_status", Description: "原生 hook 状态", Method: "GET", Path: "/api/hook/native/status"},
		{Name: "capx_hook_agents", Description: "Frida agent 列表", Method: "GET", Path: "/api/hook/agents"},
		{Name: "capx_hook_agent_upload", Description: "上传 Frida agent", Method: "POST", Path: "/api/hook/agents", Body: true, Active: true},
		{Name: "capx_hook_agent_delete", Description: "删除 Frida agent", Method: "DELETE", Path: "/api/hook/agents/{name}", PathParams: []string{"name"}, Active: true},

		{Name: "capx_keylog", Description: "TLS keylog 状态", Method: "GET", Path: "/api/keylog"},
		{Name: "capx_keylog_add", Description: "追加 keylog 行", Method: "POST", Path: "/api/keylog", Body: true},
		{Name: "capx_keylog_export", Description: "导出 SSLKEYLOG", Method: "GET", Path: "/api/keylog/export"},
		{Name: "capx_decode_protobuf", Description: "解码 protobuf", Method: "POST", Path: "/api/decode/protobuf", Body: true},
		{Name: "capx_decode_grpc", Description: "解码 gRPC 帧", Method: "POST", Path: "/api/decode/grpc", Body: true},
		{Name: "capx_decode_packet", Description: "解码原始包", Method: "POST", Path: "/api/decode/packet", Body: true},
		{Name: "capx_decode_quic", Description: "解密 QUIC Initial", Method: "POST", Path: "/api/decode/quic", Body: true},
		{Name: "capx_crypto_codec", Description: "编解码", Method: "POST", Path: "/api/crypto/codec", Body: true},
		{Name: "capx_crypto_digest", Description: "摘要", Method: "POST", Path: "/api/crypto/digest", Body: true},
		{Name: "capx_scan_passive", Description: "被动问题检测", Method: "GET", Path: "/api/scan/passive"},
		{Name: "capx_scan_passive_tx", Description: "单条被动检测", Method: "GET", Path: "/api/scan/passive/{id}", PathParams: []string{"id"}},
		{Name: "capx_hae", Description: "HaE 状态", Method: "GET", Path: "/api/hae"},
		{Name: "capx_hae_rules", Description: "HaE 规则", Method: "GET", Path: "/api/hae/rules"},
		{Name: "capx_hae_rules_upload", Description: "上传 HaE Rules.yml", Method: "POST", Path: "/api/hae/rules", Body: true},
		{Name: "capx_hae_scan", Description: "HaE 扫描历史", Method: "GET", Path: "/api/hae/scan"},
		{Name: "capx_hae_tx", Description: "HaE 单条", Method: "GET", Path: "/api/hae/tx/{id}", PathParams: []string{"id"}},
		{Name: "capx_oob_start", Description: "启动 OOB 捕获", Method: "POST", Path: "/api/oob/start", Body: true, Active: true},
		{Name: "capx_oob_stop", Description: "停止 OOB", Method: "POST", Path: "/api/oob/stop", Active: true},
		{Name: "capx_oob_status", Description: "OOB 状态", Method: "GET", Path: "/api/oob/status"},
		{Name: "capx_oob_hits", Description: "OOB 命中", Method: "GET", Path: "/api/oob/hits"},
		{Name: "capx_oob_payload", Description: "生成 OOB payload", Method: "POST", Path: "/api/oob/payload", Body: true},
		{Name: "capx_wxapkg_scan", Description: "扫描微信小程序缓存；root 留空自动检测，dir 为旧参数别名", Method: "GET", Path: "/api/wxapkg/scan", Query: []string{"root", "dir"}},
		{Name: "capx_wxapkg_rules", Description: "wxapkg 规则", Method: "GET", Path: "/api/wxapkg/rules"},
		{Name: "capx_wxapkg_unpack", Description: "解包 wxapkg", Method: "POST", Path: "/api/wxapkg/unpack", Body: true, Active: true},
		{Name: "capx_wxapkg_read", Description: "读取解包文件；dir 为解包目录，name 为目录内的相对文件名", Method: "GET", Path: "/api/wxapkg/read", Query: []string{"dir", "name"}},
		{Name: "capx_collect", Description: "CaA 风格提取", Method: "GET", Path: "/api/collect"},
		{Name: "capx_collect_wordlist", Description: "导出 fuzz 字典", Method: "GET", Path: "/api/collect/wordlist", Query: []string{"type"}},
		{Name: "capx_project_export", Description: "导出项目", Method: "GET", Path: "/api/project/export"},
		{Name: "capx_project_import", Description: "导入项目", Method: "POST", Path: "/api/project/import", Body: true, Active: true},
		{Name: "capx_spoof_status", Description: "ARP 欺骗状态", Method: "GET", Path: "/api/spoof/arp"},
		{Name: "capx_spoof_start", Description: "启动 ARP 欺骗", Method: "POST", Path: "/api/spoof/arp/start", Body: true, Active: true},
		{Name: "capx_spoof_stop", Description: "停止 ARP 欺骗", Method: "POST", Path: "/api/spoof/arp/stop", Active: true},
		{Name: "capx_rules", Description: "HTTP Match&Replace", Method: "GET", Path: "/api/rules"},
		{Name: "capx_rules_add", Description: "添加 HTTP 规则", Method: "POST", Path: "/api/rules", Body: true},
		{Name: "capx_rules_delete", Description: "删除 HTTP 规则", Method: "DELETE", Path: "/api/rules/{id}", PathParams: []string{"id"}},
		{Name: "capx_wsrules", Description: "WS Match&Replace", Method: "GET", Path: "/api/wsrules"},
		{Name: "capx_wsrules_add", Description: "添加 WS 规则", Method: "POST", Path: "/api/wsrules", Body: true},
		{Name: "capx_wsrules_delete", Description: "删除 WS 规则", Method: "DELETE", Path: "/api/wsrules/{id}", PathParams: []string{"id"}},
		{Name: "capx_inline_status", Description: "内联改包后端", Method: "GET", Path: "/api/inline/status"},
		{Name: "capx_inline_start", Description: "启动 WinDivert/NFQUEUE", Method: "POST", Path: "/api/inline/start", Body: true, Active: true},
		{Name: "capx_inline_stop", Description: "停止内联改包", Method: "POST", Path: "/api/inline/stop", Active: true},
		{Name: "capx_inline_send", Description: "注入原始包", Method: "POST", Path: "/api/inline/send", Body: true, Active: true},
		{Name: "capx_inline_rules", Description: "内联规则", Method: "GET", Path: "/api/inline/rules"},
		{Name: "capx_inline_rules_add", Description: "添加内联规则", Method: "POST", Path: "/api/inline/rules", Body: true, Active: true},
		{Name: "capx_inline_rules_delete", Description: "删除内联规则", Method: "DELETE", Path: "/api/inline/rules/{id}", PathParams: []string{"id"}, Active: true},

		{Name: "capx_wxhook_status", Description: "小程序 hook 状态", Method: "GET", Path: "/api/wxhook/status"},
		{Name: "capx_wxhook_procs", Description: "微信相关进程", Method: "GET", Path: "/api/wxhook/procs"},
		{Name: "capx_wxhook_enable", Description: "公开版不内置强开 F12；需使用外部调试提供方和 CDP 连接", Method: "POST", Path: "/api/wxhook/enable", Body: true, Active: true},
		{Name: "capx_wxhook_disable", Description: "关闭 F12 hook", Method: "POST", Path: "/api/wxhook/disable", Active: true},
		{Name: "capx_wxhook_capture_start", Description: "小程序抓流量", Method: "POST", Path: "/api/wxhook/capture/start", Body: true, Active: true},
		{Name: "capx_wxhook_capture_stop", Description: "停止小程序抓流量", Method: "POST", Path: "/api/wxhook/capture/stop", Active: true},
		{Name: "capx_wxhook_cdp_status", Description: "小程序 CDP", Method: "GET", Path: "/api/wxhook/cdp/status"},
		{Name: "capx_wxhook_cdp_targets", Description: "从本机标准 CDP 服务的 /json/list 发现可连接页面；endpoint 例如 http://127.0.0.1:9222，需要调试提供方已经运行", Method: "GET", Path: "/api/wxhook/cdp/targets", Query: []string{"endpoint"}},
		{Name: "capx_wxhook_cdp_start", Description: "连接外部标准 CDP；body.endpoint 可直接传地址，留空使用 CAPX_CDP_WS", Method: "POST", Path: "/api/wxhook/cdp/start", Body: true, Active: true},
		{Name: "capx_wxhook_cdp_stop", Description: "停 CDP", Method: "POST", Path: "/api/wxhook/cdp/stop", Active: true},
		{Name: "capx_wxhook_cdp_eval", Description: "CDP eval", Method: "POST", Path: "/api/wxhook/cdp/eval", Body: true, Active: true},
		{Name: "capx_wxhook_cdp_call", Description: "CDP call", Method: "POST", Path: "/api/wxhook/cdp/call", Body: true, Active: true},
		{Name: "capx_wxauto_snapshot", Description: "小程序页面快照", Method: "GET", Path: "/api/wxhook/auto/snapshot", Query: []string{"screenshot"}},
		{Name: "capx_wxauto_screenshot", Description: "小程序截图", Method: "GET", Path: "/api/wxhook/auto/screenshot"},
		{Name: "capx_wxauto_click", Description: "小程序点击", Method: "POST", Path: "/api/wxhook/auto/click", Body: true, Active: true},
		{Name: "capx_wxauto_input", Description: "小程序输入", Method: "POST", Path: "/api/wxhook/auto/input", Body: true, Active: true},
		{Name: "capx_wxauto_scroll", Description: "小程序滚动", Method: "POST", Path: "/api/wxhook/auto/scroll", Body: true, Active: true},
		{Name: "capx_wxauto_back", Description: "小程序返回", Method: "POST", Path: "/api/wxhook/auto/back", Active: true},
		{Name: "capx_wxauto_start", Description: "自动遍历小程序", Method: "POST", Path: "/api/wxhook/auto/start", Body: true, Active: true},
		{Name: "capx_wxauto_stop", Description: "停止自动遍历", Method: "POST", Path: "/api/wxhook/auto/stop", Active: true},
		{Name: "capx_wxauto_status", Description: "自动遍历状态", Method: "GET", Path: "/api/wxhook/auto/status"},
		{Name: "capx_wxdesk_environment", Description: "读取独立微信沙箱状态；主机默认仅连接沙箱，不操作本机主号", Method: "GET", Path: "/api/wxdesk/environment"},
		{Name: "capx_wxdesk_windows", Description: "列出隔离环境中的微信和已发布小程序窗口，枚举不代表已登录", Method: "GET", Path: "/api/wxdesk/windows"},
		{Name: "capx_wxdesk_screenshot", Description: "读取指定微信窗口画面，图片像素坐标；窗口 ID 从 windows 工具取得", Method: "GET", Path: "/api/wxdesk/screenshot", Query: []string{"window_id"}},
		{Name: "capx_wxdesk_launch", Description: "打开或前置官方电脑版微信；首次登录按客户端要求确认", Method: "POST", Path: "/api/wxdesk/launch", Active: true},
		{Name: "capx_wxdesk_show", Description: "前置所选官方微信窗口，body 使用 window_id", Method: "POST", Path: "/api/wxdesk/show", Body: true, Active: true},
		{Name: "capx_wxdesk_tap", Description: "点击截图坐标，body 必须含 window_id、x、y、width、height，尺寸应取自当前截图", Method: "POST", Path: "/api/wxdesk/tap", Body: true, Active: true},
		{Name: "capx_wxdesk_input", Description: "向所选微信窗口焦点输入 Unicode，body 使用 window_id、value；先确认焦点位于目标输入框", Method: "POST", Path: "/api/wxdesk/input", Body: true, Active: true},
		{Name: "capx_wxdesk_key", Description: "所选窗口按键：ESC/ENTER/TAB/BACKSPACE/UP/DOWN/LEFT/RIGHT/CTRL_A/CTRL_F，body 使用 window_id、key", Method: "POST", Path: "/api/wxdesk/key", Body: true, Active: true},
		{Name: "capx_wxdesk_scroll", Description: "所选窗口滚动，body 使用 window_id、delta（向下负数，例如 -360）", Method: "POST", Path: "/api/wxdesk/scroll", Body: true, Active: true},
		{Name: "capx_mobile_ios_setup", Description: "检查 go-ios、USB 设备、签名配置及 WDA 准备状态", Method: "GET", Path: "/api/mobile/ios/setup"},
		{Name: "capx_mobile_ios_prepare", Description: "异步准备 WDA：检查签名、自动签名/安装、准备开发镜像与隧道、启动 XCTest 和 USB 转发并连接；口令只接受本地 password_env 名称", Method: "POST", Path: "/api/mobile/ios/prepare", Body: true, Active: true},
		{Name: "capx_mobile_ios_prepare_status", Description: "读取 WDA 准备任务阶段与明确失败原因", Method: "GET", Path: "/api/mobile/ios/setup/status"},
		{Name: "capx_mobile_ios_prepare_stop", Description: "取消本实例的 WDA 准备任务，仅停止本实例启动的辅助进程", Method: "POST", Path: "/api/mobile/ios/prepare/stop"},
		{Name: "capx_mobile_ios_connect", Description: "连接已运行的 iOS WDA：body endpoint 为本机转发地址，可选 session_id；不安装 WDA", Method: "POST", Path: "/api/mobile/ios/connect", Body: true, Active: true},
		{Name: "capx_mobile_ios_disconnect", Description: "断开 Capx 的 WDA 连接，保留手机 App 和 XCTest", Method: "POST", Path: "/api/mobile/ios/disconnect", Body: true},
		{Name: "capx_mobile_home", Description: "手机返回桌面", Method: "POST", Path: "/api/mobile/home", Query: []string{"serial", "platform"}, Active: true},
		{Name: "capx_mobile_devices", Description: "列出手机设备；platform 为 android（默认）或 ios", Method: "GET", Path: "/api/mobile/devices", Query: []string{"platform"}},
		{Name: "capx_mobile_status", Description: "手机代理链路状态", Method: "GET", Path: "/api/mobile/status", Query: []string{"serial", "platform"}},
		{Name: "capx_mobile_snapshot", Description: "手机元素树及来源能力", Method: "GET", Path: "/api/mobile/snapshot", Query: []string{"serial", "platform"}},
		{Name: "capx_mobile_screenshot", Description: "手机截图（MCP 图片）", Method: "GET", Path: "/api/mobile/screenshot", Query: []string{"serial", "platform"}},
		{Name: "capx_mobile_foreground", Description: "手机当前前台 App", Method: "GET", Path: "/api/mobile/foreground", Query: []string{"serial", "platform"}},
		{Name: "capx_mobile_capture_start", Description: "配置手机代理抓包", Method: "POST", Path: "/api/mobile/capture/start", Query: []string{"serial", "platform"}, Body: true, Active: true},
		{Name: "capx_mobile_capture_stop", Description: "停止并恢复手机代理", Method: "POST", Path: "/api/mobile/capture/stop", Query: []string{"serial", "platform"}, Body: true},
		{Name: "capx_mobile_ca", Description: "推送 CA 并打开手机证书设置", Method: "POST", Path: "/api/mobile/ca", Query: []string{"serial", "platform"}, Active: true},
		{Name: "capx_mobile_tap", Description: "手机点击：body 使用 x/y 或 resource_id/text/content_desc；iOS x/y 使用 status.screen 的 points，须将截图像素按比例换算", Method: "POST", Path: "/api/mobile/tap", Query: []string{"serial", "platform"}, Body: true, Active: true},
		{Name: "capx_mobile_input", Description: "手机输入：body 使用 value；Android 为 ASCII，iOS 支持中文", Method: "POST", Path: "/api/mobile/input", Query: []string{"serial", "platform"}, Body: true, Active: true},
		{Name: "capx_mobile_swipe", Description: "手机滑动：body 使用 x1/y1/x2/y2/duration_ms；iOS 坐标使用 points", Method: "POST", Path: "/api/mobile/swipe", Query: []string{"serial", "platform"}, Body: true, Active: true},
		{Name: "capx_mobile_key", Description: "手机按键：body 使用 keycode", Method: "POST", Path: "/api/mobile/key", Query: []string{"serial", "platform"}, Body: true, Active: true},
		{Name: "capx_mobile_back", Description: "手机返回", Method: "POST", Path: "/api/mobile/back", Query: []string{"serial", "platform"}, Active: true},
		{Name: "capx_mobile_launch", Description: "启动手机 App：body 使用 package，Android 微信为 com.tencent.mm，iOS 为 com.tencent.xin", Method: "POST", Path: "/api/mobile/launch", Query: []string{"serial", "platform"}, Body: true, Active: true},

		{Name: "capx_policy", Description: "安全策略", Method: "GET", Path: "/api/policy"},
		{Name: "capx_policy_set", Description: "开关 allow_active", Method: "POST", Path: "/api/policy", Body: true, Active: true},
		{Name: "capx_audit", Description: "审计日志", Method: "GET", Path: "/api/audit"},
		{Name: "capx_correlate", Description: "跨层关联", Method: "GET", Path: "/api/correlate", Query: []string{"id", "kind"}},
		{Name: "capx_scripts", Description: "Lua 脚本列表", Method: "GET", Path: "/api/scripts"},
		{Name: "capx_scripts_add", Description: "加载 Lua 脚本", Method: "POST", Path: "/api/scripts", Body: true, Active: true},
		{Name: "capx_scripts_delete", Description: "删除 Lua 脚本", Method: "DELETE", Path: "/api/scripts/{id}", PathParams: []string{"id"}, Active: true},
		{Name: "capx_scripts_log", Description: "脚本日志", Method: "GET", Path: "/api/scripts/{id}/log", PathParams: []string{"id"}},
		{Name: "capx_dnslog_status", Description: "DNSLog 状态", Method: "GET", Path: "/api/dnslog/status"},
		{Name: "capx_dnslog_logs", Description: "分页读取 DNS 日志；page 默认1，page_size 默认20，可按 subdomain 筛选", Method: "GET", Path: "/api/dnslog/logs", Query: []string{"page", "page_size", "subdomain"}},
		{Name: "capx_dnslog_config", Description: "配置 DNSLog", Method: "POST", Path: "/api/dnslog/config", Body: true},
		{Name: "capx_dnslog_payloads", Description: "DNSLog payloads", Method: "GET", Path: "/api/dnslog/payloads"},
		{Name: "capx_dnslog_new_payload", Description: "新 DNSLog payload", Method: "POST", Path: "/api/dnslog/payloads", Body: true},
		{Name: "capx_dnslog_forget", Description: "删除 payload", Method: "DELETE", Path: "/api/dnslog/payloads/{subdomain}", PathParams: []string{"subdomain"}},
		{Name: "capx_dnslog_check", Description: "检查 DNSLog 命中", Method: "GET", Path: "/api/dnslog/check", Query: []string{"subdomain"}},
		{Name: "capx_dnslog_poll", Description: "轮询 DNSLog", Method: "POST", Path: "/api/dnslog/poll"},
		{Name: "capx_runtime_shutdown", Description: "核对健康与实例身份后条件关闭 captured；可指定 expected_instance_id / expected_generation，身份变化时拒绝停止", Method: "POST", Path: "/api/runtime/shutdown", Active: true, Body: true},
	}
}

func catalogTool(r mcpRoute) toolSpec {
	desc := r.Description + " → " + r.Method + " " + r.Path
	if r.Active {
		desc += "（需 CAPX_MCP_ACTIVE=1）"
	}
	return toolSpec{Name: r.Name, Description: desc, InputSchema: r.schema()}
}

func findRoute(name string) (mcpRoute, bool) {
	for _, r := range allRoutes() {
		if r.Name == name {
			return r, true
		}
	}
	return mcpRoute{}, false
}

func (s *Server) dispatchRoute(r mcpRoute, m map[string]any) (any, error) {
	if r.Active && !s.api.active {
		return nil, fmt.Errorf("%s requires CAPX_MCP_ACTIVE=1", r.Name)
	}
	if r.Name == "capx_runtime_shutdown" {
		return s.shutdownRuntime(m)
	}
	path := r.Path
	for _, p := range r.PathParams {
		v := strArg(m, p)
		if v == "" {
			v = strconv.Itoa(intArg(m, p, 0))
			if v == "0" && strArg(m, p) == "" {
				return nil, fmt.Errorf("missing path parameter %s", p)
			}
		}
		if strings.Contains(v, "/") || strings.Contains(v, "..") {
			return nil, fmt.Errorf("invalid path parameter %s", p)
		}
		path = strings.ReplaceAll(path, "{"+p+"}", url.PathEscape(v))
	}
	q := url.Values{}
	for _, k := range r.Query {
		if v := strArg(m, k); v != "" {
			q.Set(k, v)
		}
	}
	if r.Name == "capx_wxapkg_scan" {
		if q.Get("root") == "" && q.Get("dir") != "" {
			q.Set("root", q.Get("dir"))
		}
		q.Del("dir")
	}
	if r.Name == "capx_wxapkg_read" && (q.Get("dir") == "" || q.Get("name") == "") {
		return nil, fmt.Errorf("capx_wxapkg_read requires dir and name from the unpack result")
	}
	if r.MaxLimit > 0 {
		limit := intArg(m, "limit", 50)
		if limit > r.MaxLimit {
			limit = r.MaxLimit
		}
		if limit < 1 {
			limit = 50
		}
		q.Set("limit", strconv.Itoa(limit))
		if off := intArg(m, "offset", 0); off > 0 {
			q.Set("offset", strconv.Itoa(off))
		}
	}
	var body any
	if r.Body {
		if nested, ok := m["body"].(map[string]any); ok {
			body = nested
		} else {
			b := map[string]any{}
			skip := map[string]struct{}{}
			for _, p := range r.PathParams {
				skip[p] = struct{}{}
			}
			for _, q := range r.Query {
				skip[q] = struct{}{}
			}
			for k, v := range m {
				if _, ok := skip[k]; ok {
					continue
				}
				b[k] = v
			}
			delete(b, "body")
			body = b
		}
	}
	switch r.Name {
	case "capx_prepare":
		b, _ := body.(map[string]any)
		if b == nil {
			b = map[string]any{}
		}
		if _, ok := b["system_proxy"]; !ok {
			b["system_proxy"] = false
		}
		body = b
	case "capx_repeater_send":
		raw := strArg(m, "raw")
		if nested, ok := m["body"].(map[string]any); ok && raw == "" {
			raw = strArg(nested, "raw")
		}
		if strings.TrimSpace(raw) == "" {
			return nil, fmt.Errorf("raw request is required")
		}
		method := firstMethod(raw)
		if !s.api.active && !safeMethod(method) {
			return nil, fmt.Errorf("refusing %s replay; set CAPX_MCP_ACTIVE=1 for PUT/PATCH/DELETE", method)
		}
	}
	switch strings.ToUpper(r.Method) {
	case "GET":
		v, err := s.api.getJSON(path, q)
		if err == nil && r.Name == "capx_get_http" {
			v = clipHTTP(v)
		}
		return v, err
	case "POST":
		if body == nil {
			body = map[string]any{}
		}
		return s.api.postJSON(withQuery(path, q), body)
	case "DELETE":
		return s.api.deleteJSON(withQuery(path, q))
	default:
		return nil, fmt.Errorf("unsupported method %s", r.Method)
	}
}

func extraTools() []toolSpec {
	return []toolSpec{{
		Name:        "capx_api",
		Description: "通用 REST 转发：任意 GET/POST/DELETE /health 或 /api/*。高危写操作仍建议 CAPX_MCP_ACTIVE=1。path 例 /api/http",
		InputSchema: map[string]any{
			"type":     "object",
			"required": []string{"method", "path"},
			"properties": map[string]any{
				"method": map[string]any{"type": "string", "description": "GET POST DELETE"},
				"path":   map[string]any{"type": "string", "description": "以 /health 或 /api/ 开头"},
				"query":  map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
				"body":   map[string]any{"type": "object"},
			},
			"additionalProperties": false,
		},
	}}
}

func (s *Server) callGenericAPI(m map[string]any) (any, error) {
	method := strings.ToUpper(strArg(m, "method"))
	path := strArg(m, "path")
	parsedPath, err := url.ParseRequestURI(path)
	if err != nil || parsedPath.IsAbs() || parsedPath.Host != "" {
		return nil, fmt.Errorf("invalid API path")
	}
	routePath := parsedPath.Path
	if !strings.HasPrefix(routePath, "/api/") && routePath != "/health" && routePath != "/capx-ca.pem" {
		return nil, fmt.Errorf("path must be /health, /capx-ca.pem, or /api/...")
	}
	if strings.Contains(routePath, "..") {
		return nil, fmt.Errorf("invalid path")
	}
	q := url.Values{}
	if qm, ok := m["query"].(map[string]any); ok {
		for k, v := range qm {
			q.Set(k, fmt.Sprint(v))
		}
	}
	activeNeeded := method != "GET" && (strings.Contains(routePath, "/mem/") || strings.Contains(routePath, "/hook/") ||
		routePath == "/api/wxapkg/unpack" || routePath == "/api/proxy/lan/start" ||
		strings.Contains(routePath, "/inline") || strings.Contains(routePath, "/spoof") ||
		strings.Contains(routePath, "/wxhook") || strings.HasPrefix(routePath, "/api/wxdesk/") || strings.HasPrefix(routePath, "/api/mobile/") || routePath == "/api/runtime/shutdown" ||
		routePath == "/api/history" || strings.Contains(routePath, "/intruder") || strings.Contains(routePath, "/turbo"))
	if activeNeeded && !s.api.active {
		return nil, fmt.Errorf("this path requires CAPX_MCP_ACTIVE=1")
	}
	switch method {
	case "GET":
		return s.api.getJSON(path, q)
	case "POST":
		body := m["body"]
		if body == nil {
			body = map[string]any{}
		}
		return s.api.postJSON(withQuery(path, q), body)
	case "DELETE":
		return s.api.deleteJSON(withQuery(path, q))
	default:
		return nil, fmt.Errorf("method must be GET, POST, or DELETE")
	}
}

func withQuery(path string, query url.Values) string {
	if len(query) == 0 {
		return path
	}
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	return path + separator + query.Encode()
}
