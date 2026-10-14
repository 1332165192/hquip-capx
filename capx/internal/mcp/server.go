package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Server is a stdio MCP adapter over the capx REST API.
type Server struct {
	api *apiClient
}

func New() *Server { return &Server{api: newAPIClient()} }

func (s *Server) Serve(in io.Reader, out io.Writer) error {
	return serveStdio(s, in, out)
}

func (s *Server) tools() []toolSpec {
	routes := allRoutes()
	out := make([]toolSpec, 0, len(routes)+1)
	for _, r := range routes {
		if s.api.isolatedWeChat && r.Name != "capx_health" && !strings.HasPrefix(r.Name, "capx_wxdesk_") {
			continue
		}
		out = append(out, catalogTool(r))
	}
	if !s.api.isolatedWeChat {
		out = append(out, extraTools()...)
	}
	return out
}

func (s *Server) handle(out io.Writer, req rpcRequest) error {
	switch req.Method {
	case "initialize":
		instructions := "capx tools map the captured REST API. captured must already be running. CAPX_API selects the backend; CAPX_TOKEN or CAPX_TOKEN_FILE selects its credentials. Mutating tools require CAPX_MCP_ACTIVE=1."
		if s.api.isolatedWeChat {
			instructions = "隔离微信模式只暴露 capx_wxdesk_* 与健康检查。先检查 environment，再枚举隔离窗口并读取截图。窗口出现不等于登录成功。每步使用最新截图定位并检查结果；不得操作宿主微信。登录由用户通过官方流程确认。"
		}
		return reply(out, req.ID, map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "capx", "version": Version},
			"instructions":    instructions,
		})
	case "notifications/initialized", "initialized":
		return nil
	case "ping":
		return reply(out, req.ID, map[string]any{})
	case "tools/list":
		return reply(out, req.ID, map[string]any{"tools": s.tools()})
	case "tools/call":
		var p callParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return replyErr(out, req.ID, -32602, "bad tools/call params")
		}
		value, err := s.callValue(p.Name, p.Arguments)
		if err != nil {
			return reply(out, req.ID, textResult(err.Error(), true))
		}
		return reply(out, req.ID, valueResult(value))
	case "resources/list":
		return reply(out, req.ID, map[string]any{"resources": []any{}})
	case "prompts/list":
		return reply(out, req.ID, map[string]any{"prompts": []any{}})
	default:
		if strings.HasPrefix(req.Method, "notifications/") {
			return nil
		}
		return replyErr(out, req.ID, -32601, "method not found: "+req.Method)
	}
}

func (s *Server) call(name string, args json.RawMessage) (string, bool) {
	v, err := s.callValue(name, args)
	if err != nil {
		return err.Error(), true
	}
	return jsonText(v), false
}

func (s *Server) callValue(name string, args json.RawMessage) (any, error) {
	if s.api.isolatedWeChat && name != "capx_health" && !strings.HasPrefix(name, "capx_wxdesk_") {
		return nil, fmt.Errorf("隔离微信模式仅允许 capx_wxdesk_* 工具，不允许操作宿主微信或通用 API")
	}
	var m map[string]any
	if len(args) > 0 && string(args) != "null" {
		if err := json.Unmarshal(args, &m); err != nil {
			return nil, fmt.Errorf("invalid tool arguments: %w", err)
		}
	}
	if m == nil {
		m = map[string]any{}
	}
	var (
		v   any
		err error
	)
	if name == "capx_api" {
		v, err = s.callGenericAPI(m)
	} else if r, ok := findRoute(name); ok {
		v, err = s.dispatchRoute(r, m)
	} else {
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
	if err != nil {
		return nil, err
	}
	return v, nil
}

func strArg(m map[string]any, k string) string {
	v, ok := m[k]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	default:
		return strings.TrimSpace(fmt.Sprint(t))
	}
}

func intArg(m map[string]any, k string, def int) int {
	v, ok := m[k]
	if !ok || v == nil {
		return def
	}
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case json.Number:
		n, _ := t.Int64()
		return int(n)
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(t))
		if err != nil {
			return def
		}
		return n
	}
	return def
}

func boolArg(m map[string]any, k string) bool {
	v, ok := m[k]
	if !ok || v == nil {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return envTruthy(t)
	}
	return false
}

func firstMethod(raw string) string {
	line := raw
	if i := strings.IndexAny(raw, "\r\n"); i >= 0 {
		line = raw[:i]
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return strings.ToUpper(fields[0])
}

func safeMethod(m string) bool {
	switch strings.ToUpper(m) {
	case "GET", "HEAD", "OPTIONS", "POST":
		return true
	}
	return false
}

func clipHTTP(v any) any {
	obj, ok := v.(map[string]any)
	if !ok {
		return v
	}
	const capN = 64 << 10
	for _, k := range []string{"req_raw", "resp_raw"} {
		s, _ := obj[k].(string)
		if len(s) > capN {
			obj[k] = s[:capN] + fmt.Sprintf("\n... [%d more bytes truncated by capx-mcp]", len(s)-capN)
		}
	}
	return obj
}
