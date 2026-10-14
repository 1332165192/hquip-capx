package mcp

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const protocolVersion = "2024-11-05"

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolSpec struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type textContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type imageContent struct {
	Type     string `json:"type"`
	Data     string `json:"data"`
	MIMEType string `json:"mimeType"`
}

// Screenshots must be MCP images so a vision-capable client can read pixels.
func valueResult(value any) map[string]any {
	if picture, ok := value.(imageContent); ok {
		return map[string]any{"content": []imageContent{picture}, "isError": false}
	}
	// Snapshot responses can optionally contain an embedded screenshot. Keep
	// the element metadata in text and expose its screenshot as an image block.
	if snapshot, ok := value.(map[string]any); ok {
		if encoded, ok := snapshot["screenshot_base64"].(string); ok && encoded != "" {
			if decoded, err := base64.StdEncoding.DecodeString(encoded); err == nil && len(decoded) >= 8 && string(decoded[:8]) == "\x89PNG\r\n\x1a\n" {
				metadata := make(map[string]any, len(snapshot)-1)
				for key, item := range snapshot {
					if key != "screenshot_base64" {
						metadata[key] = item
					}
				}
				return map[string]any{"content": []any{textContent{Type: "text", Text: jsonText(metadata)}, imageContent{Type: "image", Data: encoded, MIMEType: "image/png"}}, "isError": false}
			}
		}
	}
	return textResult(jsonText(value), false)
}

func writeRPC(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

func reply(w io.Writer, id json.RawMessage, result any) error {
	if len(id) == 0 {
		return nil
	}
	return writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: id, Result: result})
}

func replyErr(w io.Writer, id json.RawMessage, code int, msg string) error {
	if len(id) == 0 {
		return nil
	}
	return writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}})
}

func textResult(text string, isError bool) map[string]any {
	return map[string]any{
		"content": []textContent{{Type: "text", Text: text}},
		"isError": isError,
	}
}

func jsonText(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

func serveStdio(s *Server, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 16<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			_ = writeRPC(out, rpcResponse{
				JSONRPC: "2.0",
				Error:   &rpcError{Code: -32700, Message: "parse error: " + err.Error()},
			})
			continue
		}
		if err := s.handle(out, req); err != nil {
			fmt.Fprintf(os.Stderr, "capx-mcp: %v\n", err)
		}
	}
	return sc.Err()
}
