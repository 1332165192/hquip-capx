package wxdesk

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// The host communicates through a dedicated mapped folder. The sandbox's
// capx API remains bound to loopback, and no host personal WeChat is operated.
type relayBackend struct{ root string }

// A fixed mailbox avoids delayed directory listings in Sandbox mapped folders.
// Serialize all controllers in this process so a request cannot be overwritten.
var relayCallMu sync.Mutex

type relayStatus struct {
	Session   string    `json:"session"`
	UpdatedAt time.Time `json:"updated_at"`
	Mode      string    `json:"mode"`
	Protocol  int       `json:"protocol"`
}
type relayRequest struct {
	ID        string    `json:"id"`
	Session   string    `json:"session"`
	Path      string    `json:"path"`
	Body      any       `json:"body,omitempty"`
	Method    string    `json:"method"`
	ExpiresAt time.Time `json:"expires_at"`
}
type relayResponse struct {
	Session string          `json:"session"`
	Status  int             `json:"status"`
	Data    json.RawMessage `json:"data,omitempty"`
	Image   string          `json:"image,omitempty"`
	Error   string          `json:"error,omitempty"`
}

func (b *relayBackend) status() (relayStatus, error) {
	var status relayStatus
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		var data []byte
		data, err = os.ReadFile(filepath.Join(b.root, "channel", "ready.json"))
		if err == nil {
			err = json.Unmarshal(data, &status)
		}
		if err == nil {
			break
		}
		if attempt < 3 {
			time.Sleep(25 * time.Millisecond)
		}
	}
	if err != nil {
		return status, err
	}
	age := time.Since(status.UpdatedAt)
	if status.Mode != "windows-sandbox" || status.Protocol != 2 || len(status.Session) != 32 || age > 15*time.Second || age < -5*time.Second {
		return status, fmt.Errorf("沙箱控制通道尚未就绪")
	}
	return status, nil
}
func (b *relayBackend) Available() bool { _, err := b.status(); return err == nil }
func (b *relayBackend) Environment() Environment {
	ready := b.Available()
	note := "隔离环境未连接，请先生成并启动微信沙箱；本机主号窗口不会成为目标"
	if ready {
		note = "已连接独立微信沙箱；登录和小程序选择在该环境内完成"
	}
	return Environment{Mode: "sandbox-relay", Available: ready, Root: b.root, Note: note}
}
func (b *relayBackend) call(method, path string, body any) (relayResponse, error) {
	relayCallMu.Lock()
	defer relayCallMu.Unlock()
	status, err := b.status()
	if err != nil {
		return relayResponse{}, fmt.Errorf("隔离微信未连接，请先启动沙箱")
	}
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return relayResponse{}, err
	}
	id := hex.EncodeToString(nonce)
	request := relayRequest{ID: id, Session: status.Session, Method: method, Path: path, Body: body, ExpiresAt: time.Now().UTC().Add(12 * time.Second)}
	data, err := json.Marshal(request)
	if err != nil {
		return relayResponse{}, err
	}
	outbox := filepath.Join(b.root, "channel", "responses")
	requestFile := filepath.Join(b.root, "channel", "request.json")
	responseFile := filepath.Join(outbox, id+".json")
	// Keep the mailbox's directory entry stable. The guest retries incomplete
	// JSON and acknowledges each ID only once before executing its operation.
	if err = os.WriteFile(requestFile, data, 0600); err != nil {
		return relayResponse{}, err
	}
	defer os.WriteFile(requestFile, []byte("{}"), 0600)
	defer os.Remove(responseFile)
	for time.Now().Before(request.ExpiresAt) {
		data, err := os.ReadFile(responseFile)
		if err == nil {
			var response relayResponse
			if err = json.Unmarshal(data, &response); err != nil {
				return response, err
			}
			if response.Session != status.Session {
				return response, fmt.Errorf("沙箱会话已变化，请刷新连接")
			}
			if response.Status < 200 || response.Status >= 300 {
				return response, fmt.Errorf("隔离微信: %s", response.Error)
			}
			return response, nil
		}
		if !os.IsNotExist(err) {
			return relayResponse{}, err
		}
		time.Sleep(60 * time.Millisecond)
	}
	return relayResponse{}, fmt.Errorf("沙箱操作超时；请刷新截图确认结果后再继续")
}
func (b *relayBackend) Windows() ([]Window, error) {
	result, err := b.call("GET", "/api/wxdesk/windows", nil)
	if err != nil {
		return nil, err
	}
	var response struct {
		Windows []Window `json:"windows"`
	}
	err = json.Unmarshal(result.Data, &response)
	return response.Windows, err
}
func (b *relayBackend) Launch() error {
	_, err := b.call("POST", "/api/wxdesk/launch", map[string]any{})
	return err
}
func (b *relayBackend) Show(id string) error {
	_, err := b.call("POST", "/api/wxdesk/show", map[string]any{"window_id": id})
	return err
}
func (b *relayBackend) Screenshot(id string) ([]byte, error) {
	result, err := b.call("GET", "/api/wxdesk/screenshot?window_id="+url.QueryEscape(id), nil)
	if err != nil {
		return nil, err
	}
	picture, err := base64.StdEncoding.DecodeString(result.Image)
	if err != nil || !bytes.HasPrefix(picture, []byte("\x89PNG\r\n\x1a\n")) {
		return nil, fmt.Errorf("沙箱没有返回有效 PNG 截图")
	}
	return picture, nil
}
func (b *relayBackend) Tap(id string, x, y, width, height int) error {
	_, err := b.call("POST", "/api/wxdesk/tap", map[string]any{"window_id": id, "x": x, "y": y, "width": width, "height": height})
	return err
}
func (b *relayBackend) Input(id, text string) error {
	_, err := b.call("POST", "/api/wxdesk/input", map[string]any{"window_id": id, "value": text})
	return err
}
func (b *relayBackend) Key(id, key string) error {
	_, err := b.call("POST", "/api/wxdesk/key", map[string]any{"window_id": id, "key": key})
	return err
}
func (b *relayBackend) Scroll(id string, delta int) error {
	_, err := b.call("POST", "/api/wxdesk/scroll", map[string]any{"window_id": id, "delta": delta})
	return err
}
