package mobile

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// CaptureInfo describes routing, not successful HTTPS decryption or CA trust.
type CaptureInfo struct {
	Serial  string `json:"serial"`
	Proxy   string `json:"proxy"`
	Reverse string `json:"reverse"`
	CANote  string `json:"ca_note,omitempty"`
}

type captureSession struct {
	port          int
	previousProxy string
	proxyOwned    bool
	reverseOwned  bool
}

func captureInfo(serial string, port int) CaptureInfo {
	p := strconv.Itoa(port)
	return CaptureInfo{Serial: serial, Proxy: "127.0.0.1:" + p, Reverse: "tcp:" + p + " -> tcp:" + p}
}

// StartCapture saves the previous proxy and only owns tunnels it creates.
// Certificate installation still requires the device user's confirmation;
// routing does not imply that the app trusts the CA or uses the global proxy.
func (c *Controller) StartCapture(proxyPort int, caPEM []byte) (CaptureInfo, error) {
	if proxyPort <= 0 || proxyPort > 65535 {
		return CaptureInfo{}, fmt.Errorf("proxy_port 无效: %d", proxyPort)
	}
	c.shared().captureMu.Lock()
	defer c.shared().captureMu.Unlock()
	serial, err := c.Serial()
	if err != nil {
		return CaptureInfo{}, err
	}
	if session := c.shared().captures[serial]; session != nil && session.port != proxyPort {
		return CaptureInfo{}, fmt.Errorf("设备已有端口 %d 的抓包会话，请先停止", session.port)
	}
	previous, err := c.readProxy(serial)
	if err != nil {
		return CaptureInfo{}, err
	}
	remote := "tcp:" + strconv.Itoa(proxyPort)
	target, err := c.reverseTarget(serial, remote)
	if err != nil {
		return CaptureInfo{}, err
	}
	info := captureInfo(serial, proxyPort)
	if session := c.shared().captures[serial]; session != nil {
		if previous != info.Proxy || target != remote {
			return CaptureInfo{}, fmt.Errorf("抓包配置已变化，请先停止旧会话再启动")
		}
	} else {
		if target != "" && target != remote {
			return CaptureInfo{}, fmt.Errorf("%s 已被其它 reverse 占用（%s）", remote, target)
		}
		session := &captureSession{port: proxyPort, previousProxy: previous}
		if target == "" {
			if _, err := c.run(serial, "reverse", "--no-rebind", remote, remote); err != nil {
				return CaptureInfo{}, fmt.Errorf("adb reverse 失败: %w", err)
			}
			session.reverseOwned = true
		}
		if c.shared().captures == nil {
			c.shared().captures = make(map[string]*captureSession)
		}
		c.shared().captures[serial] = session
		if previous != info.Proxy {
			session.proxyOwned = true
			if _, err := c.run(serial, "shell", "settings", "put", "global", "http_proxy", info.Proxy); err != nil {
				cleanupErr := c.stopCaptureLocked(serial)
				return CaptureInfo{}, errors.Join(fmt.Errorf("设置设备代理失败: %w", err), cleanupErr)
			}
		}
	}
	if len(caPEM) > 0 {
		if note, err := c.pushCA(serial, caPEM); err != nil {
			info.CANote = "CA 推送失败：" + err.Error()
		} else {
			info.CANote = note
		}
	}
	return info, nil
}

// StopCapture restores this controller's session. Port zero uses the saved
// port. Without a session it is a no-op, leaving other tools' settings intact.
func (c *Controller) StopCapture(proxyPort int) error {
	if proxyPort < 0 || proxyPort > 65535 {
		return fmt.Errorf("proxy_port 无效: %d", proxyPort)
	}
	c.shared().captureMu.Lock()
	defer c.shared().captureMu.Unlock()
	serial, err := c.Serial()
	if err != nil {
		return err
	}
	if session := c.shared().captures[serial]; session != nil && proxyPort != 0 && session.port != proxyPort {
		return fmt.Errorf("抓包会话端口为 %d，不能停止端口 %d", session.port, proxyPort)
	}
	return c.stopCaptureLocked(serial)
}

func (c *Controller) stopCaptureLocked(serial string) error {
	session := c.shared().captures[serial]
	if session == nil {
		return nil
	}
	if session.proxyOwned {
		current, err := c.readProxy(serial)
		if err != nil {
			return err // Keep the tunnel until proxy restoration can be attempted.
		}
		if current == captureInfo(serial, session.port).Proxy {
			var err error
			if session.previousProxy == "" {
				_, err = c.run(serial, "shell", "settings", "delete", "global", "http_proxy")
			} else {
				_, err = c.run(serial, "shell", "settings", "put", "global", "http_proxy", shellQuote(session.previousProxy))
			}
			if err != nil {
				return fmt.Errorf("恢复设备代理: %w", err)
			}
		}
		// Another tool's replacement proxy must not be overwritten.
		session.proxyOwned = false
	}
	if session.reverseOwned {
		remote := "tcp:" + strconv.Itoa(session.port)
		target, err := c.reverseTarget(serial, remote)
		if err != nil {
			return err
		}
		if target == remote {
			if _, err := c.run(serial, "reverse", "--remove", remote); err != nil {
				return fmt.Errorf("移除 reverse: %w", err)
			}
		}
		session.reverseOwned = false
	}
	delete(c.shared().captures, serial)
	return nil
}

// Close restores all sessions, even if the selected device has since changed.
func (c *Controller) Close() error {
	c.shared().captureMu.Lock()
	defer c.shared().captureMu.Unlock()
	var errs []error
	for serial := range c.shared().captures {
		if err := c.stopCaptureLocked(serial); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", serial, err))
		}
	}
	return errors.Join(errs...)
}

func (c *Controller) readProxy(serial string) (string, error) {
	proxy, err := c.run(serial, "shell", "settings", "get", "global", "http_proxy")
	if err != nil {
		return "", fmt.Errorf("读取设备代理: %w", err)
	}
	proxy = strings.TrimSpace(proxy)
	if proxy == "null" {
		proxy = ""
	}
	return proxy, nil
}

func (c *Controller) reverseTarget(serial, remote string) (string, error) {
	out, err := c.run(serial, "reverse", "--list")
	if err != nil {
		return "", fmt.Errorf("读取 reverse: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[len(fields)-2] == remote {
			return fields[len(fields)-1], nil
		}
	}
	return "", nil
}

// Status verifies both loopback proxy configuration and the matching reverse.
// wired reports routing only; it cannot verify listener availability or CA trust.
func (c *Controller) Status() (map[string]any, error) {
	c.shared().captureMu.Lock()
	defer c.shared().captureMu.Unlock()
	serial, err := c.Serial()
	if err != nil {
		return nil, err
	}
	proxy, err := c.readProxy(serial)
	if err != nil {
		return nil, err
	}
	status := map[string]any{"serial": serial, "proxy": proxy, "wired": false, "reverse": "", "managed": c.shared().captures[serial] != nil}
	host, p, err := net.SplitHostPort(proxy)
	port, portErr := strconv.Atoi(p)
	if err != nil || portErr != nil || port <= 0 || port > 65535 || host != "127.0.0.1" {
		return status, nil
	}
	remote := "tcp:" + p
	target, err := c.reverseTarget(serial, remote)
	if err != nil {
		return nil, err
	}
	status["reverse"] = target
	status["wired"] = target == remote
	return status, nil
}

// InstallCA opens the device's certificate settings without changing routing.
func (c *Controller) InstallCA(caPEM []byte) (string, error) {
	if len(caPEM) == 0 {
		return "", fmt.Errorf("CA 证书为空")
	}
	c.shared().uiMu.Lock()
	defer c.shared().uiMu.Unlock()
	serial, err := c.Serial()
	if err != nil {
		return "", err
	}
	return c.pushCA(serial, caPEM)
}

func (c *Controller) pushCA(serial string, caPEM []byte) (string, error) {
	const remote = "/sdcard/Download/capx-ca.crt"
	tmp := writeTempCA(caPEM)
	if tmp == "" {
		return "", fmt.Errorf("写入临时 CA 文件失败")
	}
	defer removeTempCA(tmp)
	if _, err := c.run(serial, "push", tmp, remote); err != nil {
		return "", err
	}
	note := "CA 已推送到 " + remote + "，请在手机安全设置中安装；用户证书不保证被目标 App 信任，证书固定需另行处理"
	if _, err := c.run(serial, "shell", "am", "start", "-a", "android.settings.SECURITY_SETTINGS"); err != nil {
		note += "；无法打开安全设置，请手动打开"
	}
	return note, nil
}
