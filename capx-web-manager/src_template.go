package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
)

// srcSessionTemplateText is provided per platform (see src_template_windows.go /
// src_template_other.go): PowerShell on Windows, bash on other platforms.
var srcSessionTemplate = template.Must(template.New("src-session-template").Parse(srcSessionTemplateText))

type srcTemplateRequest struct {
	RuntimeAPIPort int    `json:"runtime_api_port"`
	InstanceID     string `json:"instance_id"`
	ProjectRoot    string `json:"project_root"`
	JADXDir        string `json:"jadx_dir"`
	APIPort        int    `json:"api_port"`
	ProxyPort      int    `json:"proxy_port"`
	CDPPort        int    `json:"cdp_port"`
}

type srcTemplateData struct {
	Source       string
	Mode         string
	InstanceID   string
	ProjectRoot  string
	JADXDir      string
	APIPort      int
	ProxyPort    int
	CDPPort      int
	StateDir     string
	TokenFile    string
	Token        string
	ManifestPath string
}

type srcTemplateResult struct {
	Text         string `json:"text"`
	Source       string `json:"source"`
	Mode         string `json:"mode"`
	InstanceID   string `json:"instance_id"`
	APIPort      int    `json:"api_port"`
	ProxyPort    int    `json:"proxy_port"`
	CDPPort      int    `json:"cdp_port"`
	TokenReady   bool   `json:"token_ready"`
	ProjectReady bool   `json:"project_ready"`
}

var srcTemplateInstanceLister = getInstances

func handleSRCTemplate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, "method not allowed")
		return
	}
	var request srcTemplateRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeErr(w, "bad json: "+err.Error())
		return
	}

	data, err := resolveSRCTemplateData(request)
	if err != nil {
		writeErr(w, err.Error())
		return
	}
	text, err := renderSRCTemplate(data)
	if err != nil {
		writeErr(w, err.Error())
		return
	}
	writeOK(w, srcTemplateResult{
		Text:         text,
		Source:       data.Source,
		Mode:         data.Mode,
		InstanceID:   data.InstanceID,
		APIPort:      data.APIPort,
		ProxyPort:    data.ProxyPort,
		CDPPort:      data.CDPPort,
		TokenReady:   data.Token != "",
		ProjectReady: projectRootExists(data.ProjectRoot),
	}, "SRC 模板已生成")
}

func resolveSRCTemplateData(request srcTemplateRequest) (srcTemplateData, error) {
	if request.RuntimeAPIPort > 0 {
		current := loadConfig()
		rows, err := srcTemplateInstanceLister(current.CapturedPath, false)
		if err != nil {
			return srcTemplateData{}, fmt.Errorf("读取运行实例: %w", err)
		}
		for _, row := range rows {
			if row.APIPort != request.RuntimeAPIPort {
				continue
			}
			id := strings.TrimSpace(row.InstanceID)
			if id == "" {
				id = defaultSRCInstanceID(row.APIPort)
			}
			tokenFile := ""
			if row.StateDir != "" {
				tokenFile = filepath.Join(row.StateDir, "token")
			}
			mode := "legacy"
			if row.InstanceID != "" && row.ProjectDir != "" && row.CDPPort > 0 {
				mode = "managed"
			}
			return normalizeSRCTemplateData(srcTemplateData{
				Source:       "runtime",
				Mode:         mode,
				InstanceID:   id,
				ProjectRoot:  row.ProjectDir,
				JADXDir:      strings.TrimSpace(request.JADXDir),
				APIPort:      row.APIPort,
				ProxyPort:    row.ProxyPort,
				CDPPort:      row.CDPPort,
				StateDir:     row.StateDir,
				TokenFile:    tokenFile,
				Token:        strings.TrimSpace(row.Token),
				ManifestPath: row.Manifest,
			})
		}
		return srcTemplateData{}, fmt.Errorf("未找到 API 端口 %d 对应的运行实例", request.RuntimeAPIPort)
	}

	rawID := strings.TrimSpace(request.InstanceID)
	rawRoot := strings.TrimSpace(request.ProjectRoot)
	if (rawID == "") != (rawRoot == "") {
		return srcTemplateData{}, errors.New("受管模式需要同时填写实例 ID 和项目根；legacy 模式请将两项都留空")
	}
	mode := "legacy"
	id := rawID
	cdpPort := 0
	if rawID != "" && rawRoot != "" {
		mode = "managed"
		cdpPort = request.CDPPort
	}
	if id == "" {
		id = defaultSRCInstanceID(request.APIPort)
	}
	return normalizeSRCTemplateData(srcTemplateData{
		Source:      "form",
		Mode:        mode,
		InstanceID:  id,
		ProjectRoot: rawRoot,
		JADXDir:     strings.TrimSpace(request.JADXDir),
		APIPort:     request.APIPort,
		ProxyPort:   request.ProxyPort,
		CDPPort:     cdpPort,
	})
}

func normalizeSRCTemplateData(data srcTemplateData) (srcTemplateData, error) {
	if err := validateInstanceID(data.InstanceID); err != nil {
		return srcTemplateData{}, err
	}
	if data.Mode == "" {
		if data.ProjectRoot != "" && data.CDPPort > 0 {
			data.Mode = "managed"
		} else {
			data.Mode = "legacy"
		}
	}
	if data.Mode != "managed" && data.Mode != "legacy" {
		return srcTemplateData{}, errors.New("模板模式需要是 managed 或 legacy")
	}
	if data.Mode == "legacy" {
		data.CDPPort = 0
	}
	automaticManagedPorts := data.Source == "form" && data.Mode == "managed" &&
		data.APIPort == 0 && data.ProxyPort == 0 && data.CDPPort == 0
	if !automaticManagedPorts {
		if !validTCPPort(data.APIPort) {
			return srcTemplateData{}, errors.New("API 端口需要填写 1-65535")
		}
		if !validTCPPort(data.ProxyPort) {
			return srcTemplateData{}, errors.New("代理端口需要填写 1-65535")
		}
	}
	if data.CDPPort < 0 || data.CDPPort > 65535 {
		return srcTemplateData{}, errors.New("CDP 端口需要填写 1-65535，或留空自动分配")
	}
	ports := []int{data.APIPort, data.ProxyPort}
	if data.CDPPort > 0 {
		ports = append(ports, data.CDPPort)
	}
	seen := map[int]struct{}{}
	for _, port := range ports {
		if port <= 0 {
			continue
		}
		if _, exists := seen[port]; exists {
			return srcTemplateData{}, errors.New("API、Proxy 和 CDP 端口需要彼此独立")
		}
		seen[port] = struct{}{}
	}
	if data.Source == "" {
		data.Source = "form"
	}
	if data.ProjectRoot != "" {
		absolute, err := filepath.Abs(data.ProjectRoot)
		if err != nil {
			return srcTemplateData{}, fmt.Errorf("解析项目根: %w", err)
		}
		data.ProjectRoot = filepath.Clean(absolute)
	}
	if data.JADXDir != "" {
		absolute, err := filepath.Abs(data.JADXDir)
		if err != nil {
			return srcTemplateData{}, fmt.Errorf("解析 JADX 目录: %w", err)
		}
		data.JADXDir = filepath.Clean(absolute)
	}
	return data, nil
}

func validTCPPort(port int) bool { return port > 0 && port <= 65535 }

func defaultSRCInstanceID(apiPort int) string {
	if validTCPPort(apiPort) {
		return fmt.Sprintf("src_%d", apiPort)
	}
	return "src_project"
}

func renderSRCTemplate(data srcTemplateData) (string, error) {
	normalized, err := normalizeSRCTemplateData(data)
	if err != nil {
		return "", err
	}
	data = normalized

	projectRoot := data.ProjectRoot
	if projectRoot == "" {
		projectRoot = "<PROJECT_ROOT>"
	}
	runtimeReady := data.Token != "" && data.StateDir != "" && data.TokenFile != ""
	stage := "启动前"
	if runtimeReady {
		stage = "运行实例"
	}

	view := struct {
		Source          string
		Mode            string
		Stage           string
		InstanceID      string
		InstanceIDPS    string
		InstanceIDSh    string
		InstanceIDJSON  string
		ProjectRoot     string
		ProjectRootPS   string
		ProjectRootSh   string
		ProjectRootJSON string
	}{
		Source:          data.Source,
		Mode:            data.Mode,
		Stage:           stage,
		InstanceID:      data.InstanceID,
		InstanceIDPS:    powerShellLiteral(data.InstanceID),
		InstanceIDSh:    shellSingleQuote(data.InstanceID),
		InstanceIDJSON:  strconv.Quote(data.InstanceID),
		ProjectRoot:     projectRoot,
		ProjectRootPS:   powerShellLiteral(projectRoot),
		ProjectRootSh:   shellSingleQuote(projectRoot),
		ProjectRootJSON: strconv.Quote(projectRoot),
	}

	var output strings.Builder
	if err := srcSessionTemplate.Execute(&output, view); err != nil {
		return "", fmt.Errorf("render SRC session template: %w", err)
	}
	return output.String(), nil
}

func cdpDisplay(port int) string {
	if port > 0 {
		return strconv.Itoa(port)
	}
	return "自动"
}

func cdpTemplateDisplay(data srcTemplateData) string {
	if data.Mode == "legacy" {
		return "未启用"
	}
	return cdpDisplay(data.CDPPort)
}

func powerShellLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

// shellSingleQuote wraps value in a POSIX single-quoted literal, escaping any
// embedded single quote as '\'' so it is safe to paste into a bash command.
func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func projectRootExists(root string) bool {
	if strings.TrimSpace(root) == "" {
		return false
	}
	info, err := os.Stat(root)
	return err == nil && info.IsDir()
}
