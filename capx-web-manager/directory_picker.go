package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

type directorySelectionRequest struct {
	Kind    string `json:"kind"`
	Initial string `json:"initial"`
}

type directorySelectionResult struct {
	Kind         string `json:"kind"`
	Path         string `json:"path"`
	InstanceID   string `json:"instance_id,omitempty"`
	ProjectBound bool   `json:"project_bound,omitempty"`
	JADXDetected bool   `json:"jadx_detected,omitempty"`
}

var directorySelector = selectNativeDirectory

func handleSelectDirectory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, "method not allowed")
		return
	}
	var request directorySelectionRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeErr(w, "bad json: "+err.Error())
		return
	}
	request.Kind = strings.ToLower(strings.TrimSpace(request.Kind))
	if request.Kind != "project" && request.Kind != "jadx" {
		writeErr(w, "directory kind must be project or jadx")
		return
	}
	description := "选择项目根目录"
	if request.Kind == "jadx" {
		description = "选择 JADX 安装或工作目录"
	}
	selected, err := directorySelector(strings.TrimSpace(request.Initial), description)
	if err != nil {
		writeErr(w, err.Error())
		return
	}
	if strings.TrimSpace(selected) == "" {
		writeOK(w, nil, "已取消选择")
		return
	}
	selected, err = canonicalSelectedDirectory(selected)
	if err != nil {
		writeErr(w, err.Error())
		return
	}

	result := directorySelectionResult{Kind: request.Kind, Path: selected}
	if request.Kind == "project" {
		result.InstanceID, result.ProjectBound, err = inspectProjectBinding(selected)
		if err != nil {
			writeErr(w, err.Error())
			return
		}
	} else {
		result.JADXDetected = jadxDirectoryDetected(selected)
	}
	writeOK(w, result, "目录已选择")
}

func canonicalSelectedDirectory(selected string) (string, error) {
	absolute, err := filepath.Abs(strings.TrimSpace(selected))
	if err != nil {
		return "", fmt.Errorf("解析所选目录: %w", err)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return "", fmt.Errorf("读取所选目录: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("所选路径不是目录: %s", absolute)
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("规范化所选目录: %w", err)
	}
	return filepath.Clean(canonical), nil
}

func inspectProjectBinding(root string) (string, bool, error) {
	paths := []struct {
		path string
		read func(string) (string, error)
	}{
		{filepath.Join(root, ".codex", "config.toml"), readProjectIDFromTOML},
		{filepath.Join(root, ".claude", "config.toml"), readProjectIDFromTOML},
		{filepath.Join(root, ".mcp.json"), readProjectIDFromMCPJSON},
	}
	ids := make([]string, 0, len(paths))
	for _, candidate := range paths {
		_, err := os.Stat(candidate.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", false, fmt.Errorf("读取项目配置: %w", err)
		}
		id, err := candidate.read(candidate.path)
		if err != nil {
			return "", false, err
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return derivedProjectInstanceID(root), false, nil
	}
	for _, id := range ids[1:] {
		if id != ids[0] {
			return "", false, errors.New("项目中的 Codex/Claude 配置绑定了不同的 CAPX_INSTANCE_ID")
		}
	}
	return ids[0], true, nil
}

func derivedProjectInstanceID(root string) string {
	base := strings.ToLower(filepath.Base(filepath.Clean(root)))
	var output strings.Builder
	lastSeparator := false
	for _, character := range base {
		valid := unicode.IsLetter(character) || unicode.IsDigit(character) || character == '.' || character == '-' || character == '_'
		if valid && character <= unicode.MaxASCII {
			output.WriteRune(character)
			lastSeparator = false
			continue
		}
		if !lastSeparator {
			output.WriteByte('_')
			lastSeparator = true
		}
	}
	id := strings.Trim(output.String(), "._-")
	if id == "" {
		id = "src_project"
	}
	if len(id) > 64 {
		id = strings.TrimRight(id[:64], "._-")
	}
	return id
}

func jadxDirectoryDetected(root string) bool {
	candidates := []string{
		filepath.Join(root, "jadx.exe"),
		filepath.Join(root, "jadx.bat"),
		filepath.Join(root, "jadx-gui.exe"),
		filepath.Join(root, "jadx-gui.bat"),
		filepath.Join(root, "bin", "jadx.bat"),
		filepath.Join(root, "bin", "jadx-gui.bat"),
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}
