package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	instanceManifestSchemaVersion = 1
	maxInstanceManifestBytes      = 64 * 1024
	maxProjectConfigBytes         = 1024 * 1024
	manifestLockTimeout           = 5 * time.Second
)

var (
	instanceIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	projectIDPattern     = regexp.MustCompile(`(?m)^\s*CAPX_INSTANCE_ID\s*=\s*(?:"([^"]+)"|'([^']+)')\s*(?:#.*)?$`)
	manifestProcessLocks = struct {
		sync.Mutex
		entries map[string]*manifestProcessLock
	}{entries: make(map[string]*manifestProcessLock)}
)

type manifestProcessLock struct {
	mutex sync.Mutex
	refs  int
}

// instanceManifest is schema version 1 consumed by
// framework/runtime/capx-instance.mjs. PID is an additive lifecycle field: the
// JavaScript reader ignores it, while the manager uses it with generation to
// avoid deleting a manifest published by a replacement process.
type instanceManifest struct {
	SchemaVersion    int    `json:"schema_version"`
	InstanceID       string `json:"instance_id"`
	ProjectRoot      string `json:"project_root"`
	APIBase          string `json:"api_base"`
	Proxy            string `json:"proxy"`
	StateDir         string `json:"state_dir"`
	TokenFile        string `json:"token_file"`
	CDPPort          int    `json:"cdp_port"`
	IdentityRequired bool   `json:"identity_required,omitempty"`
	PID              int    `json:"pid,omitempty"`
	BrowserPID       int    `json:"browser_pid,omitempty"`
	ProcessStartedAt string `json:"process_started_at,omitempty"`
	Generation       string `json:"generation"`
	UpdatedAt        string `json:"updated_at"`
}

// validateManagedProject returns the canonical project root after confirming
// that its Codex or Claude project configuration selects exactly id.
func validateManagedProject(id, root string) (string, error) {
	if err := validateInstanceID(id); err != nil {
		return "", err
	}
	if strings.TrimSpace(root) == "" {
		return "", errors.New("project root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve project root: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("stat project root: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("project root is not a directory: %s", abs)
	}
	canonical, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("canonicalize project root: %w", err)
	}

	configPaths := []string{
		filepath.Join(canonical, ".codex", "config.toml"),
		filepath.Join(canonical, ".claude", "config.toml"),
	}
	configuredIDs := []string{}
	configuredPaths := []string{}
	for _, configPath := range configPaths {
		if _, statErr := os.Stat(configPath); errors.Is(statErr, os.ErrNotExist) {
			continue
		} else if statErr != nil {
			return "", fmt.Errorf("stat project config: %w", statErr)
		}
		configured, parseErr := readProjectIDFromTOML(configPath)
		if parseErr != nil {
			return "", parseErr
		}
		configuredIDs = append(configuredIDs, configured)
		configuredPaths = append(configuredPaths, configPath)
	}

	mcpPath := filepath.Join(canonical, ".mcp.json")
	if _, statErr := os.Stat(mcpPath); statErr == nil {
		configured, parseErr := readProjectIDFromMCPJSON(mcpPath)
		if parseErr != nil {
			return "", parseErr
		}
		configuredIDs = append(configuredIDs, configured)
		configuredPaths = append(configuredPaths, mcpPath)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", fmt.Errorf("stat project MCP config: %w", statErr)
	}

	if len(configuredIDs) == 0 {
		return "", fmt.Errorf("CAPX_INSTANCE_ID project config is missing under %s", canonical)
	}
	for index, configured := range configuredIDs {
		if configured != id {
			return "", fmt.Errorf("project CAPX_INSTANCE_ID %q in %s does not match %q", configured, configuredPaths[index], id)
		}
	}
	return filepath.Clean(canonical), nil
}

func readProjectIDFromTOML(configPath string) (string, error) {
	config, err := readBoundedRegularFile(configPath, maxProjectConfigBytes)
	if err != nil {
		return "", fmt.Errorf("read project config: %w", err)
	}
	config = bytes.TrimPrefix(config, []byte{0xef, 0xbb, 0xbf})
	matches := projectIDPattern.FindAllSubmatch(config, -1)
	if len(matches) == 0 {
		return "", fmt.Errorf("CAPX_INSTANCE_ID is missing from %s", configPath)
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("CAPX_INSTANCE_ID must occur exactly once in %s", configPath)
	}
	configured := string(matches[0][1])
	if configured == "" {
		configured = string(matches[0][2])
	}
	configured = strings.TrimSpace(configured)
	if err := validateInstanceID(configured); err != nil {
		return "", fmt.Errorf("invalid project CAPX_INSTANCE_ID: %w", err)
	}
	return configured, nil
}

func readProjectIDFromMCPJSON(configPath string) (string, error) {
	config, err := readBoundedRegularFile(configPath, maxProjectConfigBytes)
	if err != nil {
		return "", fmt.Errorf("read project MCP config: %w", err)
	}
	config = bytes.TrimPrefix(config, []byte{0xef, 0xbb, 0xbf})
	var document struct {
		MCPServers map[string]struct {
			Env map[string]json.RawMessage `json:"env"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(config, &document); err != nil {
		return "", fmt.Errorf("parse project MCP config %s: %w", configPath, err)
	}
	configuredIDs := []string{}
	for serverName, server := range document.MCPServers {
		raw, exists := server.Env["CAPX_INSTANCE_ID"]
		if !exists {
			continue
		}
		var configured string
		if err := json.Unmarshal(raw, &configured); err != nil {
			return "", fmt.Errorf("CAPX_INSTANCE_ID for MCP server %q in %s must be a string", serverName, configPath)
		}
		configured = strings.TrimSpace(configured)
		if err := validateInstanceID(configured); err != nil {
			return "", fmt.Errorf("invalid project CAPX_INSTANCE_ID in %s: %w", configPath, err)
		}
		configuredIDs = append(configuredIDs, configured)
	}
	if len(configuredIDs) == 0 {
		return "", fmt.Errorf("CAPX_INSTANCE_ID is missing from %s", configPath)
	}
	if len(configuredIDs) != 1 {
		return "", fmt.Errorf("CAPX_INSTANCE_ID must occur exactly once in %s", configPath)
	}
	return configuredIDs[0], nil
}

// loadInstanceManifest reads and validates one manifest from the configured
// registry. Schema-1 manifests created by the framework before PID support are
// accepted, but cannot pass PID-guarded removal.
func loadInstanceManifest(id string) (instanceManifest, error) {
	path, err := instanceManifestPath(id)
	if err != nil {
		return instanceManifest{}, err
	}
	return loadInstanceManifestAt(path, id, false)
}

// writeInstanceManifest validates and atomically publishes a live instance.
// The temporary file is created in the registry directory, flushed, closed,
// and renamed over the destination. Token contents are never represented by
// the schema or written to the registry.
func writeInstanceManifest(manifest instanceManifest) error {
	canonical, err := validateManagedProject(manifest.InstanceID, manifest.ProjectRoot)
	if err != nil {
		return err
	}
	manifest.ProjectRoot = canonical
	// Records published by the manager require the runtime health endpoint to
	// prove both the instance ID and generation. Legacy records may omit this
	// additive field and remain readable.
	manifest.IdentityRequired = true
	if err := validateInstanceManifest(manifest, true); err != nil {
		return err
	}

	target, err := instanceManifestPath(manifest.InstanceID)
	if err != nil {
		return err
	}
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create instance registry: %w", err)
	}
	releaseLock, err := acquireManifestIOLock(manifest.InstanceID)
	if err != nil {
		return err
	}
	defer releaseLock()
	return publishInstanceManifestLocked(target, manifest)
}

func publishInstanceManifestLocked(target string, manifest instanceManifest) error {
	dir := filepath.Dir(target)
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal instance manifest: %w", err)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(dir, "."+manifest.InstanceID+".*.tmp")
	if err != nil {
		return fmt.Errorf("create manifest temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("secure manifest temporary file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write manifest temporary file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("flush manifest temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close manifest temporary file: %w", err)
	}
	if err := renameWithRetry(tmpPath, target); err != nil {
		return fmt.Errorf("publish instance manifest: %w", err)
	}
	committed = true
	return syncRegistryDirectory(dir)
}

// reserveInstanceManifestIfMatch converts a stopped live manifest into an
// offline reservation without losing its port and state mapping. The match is
// checked under the same manifest lock used by writers, so a replacement live
// generation is never overwritten by a concurrent stop.
func reserveInstanceManifestIfMatch(live instanceManifest) (bool, error) {
	canonical, err := validateManagedProject(live.InstanceID, live.ProjectRoot)
	if err != nil {
		return false, err
	}
	target, err := instanceManifestPath(live.InstanceID)
	if err != nil {
		return false, err
	}
	releaseLock, err := acquireManifestIOLock(live.InstanceID)
	if err != nil {
		return false, err
	}
	defer releaseLock()

	current, err := loadInstanceManifestAt(target, live.InstanceID, false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if current.Generation != live.Generation || current.PID != live.PID {
		return false, nil
	}
	reservation := current
	reservation.ProjectRoot = canonical
	reservation.IdentityRequired = false
	reservation.PID = 0
	reservation.BrowserPID = 0
	reservation.ProcessStartedAt = ""
	reservation.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := validateInstanceManifest(reservation, false); err != nil {
		return false, err
	}
	if err := publishInstanceManifestLocked(target, reservation); err != nil {
		return false, err
	}
	return true, nil
}

// removeInstanceManifestIfMatch removes exactly the manifest identified by
// generation and PID. Writers and removers serialize on an OS-backed lock, so
// the checked path cannot be replaced by another manager between validation
// and removal.
func removeInstanceManifestIfMatch(id, generation string, pid int) (bool, error) {
	if err := validateInstanceID(id); err != nil {
		return false, err
	}
	if strings.TrimSpace(generation) == "" {
		return false, errors.New("generation is required for manifest removal")
	}
	if pid <= 0 {
		return false, errors.New("positive PID is required for manifest removal")
	}

	target, err := instanceManifestPath(id)
	if err != nil {
		return false, err
	}
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, fmt.Errorf("create instance registry: %w", err)
	}
	releaseLock, err := acquireManifestIOLock(id)
	if err != nil {
		return false, err
	}
	defer releaseLock()

	manifest, err := loadInstanceManifestAt(target, id, false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if manifest.Generation != generation || manifest.PID != pid {
		return false, nil
	}
	if err := os.Remove(target); err != nil {
		return false, fmt.Errorf("remove instance manifest: %w", err)
	}
	return true, syncRegistryDirectory(dir)
}

func acquireManifestIOLock(id string) (func(), error) {
	dir, err := instanceRegistryDirectory()
	if err != nil {
		return nil, err
	}
	lockPath := filepath.Join(dir, "."+id+".manifest.lock")
	releaseProcessLock := acquireManifestProcessLock(id)
	// Publishing includes file and directory fsync calls. Concurrent writers
	// queue in-process before competing for the cross-process file lock.
	deadline := time.Now().Add(manifestLockTimeout)
	for {
		file, unlock, lockErr := acquireLifecycleFileLock(lockPath)
		if lockErr == nil {
			return func() {
				_ = unlock()
				_ = file.Close()
				releaseProcessLock()
			}, nil
		}
		if !errors.Is(lockErr, errLifecycleLockBusy) || time.Now().After(deadline) {
			releaseProcessLock()
			return nil, fmt.Errorf("acquire manifest lock: %w", lockErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func acquireManifestProcessLock(id string) func() {
	manifestProcessLocks.Lock()
	entry := manifestProcessLocks.entries[id]
	if entry == nil {
		entry = &manifestProcessLock{}
		manifestProcessLocks.entries[id] = entry
	}
	entry.refs++
	manifestProcessLocks.Unlock()

	entry.mutex.Lock()
	var once sync.Once
	return func() {
		once.Do(func() {
			manifestProcessLocks.Lock()
			entry.refs--
			if entry.refs == 0 && manifestProcessLocks.entries[id] == entry {
				delete(manifestProcessLocks.entries, id)
			}
			entry.mutex.Unlock()
			manifestProcessLocks.Unlock()
		})
	}
}

func loadInstanceManifestAt(path, expectedID string, requirePID bool) (instanceManifest, error) {
	data, err := readBoundedRegularFile(path, maxInstanceManifestBytes)
	if err != nil {
		return instanceManifest{}, err
	}
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return instanceManifest{}, fmt.Errorf("parse instance manifest: %w", err)
	}
	for key := range fields {
		normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "_", ""), "-", ""))
		if strings.Contains(normalized, "token") && key != "token_file" {
			return instanceManifest{}, fmt.Errorf("manifest contains forbidden token content field %q", key)
		}
	}

	var manifest instanceManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return instanceManifest{}, fmt.Errorf("decode instance manifest: %w", err)
	}
	if manifest.InstanceID != expectedID {
		return instanceManifest{}, fmt.Errorf("manifest instance_id %q does not match %q", manifest.InstanceID, expectedID)
	}
	if err := validateInstanceManifest(manifest, requirePID); err != nil {
		return instanceManifest{}, err
	}
	if filepath.Clean(manifest.ProjectRoot) != manifest.ProjectRoot {
		return instanceManifest{}, errors.New("manifest project_root must be clean")
	}
	return manifest, nil
}

func validateInstanceManifest(manifest instanceManifest, requirePID bool) error {
	if manifest.SchemaVersion != instanceManifestSchemaVersion {
		return fmt.Errorf("unsupported manifest schema %d", manifest.SchemaVersion)
	}
	if err := validateInstanceID(manifest.InstanceID); err != nil {
		return err
	}
	if !filepath.IsAbs(manifest.ProjectRoot) {
		return errors.New("project_root must be absolute")
	}
	apiPort, err := validateLoopbackEndpoint(manifest.APIBase, "api_base")
	if err != nil {
		return err
	}
	proxyPort, err := validateLoopbackEndpoint(manifest.Proxy, "proxy")
	if err != nil {
		return err
	}
	if !filepath.IsAbs(manifest.StateDir) {
		return errors.New("state_dir must be absolute")
	}
	if !filepath.IsAbs(manifest.TokenFile) {
		return errors.New("token_file must be absolute")
	}
	expectedToken := filepath.Join(filepath.Clean(manifest.StateDir), "token")
	if !sameCanonicalPath(expectedToken, manifest.TokenFile) {
		return errors.New("token_file must be the token file inside state_dir")
	}
	if manifest.CDPPort < 1 || manifest.CDPPort > 65535 {
		return errors.New("cdp_port must be between 1 and 65535")
	}
	if apiPort == proxyPort || apiPort == manifest.CDPPort || proxyPort == manifest.CDPPort {
		return errors.New("API, proxy, and CDP ports must be distinct")
	}
	if requirePID && manifest.PID <= 0 {
		return errors.New("positive pid is required when publishing a manifest")
	}
	if manifest.PID < 0 {
		return errors.New("pid must not be negative")
	}
	if manifest.BrowserPID < 0 {
		return errors.New("browser_pid must not be negative")
	}
	if manifest.ProcessStartedAt != "" {
		if _, err := time.Parse(time.RFC3339, manifest.ProcessStartedAt); err != nil {
			return fmt.Errorf("process_started_at must be RFC3339 when present: %w", err)
		}
	}
	if strings.TrimSpace(manifest.Generation) == "" || len(manifest.Generation) > 128 {
		return errors.New("generation is required and must not exceed 128 bytes")
	}
	if _, err := time.Parse(time.RFC3339, manifest.UpdatedAt); err != nil {
		return fmt.Errorf("updated_at must be RFC3339: %w", err)
	}
	return nil
}

func validateLoopbackEndpoint(raw, field string) (int, error) {
	endpoint, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" {
		return 0, fmt.Errorf("%s is not a valid URL", field)
	}
	if endpoint.Scheme != "http" && endpoint.Scheme != "https" {
		return 0, fmt.Errorf("%s must use http or https", field)
	}
	if endpoint.User != nil {
		return 0, fmt.Errorf("%s must not contain credentials", field)
	}
	host := strings.ToLower(endpoint.Hostname())
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return 0, fmt.Errorf("%s must point to 127.0.0.1, localhost, or ::1", field)
	}
	if endpoint.Path != "" && endpoint.Path != "/" {
		return 0, fmt.Errorf("%s must not contain a path", field)
	}
	if endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return 0, fmt.Errorf("%s must not contain a query or fragment", field)
	}
	portText := endpoint.Port()
	if portText == "" {
		if endpoint.Scheme == "https" {
			portText = "443"
		} else {
			portText = "80"
		}
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("%s port must be between 1 and 65535", field)
	}
	return port, nil
}

func validateInstanceID(id string) error {
	if !instanceIDPattern.MatchString(id) {
		return fmt.Errorf("invalid CAPX_INSTANCE_ID %q", id)
	}
	return nil
}

func instanceManifestPath(id string) (string, error) {
	if err := validateInstanceID(id); err != nil {
		return "", err
	}
	dir, err := instanceRegistryDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, id+".json"), nil
}

func instanceRegistryDirectory() (string, error) {
	if configured := strings.TrimSpace(os.Getenv("CAPX_INSTANCE_DIR")); configured != "" {
		return filepath.Abs(configured)
	}
	if local := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); local != "" {
		return filepath.Abs(filepath.Join(local, "capx", "instances"))
	}
	if profile := strings.TrimSpace(os.Getenv("USERPROFILE")); profile != "" {
		return filepath.Abs(filepath.Join(profile, "AppData", "Local", "capx", "instances"))
	}
	return "", errors.New("LOCALAPPDATA and USERPROFILE are both unavailable")
}

func readBoundedRegularFile(path string, maxBytes int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file: %s", path)
	}
	if info.Size() < 2 || info.Size() > maxBytes {
		return nil, fmt.Errorf("file size is outside the allowed range: %s", path)
	}
	return os.ReadFile(path)
}

func sameCanonicalPath(left, right string) bool {
	canonical := func(value string) string {
		absolute, err := filepath.Abs(value)
		if err != nil {
			absolute = filepath.Clean(value)
		}
		if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
			absolute = resolved
		}
		absolute = filepath.Clean(absolute)
		if runtime.GOOS == "windows" {
			absolute = strings.ToLower(absolute)
		}
		return absolute
	}
	return canonical(left) == canonical(right)
}

func renameWithRetry(oldPath, newPath string) error {
	var last error
	for attempt := 0; attempt < 8; attempt++ {
		if err := os.Rename(oldPath, newPath); err == nil {
			return nil
		} else {
			last = err
		}
		if runtime.GOOS != "windows" {
			break
		}
		time.Sleep(time.Duration(attempt+1) * 10 * time.Millisecond)
	}
	return last
}

func syncRegistryDirectory(dir string) error {
	// Windows does not provide a useful directory fsync through os.File.Sync.
	// The manifest file itself is always synced before the same-directory rename.
	if runtime.GOOS == "windows" {
		return nil
	}
	handle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open registry directory for sync: %w", err)
	}
	defer handle.Close()
	if err := handle.Sync(); err != nil {
		return fmt.Errorf("sync registry directory: %w", err)
	}
	return nil
}
