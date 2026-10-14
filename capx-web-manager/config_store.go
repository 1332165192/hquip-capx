package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Serialize in-process writers before taking the cross-process file lock.
// Concurrent requests should not consume each other's lock timeout.
var configSaveMu sync.Mutex

func saveConfig(c config) error {
	configSaveMu.Lock()
	defer configSaveMu.Unlock()
	dir := managerDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create manager config directory: %w", err)
	}
	release, err := acquireManagerFileLock(filepath.Join(dir, ".manager-config.lock"))
	if err != nil {
		return err
	}
	defer release()

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manager config: %w", err)
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(dir, ".manager-config-*.tmp")
	if err != nil {
		return fmt.Errorf("create manager config temporary file: %w", err)
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
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := renameWithRetry(tmpPath, configPath()); err != nil {
		return fmt.Errorf("publish manager config: %w", err)
	}
	committed = true
	return syncRegistryDirectory(dir)
}

func acquireManagerFileLock(path string) (func(), error) {
	deadline := time.Now().Add(5 * time.Second)
	for {
		file, unlock, err := acquireLifecycleFileLock(path)
		if err == nil {
			return func() {
				_ = unlock()
				_ = file.Close()
			}, nil
		}
		if !errors.Is(err, errLifecycleLockBusy) || time.Now().After(deadline) {
			return nil, fmt.Errorf("acquire manager file lock: %w", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
