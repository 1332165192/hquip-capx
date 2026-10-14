package main

import (
	"errors"
	"fmt"
	"path/filepath"
)

type managedBrowserProcessHandle interface {
	imagePath() (string, error)
	terminate() (bool, error)
	close()
}

var (
	openManagedBrowserHandle  = openManagedBrowserProcessHandle
	managedBrowserListenerPID = findLoopbackListenerPID
)

func terminateManagedBrowser(manifest instanceManifest) (bool, error) {
	if manifest.BrowserPID <= 0 {
		return false, errors.New("positive managed browser PID is required")
	}
	handle, err := openManagedBrowserHandle(manifest.BrowserPID)
	if err != nil {
		return false, err
	}
	defer handle.close()

	listenerPID, err := managedBrowserListenerPID(manifest.CDPPort)
	if err != nil {
		return false, fmt.Errorf("verify managed browser CDP listener: %w", err)
	}
	if listenerPID != manifest.BrowserPID {
		return false, fmt.Errorf(
			"CDP listener PID %d does not match manifest browser PID %d",
			listenerPID,
			manifest.BrowserPID,
		)
	}
	executablePath, err := handle.imagePath()
	if err != nil {
		return false, err
	}
	if err := verifyManagedBrowserIdentity(listenerPID, executablePath, managedBrowserManifestFlags(manifest)); err != nil {
		return false, err
	}
	return handle.terminate()
}

func managedBrowserManifestFlags(manifest instanceManifest) []string {
	return []string{
		fmt.Sprintf("--remote-debugging-port=%d", manifest.CDPPort),
		"--user-data-dir=" + filepath.Join(manifest.StateDir, "browser-profile"),
		"--proxy-server=" + manifest.Proxy,
		"--capx-instance-id=" + manifest.InstanceID,
		"--capx-generation=" + manifest.Generation,
	}
}
