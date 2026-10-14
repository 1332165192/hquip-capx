//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func selectNativeDirectory(initial, description string) (string, error) {
	const script = `$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = $utf8
$OutputEncoding = $utf8
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.FolderBrowserDialog
$dialog.Description = $env:CAPX_DIRECTORY_DESCRIPTION
$dialog.ShowNewFolderButton = $true
$dialog.RootFolder = [System.Environment+SpecialFolder]::Desktop
if ($env:CAPX_DIRECTORY_INITIAL -and (Test-Path -LiteralPath $env:CAPX_DIRECTORY_INITIAL -PathType Container)) {
  $dialog.SelectedPath = $env:CAPX_DIRECTORY_INITIAL
}
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
  [Console]::Out.Write($dialog.SelectedPath)
}`
	command := exec.Command("powershell.exe", "-NoProfile", "-STA", "-Command", script)
	command.Env = append(os.Environ(),
		"CAPX_DIRECTORY_INITIAL="+strings.TrimSpace(initial),
		"CAPX_DIRECTORY_DESCRIPTION="+description,
	)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("打开目录选择器: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}
