$ErrorActionPreference = 'Stop'
if (-not (Get-Command go -ErrorAction SilentlyContinue)) { throw 'Install Go 1.26.9 or newer.' }
if (-not (Get-Command wails -ErrorAction SilentlyContinue)) {
  throw 'Install the pinned CLI: go install github.com/wailsapp/wails/v2/cmd/wails@v2.12.0'
}
Push-Location $PSScriptRoot
try {
  & go mod download
  if ($LASTEXITCODE -ne 0) { throw 'Dependency download failed.' }
  & wails build
  if ($LASTEXITCODE -ne 0) { throw 'Wails build failed.' }
} finally { Pop-Location }
Write-Host "artifact: $PSScriptRoot/build/bin/capx-desktop.exe"
