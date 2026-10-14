[CmdletBinding()]
param([string]$Tags = '', [string]$Output = '')
$ErrorActionPreference = 'Stop'
$moduleRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$buildDir = Join-Path $moduleRoot 'dist'
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
if (-not (Get-Command go -ErrorAction SilentlyContinue)) { throw 'Install Go 1.26.9 or newer.' }
# Native tags require separately installed SDK/static libraries. This script
# never mutates go.mod or downloads executables.
Push-Location $moduleRoot
try {
  foreach ($command in @('captured', 'capx-desktop', 'capx-mcp')) {
    $destination = Join-Path $buildDir ($command + '.exe')
    if ($command -eq 'captured' -and $Output) { $destination = $Output }
	$taskBuildArgs = @('build', '-mod=readonly', '-trimpath', '-ldflags=-s -w')
	if ($Tags) { $taskBuildArgs += @('-tags', $Tags) }
	$taskBuildArgs += @('-o', $destination, "./cmd/$command")
	& go @taskBuildArgs
    if ($LASTEXITCODE -ne 0) { throw "Build failed: $command ($LASTEXITCODE)" }
  }
} finally { Pop-Location }
Write-Host "Built captured, capx-desktop and capx-mcp in $buildDir"
