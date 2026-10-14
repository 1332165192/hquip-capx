$ErrorActionPreference = 'Stop'
$taskConfig = Get-Content -LiteralPath 'C:\CapxTools\environment.json' -Raw | ConvertFrom-Json
$taskWeChatDir = 'C:\CapxRuntime\WeChat'
$taskDataDir = 'C:\CapxChannel\state'
New-Item -ItemType Directory -Path $taskWeChatDir -Force | Out-Null
New-Item -ItemType Directory -Path $taskDataDir -Force | Out-Null
$env:CAPX_WECHAT_SANDBOX = '1'
$taskInstallerMode = $taskConfig.source_mode -eq 'installer'
if ($taskInstallerMode) {
  # The imported signed installer is executed only inside the sandbox.
  $taskInstallerSource = Join-Path 'C:\CapxTools' $taskConfig.installer_filename
  $env:CAPX_WECHAT_INSTALLER = 'C:\CapxRuntime\WeChatSetup.exe'
  $env:CAPX_WECHAT_EXE = ''
  if ($taskConfig.installer_verified -ne $true -or !(Test-Path -LiteralPath $taskInstallerSource)) { throw 'The verified official WeChat installer is missing.' }
  # Setup needs a writable working directory; the shared tools stay read-only.
  Copy-Item -LiteralPath $taskInstallerSource -Destination $env:CAPX_WECHAT_INSTALLER -Force
  if ((Get-FileHash -LiteralPath $taskInstallerSource).Hash -ne (Get-FileHash -LiteralPath $env:CAPX_WECHAT_INSTALLER).Hash) { throw 'The staged WeChat installer does not match the verified source.' }
} else {
  # Optional compatibility mode shares only installed application binaries.
  # Account/cache directories belong to the sandbox user, never the host.
  Get-ChildItem -LiteralPath 'C:\WeChatSource' -Force | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination $taskWeChatDir -Recurse -Force
  }
  $env:CAPX_WECHAT_EXE = Join-Path $taskWeChatDir $taskConfig.wechat_filename
}
$env:CAPX_DATA_DIR = 'C:\CapxChannel\ca'
$env:CAPX_WECHAT_BOX_DIR = 'C:\CapxChannel'
$taskBackend = 'C:\CapxTools\capx-captured.exe'
$taskProc = Start-Process -FilePath $taskBackend -ArgumentList @('-addr','127.0.0.1:19181','-proxy','127.0.0.1:18181','-state-dir',$taskDataDir,'-allow-active','-strict-addr') -WindowStyle Hidden -PassThru -RedirectStandardOutput 'C:\CapxChannel\backend.stdout.log' -RedirectStandardError 'C:\CapxChannel\backend.stderr.log'
$taskTokenFile = Join-Path $taskDataDir 'token'
$taskDeadline = (Get-Date).AddSeconds(30)
while (!(Test-Path -LiteralPath $taskTokenFile) -and (Get-Date) -lt $taskDeadline) {
  if ($taskProc.HasExited) { throw 'The isolated capture backend exited; inspect backend.stderr.log.' }
  Start-Sleep -Milliseconds 200
}
if (!(Test-Path -LiteralPath $taskTokenFile)) { throw 'Isolated backend token not ready.' }
$taskHeaders = @{ Authorization = 'Bearer ' + (Get-Content -LiteralPath $taskTokenFile -Raw).Trim() }
$taskReady = $false
while (!$taskReady -and (Get-Date) -lt $taskDeadline) {
  try { Invoke-RestMethod -Uri 'http://127.0.0.1:19181/health' -Headers $taskHeaders -TimeoutSec 2 | Out-Null; $taskReady = $true }
  catch { Start-Sleep -Milliseconds 200 }
}
if (!$taskReady) { throw 'Isolated backend did not become ready.' }
if ($taskInstallerMode) {
  # Keep the official interactive setup flow; do not guess undocumented silent
  # installer flags or run setup on the host. The user finishes setup in Sandbox.
  Start-Process -FilePath $env:CAPX_WECHAT_INSTALLER -WorkingDirectory 'C:\CapxRuntime' -WindowStyle Normal
} else {
  Start-Process -FilePath $env:CAPX_WECHAT_EXE -WorkingDirectory $taskWeChatDir -WindowStyle Normal
}
Start-Process 'http://127.0.0.1:19181/#wxdesk'
& 'C:\CapxTools\Relay.ps1' -BackendPID $taskProc.Id
