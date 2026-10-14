$ErrorActionPreference = 'Stop'
if ($env:USERNAME -ne 'WDAGUtilityAccount') { throw 'Refresh is restricted to the sandbox user.' }
$taskRoot='C:\CapxChannel'
$taskTokenFile=Join-Path $taskRoot 'state\token'
$taskHeader=@{Authorization='Bearer '+(Get-Content -LiteralPath $taskTokenFile -Raw).Trim()}
# Replace only the sandbox's control processes; keep WeChat/setup windows alive.
Get-CimInstance Win32_Process | Where-Object {$_.Name -match '^powershell.exe$' -and $_.ProcessId -ne $PID -and ($_.CommandLine -like '*Start-Environment.ps1*' -or $_.CommandLine -like '*Refresh-Environment.ps1*')} | ForEach-Object {Stop-Process -Id $_.ProcessId -Force}
Remove-Item -LiteralPath (Join-Path $taskRoot 'ready.json') -Force -ErrorAction SilentlyContinue
try {Invoke-RestMethod -Uri 'http://127.0.0.1:19181/api/runtime/shutdown' -Method Post -Headers $taskHeader -ContentType 'application/json' -Body '{}' -TimeoutSec 3 | Out-Null} catch {}
$taskDeadline=(Get-Date).AddSeconds(7)
while((Get-Date) -lt $taskDeadline -and (Get-CimInstance Win32_Process | Where-Object {$_.Name -like 'capx-captured*.exe' -and $_.ExecutablePath -like 'C:\CapxTools\capx-captured*.exe'})){Start-Sleep -Milliseconds 200}
Get-CimInstance Win32_Process | Where-Object {$_.Name -like 'capx-captured*.exe' -and $_.ExecutablePath -like 'C:\CapxTools\capx-captured*.exe'} | ForEach-Object {Stop-Process -Id $_.ProcessId -Force}
$env:CAPX_WECHAT_SANDBOX='1'
$env:CAPX_WECHAT_BOX_DIR=$taskRoot
$env:CAPX_DATA_DIR=Join-Path $taskRoot 'ca'
$env:CAPX_WECHAT_INSTALLER='C:\CapxRuntime\WeChatSetup.exe'
$env:CAPX_WXDESK_DIAGNOSTICS='1'
$taskEngine='capx-captured.updated.exe'
if(Test-Path -LiteralPath 'C:\CapxTools\refresh-engine.txt'){$taskEngine=(Get-Content -LiteralPath 'C:\CapxTools\refresh-engine.txt' -Raw).Trim()}
if($taskEngine -notmatch '^capx-captured[.a-zA-Z0-9_-]*\.exe$'){throw 'Invalid isolated control engine name.'}
$taskProcess=Start-Process -FilePath (Join-Path 'C:\CapxTools' $taskEngine) -ArgumentList @('-addr','127.0.0.1:19181','-proxy','127.0.0.1:18181','-state-dir','C:\CapxChannel\state','-allow-active','-strict-addr') -WindowStyle Hidden -PassThru -RedirectStandardOutput 'C:\CapxChannel\updated.stdout.log' -RedirectStandardError 'C:\CapxChannel\updated.stderr.log'
Start-Sleep -Milliseconds 900
& 'C:\CapxTools\Relay.ps1' -BackendPID $taskProcess.Id
