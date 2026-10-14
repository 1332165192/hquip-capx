param([int]$BackendPID)
$ErrorActionPreference = 'Stop'
$taskRoot = 'C:\CapxChannel'
$taskRequests = Join-Path $taskRoot 'requests'
$taskResponses = Join-Path $taskRoot 'responses'
$taskMailbox = Join-Path $taskRoot 'request.json'
New-Item -ItemType Directory -Path $taskRequests,$taskResponses -Force | Out-Null
$taskTokenFile = 'C:\CapxChannel\state\token'
$taskHeaders = @{ Authorization = 'Bearer ' + (Get-Content -LiteralPath $taskTokenFile -Raw).Trim() }
$taskSession = [Guid]::NewGuid().ToString('N')
$taskLastRequestID = ''
$taskNextHeartbeat = [DateTime]::MinValue
$taskEncoding = New-Object System.Text.UTF8Encoding($false)
$taskAllowed = @('/api/wxdesk/windows','/api/wxdesk/screenshot','/api/wxdesk/launch','/api/wxdesk/show','/api/wxdesk/tap','/api/wxdesk/input','/api/wxdesk/key','/api/wxdesk/scroll')
function Write-AtomicJson([string]$taskTarget,[object]$taskObject) {
  $taskJSON = $taskObject | ConvertTo-Json -Depth 20 -Compress
  $taskTemp = $taskTarget + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
  $taskBackup = $taskTemp + '.bak'
  try {
    [IO.File]::WriteAllText($taskTemp,$taskJSON,$taskEncoding)
    for ($taskAttempt=0; $taskAttempt -lt 4; $taskAttempt++) {
      try {
        if ([IO.File]::Exists($taskTarget)) { [IO.File]::Replace($taskTemp,$taskTarget,$taskBackup) }
        else { [IO.File]::Move($taskTemp,$taskTarget) }
        return
      } catch {
        if ($taskAttempt -eq 3) { throw }
        Start-Sleep -Milliseconds 20
      }
    }
  } finally {
    Remove-RelayFile $taskTemp
    Remove-RelayFile $taskBackup
  }
}
function Remove-RelayFile([string]$taskPath) {
  # File.Delete is idempotent. The host may already have consumed/deleted it;
  # PowerShell's mapped-folder provider can throw even with SilentlyContinue.
  try { [IO.File]::Delete($taskPath) } catch { Write-Warning ('Relay cleanup: '+$_.Exception.Message) }
}
function Write-RelayHeartbeat {
  $taskBytes=$taskEncoding.GetBytes((@{session=$taskSession;mode='windows-sandbox';protocol=2;updated_at=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Compress))
  # Replace on a redirected drive may briefly remove the target on the host.
  # Keep this entry stable and allow the host to read while writing one record.
  $taskStream=[IO.FileStream]::new((Join-Path $taskRoot 'ready.json'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::Write,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
  try {$taskStream.Write($taskBytes,0,$taskBytes.Length);$taskStream.SetLength($taskBytes.Length);$taskStream.Flush($true)}
  finally {$taskStream.Dispose()}
}
function Write-RelayTrace([string]$taskMessage) {
  if ($env:CAPX_WXDESK_DIAGNOSTICS -ne '1') { return }
  Write-Output ([DateTime]::UtcNow.ToString('o')+' '+$taskMessage)
  try { [IO.File]::AppendAllText((Join-Path $taskRoot 'relay-debug.log'),[DateTime]::UtcNow.ToString('o')+' '+$taskMessage+[Environment]::NewLine,$taskEncoding) } catch {}
}
while (Get-Process -Id $BackendPID -ErrorAction SilentlyContinue) {
  if ([DateTime]::UtcNow -ge $taskNextHeartbeat) {
    try { Write-RelayHeartbeat; $taskNextHeartbeat=[DateTime]::UtcNow.AddSeconds(1) }
    catch { Write-Warning ('Relay heartbeat: '+$_.Exception.Message); Start-Sleep -Milliseconds 200; continue }
  }
  # Open a known, stable path; mapped-folder directory enumeration can lag
  # over 12 seconds and miss a short-lived request entirely.
  foreach ($taskFile in @($taskMailbox)) {
    $taskRequest = $null
    try { $taskRequest = [IO.File]::ReadAllText($taskFile,$taskEncoding) | ConvertFrom-Json }
    catch { continue } # Host may be writing; retry without deleting its mailbox.
    if (!$taskRequest.id -or $taskRequest.id -eq $taskLastRequestID) { continue }
    try {
      Write-RelayTrace ('received '+$taskRequest.path)
      if ($taskRequest.id -notmatch '^[0-9a-f]{32}$') { Write-RelayTrace 'skipped invalid request identity'; continue }
      if ($taskRequest.session -ne $taskSession) { Write-RelayTrace 'skipped previous session'; continue }
      if ([DateTime]::Parse($taskRequest.expires_at).ToUniversalTime() -lt [DateTime]::UtcNow) { Write-RelayTrace 'skipped expired request'; continue }
      $taskLastRequestID = $taskRequest.id # Never repeat an action after delivery/cleanup fails.
      $taskURI = [Uri]('http://127.0.0.1:19181' + $taskRequest.path)
      if ($taskURI.Host -ne '127.0.0.1' -or $taskAllowed -notcontains $taskURI.AbsolutePath -or $taskRequest.method -notin @('GET','POST')) { throw 'Unsupported isolated control request.' }
      if (($taskURI.AbsolutePath -in @('/api/wxdesk/windows','/api/wxdesk/screenshot')) -ne ($taskRequest.method -eq 'GET')) { throw 'Unsupported method.' }
      $taskInvoke = @{Uri=$taskURI.AbsoluteUri;Headers=$taskHeaders;TimeoutSec=8;Method=$taskRequest.method;UseBasicParsing=$true}
      if ($taskRequest.method -eq 'POST') { $taskInvoke.ContentType='application/json; charset=utf-8'; $taskInvoke.Body=[Text.Encoding]::UTF8.GetBytes(($taskRequest.body | ConvertTo-Json -Depth 12 -Compress)) }
      $taskHTTP = Invoke-WebRequest @taskInvoke
      Write-RelayTrace ('response '+$taskURI.AbsolutePath)
      if ($taskURI.AbsolutePath -eq '/api/wxdesk/screenshot') {
        $taskMemory = New-Object IO.MemoryStream
        $taskHTTP.RawContentStream.Position=0; $taskHTTP.RawContentStream.CopyTo($taskMemory)
        $taskResult=@{session=$taskSession;status=[int]$taskHTTP.StatusCode;image=[Convert]::ToBase64String($taskMemory.ToArray())};$taskMemory.Dispose()
      } else {
        $taskMemory = New-Object IO.MemoryStream
        $taskHTTP.RawContentStream.Position=0; $taskHTTP.RawContentStream.CopyTo($taskMemory)
        $taskJSON = [Text.Encoding]::UTF8.GetString($taskMemory.ToArray());$taskMemory.Dispose()
        $taskResult=@{session=$taskSession;status=[int]$taskHTTP.StatusCode;data=($taskJSON | ConvertFrom-Json)}
      }
      Write-AtomicJson (Join-Path $taskResponses ($taskRequest.id+'.json')) $taskResult
      Write-RelayTrace ('delivered '+$taskRequest.id)
    } catch {
      Write-RelayTrace ('failed '+$_.Exception.Message)
      if ($taskRequest -and $taskRequest.id -match '^[0-9a-f]{32}$') {
        $taskError = $_.Exception.Message
        if ($_.ErrorDetails.Message) { try { $taskError=($_.ErrorDetails.Message|ConvertFrom-Json).error } catch {} }
        try { Write-AtomicJson (Join-Path $taskResponses ($taskRequest.id+'.json')) @{session=$taskSession;status=409;error=$taskError} }
        catch { Write-Warning ('Relay response: '+$_.Exception.Message) }
      }
    }
  }
  # Responses are one-use; remove only old files in this dedicated directory.
  foreach ($taskFile in [IO.Directory]::GetFiles($taskResponses,'*.json')) {
    if ([IO.File]::GetLastWriteTimeUtc($taskFile) -lt [DateTime]::UtcNow.AddMinutes(-2)) { Remove-RelayFile $taskFile }
  }
  Start-Sleep -Milliseconds 80
}
Remove-RelayFile (Join-Path $taskRoot 'ready.json')
