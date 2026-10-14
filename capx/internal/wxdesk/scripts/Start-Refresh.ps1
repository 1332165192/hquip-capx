$ErrorActionPreference='Stop'
Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File','C:\CapxTools\Refresh-Environment.ps1') -WindowStyle Hidden -RedirectStandardOutput 'C:\CapxChannel\refresh.stdout.log' -RedirectStandardError 'C:\CapxChannel\refresh.stderr.log'
