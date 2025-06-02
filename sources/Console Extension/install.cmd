cd /D %~dp0

START powershell.exe -NoProfile -NoLogo -ExecutionPolicy Bypass -File ".\Install-CMClientHealthConsoleExtension.ps1" -Path "D:\ConsoleExtensions\CMClientHealth" -ScheduledTaskName "ConfigMgr Client Health Remediation Script" -MaxThreads 20 -SiteCode CM1 -Verbose

pause