cd /D %~dp0

powershell.exe -NoProfile -NoLogo -ExecutionPolicy Bypass -Command "& {.\uninstall.ps1; Exit $LASTEXITCODE}"