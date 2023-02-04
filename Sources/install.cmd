cd /D %~dp0

powershell.exe -NoProfile -NoLogo -ExecutionPolicy Bypass -Command "& {.\install.ps1 -MachineType 'Client'; Exit $LASTEXITCODE}"