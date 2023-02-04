[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('Client','Server')]
    [String]$MachineType
)

$Error.Clear()

$ScriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
$Sources = "$ScriptPath\Sources"
$InstallFolder = "$env:ALLUSERSPROFILE\ConfigMgrClientHealth"
$ClientFolder = "$InstallFolder\CMClient"
$LogFolder = "$InstallFolder\Logs"
$TaskXmlName = "ConfigMgrClientHealth-$MachineType.xml"
$TaskXml = "$Sources\Tasks\$TaskXmlName"
$NewTaskXml = "$InstallFolder\$TaskXmlName"
$taskName = "ConfigMgr Client Health - $MachineType"
$WebService = 'https://SRV........./ConfigMgrClientHealth' # A MODIFIER
$Execute = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$ArgumentList = "-ExecutionPolicy Bypass -NoProfile -NoLogo -Command `".\ConfigMgrClientHealth.ps1 -WebService '$WebService' -Config '.\Config-$MachineType.xml' -Verbose`""

If ((Test-Path -Path $InstallFolder) -and (Test-Path -Path "$env:SystemRoot\System32\Tasks\$taskName")) {
    # Already installed
    Exit 0
}

If ($MachineType -eq 'Client') {
    If (! (Test-Path -Path "$ClientFolder")) {
        $null = New-Item -Path "$ClientFolder" -ItemType Directory -Force -Verbose
    }
    If (! (Test-Path -Path "$LogFolder")) {
        $null = New-Item -Path "$LogFolder" -ItemType Directory -Force -Verbose
    }

    $acl = Get-Acl -Path $InstallFolder
    # https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.objectsecurity.setaccessruleprotection?view=netframework-4.8
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetSecurityDescriptorSddlForm('D:PAI(A;OICIIO;FA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)','Access')
    Set-Acl -Path $InstallFolder -AclObject $acl -Verbose

    Copy-Item -Path "$Sources\ConfigMgrClientHealth*.ps1" -Destination "$InstallFolder" -Force -Verbose
    Copy-Item -Path "$Sources\Config-$MachineType.xml" -Destination "$InstallFolder" -Force -Verbose
    Copy-Item -Path "$ScriptPath\CMClient\*" -Destination "$ClientFolder" -Force -Verbose -Container -Recurse
}

[xml]$xml = Get-Content -Path "$TaskXml"
$xml.Task.Actions.Exec.Command = $Execute
$xml.Task.Actions.Exec.Arguments = $argumentList
If ($MachineType -eq 'Client') {
    $xml.Task.Actions.Exec.WorkingDirectory = $InstallFolder
}
Else {
    $xml.Task.Actions.Exec.WorkingDirectory = $Sources
}
$xml.Save($NewTaskXml)

$ProcessSplat = @{
    FilePath = 'schtasks.exe' 
    ArgumentList = "/Create /XML `"$NewTaskXml`" /TN `"$taskName`" /F" 
    Wait = $true
    PassThru = $true
}
$Process = Start-Process @ProcessSplat

[long]$ExitCode = $Process.ExitCode

If ($Error.Count -gt 1) {
    $ExitCode += $Error.Count
}

$Date = Get-Date
$UTCDateDiff = "+$(($Date - $Date.ToUniversalTime()).TotalHours)" -replace '\+-','-'
"$($Date.ToString('dd/MM/yyyy HH:mm:ss')) (UTC$UTCDateDiff) - [$MachineType] $env:COMPUTERNAME ($ExitCode)" | Out-File -FilePath '\\srv\cmclienthealth$\Logs\GPODeployment.log' -Append -Force

Exit $ExitCode