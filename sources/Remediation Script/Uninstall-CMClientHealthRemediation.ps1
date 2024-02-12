[CmdletBinding()]
Param (
    [String]$TaskName = "ConfigMgr Client Health Remediation Script",

    [String]$InstallFolder = "$Env:ProgramData\ConfigMgrClientHealth",

    [String]$LogFolder = "$Env:ProgramData\ConfigMgrClientHealth\Logs"
)

If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Throw 'Powershell not running as Administrator'
    Exit 1
}

$Error.Clear()

$RegKeyList = @('HKLM:\SOFTWARE\ConfigMgrClientHealth', 'HKLM:\SOFTWARE\WOW6432Node\ConfigMgrClientHealth')

If ((Test-Path -Path "$LogFolder")) {
    # Backup logs
    $BackupFolder = "$env:SystemRoot\Temp\CMClientHealth"
    Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Backup existing logs to '$BackupFolder'"
    If (! (Test-Path -Path $BackupFolder)) {
        $null = New-Item -Path $BackupFolder -ItemType Directory -Force
    }
    Copy-Item -Path "$LogFolder\*" -Destination $BackupFolder -Force
    Remove-Item -Path $LogFolder -Recurse -Force -EA Ignore
    Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Remove log folder '$LogFolder'"
}

$service = New-Object -ComObject 'Schedule.service'
$service.Connect($env:COMPUTERNAME)
Try {
    $Folder = $service.GetFolder('\')
    $Task = $Folder.GetTasks($null) | Where-Object { $_.Name -like $TaskName }
    If ($null -ne $Task) {
        $Task.Stop(0)
        $Folder.DeleteTask($Task.Name, 0)
        Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Remove scheduled task '$($Task.Name)'"
    }
}
Catch [System.IO.FileNotFoundException] {
    $Error.RemoveAt(0)
}


Foreach ($Key in $RegKeyList) {
    If (Test-Path -Path $Key) {
        Remove-Item -Path $Key -Force -Recurse
        Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Remove registry key '$Key'"
    }
}

If ((Test-Path -Path "$InstallFolder")) {
    Remove-Item -Path "$InstallFolder" -Force -Recurse
    Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Remove installation folder '$InstallFolder'"
}

Exit $Error.Count