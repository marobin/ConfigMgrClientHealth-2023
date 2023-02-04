$Error.Clear()

$RegKeyList = @('HKLM:\SOFTWARE\ConfigMgrClientHealth', 'HKLM:\SOFTWARE\WOW6432Node\ConfigMgrClientHealth')
$InstallFolder = "$env:ALLUSERSPROFILE\ConfigMgrClientHealth"
$LogFolder = "$InstallFolder\Logs"
If ((Test-Path -Path "$LogFolder")) {
    # Backup logs
    $BackupFolder = "$env:SystemRoot\Temp\CMClientHealth"
    If (! (Test-Path -Path $BackupFolder)) {
        $null = New-Item -Path $BackupFolder -ItemType Directory -Force -Verbose
    }
    Copy-Item -Path "$LogFolder\*" -Destination $BackupFolder -Force -Verbose
}

$service = New-Object -ComObject 'Schedule.service'
$service.Connect($env:COMPUTERNAME)
Try {
    $Folder = $service.GetFolder('\')
    $Task = $Folder.GetTasks($null) | Where-Object { $_.Name -like 'ConfigMgr Client Health - *' }
    If ($null -ne $Task) {
        $Task.Stop(0)
        $Folder.DeleteTask($Task.Name, 0)
    }
}
Catch [System.IO.FileNotFoundException] {
    $Error.RemoveAt(0)
}


Foreach ($Key in $RegKeyList) {
    If (Test-Path -Path $Key) {
        Remove-Item -Path $Key -Force -Recurse
    }
}


If ((Test-Path -Path "$InstallFolder")) {
    Remove-Item -Path "$InstallFolder" -Force -Recurse -Verbose
}

Exit $Error.Count