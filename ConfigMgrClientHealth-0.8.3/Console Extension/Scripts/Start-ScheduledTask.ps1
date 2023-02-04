[CmdLetBinding()]
param(
    [Parameter(Mandatory=$True)][string]$Computer,
    [Parameter(Mandatory=$True)][string]$scheduledTaskName
)
$ScriptBlock = {schtasks.exe /Run /TN $using:ScheduledTaskName}
$result = Invoke-Command -ComputerName $Computer -ScriptBlock $ScriptBlock

if ($result -like "*SUCCESS*") {
    $text = 'ConfigMgr Client Health started: '+$Computer
    Write-Host $text -ForegroundColor Green
}
else {
    $text = 'ConfigMgr Client Health failed to start: '+$Computer
    Write-Host $text -ForegroundColor Red
}