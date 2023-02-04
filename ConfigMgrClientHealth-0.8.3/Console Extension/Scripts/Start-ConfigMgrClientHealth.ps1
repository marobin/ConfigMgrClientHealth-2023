[CmdLetBinding()]
param(
    [Parameter(Mandatory=$True)][string]$Type,
    [Parameter(Mandatory=$True)][string]$Name,
    [Parameter(Mandatory=$True)][string]$ScheduledTaskName,
    [Parameter(Mandatory=$False)][string]$MaxThreads = 20
)

# Define the multhithreader function (Authored by Ryan Witschger - http://www.Get-Blog.com)
Function Invoke-Multithreader {
    Param($Command = $(Read-Host "Enter the script file"), 
        [Parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]$ObjectList,
        $InputParam = $Null,
        $MaxThreads = 20,
        $SleepTimer = 200,
        $MaxResultTime = 120,
        [HashTable]$AddParam = @{},
        [Array]$AddSwitch = @()
    )

    Begin{
        $ISS = [system.management.automation.runspaces.initialsessionstate]::CreateDefault()
        $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $ISS, $Host)
        $RunspacePool.Open()
        <#
        If ($(Get-Command | Select-Object Name) -match $Command) {
            $Code = $Null
        }Else{
            $OFS = "`r`n"
            $Code = [ScriptBlock]::Create($(Get-Content $Command))
            Remove-Variable OFS
        }
        #>
        $Jobs = @()
    }

    Process{
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            If ($Code -eq $Null){
                $PowershellThread = [powershell]::Create().AddCommand($Command)
            }Else{
                $PowershellThread = [powershell]::Create().AddScript($Code)
            }
            If ($InputParam -ne $Null){
                $PowershellThread.AddParameter($InputParam, $Object.ToString()) | out-null
            }Else{
                $PowershellThread.AddArgument($Object.ToString()) | out-null
            }
            ForEach($Key in $AddParam.Keys){
                $PowershellThread.AddParameter($Key, $AddParam.$key) | out-null
            }
            ForEach($Switch in $AddSwitch){
                $Switch
                $PowershellThread.AddParameter($Switch) | out-null
            }
            $PowershellThread.RunspacePool = $RunspacePool
            $Handle = $PowershellThread.BeginInvoke()
            $Job = "" | Select-Object Handle, Thread, object
            $Job.Handle = $Handle
            $Job.Thread = $PowershellThread
            $Job.Object = $Object.ToString()
            $Jobs += $Job
        }
        
    }

    End{
        $ResultTimer = Get-Date
        While (@($Jobs | Where-Object {$_.Handle -ne $Null}).count -gt 0)  {
    
            $Remaining = "$($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False}).object)"
            If ($Remaining.Length -gt 60){
                $Remaining = $Remaining.Substring(0,60) + "..."
            }
            Write-Progress `
                -Activity "Waiting for Jobs - $($MaxThreads - $($RunspacePool.GetAvailableRunspaces())) of $MaxThreads threads running" `
                -PercentComplete (($Jobs.count - $($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False}).count)) / $Jobs.Count * 100) `
                -Status "$(@($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False})).count) remaining - $remaining" 

            ForEach ($Job in $($Jobs | Where-Object {$_.Handle.IsCompleted -eq $True})){
                $Job.Thread.EndInvoke($Job.Handle)
                $Job.Thread.Dispose()
                $Job.Thread = $Null
                $Job.Handle = $Null
                $ResultTimer = Get-Date
            }
            If (($(Get-Date) - $ResultTimer).totalseconds -gt $MaxResultTime){
                Write-Error "Child script appears to be frozen, try increasing MaxResultTime"
                Exit
            }
            Start-Sleep -Milliseconds $SleepTimer
        
        } 
        Write-Progress -Activity "Waiting for Jobs - $($MaxThreads - $($RunspacePool.GetAvailableRunspaces())) of $MaxThreads threads running" -Status "Ready" -Completed
        $RunspacePool.Close() | Out-Null
        $RunspacePool.Dispose() | Out-Null
    } 
}
# End Invoke-Multhithreader

switch ($Type) {
    "Device" {
        $Computer = $Name
        $ScriptBlock = {schtasks.exe /Run /TN $using:ScheduledTaskName}
        $result = Invoke-Command -ComputerName $Computer -ScriptBlock $ScriptBlock

        if ($result -like "*SUCCESS*") {
            $text = "ConfigMgr Client Health started: $Computer"
            Write-Host $text -ForegroundColor Green
        }
        else {
            $text = "ConfigMgr Client Health failed to start: $Computer"
            Write-Host $text -ForegroundColor Red
        }
    }
    "Collection" {
        # We need to list out all collection members before we can process them. Connect to SCCM to get hostnames.
        #$SiteCode = Get-WMIObject -Namespace "root\SMS" -Class "SMS_ProviderLocation" | Select-Object -ExpandProperty SiteCode
        $SiteCode = (Get-WmiObject -Namespace 'root\ccm' -Class 'SMS_Authority').Name.split(":")[1]
        Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1"
        Set-Location "$($SiteCode):\"
        $Computers = Get-CMDevice -CollectionName $Name | Select-Object -ExpandProperty Name
        Set-Location $PSScriptRoot
        
        # Using the Invoke-Multithreader function to start ConfigMgr Client Health on several computers at the same time.
        #$Computers | Invoke-Multithreader -Command $PSScriptRoot\Start-ScheduledTask.ps1 -InputParam Computer -AddParam @{"scheduledTaskName" = $ScheduledTaskName}
        Invoke-Multithreader -Command $PSScriptRoot\Start-ScheduledTask.ps1 -ObjectList $Computers -MaxThreads $MaxThreads -InputParam Computer -AddParam @{"scheduledTaskName" = $ScheduledTaskName}
    }
}

Write-Host "Press any key to continue ..."
$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")