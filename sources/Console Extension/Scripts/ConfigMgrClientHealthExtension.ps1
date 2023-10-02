[CmdLetBinding()]
param(
    [Parameter(Mandatory = $True,Position = 0, ParameterSetName = 'Install')]
    [Parameter(Mandatory = $True,Position = 0, ParameterSetName = 'Start')]
    [Parameter(Mandatory = $True,Position = 0, ParameterSetName = 'Uninstall')]
    [string]$Type,
    
    [Parameter(Mandatory = $True,Position = 1, ParameterSetName = 'Install')]
    [Parameter(Mandatory = $True,Position = 1, ParameterSetName = 'Start')]
    [Parameter(Mandatory = $True,Position = 1, ParameterSetName = 'Uninstall')]
    [string]$ResourceId,
    
    [Parameter(Mandatory = $False,Position = 2, ParameterSetName = 'Install')]
    [Parameter(Mandatory = $False,Position = 2, ParameterSetName = 'Start')]
    [Parameter(Mandatory = $False,Position = 2, ParameterSetName = 'Uninstall')]
    [string]$MaxThreads = 20,
    
    [Parameter(Position = 3, ParameterSetName = 'Install')]
    [Parameter(Position = 3, ParameterSetName = 'Start')]
    [Parameter(Position = 3, ParameterSetName = 'Uninstall')]
    [String]$TaskName,
    
    [Parameter(Position = 4, ParameterSetName = 'Install')]
    [Parameter(Position = 4, ParameterSetName = 'Start')]
    [Parameter(Position = 4, ParameterSetName = 'Uninstall')]
    [ValidateLength(3,3)]
    [String]$SiteCode,
    
    [Parameter(ParameterSetName = 'Install')]
    [switch]$Install,
    
    [Parameter(ParameterSetName = 'Start')]
    [switch]$Start,
    
    [Parameter(ParameterSetName = 'Uninstall')]
    [switch]$Uninstall
)



#region variables
$SourcePath = "$env:ALLUSERSPROFILE\ConfigMgrClientHealth"
# TODO : Fill up the following table with your domains
$DomainTranslationTable = @(
    @{Netbios = 'CORP'; Domain = 'corp.contoso.com'; Credential = $null}
)
#endregion variables

#region CM Provider
Try {
    $ModuleName = 'ConfigurationManager'
    $ModulePath = "$env:SMS_ADMIN_UI_PATH\..\$ModuleName.psd1"
    
    If (!(Get-Module -Name $ModuleName) -and (Test-Path -Path $ModulePath)) {
        Import-Module -Name $ModulePath -Verbose:$false
    }
    Else {
        Throw "Cannot find $ModuleName module at '$ModulePath'"
    }
    
    $CMSiteProv = Get-PSDrive -PSProvider 'CMSite' -ErrorAction Ignore | Where-Object -Property Name -eq $SiteCode
    $CMPsDrive = "$($CMSiteProv | Select-Object -First 1 -ExpandProperty Name):"
    Set-Location -Path $CMPsDrive -Verbose:$false
    
    # Getting the SMS Provider FQDN in order to use the admin web service
    #$ServerName = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\ConfigMgr10\AdminUI\Connection' -Name 'Server').Server
    # We could also use the parameter ##SUB:__Server## in the xml but it does not contain the server FQDN
    $ServerName = (Get-CMSiteRole -RoleName 'SMS Provider' -Verbose:$false | Select-Object -ExpandProperty NetworkOSPath -First 1).Trim('\')
    $CMAdminServiceURI = "https://$ServerName/adminService"
    
    Set-Location -Path $env:SystemDrive -Verbose:$false
}
Catch {
    Write-Host "Could not connect to $ModuleName provider : $($_.Exception.Message)"
    Write-Host 'Press any key to continue ...'
    $null = $host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    Exit 
}
#endregion CM Provider


#region Functions
Function Get-DomainCredential {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [String]$Domain
    )

    $DomainHash = $Script:DomainTranslationTable | Where-Object -Property Domain -eq $Domain

    $DomainCred = $DomainHash['Credential']
    If ($null -eq $DomainCred) {
        $DomainNetBIOS = $DomainHash['Netbios']
        $DomainCred = $DomainHash['Credential'] = Get-Credential -Message "Enter credentials for domain '$Domain'" -UserName "$DomainNetBIOS\"
    }
    Return $DomainCred
}

# Define the multhithreader function (Authored by Ryan Witschger - http://www.Get-Blog.com)

Function Invoke-Multithreader {
    Param(
        $Command = $(Read-Host 'Enter the script file'), 
        [Parameter(ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)]$ObjectList,
        $InputParam = $Null,
        $MaxThreads = 20,
        $SleepTimer = 200,
        $MaxResultTime = 120,
        [HashTable]$AddParam = @{},
        [Array]$AddSwitch = @()
    )

    Begin {
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
    Process {
        Write-Progress -Activity 'Preloading threads' -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList) {
            If ($Null -eq $Code) {
                $PowershellThread = [powershell]::Create().AddCommand($Command)
            }
            Else {
                $PowershellThread = [powershell]::Create().AddScript($Code)
            }
            If ($Null -ne $InputParam) {
                $null = $PowershellThread.AddParameter($InputParam, $Object.ToString())
            }
            Else {
                $null = $PowershellThread.AddArgument($Object.ToString())
            }
            ForEach ($Key in $AddParam.Keys) {
                $null = $PowershellThread.AddParameter($Key, $AddParam.$key)
            }
            ForEach ($Switch in $AddSwitch) {
                #$Switch
                $null = $PowershellThread.AddParameter($Switch)
            }
            $PowershellThread.RunspacePool = $RunspacePool
            $Handle = $PowershellThread.BeginInvoke()
            $Job = '' | Select-Object Handle, Thread, object
            $Job.Handle = $Handle
            $Job.Thread = $PowershellThread
            $Job.Object = $Object.ToString()
            $Jobs += $Job
        }
        
    }
    End {
        $ResultTimer = Get-Date
        While (@($Jobs | Where-Object { $null -ne $_.Handle }).count -gt 0) {
    
            $Remaining = "$($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False}).object)"
            If ($Remaining.Length -gt 60) {
                $Remaining = $Remaining.Substring(0,60) + '...'
            }
            $ProgressSplat = @{
                Activity = "Waiting for Jobs - $($MaxThreads - $($RunspacePool.GetAvailableRunspaces())) of $MaxThreads threads running"
                PercentComplete = (($Jobs.count - $($($Jobs | Where-Object { $_.Handle.IsCompleted -eq $False }).count)) / $Jobs.Count * 100)
                Status = "$(@($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False})).count) remaining - $remaining"
            }
            Write-Progress @ProgressSplat

            ForEach ($Job in $($Jobs | Where-Object { $_.Handle.IsCompleted -eq $True })) {
                $Job.Thread.EndInvoke($Job.Handle)
                $Job.Thread.Dispose()
                $Job.Thread = $Null
                $Job.Handle = $Null
                $ResultTimer = Get-Date
            }
            If (($(Get-Date) - $ResultTimer).totalseconds -gt $MaxResultTime) {
                Write-Error 'Child script appears to be frozen, try increasing MaxResultTime'
                Exit
            }
            Start-Sleep -Milliseconds $SleepTimer
        
        } 
        Write-Progress -Activity "Waiting for Jobs - $($MaxThreads - $($RunspacePool.GetAvailableRunspaces())) of $MaxThreads threads running" -Status 'Ready' -Completed
        $null = $RunspacePool.Close()
        $null = $RunspacePool.Dispose()
    } 
}
# End Invoke-Multithreader

Function Start-ClientHealthScheduledTask {
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory = $True)][string]$ComputerName,
        [Parameter(Mandatory = $True)][string]$TaskName,
        [Parameter(Mandatory = $True)][string]$SourcePath
    )
    $ScriptBlock = { 
        $Error.Clear()
        $service = New-Object -ComObject 'Schedule.service'
        $service.Connect()
        Try {
            $Folder = $service.GetFolder('\')
            $Task = $Folder.GetTask("$using:TaskName")
            If ($null -eq $Task) {
                Throw
            }
        }
        Catch [System.IO.FileNotFoundException] {
            $Error.Clear()
            Write-Warning -Message "[$Using:ComputerName] Task '\$using:TaskName' does not exist, installing ConfigMgr Client Health Remediation Script..."
            If (! (Test-Path -Path $Using:SourcePath)) {
                Write-Output "Failure"
                Throw "Could not find Client Health source files in '$Using:SourcePath'"
            }
            & "$using:SourcePath\Install-CMClientHealthRemediation.ps1" -Force -EA Continue
            $ExitCode = $LASTEXITCODE
            Switch ($LASTEXITCODE) {
                0 {
                    Write-Output "Installation success"
                }
                Default {
                    Write-Output "Installation failure"
                    Throw "Failed to install Client Health Remediation Script (ExitCode $ExitCode)"
                }
            }
        }
        Try {
            If ($null -ne $Task) {
                If ($task.Enabled -eq $False) {
                    $task.Enabled = $true
                    Write-Warning -Message "[$Using:ComputerName] Task '$($Task.Name)' was disabled"
                }
                $null = $Task.Run(0)
                Write-Verbose -Message "[$Using:ComputerName] Started Task '$($Task.Name)'"
            }
            Else {
                $ArgumentList = "/Run /TN `"\$using:TaskName`""
                $null = Start-Process -FilePath 'schtasks.exe' -ArgumentList $ArgumentList
                Write-Verbose -Message "[$Using:ComputerName] Started Task '\$using:TaskName'"
            }
            Write-Output "Task started successfully"
        }
        Catch {
            Write-Output "Fail to start task : $($_.Exception.Message)"
        }
        Return $Error.Count
    }

    $Splat = @{
        ComputerName = $ComputerName
        ScriptBlock = $ScriptBlock
        #ErrorAction = 'Stop'
    }

    $ComputerDomain = (($ComputerName -split '\.' | Select-Object -Skip 1) -join '.')
    If ($env:USERDNSDOMAIN -ne $ComputerDomain) {
        $Splat.Credential = Get-DomainCredential -Domain $ComputerDomain
    }

    If (! (Test-Connection -ComputerName $ComputerName -Quiet -Count 1 -EA Ignore)) {
        Write-Host "[$ComputerName] Is offline" -ForegroundColor Red
    }
    Else {
        Try {
            $result = $null
            $result = Invoke-Command @Splat
            [int]$ExitCode = $result | Where-Object {$_.Gettype().Name -match 'int32'}
            if (($result -like '*success*' ) -and ($ExitCode -eq 0)) {
                $text = '[{0}] ConfigMgr Client Health started' -f $ComputerName
                Write-Host $text -ForegroundColor Green
            }
            else {
                Throw $result
            }
        }
        Catch {
            $text = '[{0}] ConfigMgr Client Health failed to start : {1}' -f $ComputerName, $_.Exception.Message
            Write-Host $text -ForegroundColor Red
        }
    }
}

Function Install-ClientHealth {
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory = $True)][string]$ComputerName,
        [Parameter(Mandatory = $True)][string]$TaskName,
        [Parameter(Mandatory = $True)][string]$SourcePath
    )
    $ScriptBlock = { 
        If (! (Test-Path -Path $Using:SourcePath)) {
            Throw "Could not find Client Health source files in '$Using:SourcePath'"
        }
        & "$using:SourcePath\Install-CMClientHealthRemediation.ps1" -Force
       Return $LASTEXITCODE
    }

    $Splat = @{
        ComputerName = $ComputerName
        ScriptBlock = $ScriptBlock
        ErrorAction = 'Stop'
    }

    $ComputerDomain = (($ComputerName -split '\.' | Select-Object -Skip 1) -join '.')
    If ($env:USERDNSDOMAIN -ne $ComputerDomain) {
        $Splat.Credential = Get-DomainCredential -Domain $ComputerDomain
    }

    If (! (Test-Connection -ComputerName $ComputerName -Quiet -Count 1 -EA Ignore)) {
        Write-Host "[$ComputerName] Is offline" -ForegroundColor Red
    }
    Else {
        Try {
            $result = $null
            $result = Invoke-Command @Splat
            if (($null -eq $result) -or ($result -eq 0)) {
                $text = '[{0}] ConfigMgr Client Health installed' -f $ComputerName
                Write-Host $text -ForegroundColor Green
            }
            else {
                Throw $result
            }
        }
        Catch {
            $text = '[{0}] ConfigMgr Client Health failed to install : {1}' -f $ComputerName, $_.Exception.Message
            Write-Host $text -ForegroundColor Red
        }
    }
}

Function Uninstall-ClientHealth {
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory = $True)][string]$ComputerName,
        [Parameter(Mandatory = $True)][string]$TaskName,
        [Parameter(Mandatory = $True)][string]$SourcePath
    )
    $ScriptBlock = { 
        If (! (Test-Path -Path $Using:SourcePath)) {
            Throw "Could not find Client Health source files in '$Using:SourcePath'"
        }
        & "$using:SourcePath\Uninstall-CMClientHealthRemediation.ps1"
        Return $LASTEXITCODE
    }

    $Splat = @{
        ComputerName = $ComputerName
        ScriptBlock = $ScriptBlock
        ErrorAction = 'Stop'
    }

    $ComputerDomain = (($ComputerName -split '\.' | Select-Object -Skip 1) -join '.')
    If ($env:USERDNSDOMAIN -ne $ComputerDomain) {
        $Splat.Credential = Get-DomainCredential -Domain $ComputerDomain
    }

    If (! (Test-Connection -ComputerName $ComputerName -Quiet -Count 1 -EA Ignore)) {
        Write-Host "[$ComputerName] Is offline" -ForegroundColor Red
    }
    Else {
        Try {
            $result = $null
            $result = Invoke-Command @Splat
            if (($null -eq $result) -or ($result -eq 0)) {
                $text = '[{0}] ConfigMgr Client Health uninstalled' -f $ComputerName
                Write-Host $text -ForegroundColor Green
            }
            else {
                Throw $result
            }
        }
        Catch {
            $text = '[{0}] ConfigMgr Client Health failed to uninstall : {1}' -f $ComputerName, $_.Exception.Message
            Write-Host $text -ForegroundColor Red
        }
    }
}

#endregion Functions

switch ($Type) {
    'Device' {
        $Uri = '{0}/wmi/SMS_R_System?$filter=ResourceID eq {1}&$Select=ResourceNames,Name,Domain' -f $CMAdminServiceURI, $ResourceId
        [String]$ComputerName = Invoke-RestMethod -Uri $URI -UseDefaultCredentials | Select-Object -ExpandProperty value | Select-Object -ExpandProperty ResourceNames -First 1
        If ($ComputerName -eq '') {
            Write-Host "Computer with resourceId $ResourceId cannot be found" -ForegroundColor Red
            break
        }
        
        $Splat = @{
            TaskName = $TaskName 
            ComputerName = $ComputerName 
            SourcePath = $SourcePath 
            Verbose = $true
        }

        switch ($PSCmdlet.ParameterSetName) {
            'Start' {
                Start-ClientHealthScheduledTask @Splat
            }
            'Install' {
                Install-ClientHealth @Splat
            }
            'Uninstall' {
                Uninstall-ClientHealth @Splat
            }
        }
    }
    'Collection' {
        $URI = "{0}/wmi/SMS_FullCollectionMembership?`$filter=CollectionID eq '{1}'&`$Select=Name,Domain" -f $CMAdminServiceURI, $ResourceId
        [String[]]$ComputerList = Invoke-RestMethod -Uri $URI -UseDefaultCredentials | 
                                    Select-Object -ExpandProperty value | 
                                    Select-Object -Property @{Label = 'Fqdn'; Expression = {"$($_.Name).$(($DomainTranslationTable | Where-Object -Property Netbios -eq $_.Domain)['Domain'])"}} |
                                    Select-Object -ExpandProperty Fqdn

        # We need to list out all collection members before we can process them. Connect to SCCM to get hostnames.
        #$SiteCode = Get-WMIObject -Namespace "root\SMS" -Class "SMS_ProviderLocation" | Select-Object -ExpandProperty SiteCode
        #$SiteCode = (Get-WmiObject -Namespace 'root\ccm' -Class 'SMS_Authority').Name.split(":")[1]

        # Using the Invoke-Multithreader function to start ConfigMgr Client Health on several computers at the same time.
        $Splat = @{
            ObjectList = $ComputerList 
            MaxThreads = $MaxThreads 
            InputParam = 'ComputerName' 
            AddParam = @{TaskName = $TaskName; SourcePath = $SourcePath}
        }
        switch ($PSCmdlet.ParameterSetName) {
            'Start' {
                $Command = "Start-ClientHealthScheduledTask"
            }
            'Install' {
                $Command = "Install-ClientHealth"
            }
            'Uninstall' {
                $Command = "Uninstall-ClientHealth"
            }
        }
        Invoke-Multithreader -Command  @Splat

    }
}

Write-Host 'Press any key to continue ...'
$null = $host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')