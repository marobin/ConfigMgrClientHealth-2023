[CmdLetBinding(DefaultParameterSetName = 'Start')]
param(
    [Parameter(Mandatory = $True,Position = 0, ParameterSetName = 'Install')]
    [Parameter(Mandatory = $True,Position = 0, ParameterSetName = 'Start')]
    [Parameter(Mandatory = $True,Position = 0, ParameterSetName = 'Uninstall')]
    [string]$ResourceId,

    [Parameter(Mandatory = $True,Position = 1, ParameterSetName = 'Install')]
    [Parameter(Mandatory = $True,Position = 1, ParameterSetName = 'Start')]
    [Parameter(Mandatory = $True,Position = 1, ParameterSetName = 'Uninstall')]
    [string]$Name,

    [Parameter(Mandatory = $true, Position = 2, ParameterSetName = 'Install')]
    [Parameter(Mandatory = $true, Position = 2, ParameterSetName = 'Start')]
    [Parameter(Mandatory = $true, Position = 2, ParameterSetName = 'Uninstall')]
    [ValidateScript({ $_ -match '^ROOT\\SMS\\site_\w{3}$' })]
    [String]$Namespace,

    [Parameter(Mandatory = $True,Position = 3, ParameterSetName = 'Install')]
    [Parameter(Mandatory = $True,Position = 3, ParameterSetName = 'Start')]
    [Parameter(Mandatory = $True,Position = 3, ParameterSetName = 'Uninstall')]
    [string]$Type,

    [Parameter(Position = 4, ParameterSetName = 'Install')]
    [Parameter(Position = 4, ParameterSetName = 'Start')]
    [Parameter(Position = 4, ParameterSetName = 'Uninstall')]
    [Alias('ScheduledTask')]
    [String]$TaskName,

    [Parameter(Mandatory = $False,Position = 5, ParameterSetName = 'Install')]
    [Parameter(Mandatory = $False,Position = 5, ParameterSetName = 'Start')]
    [Parameter(Mandatory = $False,Position = 5, ParameterSetName = 'Uninstall')]
    [string]$MaxThreads = 20,

    [Parameter(Position = 6, ParameterSetName = 'Install')]
    [switch]$Install,

    [Parameter(Position = 6, ParameterSetName = 'Start')]
    [switch]$Start,

    [Parameter(Position = 6, ParameterSetName = 'Uninstall')]
    [switch]$Uninstall
)


#region variables
$SourcePath = "$env:ALLUSERSPROFILE\ConfigMgrClientHealth"
$RegistryKey = 'HKLM:\Software\ConfigMgrClientHealth'
# TODO : Fill up the following table with your domains
# The Credential attribute must be set to null and will hold the credentials for the specified domain if needed
$DomainTranslationTable = @(
    @{Netbios = 'CORP'; Domain = 'corp.contoso.com'; Credential = $null }
)
#endregion variables

#region CM Provider
$SiteCode = $Namespace.Substring(14)

try {
    $ModuleName = 'ConfigurationManager'
    $ModulePath = "$env:SMS_ADMIN_UI_PATH\..\$ModuleName.psd1"

    if (!(Get-Module -Name $ModuleName) -and (Test-Path -Path $ModulePath)) {
        Import-Module -Name $ModulePath -Verbose:$false
    }
    else {
        throw "Cannot find $ModuleName module at '$ModulePath'"
    }

    $CMSiteProv = Get-PSDrive -PSProvider 'CMSite' -ErrorAction Ignore | Where-Object -Property Name -EQ $SiteCode
    $CMPsDrive = "$($CMSiteProv | Select-Object -First 1 -ExpandProperty Name):"
    Set-Location -Path $CMPsDrive -Verbose:$false

    # Getting the SMS Provider FQDN in order to use the admin web service
    #$ServerName = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\ConfigMgr10\AdminUI\Connection' -Name 'Server').Server
    # We could also use the parameter ##SUB:__Server## in the xml but it does not contain the server FQDN
    $ServerName = (Get-CMSiteRole -RoleName 'SMS Provider' -Verbose:$false | Select-Object -ExpandProperty NetworkOSPath -First 1).Trim('\')
    $CMAdminServiceURL = "https://$ServerName/adminService/wmi"

    Set-Location -Path $env:SystemDrive -Verbose:$false
}
catch {
    Write-Host "Could not connect to $ModuleName provider : $($_.Exception.Message)"
    Write-Host 'Press any key to continue ...'
    $null = $host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    exit
}
#endregion CM Provider


#region Functions
function Get-DomainCredential {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [String]$Domain
    )

    $DomainHash = $Script:DomainTranslationTable | Where-Object -Property Domain -EQ $Domain

    $DomainCred = $DomainHash['Credential']
    if ($null -eq $DomainCred) {
        $DomainNetBIOS = $DomainHash['Netbios']
        $DomainCred = $DomainHash['Credential'] = Get-Credential -Message "Enter credentials for domain '$Domain'" -UserName "$DomainNetBIOS\..."
    }
    return $DomainCred
}

# Define the multhithreader function (Authored by Ryan Witschger - http://www.Get-Blog.com)

function Invoke-Multithreader {
    param(
        $Command = $(Read-Host 'Enter the script file'),
        [Parameter(ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)]$ObjectList,
        $InputParam = $Null,
        $MaxThreads = 20,
        $SleepTimer = 200,
        $MaxResultTime = 120,
        [HashTable]$AddParam = @{},
        [Array]$AddSwitch = @()
    )

    begin {
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
        $JobList = New-Object -TypeName System.Collections.ArrayList

    }
    process {
        Write-Progress -Activity 'Preloading threads' -Status "Starting Job $($JobList.count)"
        foreach ($Object in $ObjectList) {
            if ($Null -eq $Code) {
                $PowershellThread = [powershell]::Create().AddCommand($Command)
            }
            else {
                $PowershellThread = [powershell]::Create().AddScript($Code)
            }
            if ($Null -ne $InputParam) {
                $null = $PowershellThread.AddParameter($InputParam, $Object.ToString())
            }
            else {
                $null = $PowershellThread.AddArgument($Object.ToString())
            }
            foreach ($Key in $AddParam.Keys) {
                $null = $PowershellThread.AddParameter($Key, $AddParam.$key)
            }
            foreach ($Switch in $AddSwitch) {
                #$Switch
                $null = $PowershellThread.AddParameter($Switch)
            }
            $PowershellThread.RunspacePool = $RunspacePool
            $Handle = $PowershellThread.BeginInvoke()
            $null = $JobList.Add(([PSCustomObject]@{
                        Handle = $Handle
                        Thread = $PowershellThread
                        Object = $Object.ToString()
                    }))
        }

    }
    end {
        $ResultTimer = Get-Date
        while (@($JobList | Where-Object { $null -ne $_.Handle }).count -gt 0) {

            $Remaining = "$($($JobList | Where-Object {$_.Handle.IsCompleted -eq $False}).object)"
            if ($Remaining.Length -gt 60) {
                $Remaining = $Remaining.Substring(0,60) + '...'
            }
            $ProgressSplat = @{
                Activity        = "Waiting for Jobs - $($MaxThreads - $($RunspacePool.GetAvailableRunspaces())) of $MaxThreads threads running"
                PercentComplete = (($JobList.count - $($($JobList | Where-Object { $_.Handle.IsCompleted -eq $False }).count)) / $JobList.Count * 100)
                Status          = "$(@($($JobList | Where-Object {$_.Handle.IsCompleted -eq $False})).count) remaining - $remaining"
            }
            Write-Progress @ProgressSplat

            foreach ($Job in $($JobList | Where-Object { $_.Handle.IsCompleted -eq $True })) {
                $Job.Thread.EndInvoke($Job.Handle)
                $Job.Thread.Dispose()
                $Job.Thread = $Null
                $Job.Handle = $Null
                $ResultTimer = Get-Date
            }
            if (($(Get-Date) - $ResultTimer).totalseconds -gt $MaxResultTime) {
                Write-Error 'Child script appears to be frozen, try increasing MaxResultTime'
                exit
            }
            Start-Sleep -Milliseconds $SleepTimer

        }
        Write-Progress -Activity "Waiting for Jobs - $($MaxThreads - $($RunspacePool.GetAvailableRunspaces())) of $MaxThreads threads running" -Status 'Ready' -Completed
        $null = $RunspacePool.Close()
        $null = $RunspacePool.Dispose()
    }
}
# End Invoke-Multithreader

function Start-ClientHealthScheduledTask {
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory = $True)][string]$ComputerName,
        [Parameter(Mandatory = $True)][string]$TaskName,
        [Parameter(Mandatory = $True)][string]$SourcePath,
        [Parameter(Mandatory = $True)][string]$RegistryKey,
        [Parameter(Mandatory = $false)][switch]$Force
    )

    $ScriptBlock = {
        param ([bool]$Force)

        $Error.Clear()
        $service = New-Object -ComObject 'Schedule.service'
        $service.Connect()
        try {
            $Folder = $service.GetFolder('\')
            $Task = $Folder.GetTask("$using:TaskName")
            if ($null -eq $Task) {
                throw
            }
        }
        catch [System.IO.FileNotFoundException] {
            $Error.Clear()
            Write-Warning -Message "[$Using:ComputerName] Task '\$using:TaskName' does not exist, installing ConfigMgr Client Health Remediation Script..."
            if (! (Test-Path -Path $Using:SourcePath)) {
                Write-Output 'Failure'
                throw "Could not find Client Health source files in '$Using:SourcePath'"
            }
            $CHScriptName = 'Install-CMClientHealthRemediation*.ps1'
            [String]$CHScriptPath = Get-ChildItem -Path $using:SourcePath -Filter $CHScriptName | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
            if ("$CHScriptPath" -ne '') {
                & $CHScriptPath -Force -EA Continue
                $ExitCode = $LASTEXITCODE
                switch ($ExitCode) {
                    0 {
                        Write-Output 'Installation success'
                    }
                    Default {
                        Write-Output 'Installation failure'
                        throw "Failed to install Client Health Remediation Script (ExitCode $ExitCode)"
                    }
                }
            }
            else {
                throw "Could not find Client Health script in '$Using:SourcePath' using filter '$CHScriptName'"
            }
        }
        try {
            if (Test-Path -Path $Using:RegistryKey) {
                # Forcing the execution of the script even if the computer was not rebooted since the last run
                $null = New-ItemProperty -Path $Using:RegistryKey -Name 'ForceExecution' -PropertyType String -Value 'True'
            }
            if ($null -ne $Task) {
                if ($task.Enabled -eq $False) {
                    $task.Enabled = $true
                    Write-Warning -Message "[$Using:ComputerName] Task '$($Task.Name)' was disabled"
                }
                $null = $Task.Run(0)
                Write-Verbose -Message "[$Using:ComputerName] Started Task '$($Task.Name)'"
            }
            else {
                $ArgumentList = "/Run /TN `"\$using:TaskName`""
                $null = Start-Process -FilePath 'schtasks.exe' -ArgumentList $ArgumentList
                Write-Verbose -Message "[$Using:ComputerName] Started Task '\$using:TaskName'"
            }
            Write-Output 'Task started successfully'
        }
        catch {
            Write-Output "Fail to start task : $($_.Exception.Message)"
        }
        return $Error.Count
    }

    $Splat = @{
        ComputerName = $ComputerName
        ScriptBlock  = $ScriptBlock
        ArgumentList = @($Force.IsPresent)
        #ErrorAction = 'Stop'
    }

    $ComputerDomain = (($ComputerName -split '\.' | Select-Object -Skip 1) -join '.')
    if ($env:USERDNSDOMAIN -ne $ComputerDomain) {
        $Splat.Credential = Get-DomainCredential -Domain $ComputerDomain
    }

    if (! (Test-Connection -ComputerName $ComputerName -Quiet -Count 1 -EA Ignore)) {
        Write-Host "[$ComputerName] Is offline" -ForegroundColor Red
    }
    else {
        try {
            $result = $null
            $result = Invoke-Command @Splat
            [int]$ExitCode = $result | Where-Object { $_.Gettype().Name -match 'int32' }
            if (($result -like '*success*' ) -and ($ExitCode -eq 0)) {
                $text = '[{0}] ConfigMgr Client Health started' -f $ComputerName
                Write-Host $text -ForegroundColor Green
            }
            else {
                throw $result
            }
        }
        catch {
            $text = '[{0}] ConfigMgr Client Health failed to start : {1}' -f $ComputerName, $_.Exception.Message
            Write-Host $text -ForegroundColor Red
        }
    }
}

function Install-ClientHealth {
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory = $True)][string]$ComputerName,
        [Parameter(Mandatory = $True)][string]$TaskName,
        [Parameter(Mandatory = $True)][string]$SourcePath,
        [Parameter(Mandatory = $True)][string]$RegistryKey
    )

    $ScriptBlock = {
        if (! (Test-Path -Path $Using:SourcePath)) {
            throw "Could not find Client Health source files in '$Using:SourcePath'"
        }
        $CHScriptName = 'Install-CMClientHealthRemediation*.ps1'
        [String]$CHScriptPath = Get-ChildItem -Path $using:SourcePath -Filter $CHScriptName | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
        if ("$CHScriptPath" -ne '') {
            & $CHScriptPath -Force
            return $LASTEXITCODE
        }
        else {
            throw "Could not find Client Health script in '$Using:SourcePath' using filter '$CHScriptName'"
        }
    }

    $Splat = @{
        ComputerName = $ComputerName
        ScriptBlock  = $ScriptBlock
        ErrorAction  = 'Stop'
    }

    $ComputerDomain = (($ComputerName -split '\.' | Select-Object -Skip 1) -join '.')
    if ($env:USERDNSDOMAIN -ne $ComputerDomain) {
        $Splat.Credential = Get-DomainCredential -Domain $ComputerDomain
    }

    if (! (Test-Connection -ComputerName $ComputerName -Quiet -Count 1 -EA Ignore)) {
        Write-Host "[$ComputerName] Is offline" -ForegroundColor Red
    }
    else {
        try {
            $result = $null
            $result = Invoke-Command @Splat
            if (($null -eq $result) -or ($result -eq 0)) {
                $text = '[{0}] ConfigMgr Client Health installed' -f $ComputerName
                Write-Host $text -ForegroundColor Green
            }
            else {
                throw $result
            }
        }
        catch {
            $text = '[{0}] ConfigMgr Client Health failed to install : {1}' -f $ComputerName, $_.Exception.Message
            Write-Host $text -ForegroundColor Red
        }
    }
}

function Uninstall-ClientHealth {
    [CmdLetBinding()]
    param(
        [Parameter(Mandatory = $True)][string]$ComputerName,
        [Parameter(Mandatory = $True)][string]$TaskName,
        [Parameter(Mandatory = $True)][string]$SourcePath,
        [Parameter(Mandatory = $True)][string]$RegistryKey
    )

    $ScriptBlock = {
        if (! (Test-Path -Path $Using:SourcePath)) {
            throw "Could not find Client Health source files in '$Using:SourcePath'"
        }
        & "$using:SourcePath\Uninstall-CMClientHealthRemediation.ps1"
        return $LASTEXITCODE
    }

    $Splat = @{
        ComputerName = $ComputerName
        ScriptBlock  = $ScriptBlock
        ErrorAction  = 'Stop'
    }

    $ComputerDomain = (($ComputerName -split '\.' | Select-Object -Skip 1) -join '.')
    if ($env:USERDNSDOMAIN -ne $ComputerDomain) {
        $Splat.Credential = Get-DomainCredential -Domain $ComputerDomain
    }

    if (! (Test-Connection -ComputerName $ComputerName -Quiet -Count 1 -EA Ignore)) {
        Write-Host "[$ComputerName] Is offline" -ForegroundColor Red
    }
    else {
        try {
            $result = $null
            $result = Invoke-Command @Splat
            if (($null -eq $result) -or ($result -eq 0)) {
                $text = '[{0}] ConfigMgr Client Health uninstalled' -f $ComputerName
                Write-Host $text -ForegroundColor Green
            }
            else {
                throw $result
            }
        }
        catch {
            $text = '[{0}] ConfigMgr Client Health failed to uninstall : {1}' -f $ComputerName, $_.Exception.Message
            Write-Host $text -ForegroundColor Red
        }
    }
}

#endregion Functions

switch ($Type) {
    'Device' {
        $Uri = '{0}/SMS_R_System?$filter=ResourceID eq {1}&$Select=ResourceNames,ResourceDomainORWorkgroup,DistinguishedName,SystemOUName,Client' -f $CMAdminServiceURL, $ResourceId
        $Result = Invoke-RestMethod -Uri $URI -UseDefaultCredentials | Select-Object -ExpandProperty value
        [String]$ComputerName = $Result | Select-Object -ExpandProperty ResourceNames -First 1
        if ($ComputerName -eq '') {
            if ($DomainNetBios = $Result | Where-Object -Property ResourceDomainORWorkgroup -NE '' | Select-Object -ExpandProperty ResourceDomainORWorkgroup) {
                $ComputerName = "$Name.$(($DomainTranslationTable | Where-Object -Property Netbios -EQ $DomainNetBios)['Domain'])"
            }
            elseif ($DN = $Result | Where-Object -Property DistinguishedName -NE '' | Select-Object -ExpandProperty DistinguishedName) {
                $Domain = $DN -replace '.*OU=[^,]+,DC=' -replace ',DC=','.'
                $ComputerName = "$Name.$Domain"
            }
            elseif ($Item = $Result | Where-Object { $_.SystemOUName -match '^([^/]+)/(Computers|Ordinateurs)$' }) {
                $Domain = $Item.SystemOUName -match '^([^/]+)/(Computers|Ordinateurs)$'
                if ($Domain.IndexOf('.') -gt 0) {
                    $ComputerName = "$Name.$Domain"
                }
                else {
                    $ComputerName = "$Name.$(($DomainTranslationTable | Where-Object -Property Netbios -EQ $DomainNetBios)['Domain'])"
                }
            }
            else {
                [String]$ComputerName = Read-Host -Prompt "Enter the fully qualified domain name of $Name ($ResourceId)"
            }
        }
        if ($ComputerName.Trim() -eq '') {
            Write-Host "Cannot determine the domain of computer $Name ($ResourceId)" -ForegroundColor Red
            break
        }

        $Splat = @{
            TaskName     = $TaskName.Trim("'")
            ComputerName = $ComputerName
            SourcePath   = $SourcePath
            RegistryKey  = $RegistryKey
            Verbose      = $true
        }

        switch ($PSCmdlet.ParameterSetName) {
            'Start' {
                Start-ClientHealthScheduledTask @Splat -Force
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
        $URI = "{0}/SMS_FullCollectionMembership?`$filter=CollectionID eq '{1}'&`$Select=Name,Domain,IsClient,ResourceId" -f $CMAdminServiceURL, $ResourceId
        [String[]]$ComputerList = Invoke-RestMethod -Uri $URI -UseDefaultCredentials |
            Select-Object -ExpandProperty value |
            Select-Object -Property @{Label = 'Fqdn'; Expression = { "$($_.Name).$(($DomainTranslationTable | Where-Object -Property Netbios -EQ $_.Domain)['Domain'])" } } |
            Select-Object -ExpandProperty Fqdn

        # We need to list out all collection members before we can process them. Connect to SCCM to get hostnames.
        #$SiteCode = Get-WMIObject -Namespace "root\SMS" -Class "SMS_ProviderLocation" | Select-Object -ExpandProperty SiteCode
        #$SiteCode = (Get-WmiObject -Namespace 'root\ccm' -Class 'SMS_Authority').Name.split(":")[1]

        # Using the Invoke-Multithreader function to start ConfigMgr Client Health on several computers at the same time.
        $Splat = @{
            ObjectList = $ComputerList
            MaxThreads = $MaxThreads
            InputParam = 'ComputerName'
            AddParam   = @{TaskName = $TaskName.Trim("'"); SourcePath = $SourcePath; RegistryKey = $RegistryKey }
        }
        switch ($PSCmdlet.ParameterSetName) {
            'Start' {
                $Splat.AddSwitch('Force')
                $Command = 'Start-ClientHealthScheduledTask'
            }
            'Install' {
                $Command = 'Install-ClientHealth'
            }
            'Uninstall' {
                $Command = 'Uninstall-ClientHealth'
            }
        }
        Invoke-Multithreader -Command @Splat
    }
}

Write-Host 'Press any key to continue ...'
$null = $host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')