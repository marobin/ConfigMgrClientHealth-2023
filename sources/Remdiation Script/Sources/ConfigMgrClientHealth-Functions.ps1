
#region functions

#region WMI
Function Get-WMIClassInstance {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [String]$Class,

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]$Namespace,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [String]$Filter,
            
        [Parameter(Position = 3)]
        [String[]]$Property
    )

    $WMISplat = @{
        Class = $Class
    }
    If ($Namespace -ne '') { $WMISplat.Namespace = $Namespace }
    If ($Filter -ne '') { $WMISplat.Filter = $Filter }
    If ($Property.Count -gt 0) { $WMISplat.Property = $Property }

    if ($Script:PowerShellVersion -ge 6) {
        Get-CimInstance @WMISplat
    }
    else {
        Get-WmiObject @WMISplat
    }
}

# Gather info about the computer
Function Get-Info {
    New-Object PSObject -Property @{
        Hostname         = $env:COMPUTERNAME;
        Manufacturer     = $WMIComputerSystem.Manufacturer
        Model            = $WMIComputerSystem.Model
        Operatingsystem  = $WMIOperatingSystem.Caption;
        Architecture     = $WMIOperatingSystem.OSArchitecture;
        Build            = $WMIOperatingSystem.BuildNumber;
        InstallDate      = Get-SmallDateTime -Date $WMIOperatingSystem.InstallDate
        LastLoggedOnUser = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\').LastLoggedOnUser;
    }
}



Function GetComputerInfo {
    $info = Get-Info | Select-Object HostName, OperatingSystem, Architecture, Build, InstallDate, Manufacturer, Model, LastLoggedOnUser
    Write-Log -Message ('Hostname: ' + $info.HostName)
    Write-Log -Message ('Operatingsystem: ' + $info.OperatingSystem)
    Write-Log -Message ('Architecture: ' + $info.Architecture)
    Write-Log -Message ('Build: ' + $info.Build)
    Write-Log -Message ('Manufacturer: ' + $info.Manufacturer)
    Write-Log -Message ('Model: ' + $info.Model)
    Write-Log -Message ('InstallDate: ' + $info.InstallDate)
    Write-Log -Message ('LastLoggedOnUser: ' + $info.LastLoggedOnUser)
}


Function Get-OperatingSystem {
    $PropertyList = @(
        'Caption',
        @{Label = 'OSName'; Expression = {
                switch -Wildcard ($_.Caption) {
                    "*Embedded*" { "Windows 7" }
                    "*Windows 7*" { "Windows 7" }
                    "*Windows 8.1*" { "Windows 8.1" }
                    "*Windows 10*" { "Windows 10" }
                    "*Windows 11*" { "Windows 11" }
                    "*Server 2008*" {
                        if ($_.Caption -like "*R2*") { "Windows Server 2008 R2" }
                        else { "Windows Server 2008" }
                    }
                    "*Server 2012*" {
                        if ($_.Caption -like "*R2*") { "Windows Server 2012 R2" }
                        else { "Windows Server 2012" }
                    }
                    "*Server 2016*" { "Windows Server 2016" }
                    "*Server 2019*" { "Windows Server 2019" }
                    "*Server 2022*" { "Windows Server 2022" }
                }
            }
        },
        @{Label = 'OSArchitecture'; Expression = { ($_.OSArchitecture -replace ('([^0-9])(\.*)', '')) + '-Bit' } },
        @{Label = 'InstallDate'; Expression = {
                If ($_.InstallDate.GetType().Name -ne 'DateTime') { $_.ConvertToDateTime($_.InstallDate) }
                Else { $_.InstallDate }
            }
        },
        @{Label = 'LastBootUpTime'; Expression = {
                If ($_.LastBootUpTime.GetType().Name -ne 'DateTime') { $_.ConvertToDateTime($_.LastBootUpTime) }
                Else { $_.LastBootUpTime }
            }
        },
        'BuildNumber',
        @{Label = 'BuildVersion'; Expression = {
                If ($_.Caption -match 'Windows (10|11)') {
                    Try{
                        [String]$build = $Script:WindowBuildHash["$($_.BuildNumber)"]
                        If ($build -eq '') { Throw }
                    }
                    Catch{
                        $Error.RemoveAt(0)
                        [String]$build = 'Insider preview'
                    }
                    $build
                }
            }
        }
    )
    Get-WMIClassInstance -Class Win32_OperatingSystem | Select-Object -Property $PropertyList
}

Function Get-ComputerSystem {
    $PropertyList = @(
        'Manufacturer',
        @{Label = 'Model'; Expression = {
                if ($_.Manufacturer -like 'Lenovo') { Get-WMIClassInstance -Class Win32_ComputerSystemProduct | Select-Object -ExpandProperty Version }
                else { $_.Model }
            }
        },
        'Domain',
        'Name'
    )
    Get-WMIClassInstance -Class Win32_ComputerSystem | Select-Object -Property $PropertyList
}

Function Get-OperatingSystemFullName {
    "$($WMIOperatingSystem.OSName) $($WMIOperatingSystem.BuildNumber)"
}

Function Get-Domain {
    $WMIComputerSystem.Domain
}

Function Get-ComputerSID {
    [System.Security.Principal.NTAccount]::new("$env:COMPUTERNAME$").Translate([System.Security.Principal.SecurityIdentifier]).Value
}

Function Get-OSDiskSpace {
    Get-WMIClassInstance -Class Win32_LogicalDisk | 
        Where-Object { $_.DeviceID -eq "$env:SystemDrive" } | 
        Select-Object FreeSpace, 
                      Size, 
                      @{Label = 'FreeSpacePct'; Expression = { [math]::Round((($_.FreeSpace / $_.Size) * 100), 2) } }
}

Function Get-Computername {
    $WMIComputerSystem.Name
}

Function Get-LastBootTime {
    $WMIOperatingSystem.LastBootTime
}



Function Test-WMI {
    Param([Parameter(Mandatory = $true)]$Log)
    $vote = 0
    $obj = $false

    $result = winmgmt /verifyrepository
    switch -wildcard ($result) {
        # Always fix if this returns inconsistent
        "*inconsistent*" { $vote = 100 } # English/Spanish
        "*not consistent*" { $vote = 100 } # English
        "*inkonsekvent*" { $vote = 100 } # Swedish
        "*epäyhtenäinen*" { $vote = 100 } # Finnish
        "*inkonsistent*" { $vote = 100 } # German
        "*incohérent*" { $vote = 100 } # French
        "*incoerente*" { $vote = 100 } # Portuguese
        # Add more languages as I learn their inconsistent value
    }

    Try {
        $WMI = Get-WMIClassInstance -Class Win32_ComputerSystem -ErrorAction Stop
    }
    Catch {
        Write-Log -Message 'Failed to connect to WMI class "Win32_ComputerSystem". Voting for WMI fix...' -Type 'WARNING'
        $vote++
    }
    Finally {
        if ($vote -eq 0) {
            $log.WMI = 'Compliant'
            Write-Log -Message 'WMI Check: OK'
        }
        else {
            $fix = Get-XMLConfigWMIRepairEnable
            if ($fix -like "True") {
                Write-Log -Message 'WMI Check: Corrupt. Attempting to repair WMI and reinstall ConfigMgr client.' -Type 'WARNING'
                Repair-WMI
                $log.WMI = 'Repaired'
            }
            else {
                Write-Log -Message 'WMI Check: Corrupt. Autofix is disabled' -Type 'WARNING'
                $log.WMI = 'Corrupt'
            }
            Write-Log -Message "returning true to tag client for reinstall" -Type 'WARNING'
            $obj = $true
        }
        #Out-LogFile -Xml $xml -Text $text
    }
    Return $obj
}

Function Repair-WMI {
    # https://techcommunity.microsoft.com/t5/ask-the-performance-team/wmi-rebuilding-the-wmi-repository/ba-p/373846
    Write-Log -Message 'Repairing WMI'

    # Check PATH
    if ((! (@(($ENV:PATH).Split(";")) -contains "$env:SystemDrive\WINDOWS\System32\Wbem")) -and (! (@(($ENV:PATH).Split(";")) -contains "%systemroot%\System32\Wbem"))) {
        Write-Log -Message "WMI Folder not in search path!." -Type 'WARNING'
    }
    # Stop WMI
    Get-Service -Name 'ccmexec','winmgmt' -ErrorAction SilentlyContinue | Stop-Service -Force -Verbose
    Write-Log -Message "Stopping services ccmexec and winmgmt"

    Remove-Item -Path "$env:SystemRoot\System32\wbem\repository" -Recurse -Force
    Write-Log -Message "Removing Repository"

    $WbemPathList = @("$env:SystemRoot\System32\wbem","$env:SystemRoot\SysWOW64\wbem")
    $WBEMDLLList = Get-ChildItem -Path $WbemPathList -Filter '*.dll' -Recurse -ErrorAction Continue | Select-Object -ExpandProperty FullName
    Register-DLLFile -FilePath $WBEMDLLList

    # WMI Binaries
    $WMIBinaries = @(
        'scrcons.exe'
        'unsecapp.exe'
        'winmgmt.exe'
        'wmiadap.exe'
        'wmiapsrv.exe'
        'wmiprvse.exe'
    )
    foreach ($WMIPath in $WbemPathList) {
        if (Test-Path -Path $WMIPath) {
            Push-Location $WMIPath
            foreach ($sBin in $WMIBinaries) {
                if (Test-Path -Path $sBin) {
                    $oCurrentBin = Get-Item -Path $sBin | Select-Object -ExpandProperty FullName
                    $Return = Invoke-Executable -FilePath "$oCurrentBin" -ArgumentList '/RegServer'
                    $StdOut = ''
                    If ($Return.ExitCode -ne 0) {
                        $StdOut = "$($Return.StdOut)`r`n$($Return.StdErr)"
                    }
                    Write-Log -Message "Registering WMI Binary '$oCurrentBin' : $StdOut"
                }
                else {
                    # Warning only for System32
                    if ($WMIPath -eq "$ENV:SystemRoot\System32\wbem") {
                        Write-Log -Message "File '$sBin' not found!" -Type 'WARNING'
                    }
                }
            }
            Pop-Location
        }
    }

    $MofList = Get-ChildItem -Path $WbemPathList -Filter '*.mof' -Recurse | 
                Where-Object {@('.mof','.mfl') -contains $_.Extension} |
                Select-Object -ExpandProperty FullName

    Foreach ($MofPath in $MofList) {
        $null = Invoke-Executable -FilePath 'mofcomp' -ArgumentList "$MofPath"
        Write-Log -Message "Launched 'mofcomp $MofPath'"
    }

    # Reregister Managed Objects
    Write-Log -Message "Reseting Repository..."
    $ActionList = @(
        @{Name = 'reset'; ArgumentList = '/resetrepository'}
        @{Name = 'salvage'; ArgumentList = '/salvagerepository'}
    )
    $WinMgmt = "$ENV:SystemRoot\system32\wbem\winmgmt.exe"
    Foreach ($action in $ActionList) {
        $Return = Invoke-Executable -FilePath $WinMgmt -ArgumentList "$($Action.ArgumentList)"
        $StdOut = ''
        If ($Return.ExitCode -ne 0) {
            $StdOut = "$($Return.StdOut)`r`n$($Return.StdErr)"
        }
        Write-Log -Message "Repository $($action.Name) done : $StdOut" -Type 'WARNING'
    }
    
    Start-Service -Name winmgmt
    Write-Log -Message 'Started service winmgmt' -Type 'WARNING'
    Write-Log -Message 'Tagging ConfigMgr client for reinstall' -Type 'WARNING'
}



Function Test-DiskSpace {
    $XMLDiskSpace = Get-XMLConfigOSDiskFreeSpace
    $freeSpace = Get-OSDiskSpace | Select-Object -ExpandProperty FreeSpacePct

    if ($freeSpace -le $XMLDiskSpace) {
        Write-Log -Message "Local disk $env:SystemDrive Less than $XMLDiskSpace % free space" -Type 'ERROR'
    }
    else {
        Write-Log -Message "Free space $env:SystemDrive OK"
    }
}

#endregion WMI


#region WebService

# Update-WebService use ClientHealth Webservice to update database. RESTful API.
Function Update-Webservice {
    Param([Parameter(Mandatory = $true)][String]$URI, $Log)

    $Hostname = $env:COMPUTERNAME
    #$ComputerSID = Get-ComputerSID
    $Obj = $Log | ConvertTo-Json
    $DebugFile = "$Script:ScriptPath\webservice.json"
    
    Out-File -InputObject $obj -FilePath $DebugFile -Encoding utf8 -Force # Debug, removed at the end
    
    $URI = $URI + "/Clients"

    # Detect if we use PUT or POST
    try {
        $null = Invoke-RestMethod -Uri "$URI/$Hostname"
        $Method = "PUT"
        $URI = $URI + "/$Hostname"
    }
    catch { 
        $Error.RemoveAt(0)
        $Method = "POST" 
    }

    $RESTSplat = @{
        Uri         = $URI 
        Body        = $Obj 
        ContentType = "application/json"
        Method      = $Method 
        ErrorAction = 'Stop'
    }
    try { 
        $null = Invoke-RestMethod @RESTSplat
        Remove-Item -Path $DebugFile -Force -ErrorAction Continue
    }
    catch {
        Write-Log -Message "Error Invoking RestMethod $Method on URI $URI. Failed to update database using webservice."
    }
}

# Retrieve configuration from SQL using webserivce
Function Get-ConfigFromWebservice {
    Param(
        [Parameter(Mandatory = $true)][String]$URI,
        [Parameter(Mandatory = $false)][String]$ProfileID
    )

    $URI = $URI + "/ConfigurationProfile"
    #Write-Log -Message "ProfileID = $ProfileID"
    if ($ProfileID -ge 0) { $URI = $URI + "/$ProfileID" }

    try {
        $Obj = Invoke-RestMethod -Uri $URI -ErrorAction Stop
        Write-Log -Message "Retrieved configuration from webservice. URI: $URI"
    }
    catch {
        Write-Log -Message "Error retrieving configuration from webservice $URI."
        Write-Log -Message ('=' * 80)
        Exit 1
    }

    Return $Obj
}

Function Get-ConfigClientInstallPropertiesFromWebService {
    Param(
        [Parameter(Mandatory = $true)][String]$URI,
        [Parameter(Mandatory = $true)][String]$ProfileID
    )

    $URI = $URI + "/ClientInstallProperties"

    try {
        $CIP = Invoke-RestMethod -Uri $URI -ErrorAction Stop
        Write-Log -Message "Retrieved client install properties from webservice"
    }
    catch {
        Write-Log -Message "Error retrieving client install properties from webservice $URI."
        Write-Log -Message ('=' * 80)
        Exit 1
    }

    $string = $CIP | Where-Object { $_.profileId -eq $ProfileID } | Select-Object -ExpandProperty cmd
    $obj = $string -join ' '

    # Remove the trailing space from the last parameter caused by the foreach loop
    #$obj = $obj.Substring(0, $obj.Length - 1)
    Return $Obj
}

Function Get-ConfigServicesFromWebservice {
    Param(
        [Parameter(Mandatory = $true)][String]$URI,
        [Parameter(Mandatory = $true)][String]$ProfileID
    )

    $URI = $URI + "/ConfigurationProfileServices"

    try {
        $CS = Invoke-RestMethod -Uri $URI -ErrorAction Stop
        Write-Log -Message "Retrieving client install properties from webservice"
    }
    catch {
        Write-Log -Message "Error retrieving client install properties from webservice $URI."
        Write-Log -Message ('=' * 80)
        Exit 1
    }

    $obj = $CS | Where-Object { $_.profileId -eq $ProfileID } | Select-Object Name, StartupType, State, Uptime

    Return $Obj
}
#endregion WebService

 
#region SQL
function Test-SQLConnection {
    $SQLServer = Get-XMLConfigSQLServer
    $Database = 'ClientHealth'
    #$FileLogLevel = ((Get-XMLConfigLoggingLevel).ToString()).ToLower()

    $ConnectionString = "Server={0};Database={1};Integrated Security=True;" -f $SQLServer, $Database

    try {
        $sqlConnection = New-Object System.Data.SqlClient.SqlConnection $ConnectionString;
        $sqlConnection.Open();
        $sqlConnection.Close();

        $obj = $true;
        Write-Log -Message "SQL connection test successfull"
    }
    catch {
        Write-Log -Message "Error connecting to SQLDatabase $Database on SQL Server $SQLServer" -Type 'ERROR'
        #if (-NOT($FileLogLevel -like "clientinstall")) { Out-LogFile -Xml $xml -Text $text -Severity 3 }
        $obj = $false
    }
    Return $obj
}

# Invoke-SqlCmd2 - Created by Chad Miller
function Invoke-Sqlcmd2 {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true)] [string]$ServerInstance,
        [Parameter(Position = 1, Mandatory = $false)] [string]$Database,
        [Parameter(Position = 2, Mandatory = $false)] [string]$Query,
        [Parameter(Position = 3, Mandatory = $false)] [string]$Username,
        [Parameter(Position = 4, Mandatory = $false)] [string]$Password,
        [Parameter(Position = 5, Mandatory = $false)] [Int32]$QueryTimeout = 600,
        [Parameter(Position = 6, Mandatory = $false)] [Int32]$ConnectionTimeout = 15,
        [Parameter(Position = 7, Mandatory = $false)] [ValidateScript({ Test-Path -Path $_ })] [string]$InputFile,
        [Parameter(Position = 8, Mandatory = $false)] [ValidateSet("DataSet", "DataTable", "DataRow")] [string]$As = "DataRow"
    )

    if ($InputFile) {
        $filePath = $(Resolve-Path $InputFile).path
        $Query = [System.IO.File]::ReadAllText("$filePath")
    }

    $conn = New-Object System.Data.SqlClient.SQLConnection

    if ($Username) { $ConnectionString = "Server={0};Database={1};User ID={2};Password={3};Trusted_Connection=False;Connect Timeout={4}" -f $ServerInstance, $Database, $Username, $Password, $ConnectionTimeout }
    else { $ConnectionString = "Server={0};Database={1};Integrated Security=True;Connect Timeout={2}" -f $ServerInstance, $Database, $ConnectionTimeout }

    $conn.ConnectionString = $ConnectionString

    #Following EventHandler is used for PRINT and RAISERROR T-SQL statements. Executed when -Verbose parameter specified by caller
    if ($PSBoundParameters.Verbose) {
        $conn.FireInfoMessageEventOnUserErrors = $true
        $handler = [System.Data.SqlClient.SqlInfoMessageEventHandler] { Write-Verbose -Message "$($_)" }
        $conn.add_InfoMessage($handler)
    }

    $conn.Open()
    $cmd = New-Object system.Data.SqlClient.SqlCommand($Query, $conn)
    $cmd.CommandTimeout = $QueryTimeout
    $ds = New-Object system.Data.DataSet
    $da = New-Object system.Data.SqlClient.SqlDataAdapter($cmd)
    [void]$da.fill($ds)
    $conn.Close()
    switch ($As) {
        'DataSet' { Return ($ds) }
        'DataTable' { Return ($ds.Tables) }
        'DataRow' { Return ($ds.Tables[0]) }
    }
}


Function Get-SQLRow {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [String]$ServerInstance,

        [Parameter(Mandatory = $true, Position = 1)]
        [String]$HostName
    )
    $Database = 'ClientHealth'
    $table = 'dbo.Clients'

    $query = "SELECT * FROM $table WHERE Hostname='$HostName'"

    $conn = New-Object System.Data.SqlClient.SQLConnection
    $ConnectionString = "Server={0};Database={1};Integrated Security=True;Connect Timeout={2}" -f $ServerInstance, $Database, $ConnectionTimeout
    $conn.ConnectionString = $ConnectionString

    $conn.Open()
    $cmd = New-Object system.Data.SqlClient.SqlCommand($Query, $conn)
    $cmd.CommandTimeout = $QueryTimeout
    $ds = New-Object system.Data.DataSet
    $da = New-Object system.Data.SqlClient.SqlDataAdapter($cmd)
    [void]$da.fill($ds)
    $conn.Close()
    Return ($ds.Tables[0])
}


Function Update-SQL {
    Param(
        [Parameter(Mandatory = $true)]$Log,
        [Parameter(Mandatory = $false)]$Table
    )

    Write-Log -Message "Start Update-SQL"
    Test-ValuesBeforeLogUpdate

    $SQLServer = Get-XMLConfigSQLServer
    $Database = 'ClientHealth'
    $table = 'dbo.Clients'
    $smallDateTime = Get-SmallDateTime

    if ($null -ne $log.OSUpdates) {
        # UPDATE
        $q1 = "OSUpdates='" + $log.OSUpdates + "', "
        # INSERT INTO
        $q2 = "OSUpdates, "
        # VALUES
        $q3 = "'" + $log.OSUpdates + "', "
    }
    else {
        $q1 = $null
        $q2 = $null
        $q3 = $null
    }

    if ("$($log.ClientInstalled)" -ne '') {
        # UPDATE
        $q10 = "ClientInstalled='" + $log.ClientInstalled + "', "
        # INSERT INTO
        $q20 = "ClientInstalled, "
        # VALUES
        $q30 = "'" + $log.ClientInstalled + "', "
    }
    else {
        $q10 = $null
        $q20 = $null
        $q30 = $null
    }

    try { 
        $CurrentData = Get-SQLRow -ServerInstance $SQLServer -HostName $Log.Hostname
        [String]$CurrentInstalledReason = $CurrentData.ClientInstalledReason
        If ("$($Log.ClientInstalledReason)" -ne '' -and ($CurrentInstalledReason -ne '') -and ($Log.ClientInstalledReason -notmatch [regex]::Escape($CurrentInstalledReason))) {
            $Log.ClientInstalledReason += " | $CurrentInstalledReason"
        }
        ElseIf ("$($Log.ClientInstalledReason)" -eq '' -and ($CurrentInstalledReason -ne '')) {
            $Log.ClientInstalledReason = $CurrentInstalledReason
        }
    }
    catch {
        Write-Log -Message "Error querying SQL with the following : $query."
    }

    #ADD ClientSettings.log...
    $query = "begin tran
        if exists (SELECT * FROM $table WITH (updlock,serializable) WHERE Hostname='"+ $log.Hostname + "')
        begin
            UPDATE $table SET Operatingsystem='"+ $log.Operatingsystem + "', Architecture='" + $log.Architecture + "', Build='" + $log.Build + "', Manufacturer='" + $log.Manufacturer + "', Model='" + $log.Model + "', InstallDate='" + $log.InstallDate + "', $q1 LastLoggedOnUser='" + $log.LastLoggedOnUser + "', ClientVersion='" + $log.ClientVersion + "', PSVersion='" + $log.PSVersion + "', PSBuild='" + $log.PSBuild + "', Sitecode='" + $log.Sitecode + "', Domain='" + $log.Domain + "', MaxLogSize='" + $log.MaxLogSize + "', MaxLogHistory='" + $log.MaxLogHistory + "', CacheSize='" + $log.CacheSize + "', ClientAuthCertificate='" + $log.ClientAuthCertificate + "', ClientCertificate='" + $log.ClientCertificate + "', ProvisioningMode='" + $log.ProvisioningMode + "', DNS='" + $log.DNS + "', Drivers='" + $log.Drivers + "', Updates='" + $log.Updates + "', PendingReboot='" + $log.PendingReboot + "', LastBootTime='" + $log.LastBootTime + "', OSDiskFreeSpace='" + $log.OSDiskFreeSpace + "', Services='" + $log.Services + "', AdminShare='" + $log.AdminShare + "', StateMessages='" + $log.StateMessages + "', WUAHandler='" + $log.WUAHandler + "', WMI='" + $log.WMI + "', RefreshComplianceState='" + $log.RefreshComplianceState + "', HWInventory='" + $log.HWInventory + "', Version='" + $Version + "', $q10 Timestamp='" + $smallDateTime + "', SWMetering='" + $log.SWMetering + "', BITS='" + $log.BITS + "', PatchLevel='" + $Log.PatchLevel + "', ClientInstalledReason='" + $log.ClientInstalledReason + "'
            WHERE Hostname = '"+ $log.Hostname + "'
        end
        else
        begin
            INSERT INTO $table (ComputerSID, Hostname, Operatingsystem, Architecture, Build, Manufacturer, Model, InstallDate, $q2 LastLoggedOnUser, ClientVersion, PSVersion, PSBuild, Sitecode, Domain, MaxLogSize, MaxLogHistory, CacheSize, ClientAuthCertificate, ClientCertificate, ProvisioningMode, DNS, Drivers, Updates, PendingReboot, LastBootTime, OSDiskFreeSpace, Services, AdminShare, StateMessages, WUAHandler, WMI, RefreshComplianceState, HWInventory, Version, $q20 Timestamp, SWMetering, BITS, PatchLevel, ClientInstalledReason)
            VALUES ('" + $log.ComputerSID + "', '" + $log.Hostname + "', '" + $log.Operatingsystem + "', '" + $log.Architecture + "', '" + $log.Build + "', '" + $log.Manufacturer + "', '" + $log.Model + "', '" + $log.InstallDate + "', $q3 '" + $log.LastLoggedOnUser + "', '" + $log.ClientVersion + "', '" + $log.PSVersion + "', '" + $log.PSBuild + "', '" + $log.Sitecode + "', '" + $log.Domain + "', '" + $log.MaxLogSize + "', '" + $log.MaxLogHistory + "', '" + $log.CacheSize + "', '" + $log.ClientAuthCertificate + "', '" + $log.ClientCertificate + "', '" + $log.ProvisioningMode + "', '" + $log.DNS + "', '" + $log.Drivers + "', '" + $log.Updates + "', '" + $log.PendingReboot + "', '" + $log.LastBootTime + "', '" + $log.OSDiskFreeSpace + "', '" + $log.Services + "', '" + $log.AdminShare + "', '" + $log.StateMessages + "', '" + $log.WUAHandler + "', '" + $log.WMI + "', '" + $log.RefreshComplianceState + "', '" + $log.HWInventory + "', '" + $log.Version + "', $q30 '" + $smallDateTime + "', '" + $log.SWMetering + "', '" + $log.BITS + "', '" + $Log.PatchLevel + "', '" + $Log.ClientInstalledReason + "')
        end
        commit tran"

    try { 
        Invoke-SqlCmd2 -ServerInstance $SQLServer -Database $Database -Query $query -ErrorAction Stop
    }
    catch {
        Write-Log -Message "Error updating SQL with the following query: $query." -Type 'ERROR'
    }
    Write-Log -Message "End Update-SQL"
}
#endregion SQL


#region Logging
Function Get-CMTraceLog {
    <#
.SYNOPSIS
Parse un log au format CMTrace pour retourner l'objet correspondant.

.DESCRIPTION
Parse un log au format CMTrace pour retourner l'objet correspondant.

.PARAMETER LogFile
Chemin du fichier de log au format CMTrace

.NOTES
    AUTHOR        : Marc-Antoine ROBIN (Metsys)
    CREATION DATE : 
    MODIFICATIONS : 

.LINK


.EXAMPLE
    PS C:\> Get-CMTraceLog -Path 'C:\Windows\CCM\Logs\ClientIDManagerStartup.log' | Where-Object -Property Severity -EQ 'ERROR'


.EXAMPLE
    PS C:\> Find-CMTraceLog -Path 'C:\Windows\CCM\Logs' -Pattern 'Failed to send registration request message' | Get-CMTraceLog | ogv
#>
    
    
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Path', 'FullName')]
        [String[]]$LogFile<# ,

        [Switch]$Tail #>
    )

    BEGIN {
        $Pattern = '<!\[LOG\[(?<Message>.*)?\]LOG\]!><time="(?<Time>.+)(?<TZAdjust>[+|-])?(?<TZOffset>\d{2,3})?"\s+date="(?<Date>.+)?"\s+component="(?<Component>.+)?"\s+context="(?<Context>.*)?"\s+type="(?<Type>\d)?"\s+thread="(?<TID>\d+)?"\s+file="(?<Reference>.+)?">'
        #$Pattern = '\<\!\[LOG\[(?<Message>.*)?\]LOG\]\!\>\<time=\"(?<Time>.+)(?<TZAdjust>[+|-])?(?<TZOffset>\d{2,3})?\"\s+date=\"(?<Date>.+)?\"\s+component=\"(?<Component>.+)?\"\s+context="(?<Context>.*)?\"\s+type=\"(?<Type>\d)?\"\s+thread=\"(?<TID>\d+)?\"\s+file=\"(?<Reference>.+)?\"\>'
    }
    PROCESS {
        Select-String -Pattern $Pattern -Path $LogFile |
            Select-Object -Property @{Label = 'Log'; Expression = { (Split-Path -Path $_.Path -Leaf) -replace '\.lo[g_]' } },
                                    LineNumber,
                                    @{Label = 'Message'; Expression = { $_.Matches.Groups.Where({ $_.Name -eq 'Message' }).Value } },
                                    @{Label = 'Severity'; Expression = {
                                            [int]$Type = $_.Matches.Groups.Where({ $_.Name -eq 'Type' }).Value
                                            Switch ($Type) {
                                                0 { 'INFO' }
                                                1 { 'INFO' }
                                                2 { 'WARNING' }
                                                3 { 'ERROR' }
                                                Default {
                                                    "$_"
                                                }
                                            }
                                        }
                                    },
                                    @{Label = 'DateTime'; Expression = {
                                            $Time = $_.Matches.Groups.Where({ $_.Name -eq 'Time' }).Value
                                            $Date = $_.Matches.Groups.Where({ $_.Name -eq 'Date' }).Value
                                            [String]$TZAdjust = $_.Matches.Groups.Where({ $_.Name -eq 'TZAdjust' }).Value
                                            [String]$TZOffset = $_.Matches.Groups.Where({ $_.Name -eq 'TZOffset' }).Value
                                            [datetime]"$Date $Time$($TZAdjust)$($TZOffset)"
                                        }
                                    },
                                    @{Label = 'Component'; Expression = { $_.Matches.Groups.Where({ $_.Name -eq 'Component' }).Value } },
                                    @{Label = 'Context'; Expression = { $_.Matches.Groups.Where({ $_.Name -eq 'Context' }).Value } },
                                    @{Label = 'Reference'; Expression = { $_.Matches.Groups.Where({ $_.Name -eq 'Reference' }).Value } },
                                    @{Label = 'ThreadID'; Expression = { $_.Matches.Groups.Where({ $_.Name -eq 'TID' }).Value } }
    }
}



#Loop backwards through a Configuration Manager log file looking for the latest matching message after the start time.
Function Search-CMLogFile {
    Param(
        [Parameter(Mandatory = $true)]$LogFile,
        [Parameter(Mandatory = $true)][String[]]$SearchStrings,
        [datetime]$StartTime = [datetime]::MinValue
    )

    Write-Log -Message "Parsing log file '$LogFile'"
    #Get the log data.
    $LogData = Get-Content -Path $LogFile
    $CMTraceLog = Get-CMTraceLog -LogFile $LogFile | Where-Object {$_.DateTime -ge $StartTime}

    If ($null -eq $CMTraceLog) {
        #If we have gone beyond the start time then stop searching.
        Write-Log -Message "No log lines in $($LogFile) matched $($SearchStrings) before $($StartTime)." -Type 'WARNING'
    }
    Else {
        $NonMatchingLines = Compare-Object -ReferenceObject (1..$LogData.Count) -DifferenceObject $CMTraceLog.LineNumber | Where-Object {$_.SideIndicator -eq '<='} | Select-Object -ExpandProperty InputObject
        Foreach ($line in $NonMatchingLines) {
            Write-Log -Message "Could not parse the line $($line) in '$($LogFile)': $($LogData[($line - 1)])" -Type 'WARNING'
        }
        $MatchingLines = $CMTraceLog | Where-Object {$_.Message | Select-String -Pattern $SearchStrings -Quiet} | Sort-Object -Property DateTime -Descending | Select-Object -First 1
        #Loop through each search string looking for a match.
        Foreach ($line in $MatchingLines) {
            Write-Log -Message "Found a match line $($line.LineNumber) in '$($LogFile)' for '$($SearchStrings -join ', ')' : $($line.Message)"
            $line
        }
    }
}

Function Test-LocalLogging {
    $clientpath = Get-LocalFilesPath

    if ((Test-Path -Path $clientpath) -eq $False) { 
        $null = New-Item -Path $clientpath -ItemType Directory -Force -Verbose
    }
}

Function Get-LogFileName {
    $logshare = Get-XMLConfigLoggingShare
    Return "$logshare\$env:computername.log"
}


Function Test-LogFileHistory {
    Param([Parameter(Mandatory = $true)]$Logfile)
    $startString = '<--- ConfigMgr Client Health Check starting --->'
    $content = ''

    # Handle the network share log file
    if (Test-Path -Path $logfile ) { 
        $content = Get-Content -Path $logfile -ErrorAction SilentlyContinue 
    }
    else { 
        return 
    }
    $maxHistory = Get-XMLConfigLoggingMaxHistory
    $startCount = [regex]::matches($content, $startString).count

    # Delete logfile if more start and stop entries than max history
    if ($startCount -ge $maxHistory) { Remove-Item -Path $logfile -Force }
}


Function Test-ConfigMgrHealthLogging {
    # Verifies that logfiles are not bigger than max history

        
    $localLogging = (Get-XMLConfigLoggingLocalFile).ToLower()
    $fileshareLogging = (Get-XMLConfigLoggingEnable).ToLower()

    if ($localLogging -eq "true") {
        $clientpath = Get-LocalFilesPath
        $ClientHealthlogFile = "$clientpath\ClientHealth.log"
        Test-LogFileHistory -Logfile $ClientHealthlogFile
    }


    if ($fileshareLogging -eq "true") {
        $ClientHealthlogFile = Get-LogFileName
        Test-LogFileHistory -Logfile $ClientHealthlogFile
    }
}


Function New-LogObject {
    # Write-Log -Message "Start New-LogObject"

    # Handles different OS languages
    $ComputerSID = Get-ComputerSID
    $Hostname = $env:COMPUTERNAME
    $OperatingSystem = $WMIOperatingSystem.Caption
    $Architecture = $WMIOperatingSystem.OSArchitecture
    $Build = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').BuildLabEx
    $Manufacturer = $WMIComputerSystem.Manufacturer
    $Model = $WMIComputerSystem.Model
    $ClientVersion = 'Unknown'
    $Sitecode = Get-Sitecode
    $Domain = Get-Domain
    [int]$MaxLogSize = 0
    $MaxLogHistory = 0
    $InstallDate = Get-SmallDateTime -Date ($WMIOperatingSystem.InstallDate)
    $InstallDate = $InstallDate -replace '\.', ':'
    $LastLoggedOnUser = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\').LastLoggedOnUser
    $CacheSize = Get-ClientCache
    $Services = 'Unknown'
    $Updates = 'Unknown'
    $DNS = 'Unknown'
    $Drivers = 'Unknown'
    $ClientAuthCertificate = 'Unknown'
    $ClientCertificate = 'Unknown'
    $PendingReboot = 'Unknown'
    $RebootApp = 'Unknown'
    $LastBootTime = Get-SmallDateTime -Date ($WMIOperatingSystem.LastBootUpTime)
    $LastBootTime = $LastBootTime -replace '\.', ':'
    $OSDiskFreeSpace = Get-OSDiskSpace | Select-Object -ExpandProperty FreeSpacePct
    $AdminShare = 'Unknown'
    $ProvisioningMode = 'Unknown'
    $StateMessages = 'Unknown'
    $WUAHandler = 'Unknown'
    $WMI = 'Unknown'
    $RefreshComplianceState = Get-SmallDateTime
    $smallDateTime = Get-SmallDateTime
    $smallDateTime = $smallDateTime -replace '\.', ':'
    [float]$PSVersion = [float]$psVersion = [float]$PSVersionTable.PSVersion.Major + ([float]$PSVersionTable.PSVersion.Minor / 10)
    [int]$PSBuild = [int]$PSVersionTable.PSVersion.Build
    if ($PSBuild -le 0) { $PSBuild = $null }
    $UBR = Get-UBR
    $BITS = $null
    $ClientSettings = $null

    $obj = New-Object PSObject -Property @{
        ComputerSID            = $ComputerSID
        Hostname               = $Hostname
        Operatingsystem        = $OperatingSystem
        Architecture           = $Architecture
        Build                  = $Build
        Manufacturer           = $Manufacturer
        Model                  = $Model 
        InstallDate            = $InstallDate
        OSUpdates              = $null
        LastLoggedOnUser       = $LastLoggedOnUser
        ClientVersion          = $ClientVersion
        PSVersion              = $PSVersion
        PSBuild                = $PSBuild
        Sitecode               = $Sitecode
        Domain                 = $Domain
        MaxLogSize             = $MaxLogSize
        MaxLogHistory          = $MaxLogHistory
        CacheSize              = $CacheSize
        ClientAuthCertificate  = $ClientAuthCertificate
        ClientCertificate      = $ClientCertificate
        ProvisioningMode       = $ProvisioningMode
        DNS                    = $DNS
        Drivers                = $Drivers
        Updates                = $Updates
        PendingReboot          = $PendingReboot
        LastBootTime           = $LastBootTime
        OSDiskFreeSpace        = $OSDiskFreeSpace
        Services               = $Services
        AdminShare             = $AdminShare
        StateMessages          = $StateMessages
        WUAHandler             = $WUAHandler
        WMI                    = $WMI
        RefreshComplianceState = $RefreshComplianceState
        ClientInstalled        = $null
        Version                = $Version
        Timestamp              = $smallDateTime
        HWInventory            = $null
        SWMetering             = $null
        ClientSettings         = $null
        BITS                   = $BITS
        PatchLevel             = $UBR
        ClientInstalledReason  = $null
        RebootApp              = $RebootApp
    }
    Return $obj
    # Write-Log -Message "End New-LogObject"
}

# Test some values are whole numbers before attempting to insert / update database
Function Test-ValuesBeforeLogUpdate {
    Write-Verbose -Message "Start Test-ValuesBeforeLogUpdate"
    [int]$Log.MaxLogSize = [Math]::Round($Log.MaxLogSize)
    [int]$Log.MaxLogHistory = [Math]::Round($Log.MaxLogHistory)
    [int]$Log.PSBuild = [Math]::Round($Log.PSBuild)
    [int]$Log.CacheSize = [Math]::Round($Log.CacheSize)

    $PropertyList = @('Operatingsystem','Architecture','Build','Manufacturer','Model','Domain','LastLoggedOnUser','ClientVersion','Services')
    Foreach ($Property in $PropertyList) {
        If ("$($Log.$Property)" -eq '') {
            $Log.$Property = 'Unknown'
        }
    }

    If (($null -eq $Log.OSDiskFreeSpace) -or ($Log.OSDiskFreeSpace -le 0)) {
        $Log.OSDiskFreeSpace = -1
    }

    Write-Verbose -Message "End Test-ValuesBeforeLogUpdate"
}

Function Test-IsClientHealthy {
    Write-Verbose -Message "Start Test-IsClientHealthy"

    $TestList = @(
        @{Name = 'WMI'; Value = 'Compliant'; Enabled = $(If (((Get-XMLConfigWMIRepairEnable) -eq 'True') -and ((Get-XMLConfigWMI) -eq 'True')){$true} Else {$False}) }
        @{Name = 'DNS'; Value = 'Compliant'; Enabled = $(If (((Get-XMLConfigDNSCheck) -eq 'True') -and ((Get-XMLConfigDNSFix) -eq 'True')) {$true} Else {$False})}
        @{Name = 'ClientCertificate'; Value = 'Compliant'; Enabled = [bool](Get-XMLConfigRemediationClientCertificate)}
        @{Name = 'ClientAuthCertificate'; Value = 'Compliant'; Enabled = $(If (((Get-XMLConfigClientAuthCertEnabled) -eq 'True') -and ((Get-XMLConfigClientAuthCertFix) -eq 'True')) {$true} Else {$False})}
        @{Name = 'ProvisioningMode'; Value = 'Compliant'; Enabled = [bool](Get-XMLConfigRemediationClientProvisioningMode)}
        @{Name = 'WUAHandler'; Value = 'Compliant'; Enabled = [bool](Get-XMLConfigRemediationClientWUAHandler)}
        @{Name = 'AdminShare'; Value = 'Compliant'; Enabled = [bool](Get-XMLConfigRemediationAdminShare)}
        @{Name = 'Services'; Value = 'Compliant', 'Started'; Enabled = $true}
        @{Name = 'BITS'; Value = 'Compliant'; Enabled = $(If (((Get-XMLConfigBITSCheck) -eq 'True') -and ((Get-XMLConfigBITSCheckFix) -eq 'True')) {$true} Else {$False})}
        @{Name = 'StateMessages'; Value = 'Compliant'; Enabled = [bool](Get-XMLConfigRemediationClientStateMessages)}
        @{Name = 'ClientSettings'; Value = 'Compliant'; Enabled = $(If (((Get-XMLConfigClientSettingsCheck) -eq 'True') -and ((Get-XMLConfigClientSettingsCheckFix) -eq 'True')) {$true} Else {$False})}
        @{Name = 'SWMetering'; Value = 'Compliant'; Enabled = $(If (((Get-XMLConfigSoftwareMeteringEnable) -eq 'True') -and ((Get-XMLConfigSoftwareMeteringFix) -eq 'True')) {$true} Else {$False})}
    )

    $Result = $true
    Foreach ($Test in $TestList) {
        [String]$TestName = $Test.Name
        [String]$LogValue = $Log.$TestName
        Write-Verbose -Message "Test : $TestName=$($Test.Value -join ', ')/$LogValue [Enabled : $($Test.Enabled)]"
        If (($Test.Enabled -eq $true) -and ($Test.Value -notcontains $LogValue)) {
            Write-Log -Message "$TestName is not compliant : $LogValue <> $($Test.Value -join ', ')" -Type WARNING
            $Result = $false
        }
    }

    If (("$($Log.ClientVersion)" -eq '') -or (([version]$Log.ClientVersion) -lt ([Version](Get-XMLConfigClientVersion)))) {
        Write-Log -Message "ClientVersion is not compliant : $($Log.ClientVersion) < $((Get-XMLConfigClientVersion))" -Type WARNING
        $Result = $false
    }
    If (
        ((Get-XMLConfigRefreshComplianceState) -eq 'True') `
        -and (($null -eq $Log.RefreshComplianceState) `
                -or ([datetime]$Log.RefreshComplianceState) -lt ((Get-Date).AddDays(-(Get-XMLConfigRefreshComplianceStateDays))))
        ) {
        Write-Log -Message "RefreshComplianceState is not compliant : $($Log.RefreshComplianceState)" -Type WARNING
        $Result = $false
    }
    If (
        ((Get-XMLConfigHardwareInventoryEnable) -eq 'True') `
        -and ((Get-XMLConfigHardwareInventoryFix) -eq 'True') `
        -and (($null -eq $Log.HWInventory) `
                -or ([datetime]$Log.HWInventory) -lt ((Get-Date).AddDays(-(Get-XMLConfigHardwareInventoryDays))))
        ) {
        Write-Log -Message "HWInventory is not compliant : $($Log.HWInventory)" -Type WARNING
        $Result = $false
    }
    
    $Error.Clear()

    Write-Verbose -Message "End Test-IsClientHealthy (Result = $Result)"
    Return $Result
}


Function Update-LogFile {
    Param(
        [Parameter(Mandatory = $true)]$Log,
        [Parameter(Mandatory = $false)]$Mode
    )
    # Start the logfile
    Write-Log -Message "Start Update-LogFile"
    #$share = Get-XMLConfigLoggingShare

    Test-ValuesBeforeLogUpdate
    $logfileName = Get-LogFileName
    Test-LogFileHistory -Logfile $logfileName
    $text = "<--- ConfigMgr Client Health Check starting --->"
    $SelectProperty = @(
        'ComputerSID',
        'Hostname',
        'Operatingsystem',
        'Architecture',
        'Build',
        'Model',
        'InstallDate',
        'OSUpdates',
        'LastLoggedOnUser',
        'ClientVersion',
        'PSVersion',
        'PSBuild',
        'SiteCode',
        'Domain',
        'MaxLogSize',
        'MaxLogHistory',
        'CacheSize',
        'ClientAuthCertificate',
        'ClientCertificate',
        'ProvisioningMode',
        'DNS',
        'PendingReboot',
        'LastBootTime',
        'OSDiskFreeSpace',
        'Services',
        'AdminShare',
        'StateMessages',
        'WUAHandler',
        'WMI',
        'RefreshComplianceState',
        'ClientInstalled',
        'Version',
        'Timestamp',
        'HWInventory',
        'SWMetering',
        'BITS',
        'ClientSettings',
        'PatchLevel',
        'ClientInstalledReason'
    )
    $text += $log | Select-Object -Property $SelectProperty | Out-String
    $text = $text.replace("`t", "")
    $text = $text.replace("  ", "")
    $text = $text.replace(" :", ":")
    $text = $text -creplace '(?m)^\s*\r?\n', ''

<#     if (@('Local','ClientInstalledFailed') -contains $Mode) { 
        Write-Log -Message $text -Mode $Mode
        #Out-LogFile -Xml $xml -Text $text -Mode $Mode -Severity 1 
    }
    else {  #>
        Write-Log -Message $text
        #Out-LogFile -Xml $xml -Text $text -Severity 1 
    #}
    Write-Log -Message "End Update-LogFile"
}



Function Write-Log {
    <#
.SYNOPSIS
    Fonction d'écriture de fichier de log.

.DESCRIPTION
    Fonction d'écriture de fichier de log.

    Cette fonction se sert de plusieurs variables publiques du script :
        - $Error : Variable automatique PowerShell
        - ErrNumber : ExitCode de la dernière fonction/commande utilisée (à définir dans le script après chaque appel à une fonction/commande)
        - ErrMsg : Message d'erreur de la dernière fonction/commande utilisée (à définir dans le script après chaque appel à une fonction/commande)
        - TagError : Variable de type [bool] que sera passée à vrai si une erreur est survenue
        - LastError : Variable de type [int] que sera passée à la valeur de ErrNumber si une erreur est survenue

.PARAMETER Message
    Message à afficher.

.PARAMETER LogFile
    Chemin du log à utiliser.
    Pour utiliser tout le temps le même fichier, on peut déclarer cette variable dans le script de cette façon : 

        $Script:LogFile = 'C:\temp\fichier.log'

.PARAMETER Component
    Utilisé par les logs au format CMTrace pour associer un mot clé à la ligne écrite qui décrit l'opération (Sauvegarde, Installation, Mise à jour, ...)

.PARAMETER Type

    Prend 3 valeurs (INFO,WARNING,ERROR) qui permettent d'indiquer le retour de l'action logguée.
    Dans un log au format CMTrace, une ligne WARNING sera colorée en jaune et une ligne ERROR sera colorée en rouge.
    Les valeurs INFO et ERROR peuvent être automatiquement gérés par la fonction grâce aux variables de gestion d'erreur (ErrNumber, ErrMsg, $Error)
    La valeur WARNING doit obligatoirement être indiquée en paramètre si l'on veut que la ligne soit définie comme avertissement.

.PARAMETER CMTrace
    Indique si l'on veut utiliser un log au format CMTrace ou non.
    Par défaut les logs seront au format CMTrace, il faut passer ce switch à $false pour désactiver cela.

    https://docs.microsoft.com/fr-fr/mem/configmgr/core/support/cmtrace

.EXAMPLE
    PS C:> $script:LogFile = 'C:\Temp\Log.log'
    PS C:> $ErrNumber = 1
    PS C:> $ErrMsg = 'Erreur de fonction'
    PS C:> Write-Log 'Execution de l'action test' -CMTrace

    Ecrira dans le log C:\Temp\Log.log la ligne suivante :

<![LOG[Execution de l'action test]LOG]!><time="HH:mm:ss.ffffff" date="MM-dd-yyyy" component=" " context="SYSTEM" "type="3" thread="10101" file="ScriptName.ps1:101">

Dans CMTrace la ligne sera colorée en rouge.

.EXAMPLE
PS C:> $ErrNumber = 0
PS C:> Write-Log 'Execution de l'action test' -LogFile 'C:\Temp\Log.log'

Ecrira dans le log C:\Temp\Log.log la ligne suivante :

<![LOG[Execution de l'action test]LOG]!><time="HH:mm:ss.ffffff" date="MM-dd-yyyy" component=" " context="SYSTEM" "type="1" thread="10101" file="ScriptName.ps1:101">

.EXAMPLE
PS C:> $ErrNumber = 1
PS C:> Write-Log 'Execution de l'action test' -LogFile 'C:\Temp\Log.txt' -CMTrace:$false

Ecrira dans le log C:\Temp\Log.txt la ligne suivante :

 ERROR - MM-dd-yyyy HH:mm:ss.ffffff - Execution de l'action test

.NOTES
    AUTHOR : Marc-Antoine ROBIN (Metsys)
    CREATION : 10/09/2018
    VERSION : 1.0

.LINK
Amélioration possible : https://wolffhaven.gitlab.io/wolffhaven_icarus_test/powershell/write-cmtracelog-dropping-logs-like-a-boss/
#>


    [CmdletBinding()]
    Param(
        [Parameter(Position = 0)]
        [Alias('Text')]
        [AllowEmptyString()]
        [String]$Message = '',

        [Parameter(Position = 1)]
        [AllowNull()]
        [String]$Component = ' ',

        [Parameter(Position = 2)]
        [ValidateSet('INFO', 'WARNING', 'ERROR')]
        [String]$Type = 'INFO'
    )

    $InvocationName = $MyInvocation.InvocationName 

    If (($null -eq $ErrNumber) -and ($null -eq $Error[0])) {
        # Assume that everything is ok if neither $ErrNumber nor $Error contains a value/error
        $ExitCode = 0
    }
    ElseIf (($null -ne $Error[0]) -and (!$ErrNumber)) {
        # Set the exit code to 1 if $ErrNumber hasn't been used but $error contains at least one error
        $ExitCode = 1
        If ($Error[0].Exception.Message -match [regex]::Escape('HKLM:\SYSTEM\CurrentControlSet\Control\MiniNT')) {
            $ExitCode = 0
        }
    }
    Else {
        # Get the exit code from the $ErrNumber variable
        $ExitCode = $ErrNumber
    }

    Try {
        # Try and get the last error details from the automatic $error variable (Will throw an exception if empty)
        $ErrorMessage = "$ErrMsg - $($Error[0].Exception.Message) (l. $($Error[0].InvocationInfo.ScriptLineNumber) in $($Error[0].InvocationInfo.PSCommandPath))"
    }
    Catch {
        # No error is store in the automatic $Error variable
        $ErrorMessage = $ErrMsg
    }
    Write-Verbose -Message "[$(Get-Date -Format 'HH:mm:ss.fff')] [$InvocationName] Message = $Message (ExitCode : $ExitCode | Error : $ErrorMessage"

    $Append = ''
    Switch ($ExitCode) {
        0 {
            [int]$TypeCode = 1
            break
        }

        3010 {
            $Append = "(Reboot required)"
            [int]$TypeCode = 1
            break
        }

        Default {
            $Append = "(ExitCode $ExitCode) - $ErrorMessage " -replace '\-  -', '-' -replace ' *\- +\(l\. +in +\) *'
            $Script:TagError = $true # $TagError can be used in the script to assert weather an error occured or not
            $script:LastError = $ExitCode # $LastError can be used in the script to get the last error number
            [int]$TypeCode = 3
            break
        }
    }

    If (($TypeCode -ne 3) -and ($Type -eq 'WARNING')) { [int]$TypeCode = 2 } # Write a warning only if no error was detected
    If ($Type -eq 'Error') { [int]$TypeCode = 3 } # Write an error even if none was detected

    [String[]]$Content = $Message -split "`r`n"
    ForEach ($line in $Content) {
        # CMTrace format
        $LogLine = "<![LOG[$line $Append]LOG]!>" + `
                    "<time=`"$(Get-Date -Format 'HH:mm:ss.ffffff')`" " + `
                    "date=`"$(Get-Date -Format 'MM-dd-yyyy')`" " + `
                    "component=`"$Component`" " + `
                    "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + `
                    "type=`"$TypeCode`" " + `
                    "thread=`"$([Threading.Thread]::CurrentThread.ManagedThreadId)`" " + `
                    "file=`"$($MyInvocation.ScriptName | Split-Path -Leaf -ErrorAction SilentlyContinue):$($MyInvocation.ScriptLineNumber)`">"
        # Write line in log
        $LogLine | Out-File -FilePath $Script:ClientHealthLogFile -Append -Encoding utf8 -Force
    }
    # Error variables cleanup
    $Script:ErrNumber = 0
    $Script:ErrMsg = [String]::Empty
    $Error.Clear()
}



Function Backup-ClientHealthLog {
    [CmdletBinding()]
    Param ( )

    $DateTime = Get-Date
    $ZipFile = "$Script:LogFolder\CMClientHealthLogs_$("$($DateTime.Month)".PadLeft(2, '0'))-$($DateTime.Year).zip"
    If (($DateTime.Day -ge 1) -and (-not (Test-Path -Path $ZipFile))) { 
        # Add last month logs in a zip file to cleanup log folder
        Try {
            $LogList = Get-ChildItem -Path "$Script:LogFolder" -Filter '*.log' |
                        Where-Object { (($_.CreationTime.Month + 1) % 13) -eq ($DateTime.Month) } |
                        Select-Object -ExpandProperty FullName 
            If ($null -ne $LogList) {
                Compress-Archive -Path $LogList -DestinationPath $ZipFile -CompressionLevel Optimal -Force -Verbose -ErrorAction Stop
                $LogList | Remove-Item -Force -Verbose -ErrorAction Continue # Remove old logs
            }
        }
        Catch {
            Write-Warning -Message "Error while archiving logs : $($_.Exception.Message)"
        }
    }

    $BackupFolder = "$env:SystemRoot\Temp\CMClientHealth"
    If (! (Test-Path -Path $BackupFolder)) {
        $null = New-Item -Path $BackupFolder -ItemType Directory -Force -Verbose
    }
    Copy-Item -Path "$LogFolder\*.zip" -Destination $BackupFolder -Force -Verbose
    $Error.Clear()
}
#endregion Logging


#region registry
Function Get-RegistryValue {
    param (
        [parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][String]$Path,
        [parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][String]$Name
    )

    Return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
}

Function Set-RegistryValue {
    param (
        [parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][String]$Path,
        [parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][String]$Name,
        [parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]$Value,
        [ValidateSet("String", "ExpandString", "Binary", "DWord", "MultiString", "Qword")][String]$ProperyType = "String"
    )

    #Make sure the key exists
    If (!(Test-Path -Path $Path)) {
        $null = New-Item $Path -Force
    }

    $null = New-ItemProperty -Force -Path $Path -Name $Name -Value $Value -PropertyType $ProperyType
}


Function Get-OSInstallationType {
    (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'InstallationType').InstallationType
}

Function Set-CMGRegistryValue {
    $Key = 'HKLM:\SOFTWARE\Microsoft\CCM'
    If (! (Test-Path -Path $Key)) {
        Write-Log -Message "Could not find registry key '$Key'" -Type WARNING
    }
    Else {
        [String]$CMGFQDNs = (Get-ItemProperty -Path $Key -Name 'CMGFQDNs' -EA SilentlyContinue).CMGFQDNs
        [int]$DisAllowCMG = (Get-ItemProperty -Path $Key -Name 'DisAllowCMG' -EA SilentlyContinue).DisAllowCMG
        $Error.Clear()

        [String]$CMGFqdn = Get-XMLConfigCMGFQDN

        If (($CMGFqdn -ne '') -and (($CMGFQDNs -eq '') -or (($CMGFQDNs -ne '') -and ($CMGFQDNs -ne $CMGFqdn)))) {
            $null = New-ItemProperty -Path $Key -Name 'CMGFQDNs' -PropertyType String -Value $CMGFqdn -Force -Verbose
            Write-Log -Message "Setting 'CMGFQDNs' to '$CMGFqdn' in key '$Key' (Previous value : $CMGFQDNs)"
        }
        $null = New-ItemProperty -Path $Key -Name 'DisAllowCMG' -PropertyType dword -Value 0 -Force -Verbose
        Write-Log -Message "Setting 'DisAllowCMG' to 0 in key '$Key' (Previous value : $DisAllowCMG)"
        
        Invoke-SCCMClientAction -ClientAction 'Machine Policy Assignments Request'
    }
}
#endregion registry


#region CCM

Function Get-MPList {
    $WMIMPList = Get-WMIClassInstance -Namespace 'Root\Ccm\LocationServices' -Class 'SMS_ActiveMPCandidate' -EA SilentlyContinue | 
                Where-Object {$_.type -eq 'Assigned'} | 
                Select-Object -ExpandProperty MP
    $LastUsedMP = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\CCM\LocationServices' -Name 'EventLastUsedMP' -ErrorAction SilentlyContinue
    $RegMPList = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\CCM' -Name 'LookupMPList','SMSSLP' -ErrorAction SilentlyContinue
    
    ($LastUsedMP.EventLastUsedMP,"$($RegMPList.LookupMPList)".split(";"),$WMIMPList,$RegMPList.SMSSLP).ForEach({
        If (("$_" -notmatch '^\s*$')) {
            $_.ToLower() -replace 'https*://' -replace '\s+'
        }
    }) | 
    Select-Object -Unique
    
    $Error.Clear()
}


Function Test-InstallationNeeded {
    $CCMExists = (Test-Path -Path 'C:\Windows\CCM') -or (Test-Path -Path 'C:\Windows\CCMSetup') -or (Test-Path -Path $Script:CMRegKey)

    If ($CCMExists -eq $true) {
        Write-Log -Message "Detected CM Client directories/registry keys, script will continue."
        Return $true
    }

<#     Try {
        $null = Get-Service -DisplayName '*Microsoft*Intune*' -ErrorAction Stop
        $IntuneServiceExists = $true
    }
    Catch {
        $IntuneServiceExists = $false
    } #>

    $CoManagementCheck = -1
    If (Test-Path -Path $CMRegKey) {
        # Check Co Management status
        $CoManagementCheck = Get-ItemProperty -Path $CMRegKey -Name 'CoManagementFlags' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CoManagementFlags
        $Error.Clear()
    }
    $IsCoManaged = $CoManagementCheck -ne -1

    If ($IsCoManaged -eq $true) {
        Write-Log -Message "Computer is co-managed (Flags=$CoManagementCheck), script will continue."
        Return $true
    }
    
    $InstallationNeeded = $true
    If ($CCMExists -eq $false) {
        # https://learn.microsoft.com/en-us/azure/active-directory/devices/troubleshoot-hybrid-join-windows-current
        If (Test-Path -Path "$env:SystemRoot\System32\dsregcmd.exe") {
            $DSRegCmd = Get-DSRegCmd | Select-Object -Property 'KeySignTest', 'AzureAdJoined', 'DomainJoined', 'DomainName', 'WorkplaceJoined'
            #$HybridCheck = $DSRegCmd.KeySignTest
            $AzureAdJoined = $DSRegCmd.AzureAdJoined
            $DomainJoined = $DSRegCmd.DomainJoined
            #$WorkplaceJoined = $DSRegCmd.WorkplaceJoined
        }
        Else {
            [String]$DomainName = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' | Select-Object -ExpandProperty 'Domain'
            $DomainJoined = $DomainName -ne ''

            $AzureAdJoined = $false
            $CloudJoinRegKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo'
            If (Test-Path -Path $CloudJoinRegKey) {
                try {
                    $DnsFullyQualifiedName = Get-ChildItem -Path "$CloudJoinRegKey" -Recurse | Get-ItemProperty | Select-Object -ExpandProperty 'DnsFullyQualifiedName'
                    If ($DnsFullyQualifiedName -match "$env:COMPUTERNAME\..+") {
                        $AzureAdJoined = $true
                    }
                }
                catch {
                    $Error.RemoveAt(0)
                    $AzureAdJoined = $false
                }
            }
        }

        If ($AzureAdJoined -eq $true -and $DomainJoined -eq $true) {
            # Hybrid joined
            $InstallationNeeded = $true
            Write-Log -Message "Computer is Azure AD Hybrid Joined, script will continue."
        }
        Else {
            $InstallationNeeded = $false
            Write-Log -Message "Computer is NOT Azure AD Hybrid Joined, script will stop." -Type 'WARNING'
        }
    }
    Return $InstallationNeeded
}


Function Get-Sitecode {
    try {
        $sms = New-Object -ComObject 'Microsoft.SMS.Client'
        $obj = $sms.GetAssignedSite()
    }
    catch { 
        $Error.RemoveAt(0)
        $obj = '...' 
    }
    Return $obj
}

Function Get-ClientVersion {
    try {
        $obj = (Get-WMIClassInstance -Namespace 'root/ccm' -Class 'SMS_Client').ClientVersion
    }
    catch { 
        $Error.RemoveAt(0)
        $obj = $false 
    }
    Return $obj
}

Function Get-ClientCache {
    try {
        $obj = (New-Object -ComObject UIResource.UIResourceMgr).GetCacheInfo().TotalSize
    }
    catch { 
        $Error.RemoveAt(0)
        $obj = 0 
    }
    if ($null -eq $obj) { $obj = 0 }
    Return $obj
}

Function Get-ClientMaxLogSize {
    try { $obj = [Math]::Round(((Get-ItemProperty -Path $SCCMLoggingKey).LogMaxSize) / 1000) }
    catch { 
        $Error.RemoveAt(0)
        $obj = 0 
    }
    Return $obj
}

Function Get-ClientLogLevel {
    try { $obj = (Get-ItemProperty -Path $SCCMLoggingKey).logLevel }
    catch { 
        $Error.RemoveAt(0)
        $obj = 1 
    }
    Return $obj
}


Function Get-ClientMaxLogHistory {
    try { $obj = (Get-ItemProperty -Path $SCCMLoggingKey).LogMaxHistory }
    catch { 
        $Error.RemoveAt(0)
        $obj = 0 
    }
    Return $obj
}

Function Get-CCMLogDirectory {
    [String]$obj = (Get-ItemProperty -Path $SCCMLoggingKey).LogDirectory
    if ("$obj" -eq '') { 
        $obj = "$env:SystemDrive\windows\ccm\Logs" 
    }
    Return $obj
}

Function Get-CCMDirectory {
    Return $Script:CCMLogDir.replace("\Logs", '')
}

Function Test-CcmSDF {
<#
.SYNOPSIS
Function to test if local database files are missing from the ConfigMgr client.

.DESCRIPTION
Function to test if local database files are missing from the ConfigMgr client. Will tag client for reinstall if less than 7. Returns $True if compliant or $False if non-compliant

.EXAMPLE
An example

.NOTES
Returns $True if compliant or $False if non-compliant. Non.compliant computers require remediation and will be tagged for ConfigMgr client reinstall.
#>
    $ccmdir = Get-CCMDirectory
    $files = @(Get-ChildItem "$ccmdir\*.sdf" -ErrorAction SilentlyContinue)
    if ($files.Count -lt 7) { $obj = $false }
    else { $obj = $true }
    Return $obj
}

Function Test-CcmSQLCELog {
    $ccmdir = Get-CCMDirectory
    $CCMSQLCElogFile = "$Script:CCMLogDir\CcmSQLCE.log"
    $logLevel = Get-ClientLogLevel

    if ( (Test-Path -Path $CCMSQLCElogFile) -and ($logLevel -ne 0) ) {
        # Not in debug mode, and CcmSQLCE.log exists. This could be bad.
        $LastWriteTime = (Get-ChildItem $CCMSQLCElogFile).LastWriteTime
        $CreationTime = (Get-ChildItem $CCMSQLCElogFile).CreationTime
        $FileDate = Get-Date($LastWriteTime)
        $FileCreated = Get-Date($CreationTime)

        $now = Get-Date
        if ( (($now - $FileDate).Days -lt 7) -and ((($now - $FileCreated).Days) -gt 7) ) {
            Write-Log -Message "CM client not in debug mode, and CcmSQLCE.log exists. This is very bad. Cleaning up local SDF files and reinstalling CM client" -Type 'ERROR'
            # Delete *.SDF Files
            $Service = Get-Service -Name ccmexec
            $Service.Stop()

            $seconds = 0
            Do {
                Start-Sleep -Seconds 1
                $seconds++
            } while ( ($Service.Status -ne "Stopped") -and ($seconds -le 60) )

            # Do another test to make sure CcmExec service really is stopped
            if ($Service.Status -ne "Stopped") { Stop-Service -Name ccmexec -Force }

            Write-Log -Message "Waiting 10 seconds to allow file locking issues to clear up"
            Start-Sleep -Seconds 10

            try {
                $files = Get-ChildItem "$ccmdir\*.sdf"
                $files | Remove-Item -Force -ErrorAction Stop
                Remove-Item -Path $CCMSQLCElogFile -Force -ErrorAction Stop
            }
            catch {
                Write-Log -Message "Obviously that wasn't enough time"
                Start-Sleep -Seconds 30
                # We try again
                $files = Get-ChildItem "$ccmdir\*.sdf"
                $files | Remove-Item -Force -ErrorAction SilentlyContinue
                Remove-Item -Path $CCMSQLCElogFile -Force -ErrorAction SilentlyContinue
            }

            $obj = $true
        }

        # CcmSQLCE.log has not been updated for two days. We are good for now.
        else { $obj = $false }
    }
    # we are good
    else { $obj = $false }
    Return $obj
}

function Test-CCMCertificateError {
    Param([Parameter(Mandatory = $true)]$Log)
    # More checks to come
    $ClientIDlogFile = "$Script:CCMLogDir\ClientIDManagerStartup.log"
    $error1 = 'Failed to find the certificate in the store'
    $error2 = '[RegTask] - Server rejected registration 3'
    $content = Get-Content -Path $ClientIDlogFile

    $ok = $true

    if ($content -match $error1) {
        $ok = $false
        Write-Log -Message 'ConfigMgr Client Certificate: Error failed to find the certificate in store. Attempting fix.' -Type 'WARNING'
        Stop-Service -Name ccmexec -Force
        # Name is persistant across systems.
        $cert = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\19c5cf9c7b5dc9de3e548adb70398402_50e417e0-e461-474b-96e2-077b80325612"
        # CCM creates new certificate when missing.
        $null = Remove-Item -Path $cert -Force -ErrorAction SilentlyContinue
        # Remove the error from the logfile to avoid double remediations based on false positives
        $newContent = $content | Select-String -Pattern $Error1 -NotMatch
        Out-File -FilePath $ClientIDlogFile -InputObject $newContent -Encoding utf8 -Force
        Start-Service -Name ccmexec

        # Update log object
        $log.ClientCertificate = 'Missing'
    }

    #$content = Get-Content -Path $logFile2
    if ($content -match $error2) {
        $ok = $false
        Write-Log -Message 'ConfigMgr Client Certificate: Error! Server rejected client registration. Client Certificate not valid. No auto-remediation.' -Type 'ERROR'
        $log.ClientCertificate = 'Server rejected registration'
    }

    if ($ok -eq $true) {
        Write-Log -Message 'ConfigMgr Client Certificate: OK'
        $log.ClientCertificate = 'Compliant'
    }
}

function Get-CertificateTemplateName {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate
    )
    PROCESS {
        # The template name is stored in the Extension data. 
        # If available, the best is the extension named "Certificate Template Name", since it contains the exact name.
        $templateExt = $certificate.Extensions | Where-Object { ( $_.Oid.FriendlyName -match 'Certificate Template Name|Nom du mod.le de certificat') } | Select-Object -First 1   
        if ($null -ne $templateExt) {
            return $templateExt.Format(1)
        }
        else {
            # Our fallback option is the "Certificate Template Information" extension, it contains the name as part of a string like:
            # "Template=Web Server v2(1.3.6.1.4.1.311.21.8.2499889.12054413.13650051.8431889.13164297.111.14326010.6783216)"
            $templateExt = $certificate.Extensions | Where-Object { ( $_.Oid.FriendlyName -match 'Certificate Template Information|Informations du mod.le de certificat') } | Select-Object -First 1   
            if ($null -ne $templateExt) {
                $information = $templateExt.Format(1)
    
                # Extract just the template name in $Matches[1]
                if ($information -match '^(Template|Mod.le)=(?<TemplateName>[^\(]+)\([0-9\.]+\)') {
                    return $Matches['TemplateName']
                }
                else {
                    # No regex match, just return the complete information then
                    return $information
                }
            }
        }
    }
}

function Get-CertificateEnhancedKeyUsage {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate
    )
    PROCESS {
        $certificate.Extensions | 
            Where-Object {$_.GetType().Name -match 'X509EnhancedKeyUsageExtension'} | 
            Select-Object -ExpandProperty EnhancedKeyUsages | 
            Select-Object -ExpandProperty FriendlyName  
    }
}


Function Test-ClientAuthCert {
    Param([Parameter(Mandatory = $true)]$Log)
    
    $CertStore = 'Cert:\LocalMachine\My'

    $Log.ClientAuthCertificate = 'Compliant'

    If ((Get-XMLConfigClientAuthCertEnabled) -eq 'True') {
        $TemplateList = Get-XMLConfigClientAuthCertTemplate
        Write-Log -Message 'Testing if a "Client Authentication" cert is enrolled in the machine Personal certificate store'

        $TemplateCert = Get-ChildItem -Path $CertStore | 
                            Where-Object { ((Get-CertificateTemplateName -Certificate $_) -in $TemplateList) -and ($_.NotAfter -gt (Get-Date)) } | 
                            Sort-Object -Descending -Property NotAfter | 
                            Select-Object -First 1 -ExpandProperty Subject
        $ClientAuthCert = Get-ChildItem -Path $CertStore | 
                            Where-Object { ((Get-CertificateEnhancedKeyUsage -Certificate $_) -match 'Client Authentication|Authentification du client') -and ($_.NotAfter -gt (Get-Date)) } |
                            Select-Object -ExpandProperty Subject
        If ($null -ne $TemplateCert) {
            Write-Log -Message ('Found a certificate using one of the templates ({0}) : {1}' -f ($TemplateList -join ', '), ($TemplateCert -join '; '))
        }
        Else {
            If ($null -ne $ClientAuthCert) {
                Write-Log -Message ('Found a "Client Authentication" certificate which does not use any of the templates ({0}) : {1}' -f ($TemplateList -join ', '), ($ClientAuthCert -join '; ')) -Type WARNING
            }
            $Log.ClientAuthCertificate = 'Missing'
            If ((Get-XMLConfigClientAuthCertFix) -eq 'True') {
                Foreach ($Template in $TemplateList) {
                    Try {
                        Get-Certificate -Template ($Template -replace '\s+') -CertStoreLocation $CertStore -Verbose -EA Stop
                        $Log.ClientAuthCertificate = 'Repaired'
                    }
                    Catch {
                        If ($Log.ClientAuthCertificate -ne 'Repaired') {
                            $Log.ClientAuthCertificate = 'Error'
                        }
                    }
                    Write-Log -Message "Trying to enroll a certificate with the template '$($Template -replace '\s+')'"
                }
            }
        }
    }
}

Function Test-InTaskSequence {
    try { $tsenv = New-Object -ComObject Microsoft.SMS.TSEnvironment }
    catch { 
        $Error.RemoveAt(0)
        $tsenv = $null 
    }

    if ($tsenv) {
        Write-Log -Message "Configuration Manager Task Sequence detected on computer. Exiting script" -Type 'WARNING'
        Write-Log -Message ('=' * 80)
        Exit 2
    }
}




Function Test-BITS {
    Param([Parameter(Mandatory = $true)]$Log)

    if ($BitsCheckEnabled -eq $true) {
        $BitsErrorList = Get-BitsTransfer -AllUsers | Where-Object { ($_.JobState -match "Error") }

        if ($null -ne $BitsErrorList) {
            $fix = (Get-XMLConfigBITSCheckFix).ToLower()

            if ($fix -eq "true") {
                $text = "BITS: Error. Remediating"
                $BitsErrorList | Remove-BitsTransfer -ErrorAction SilentlyContinue
                Write-Log -Message "Removed stuck BITS transfers"
                $null = Invoke-Executable -FilePath 'sc.exe' -ArgumentList 'sdset bits "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)"'
                Write-Log -Message "Modified the BITS service acl"
                $log.BITS = 'Remediated'
                $obj = $true
            }
            else {
                $text = "BITS: Error. Monitor only"
                $log.BITS = 'Error'
                $obj = $false
            }
        }

        else {
            $text = "BITS: OK"
            $log.BITS = 'Compliant'
            $Obj = $false
        }

    }
    else {
        $text = "BITS: PowerShell Module BitsTransfer missing. Skipping check"
        $log.BITS = "PS Module BitsTransfer missing"
        $obj = $false
    }

    Write-Log -Message $text
    Return $Obj

}

# TODO : Enable function
Function Test-ClientSettingsConfiguration {
    Param([Parameter(Mandatory = $true)]$Log)

    $SMSAgentConfigSplat = @{
        Namespace   = "root\ccm\Policy\DefaultMachine\RequestedConfig" 
        Class       = 'CCM_ClientAgentConfig'
        ErrorAction = 'SilentlyContinue'
    }

    $ClientSettingsConfig = @(Get-WMIClassInstance @SMSAgentConfigSplat | Where-Object { $_.PolicySource -eq "CcmTaskSequence" })

    if ($ClientSettingsConfig.Count -gt 0) {

        $fix = (Get-XMLConfigClientSettingsCheckFix).ToLower()

        if ($fix -eq "true") {
            $text = "ClientSettings: Error. Remediating"
            DO {
                $InstanceList = Get-WMIClassInstance @SMSAgentConfigSplat | 
                                    Where-Object { $_.PolicySource -eq "CcmTaskSequence" } | 
                                    Select-Object -First 1000 
                foreach ($Instance in $InstanceList) {
                    Switch -Regex ($Instance.GetType().Name) {
                        'CimInstance' {
                            Remove-CimInstance -InputObject $Instance
                            break
                        }
                        Default {
                            Remove-WmiObject -InputObject $Instance 
                            break
                        }
                    }
                }
            } Until ($null -eq (Get-WMIClassInstance @SMSAgentConfigSplat | Where-Object { $_.PolicySource -eq "CcmTaskSequence" } | Select-Object -First 1))
            $log.ClientSettings = 'Remediated'
            $obj = $true
        }
        else {
            $text = "ClientSettings: Error. Monitor only"
            $log.ClientSettings = 'Error'
            $obj = $false
        }
    }

    else {
        $text = "ClientSettings: OK"
        $log.ClientSettings = 'Compliant'
        $Obj = $false
    }
    Write-Log -Message $text
    #Return $Obj
}

Function New-ClientInstalledReason {
    Param(
        [Parameter(Mandatory = $true)]$Message,
        [Parameter(Mandatory = $true)]$Log
    )

    if ($null -eq $log.ClientInstalledReason) { $log.ClientInstalledReason = $Message }
    else { $log.ClientInstalledReason += " | $Message" }
    $log.ClientInstalledReason = "$($log.ClientInstalledReason)".Replace(".",'')
}



Function Get-ProvisioningMode {
    $registryPath = 'HKLM:\SOFTWARE\Microsoft\CCM\CcmExec'
    $provisioningMode = (Get-ItemProperty -Path $registryPath).ProvisioningMode
    if ($provisioningMode -eq 'true') { $obj = $true }
    else { $obj = $false }
    $Error.Clear()
    Return $obj
}


# Function to test that 'HKU:\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\' is set to '%USERPROFILE%\AppData\Roaming'. CCMSETUP will fail if not.
# Reference: https://www.systemcenterdudes.com/could-not-access-network-location-appdata-ccmsetup-log/
Function Test-CCMSetup1 {
    $KeyPath = 'HKU:\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\'
    $null = New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS -ErrorAction SilentlyContinue
    $correctValue = '%USERPROFILE%\AppData\Roaming'
    $currentValue = (Get-Item -Path $KeyPath).GetValue('AppData', $null, 'DoNotExpandEnvironmentNames')

    # Only fix if the value is wrong
    if ($currentValue -ne $correctValue) { 
        Set-ItemProperty -Path $KeyPath -Name 'AppData' -Value $correctValue -Force
        Write-Log -Message "Setting registry value 'AppData' in key '$KeyPath' to : $correctValue (old : $currentValue)"
    }
}



Function Test-ConfigMgrClient {
    Param([Parameter(Mandatory = $true)]$Log)

    # Check if the SCCM Agent is installed or not.
    # If installed, perform tests to decide if reinstall is needed or not.
    if (Get-Service -Name ccmexec -ErrorAction SilentlyContinue) {
        Write-Log -Message "Configuration Manager Client is installed"

        # Lets not reinstall client unless tests tells us to.
        $Reinstall = $false
        $Uninstall = $false

        # We test that the local database files exists. Less than 7 means the client is horrible broken and requires reinstall.
        $LocalDBFilesPresent = Test-CcmSDF
        if ($LocalDBFilesPresent -eq $False) {
            New-ClientInstalledReason -Log $Log -Message "ConfigMgr Client database files missing."
            Write-Log -Message "ConfigMgr Client database files missing. Reinstalling..."
            # Add /ForceInstall to Client Install Properties to ensure the client is uninstalled before we install client again.
            #if (-NOT ($clientInstallProperties -like "*/forceinstall*")) { $clientInstallProperties = $clientInstallProperties + " /forceinstall" }
            $Reinstall = $true
            $Uninstall = $true
        }

        # Only test CM client local DB if this check is enabled
        $testLocalDB = (Get-XMLConfigCcmSQLCELog).ToLower()
        if ($testLocalDB -like "enable") {
            Write-Log -Message "Testing CcmSQLCELog"
            $LocalDB = Test-CcmSQLCELog
            if ($LocalDB -eq $true) {
                # LocalDB is messed up
                New-ClientInstalledReason -Log $Log -Message "ConfigMgr Client database corrupt."
                Write-Log -Message "ConfigMgr Client database corrupt. Reinstalling..." -Type 'WARNING'
                $Reinstall = $true
                $Uninstall = $true
            }
        }

        If (("$($Log.WMI)" -ne '') -and ($Log.WMI -ne 'Compliant')) {
            $Reinstall = $true
            $Uninstall = $true
        }

        $CCMService = Get-Service -Name ccmexec -ErrorAction SilentlyContinue

        # Reinstall if we are unable to start the CM client
        if (($CCMService.Status -eq "Stopped") -and ($LocalDB -eq $false)) {
            try {
                Write-Log -Message "ConfigMgr Agent not running. Attempting to start it."
                if ($CCMService.StartType -ne "Automatic") {
                    Set-Service -Name CcmExec -StartupType Automatic
                    Write-Log -Message "Configuring service CcmExec StartupType to: Automatic (Delayed Start)..."
                }
                Start-Service -Name CcmExec
                Write-Log -Message "Started CcmExec service."
            }
            catch {
                Write-Log -Message "Fail to start CcmExec service."
                $Error.RemoveAt(0)
                $Reinstall = $true
                New-ClientInstalledReason -Log $Log -Message "Service not running, failed to start."
            }
        }

        # Test that we are able to connect to SMS_Client WMI class
        Try {
            $WMI = Get-WMIClassInstance -Namespace 'root/ccm' -Class 'SMS_Client' -ErrorAction Stop
        }
        Catch {
            Write-Log 'Failed to connect to WMI namespace "root/ccm" class "SMS_Client". Clearing WMI and tagging client for reinstall to fix.' -Type 'WARNING'
                
            # Clear the WMI namespace to avoid having to uninstall first
            # This is the same action the install after an uninstall would perform
            Get-WmiObject -Query "Select * from __Namespace WHERE Name='CCM'" -Namespace root | Remove-WmiObject
                
            $Reinstall = $true
            New-ClientInstalledReason -Log $Log -Message "Failed to connect to SMS_Client WMI class."
        }

        if ( $reinstall -eq $true) {
            Write-Log -Message "ConfigMgr Client Health thinks the agent needs to be reinstalled.." -Type 'WARNING'
            # Lets check that registry settings are OK before we try a new installation.
            Test-CCMSetup1

            # Adding forceinstall to the client install properties to make sure previous client is uninstalled.
            #if ( ($localDB -eq $true) -and (-NOT ($clientInstallProperties -like "*/forceinstall*")) ) { $clientInstallProperties = $clientInstallProperties + " /forceinstall" }
            $InstallResult = Resolve-Client -Xml $xml -ClientInstallProperties $clientInstallProperties -FirstInstall $false -Uninstall $Uninstall
            If ($InstallResult -ne $false) {
                $log.ClientInstalled = Get-SmallDateTime
            }
            Write-Log -Message "Waiting 10min for the client installation to finish"
            Start-Sleep 600
        }
    }
    else {
        $Error.Clear()
        Write-Log -Message "Configuration Manager client is not installed. Installing..." -Type 'WARNING'
        $InstallResult = Resolve-Client -Xml $xml -ClientInstallProperties $clientInstallProperties -FirstInstall $true -Uninstall $false
        New-ClientInstalledReason -Log $Log -Message "No agent found."
        If ($InstallResult -ne $false) {
            $log.ClientInstalled = Get-SmallDateTime
        }
        #Start-Sleep 600

        # Test again if agent is installed
        if (Get-Service -Name ccmexec -ErrorAction SilentlyContinue) {}
        else { 
            Write-Log -Message "ConfigMgr Client installation failed. Agent not detected 10 minutes after triggering installation." -Type 'ERROR' 
            #Out-LogFile "ConfigMgr Client installation failed. Agent not detected 10 minutes after triggering installation."  -Mode "ClientInstall" -Severity 3 
        }
    }
}


Function Invoke-SCCMClientCleanup {
    Write-Log -Message "START - Client Cleanup"
    
    Try {
        $resman = New-Object -ComObject "UIResource.UIResourceMgr"
        $cacheInfo = $resman.GetCacheInfo()
    }
    Catch {
        $Error.RemoveAt(0)
    }

    $ItemsToBeDeleted = @(
        "$($cacheInfo.Location)"
        "$env:SystemRoot\ccmcache",
        "$env:SystemRoot\ccmsetup",
        "$env:SystemRoot\SMSCFG.INI",
        $(Get-ChildItem -Path $env:SystemRoot -Filter 'SMS*.mif' | Select-Object -ExpandProperty Fullname),
        "$env:SystemRoot\smsts.ini",
        "HKLM:\Software\Microsoft\SMS",
        "HKLM:\Software\Microsoft\CCM",
        "HKLM:\Software\Microsoft\CCMSetup",
        "HKLM:\Software\Wow6432Node\Microsoft\SMS",
        "HKLM:\Software\Wow6432Node\Microsoft\CCM",
        "HKLM:\Software\Wow6432Node\Microsoft\CCMSetup*",
        'HKLM:\SOFTWARE\Microsoft\DeviceManageabilityCSP',
        "HKCU:\Software\Microsoft\SMS",
        "Cert:\LocalMachine\SMS\*",
        # https://github.com/sntcz/Clear-MachineKeys
        "$env:SystemRoot\ProgramData\Microsoft\Crypto\RSA\MachineKeys\19c5cf9*",
        'HKLM:\Software\Microsoft\SystemCertificates\SMS\Certificates\*',
        "$env:SystemRoot\CCM"
    ) | Select-Object -Unique

    # Stop the related processes
    Get-Process -Name 'CCM*', 'CmRcService' -ErrorAction SilentlyContinue | Stop-Process -Force -Verbose
    $Error.Clear()
    Write-Log -Message "Stopped Configuration Manager related processes"

    Restart-Service -Name 'Winmgmt' -Force -Verbose
    Write-Log -Message "Restart WMI service"
   
    $ServiceList = @(
        'ccmexec',
        'CmRcService',
        'smstsmgr'
    )
    ForEach ($ServiceName in $ServiceList) {
        $WMIservice = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'"
        If ($null -ne $WMIservice) {
            $WMIservice.delete()
            Write-Log -Message "Removing service '$ServiceName'"
        }
    }
    
    ForEach ($namespaceName in @('ccm','CCMVDI','SmsDm')) {
        $NameSpaceObj = Get-WmiObject -Namespace 'root' -Class '__Namespace' -Filter "name = '$namespaceName'" -ErrorAction Continue
        If ($null -ne $NameSpaceObj) {
            $NameSpaceObj | Remove-WmiObject -Verbose
            Write-Log -Message "Removed CCM '$namespaceName' namespaces"
        }
    }
    $Error.Clear()
    $NameSpaceObj = Get-WmiObject -Namespace 'root/cimv2' -Class '__Namespace' -Filter "name = 'sms'" -ErrorAction Continue | Remove-WmiObject -Verbose
    If ($null -ne $NameSpaceObj) {
        $NameSpaceObj | Remove-WmiObject -Verbose
        Write-Log -Message "Removed CCM 'SMS' namespaces"
    }
    $Error.Clear()
    
    Remove-ScheduledTask -TaskPath '\Microsoft\Configuration Manager' -TaskName '*'

    Remove-ScheduledTaskFolder -TaskPath '\Microsoft\Configuration Manager'
    
    Write-Log -Message "Waiting for 15 seconds"
    Start-Sleep -Seconds 15

    ForEach ($item in $ItemsToDelete) {
        If (("$item" -ne '') -and (Test-Path -Path $item)) {
            Try {
                If (($Item -notmatch '(Cert|HKLM):') -and (Test-Path -Path $Item)) {
                    Get-ChildItem -Path $item -Recurse -File -ErrorAction Continue | Remove-Item -Force -ErrorAction Stop -Confirm:$False -Verbose
                }
                If (Test-Path -Path $Item) {
                    Remove-Item -Path $item -Recurse -Force -ErrorAction Continue -Confirm:$False
                }
                Write-Log -Message "Removed '$item'"
            }
            Catch {
                Write-Log -Message "Failed to remove '$item'"
            }
        }
    }

    Write-Log -Message "END - Client Cleanup"
}


Function Test-ClientCacheSize {
    Param([Parameter(Mandatory = $true)]$Log)
    $ClientCacheSize = Get-XMLConfigClientCache
    #$Cache = Get-WMIClassInstance -Namespace "ROOT\CCM\SoftMgmtAgent" -Class CacheConfig

    $CurrentCache = Get-ClientCache

    if ($ClientCacheSize -match '%') {
        $type = 'percentage'
        # percentage based cache based on disk space
        $num = $ClientCacheSize -replace '%'
        $num = ($num / 100)
        # TotalDiskSpace in Byte
        $TotalDiskSpace = Get-OSDiskSpace | Select-Object -ExpandProperty Size
        $ClientCacheSize = ([math]::Round(($TotalDiskSpace * $num) / 1048576))
    }
    else { $type = 'fixed' }

    if ($CurrentCache -eq $ClientCacheSize) {
        Write-Log -Message "ConfigMgr Client Cache Size: OK"
        $Log.CacheSize = $CurrentCache
        $obj = $false
    }

    else {
        switch ($type) {
            'fixed' { $text = "ConfigMgr Client Cache Size: $CurrentCache. Expected: $ClientCacheSize. Redmediating." }
            'percentage' {
                $percent = Get-XMLConfigClientCache
                if ($ClientCacheSize -gt "99999") { $ClientCacheSize = "99999" }
                $text = "ConfigMgr Client Cache Size: $CurrentCache. Expected: $ClientCacheSize ($percent). (99999 maxium). Redmediating."
            }
        }

        Write-Log -Message $text -Type 'WARNING'
        #$Cache.Size = $ClientCacheSize
        #$Cache.Put()
        $log.CacheSize = $ClientCacheSize
        (New-Object -ComObject UIResource.UIResourceMgr).GetCacheInfo().TotalSize = "$ClientCacheSize"
        $obj = $true
    }
    Return $obj
}

Function Test-ClientVersion {
    Param([Parameter(Mandatory = $true)]$Log)
    $ClientVersion = Get-XMLConfigClientVersion
    [String]$ClientAutoUpgrade = Get-XMLConfigClientAutoUpgrade
    $ClientAutoUpgrade = $ClientAutoUpgrade.ToLower()
    $installedVersion = Get-ClientVersion
    $log.ClientVersion = $installedVersion

    if ($installedVersion -ge $ClientVersion) {
        Write-Log -Message "ConfigMgr Client version is: $installedVersion : OK"
        $obj = $false
    }
    elseif ($ClientAutoUpgrade -like 'true') {
        Write-Log -Message "ConfigMgr Client version is: $installedVersion : Tagging client for upgrade to version: $ClientVersion" -Type 'WARNING'
        $obj = $true
    }
    else {
        Write-Log -Message "ConfigMgr Client version is: $installedVersion : Required version: $ClientVersion AutoUpgrade: false. Skipping upgrade" -Type 'WARNING'
        $obj = $false
    }
    Return $obj
}

Function Test-ClientSiteCode {
    Param([Parameter(Mandatory = $true)]$Log)
    $sms = New-Object -ComObject "Microsoft.SMS.Client"
    $ClientSiteCode = Get-XMLConfigClientSitecode
    #[String]$currentSiteCode = Get-Sitecode
    $currentSiteCode = $sms.GetAssignedSite()
    $currentSiteCode = $currentSiteCode.Trim()
    $Log.Sitecode = $currentSiteCode

    # Do more investigation and testing on WMI Method "SetAssignedSite" to possible avoid reinstall of client for this check.
    if ($ClientSiteCode -like $currentSiteCode) {
        Write-Log -Message "ConfigMgr Client Site Code: OK"
        #$obj = $false
    }
    else {
        $sms.SetAssignedSite($ClientSiteCode)
        Write-Log -Message ('ConfigMgr Client Site Code is "' + $currentSiteCode + '". Expected: "' + $ClientSiteCode + '". Changing sitecode.') -Type 'WARNING'
        #$obj = $true
    }
    #Return $obj
}



# Functions to detect and fix errors
Function Test-ProvisioningMode {
    Param([Parameter(Mandatory = $true)]$Log)
    $registryPath = 'HKLM:\SOFTWARE\Microsoft\CCM\CcmExec'
    $provisioningMode = (Get-ItemProperty -Path $registryPath).ProvisioningMode

    if ($provisioningMode -eq 'true') {
        Set-ItemProperty -Path $registryPath -Name ProvisioningMode -Value "false" -Force
        Set-ClientProvisioningMode -ArgumentList $False
        Write-Log -Message 'ConfigMgr Client Provisioning Mode: YES. Remediating...' -Type 'WARNING'
        $log.ProvisioningMode = 'Repaired'
    }
    else {
        $log.ProvisioningMode = 'Compliant'
        Write-Log -Message 'ConfigMgr Client Provisioning Mode: OK'
    }
}

Function Update-State {
    Write-Log -Message "Start Update-State"
    $SCCMUpdatesStore = New-Object -ComObject Microsoft.CCM.UpdatesStore
    $SCCMUpdatesStore.RefreshServerComplianceState()
    $log.StateMessages = 'Compliant'
    Write-Log -Message "End Update-State"
}

Function Test-StateMessage {
    Param([Parameter(Mandatory = $true)]$Log)
    Write-Log -Message "Check StateMessage.log if State Messages are successfully forwarded to Management Point"
    $StateMessagelogFile = "$Script:CCMLogDir\StateMessage.log"
    $StateMessage = Get-Content -Path $StateMessagelogFile
    if ($StateMessage -match 'Successfully forwarded State Messages to the MP') {
        $log.StateMessages = 'Compliant'
        Write-Log -Message 'StateMessage: OK'
    }
    else {
        Update-State
        Write-Log -Message 'StateMessage: ERROR. Remediating...' -Type 'WARNING'
        $log.StateMessages = 'Repaired'
    }
}


Function Test-ClientLogSize {
    Param([Parameter(Mandatory = $true)]$Log)
    [int]$currentLogSize = Get-ClientMaxLogSize
    [int]$currentMaxHistory = Get-ClientMaxLogHistory
    [int]$logLevel = Get-ClientLogLevel

    $clientLogSize = Get-XMLConfigClientMaxLogSize
    $clientLogMaxHistory = Get-XMLConfigClientMaxLogHistory

    if ( ($currentLogSize -eq $clientLogSize) -and ($currentMaxHistory -eq $clientLogMaxHistory) ) {
        $Log.MaxLogSize = $currentLogSize
        $Log.MaxLogHistory = $currentMaxHistory
        Write-Log -Message "ConfigMgr Client Max Log Size: OK ($currentLogSize)"
        Write-Log -Message "ConfigMgr Client Max Log History: OK ($currentMaxHistory)"
        $obj = $false
    }
    else {
        if ($currentLogSize -ne $clientLogSize) {
            $Log.MaxLogSize = $clientLogSize
            Write-Log -Message ('ConfigMgr Client Max Log Size: Configuring to ' + $clientLogSize + ' KB') -Type 'WARNING'
        }
        else {
            Write-Log -Message "ConfigMgr Client Max Log Size: OK ($currentLogSize)"
        }
        if ($currentMaxHistory -ne $clientLogMaxHistory) {
            $Log.MaxLogHistory = $clientLogMaxHistory
            Write-Log -Message ('ConfigMgr Client Max Log History: Configuring to ' + $clientLogMaxHistory) -Type 'WARNING'
        }
        else {
            Write-Log -Message "ConfigMgr Client Max Log History: OK ($currentMaxHistory)"
        }

        $newLogSize = [int]$clientLogSize
        $newLogSize = $newLogSize * 1000

        <#
            if ($PowerShellVersion -ge 6) {Invoke-CimMethod -Namespace "root/ccm" -ClassName "sms_client" -MethodName SetGlobalLoggingConfiguration -Arguments @{LogLevel=$loglevel; LogMaxHistory=$clientLogMaxHistory; LogMaxSize=$newLogSize} }
            else {
                $smsClient = [wmiclass]"root/ccm:sms_client"
                $smsClient.SetGlobalLoggingConfiguration($logLevel, $newLogSize, $clientLogMaxHistory)
            }
            #Write-Log 'Returning true to trigger restart of ccmexec service'
            #>
            
        # Rewrote after the WMI Method stopped working in previous CM client version
        $null = New-ItemProperty -Path $SCCMLoggingKey -Name LogMaxHistory -PropertyType DWORD -Value $clientLogMaxHistory -Force
        $null = New-ItemProperty -Path $SCCMLoggingKey -Name LogMaxSize -PropertyType DWORD -Value $newLogSize -Force

        #Write-Log 'Sleeping for 5 seconds to allow WMI method complete before we collect new results...'
        #Start-Sleep -Seconds 5

        $Log.MaxLogSize = Get-ClientMaxLogSize
        $Log.MaxLogHistory = Get-ClientMaxLogHistory
        $obj = $true
    }
    Return $obj
}

Function Remove-CCMOrphanedCache {
    Write-Log -Message "Clearing ConfigMgr orphaned Cache items."
    try {
        $CacheInfo = (New-Object -ComObject "UIResource.UIResourceMgr").GetCacheInfo()
        $CCMCache = $CacheInfo.Location
        if ($null -eq $CCMCache) { $CCMCache = "$env:SystemDrive\Windows\ccmcache" }
        $ValidCachedFolders = $CacheInfo.GetCacheElements() | Select-Object -ExpandProperty 'Location'
        $AllCachedFolders = (Get-ChildItem -Path $CCMCache -Force -ErrorAction SilentlyContinue) | Where-Object {$_.Name -ne 'skpswi.dat'} | Select-Object -ExpandProperty Fullname

        $Error.Clear()
        ForEach ($CachedFolder in $AllCachedFolders) {
            If ($ValidCachedFolders -notcontains $CachedFolder) {
                #Don't delete new folders that might be syncing data with BITS
                if ((Get-Item -Path $CachedFolder -Force).LastWriteTime -le (Get-Date).AddDays(-14)) {
                    Remove-Item -Path $CachedFolder -Force -Recurse
                    Write-Log -Message "Removing orphaned folder: $CachedFolder - LastWriteTime: $((Get-ItemProperty $CachedFolder).LastWriteTime)"
                }
            }
        }
    }
    catch { Write-Log -Message "Failed Clearing ConfigMgr orphaned Cache items." }
}

Function Resolve-Client {
    Param(
        [Parameter(Mandatory = $false)]$Xml,
        [Parameter(Mandatory = $true)]$ClientInstallProperties,
        [Parameter(Mandatory = $false)]$FirstInstall = $false,
        [Parameter(Mandatory = $true)][bool]$Uninstall
    )

    $ClientInstallResult = $false
    $ClientShare = Get-XMLConfigClientShare
    if ((Test-Path -Path $ClientShare -ErrorAction SilentlyContinue) -eq $true) {
        If ($ClientShare -match '^\\\\') {
            If (! (Test-Path -Path "$Script:ScriptPath\CMClient")) {
                $null = New-Item -Path "$Script:ScriptPath\CMClient" -ItemType Directory -Force -Verbose
            }
            Copy-Item -Path "$ClientShare\*" -Destination "$Script:ScriptPath\CMClient" -Recurse -Force -Verbose
            Write-Log -Message "Copied client sources from '$ClientShare' to '$Script:ScriptPath\CMClient'"
            $ClientShare = "$Script:ScriptPath\CMClient"
        }
        $SetupPath = "$ClientShare\ccmsetup.exe"
        if ($FirstInstall -eq $true) { $text = 'Installing Configuration Manager Client.' }
        else { $text = 'Client tagged for reinstall. Reinstalling client...' }
        Write-Log -Message $text

        Write-Log -Message "Perform a test on a specific registry key required for ccmsetup to succeed."
        Test-CCMSetup1

        Write-Log -Message "Enforce registration of common DLL files to make sure CCM Agent works."
        $System32DllList = @(
            "$env:SystemRoot\System32\scecli.dll",
            "$Env:SystemRoot\System32\actxprxy.dll", 
            "$Env:SystemRoot\System32\atl.dll", 
            "$Env:SystemRoot\System32\cryptdlg.dll", 
            "$Env:SystemRoot\System32\dssenh.dll", 
            "$Env:SystemRoot\System32\jscript.dll",
            "$Env:SystemRoot\System32\msi.dll", 
            "$Env:SystemRoot\System32\mssip32.dll", 
            "$Env:SystemRoot\System32\msxml3.dll", 
            "$Env:SystemRoot\System32\msxml6.dll", 
            "$Env:SystemRoot\System32\ole32.dll", 
            "$Env:SystemRoot\System32\oleaut32.dll", 
            "$Env:SystemRoot\System32\rsaenh.dll", 
            "$Env:SystemRoot\System32\scrrun.dll", 
            "$Env:SystemRoot\System32\softpub.dll", 
            "$Env:SystemRoot\System32\userenv.dll", 
            "$Env:SystemRoot\System32\vbscript.dll", 
            "$Env:SystemRoot\System32\wuapi.dll", 
            "$Env:SystemRoot\System32\wups.dll", 
            "$Env:SystemRoot\System32\wups2.dll", 
            "$Env:SystemRoot\System32\WBEM\wmisvc.dll",

            "$Env:SystemRoot\System32\Bitsprx2.dll", 
            "$Env:SystemRoot\System32\Bitsprx3.dll", 
            "$Env:SystemRoot\System32\browseui.dll", 
            "$Env:SystemRoot\System32\gpkcsp.dll", 
            "$Env:SystemRoot\System32\initpki.dll", 
            "$Env:SystemRoot\System32\mshtml.dll", 
            "$Env:SystemRoot\System32\msxml.dll", 
            "$Env:SystemRoot\System32\msxml3a.dll", 
            "$Env:SystemRoot\System32\msxml3r.dll", 
            "$Env:SystemRoot\System32\msxml4.dll", 
            "$Env:SystemRoot\System32\msxml4a.dll", 
            "$Env:SystemRoot\System32\msxml4r.dll", 
            "$Env:SystemRoot\System32\msxml6r.dll", 
            "$Env:SystemRoot\System32\muweb.dll", 
            "$Env:SystemRoot\System32\Qmgr.dll", 
            "$Env:SystemRoot\System32\Qmgrprxy.dll", 
            "$Env:SystemRoot\System32\sccbase.dll", 
            "$Env:SystemRoot\System32\shdocvw.dll", 
            "$Env:SystemRoot\System32\shell32.dll", 
            "$Env:SystemRoot\System32\slbcsp.dll", 
            "$Env:SystemRoot\System32\rlmon.dll", 
            "$Env:SystemRoot\System32\Winhttp.dll", 
            "$Env:SystemRoot\System32\wintrust.dll", 
            "$Env:SystemRoot\System32\wuaueng.dll", 
            "$Env:SystemRoot\System32\wuaueng1.dll", 
            "$Env:SystemRoot\System32\wucltui.dll", 
            "$Env:SystemRoot\System32\wucltux.dll", 
            "$Env:SystemRoot\System32\wuweb.dll", 
            "$Env:SystemRoot\System32\wuwebv.dll", 
            "$Env:SystemRoot\System32\Xpob2res.dll" 
        )
        Register-DLLFile -FilePath $System32DllList

        if ($Uninstall -eq $true) {
            Write-Log -Message "Trigger ConfigMgr Client uninstallation"
            $Return = Invoke-Executable -FilePath "$SetupPath" -ArgumentList '/uninstall' -IgnoreExitCode @(0,3010,7)
            If ($Return.ExitCode -eq 7) {
                $log.PendingReboot = 'Pending Reboot'
                $ErrNumber = 3010
            }
            Write-Log -Message "ConfigMgr Client uninstallation done."
            If (@(0,7) -contains $Return.ExitCode) {
                Invoke-SCCMClientCleanup
            }
        }

        Write-Log -Message "Trigger ConfigMgr Client installation"
        Write-Log -Message "Client install string: $SetupPath $ClientInstallProperties"
        $Return = Invoke-Executable -FilePath "$SetupPath" -ArgumentList "$ClientInstallProperties" -IgnoreExitCode @(0,3010,7)
        $ErrNumber = $Return.ExitCode
        If ($Return.ExitCode -eq 7) {
            $log.PendingReboot = 'Pending Reboot'
            $ErrNumber = 3010
            $ClientInstallResult = $true
        }
        ElseIf ($Return.ExitCode -eq 0) {
            $ClientInstallResult = $true
            If ((Get-XMLConfigCMGEnabled) -eq 'True') {
                Set-CMGRegistryValue
            }
        }
        Write-Log -Message "ConfigMgr Client installation done."

        if ($FirstInstall -eq $true) {
            Write-Log -Message "ConfigMgr Client was installed for the first time. Waiting 6 minutes for client to syncronize policy before proceeding." -Type 'WARNING'
            Start-Sleep -Seconds 360
        }
    }
    else {
        Write-Log -Message ('ERROR: Client tagged for reinstall, but failed to access fileshare: ' + $ClientShare) -Type 'ERROR'
        Write-Log -Message ('=' * 80)
        Exit 1
    }
    Return $ClientInstallResult
}



# Test if the compliance state messages should be resent.
Function Test-RefreshComplianceState {
    Param(
        $Days = 0,
        [Parameter(Mandatory = $true)]$RegistryKey,
        [Parameter(Mandatory = $true)]$Log
    )
    $RegValueName = "RefreshServerComplianceState"

    #Get the last time this script was ran.  If the registry isn't found just use the current date.
    [datetime]$LastSent = Get-Date 
    If (Test-Path -Path $RegistryKey) {
        Try { 
            [datetime]$LastSent = Get-RegistryValue -Path $RegistryKey -Name $RegValueName 
        }
        Catch { 
            $Error.RemoveAt(0)
        }
    }
    Write-Log -Message "The compliance states were last sent on $($LastSent)"
    #Determine the number of days until the next run.
    $NumberOfDays = (New-TimeSpan -Start (Get-Date) -End ($LastSent.AddDays($Days))).Days

    #Resend complianc states if the next interval has already arrived or randomly based on the number of days left until the next interval.
    If (($NumberOfDays -le 0) -or ((Get-Random -Maximum $NumberOfDays) -eq 0 )) {
        Try {
            Write-Log -Message "Resending compliance states."
                (New-Object -ComObject Microsoft.CCM.UpdatesStore).RefreshServerComplianceState()
            $LastSent = Get-Date
            Write-Log -Message "Compliance States: Refreshed."
        }
        Catch {
            Write-Log -Message "Failed to resend the compliance states."
            $LastSent = [datetime]::MinValue
        }
    }
    Else {
        Write-Log -Message "Compliance States: OK."
    }

    Set-RegistryValue -Path $RegistryKey -Name $RegValueName -Value $LastSent
    If ($LastSent -eq [datetime]::MinValue) {
        $Log.RefreshComplianceState = $null
    }
    Else {
        $Log.RefreshComplianceState = Get-SmallDateTime $LastSent
    }
}

# Start ConfigMgr Agent if not already running
Function Test-SCCMService {
    try { 
        Get-Service -Name 'CcmExec' -ErrorAction SilentlyContinue | 
        Where-Object { $_.Status -ne 'Running' } | 
        Start-Service -Verbose -ErrorAction Stop
    }
    catch {
        $Error.RemoveAt(0)
    }
}

Function Test-SMSTSMgr {
    $ServiceName = 'smstsmgr'
    $service = Get-Service -Name $ServiceName
    $ProcessSplat = @{
        FilePath     = 'sc.exe' 
        ArgumentList = "config $ServiceName depend= winmgmt" 
    }
    $RegisterService = $false
    if (($service.ServicesDependedOn).name -contains "ccmexec") {
        Write-Log -Message "$ServiceName`: Removing dependency on CCMExec service."
        $RegisterService = $true
    }
        
    # WMI service depenency is present by default
    if (($service.ServicesDependedOn).name -notcontains "Winmgmt") {
        Write-Log -Message "$ServiceName`: Adding dependency on Windows Management Instrumentaion service."
        $RegisterService = $true
    }
    else { Write-Log -Message "$ServiceName`: OK" }
        
    If ($RegisterService -eq $true) {
        $null = Invoke-Executable @ProcessSplat
        Write-Log -Message "Registered service $ServiceName"
    }
}


Function Test-CCMSoftwareDistribution {
    # TODO Implement this function
    Get-WMIClassInstance -Class CCM_SoftwareDistributionClientConfig -Namespace 'ROOT\CCM\Policy\Machine'
}


Function Start-Ccmeval {
    Write-Log -Message "Starting Built-in Configuration Manager Client Health Evaluation"
    $task = "Microsoft\Configuration Manager\Configuration Manager Health Evaluation"
    $Return = Invoke-Executable -FilePath 'schtasks.exe' -ArgumentList "/Run /TN `"$task`""
    $TaskRunResult = ''
    If ($Return.ExitCode -ne 0) {
        $TaskRunResult = "$($Return.StdOut)`r`n$($Return.StdErr)"
    }
    Write-Log -Message "Result : ($($Return.ExitCode)) $TaskRunResult"
}



# Function to store SCCM log file changes to be processed
Function New-SCCMLogFileJob {
    Param(
        [Parameter(Mandatory = $true)]$Logfile,
        [Parameter(Mandatory = $true)]$Text,
        [Parameter(Mandatory = $true)]$SCCMLogJobs
    )

    $file = "$Script:CCMLogDir\$LogFile"
    $SCCMLogJobs.Rows.Add($file, $text)
}

# Function to remove info in SCCM logfiles after remediation. This to prevent false positives triggering remediation next time script runs
Function Update-SCCMLogFile {
    Param([Parameter(Mandatory = $true)]$SCCMLogJobs)
    Write-Log -Message "Start Update-SCCMLogFile"
    foreach ($job in $SCCMLogJobs) { 
        Get-Content -Path $job.File | 
            Where-Object { $_ -notmatch $job.Text } | 
            Out-File -FilePath $job.File -Force 
    }
    Write-Log -Message "End Update-SCCMLogFile"
}


Function Invoke-SCCMClientAction {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true,
                   Position = 0)]
        [ValidateSet(
            'Hardware Inventory',
            'Software Inventory',
            'Data Discovery Record',
            'File Collection',
            'IDMIF Collection',
            'Client Machine Authentication',
            'Machine Policy Assignments Request',
            'Machine Policy Evaluation',
            'Refresh Default MP Task',
            'LS (Location Service) Refresh Locations Task',
            'LS (Location Service) Timeout Refresh Task',
            'Policy Agent Request Assignment (User)',
            'Policy Agent Evaluate Assignment (User)',
            'Software Metering Generating Usage Report',
            'Source Update Message',
            'Clearing proxy settings cache',
            'Machine Policy Agent Cleanup',
            'User Policy Agent Cleanup',
            'Policy Agent Validate Machine Policy / Assignment',
            'Policy Agent Validate User Policy / Assignment',
            'Retrying/Refreshing certificates in AD on MP',
            'Peer DP Status reporting',
            'Peer DP Pending package check schedule',
            'SUM Updates install schedule',
            'Hardware Inventory Collection Cycle',
            'Software Inventory Collection Cycle',
            'Discovery Data Collection Cycle',
            'File Collection Cycle',
            'IDMIF Collection Cycle',
            'Software Metering Usage Report Cycle',
            'Windows Installer Source List Update Cycle',
            'Software Updates Assignments Evaluation Cycle',
            'Branch Distribution Point Maintenance Task',
            'Send Unsent State Message',
            'State System policy cache cleanout',
            'Scan by Update Source',
            'Update Store Policy',
            'State system policy bulk send high',
            'State system policy bulk send low',
            'Application manager policy action',
            'Application manager user policy action',
            'Application manager global evaluation action',
            'Power management start summarizer',
            'Endpoint deployment reevaluate',
            'Endpoint AM policy reevaluate',
            'External event detection' )]
        [string]$ClientAction
    )

    $ScheduleIDMappings = @{
        'Hardware Inventory' = '{00000000-0000-0000-0000-000000000001}'
        'Software Inventory' = '{00000000-0000-0000-0000-000000000002}'
        'Data Discovery Record' = '{00000000-0000-0000-0000-000000000003}'
        'File Collection' = '{00000000-0000-0000-0000-000000000010}'
        'IDMIF Collection' = '{00000000-0000-0000-0000-000000000011}'
        'Client Machine Authentication' = '{00000000-0000-0000-0000-000000000012}'
        'Machine Policy Assignments Request' = '{00000000-0000-0000-0000-000000000021}'
        'Machine Policy Evaluation' = '{00000000-0000-0000-0000-000000000022}'
        'Refresh Default MP Task' = '{00000000-0000-0000-0000-000000000023}'
        'LS (Location Service) Refresh Locations Task' = '{00000000-0000-0000-0000-000000000024}'
        'LS (Location Service) Timeout Refresh Task' = '{00000000-0000-0000-0000-000000000025}'
        'Policy Agent Request Assignment (User)' = '{00000000-0000-0000-0000-000000000026}'
        'Policy Agent Evaluate Assignment (User)' = '{00000000-0000-0000-0000-000000000027}'
        'Software Metering Generating Usage Report' = '{00000000-0000-0000-0000-000000000031}'
        'Source Update Message' = '{00000000-0000-0000-0000-000000000032}'
        'Clearing proxy settings cache' = '{00000000-0000-0000-0000-000000000037}'
        'Machine Policy Agent Cleanup' = '{00000000-0000-0000-0000-000000000040}'
        'User Policy Agent Cleanup' = '{00000000-0000-0000-0000-000000000041}'
        'Policy Agent Validate Machine Policy / Assignment' = '{00000000-0000-0000-0000-000000000042}'
        'Policy Agent Validate User Policy / Assignment' = '{00000000-0000-0000-0000-000000000043}'
        'Retrying/Refreshing certificates in AD on MP' = '{00000000-0000-0000-0000-000000000051}'
        'Peer DP Status reporting' = '{00000000-0000-0000-0000-000000000061}'
        'Peer DP Pending package check schedule' = '{00000000-0000-0000-0000-000000000062}'
        'SUM Updates install schedule' = '{00000000-0000-0000-0000-000000000063}'
        'Hardware Inventory Collection Cycle' = '{00000000-0000-0000-0000-000000000101}'
        'Software Inventory Collection Cycle' = '{00000000-0000-0000-0000-000000000102}'
        'Discovery Data Collection Cycle' = '{00000000-0000-0000-0000-000000000103}'
        'File Collection Cycle' = '{00000000-0000-0000-0000-000000000104}'
        'IDMIF Collection Cycle' = '{00000000-0000-0000-0000-000000000105}'
        'Software Metering Usage Report Cycle' = '{00000000-0000-0000-0000-000000000106}'
        'Windows Installer Source List Update Cycle' = '{00000000-0000-0000-0000-000000000107}'
        'Software Updates Assignments Evaluation Cycle' = '{00000000-0000-0000-0000-000000000108}'
        'Branch Distribution Point Maintenance Task' = '{00000000-0000-0000-0000-000000000109}'
        'Send Unsent State Message' = '{00000000-0000-0000-0000-000000000111}'
        'State System policy cache cleanout' = '{00000000-0000-0000-0000-000000000112}'
        'Scan by Update Source' = '{00000000-0000-0000-0000-000000000113}'
        'Update Store Policy' = '{00000000-0000-0000-0000-000000000114}'
        'State system policy bulk send high' = '{00000000-0000-0000-0000-000000000115}'
        'State system policy bulk send low' = '{00000000-0000-0000-0000-000000000116}'
        'Application manager policy action' = '{00000000-0000-0000-0000-000000000121}'
        'Application manager user policy action' = '{00000000-0000-0000-0000-000000000122}'
        'Application manager global evaluation action' = '{00000000-0000-0000-0000-000000000123}'
        'Power management start summarizer' = '{00000000-0000-0000-0000-000000000131}'
        'Endpoint deployment reevaluate' = '{00000000-0000-0000-0000-000000000221}'
        'Endpoint AM policy reevaluate' = '{00000000-0000-0000-0000-000000000222}'
        'External event detection' = '{00000000-0000-0000-0000-000000000223}'
    }
    $ScheduleID = $ScheduleIDMappings[$ClientAction]
    Write-Verbose -Message "$ClientAction : $ScheduleID"

    if ($PowerShellVersion -ge 6) { 
        $Return = Invoke-CimMethod @Script:SMSClientSplat -MethodName TriggerSchedule -Arguments @{sScheduleID = $ScheduleID } -ErrorAction Continue
    }
    else { 
        $Return = ([wmiclass]"$($Script:SMSClientSplat.Namespace):$($Script:SMSClientSplat.Class)").TriggerSchedule($ScheduleID)
        #$Return = Invoke-WmiMethod @Script:SMSClientSplat -Name TriggerSchedule -ArgumentList @($ScheduleID) -ErrorAction Continue 
    }
    
    if ($Return.ReturnValue) {
        Write-Error -Message "$ScheduleID Error code = $($Return.ReturnValue)"
    }
    Write-Log -Message "Triggered client action $ClientAction : $ScheduleID"
}


Function Set-ClientProvisioningMode {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        $ArgumentList
    )
    
    $MethodName = 'SetClientProvisioningMode'

    if ($PowerShellVersion -ge 6) {
        $Splat.MethodName = 
        $null = Invoke-CimMethod @Script:SMSClientSplat -MethodName $MethodName -Arguments @{bEnable = $ArgumentList }
    }
    else { 
        $null = Invoke-WmiMethod @Script:SMSClientSplat -Name $MethodName -ArgumentList $ArgumentList
    }
}


Function Test-SCCMRebootPending {
    try {
        If ($PowerShellVersion -ge 6) {
            $RebootPendingSplat = @{
                Namespace = 'root\ccm\clientsdk' 
                ClassName = 'CCM_ClientUtilities' 
                MethodName = 'DetermineIfRebootPending' 
                ErrorAction = 'Stop'
            }
            $status = Invoke-CimMethod @RebootPendingSplat
        }
        Else {
            $util = [wmiclass]'\\.\root\ccm\clientsdk:CCM_ClientUtilities'
            $status = $util.DetermineIfRebootPending()
        }
    }
    catch {
        $Error.RemoveAt(0)
    }
    if (($null -ne $status) -and $status.RebootPending) { 
        Return $true 
    }
    Return $false
}

Function Get-SCCMHardwareInventoryDate {
    $InvSplat = @{
        Namespace = 'root\ccm\invagt'
        Class     = 'InventoryActionStatus'
    }

    Get-WMIClassInstance @InvSplat | 
        Where-Object { $_.InventoryActionID -eq '{00000000-0000-0000-0000-000000000001}' } | 
        Select-Object @{label = 'HWSCAN'; expression = { 
                If ($_.LastCycleStartedDate.GetType().Name -ne 'DateTime') { $_.ConvertToDateTime($_.LastCycleStartedDate) } 
                Else { $_.LastCycleStartedDate } 
            } 
        } 
}

Function Test-SCCMHardwareInventoryScan {
    Param([Parameter(Mandatory = $true)]$Log)


    Write-Log -Message "Start Test-SCCMHardwareInventoryScan"
    $days = Get-XMLConfigHardwareInventoryDays
    $wmi = Get-SCCMHardwareInventoryDate
    $HWScanDate = $wmi | Select-Object -ExpandProperty HWSCAN
    $HWScanDate = Get-SmallDateTime -Date $HWScanDate
    $minDate = Get-SmallDateTime -Date ((Get-Date).AddDays(-$days))
    if ($HWScanDate -le $minDate) {
        $fix = (Get-XMLConfigHardwareInventoryFix).ToLower()
        if ($fix -eq "true") {
            Write-Log -Message "ConfigMgr Hardware Inventory scan: $HWScanDate. Starting hardware inventory scan of the client."
            Invoke-SCCMClientAction -ClientAction 'Hardware Inventory'

            # Get the new date after policy trigger
            $wmi = Get-SCCMHardwareInventoryDate
            $HWScanDate = $wmi | Select-Object -ExpandProperty HWSCAN
            $HWScanDate = Get-SmallDateTime -Date $HWScanDate
        }
        else {
            # No need to update anything if fix = false. Last date will still be set in log
        }
    }
    else {
        Write-Log -Message "ConfigMgr Hardware Inventory scan: OK"
    }
    $log.HWInventory = $HWScanDate
    Write-Log -Message "End Test-SCCMHardwareInventoryScan"
}



# Get the clients SiteName in Active Directory
Function Get-ClientSiteName {
    try {
        (Get-WMIClassInstance -Class Win32_NTDomain).ClientSiteName | Select-Object -First 1
    }
    catch { 
        $Error.RemoveAt(0)
    }
}
#endregion CCM


#region patches

Function Get-MissingUpdates {
    $UpdateShare = Get-XMLConfigUpdatesShare
    $OSName = Get-OperatingSystemFullName

    $Updates = $UpdateShare + "\" + $OSName + "\"
    $obj = New-Object PSObject @{}
    If ((Test-Path -Path $Updates) -eq $true) {
        $regex = "\b(?!(KB)+(\d+)\b)\w+"
        $hotfixes = (Get-ChildItem $Updates | Select-Object -ExpandProperty Name)
        $installedUpdates = (Get-WMIClassInstance -Class Win32_QuickFixEngineering).HotFixID

        foreach ($hotfix in $hotfixes) {
            $kb = $hotfix -replace $regex -replace "\." -replace "-"
            if ($installedUpdates -like $kb) {}
            else { $obj.Add('Hotfix', $hotfix) }
        }
    }
    Return $obj
}

Function Get-LastInstalledPatches {
    Param([Parameter(Mandatory = $true)]$Log)

    # Reading date from Windows Update COM object.
    $Session = New-Object -ComObject Microsoft.Update.Session
    $Searcher = $Session.CreateUpdateSearcher()
    $HistoryCount = $Searcher.GetTotalHistoryCount()

    Switch -Regex ($Script:WMIOperatingSystem.OSName) {
        "Windows 7|Server 2008" {
            $ClientApplicationId = 'AutomaticUpdates'
        }
        "Windows 8|Server 2012" {
            $ClientApplicationId = 'AutomaticUpdatesWuApp'
        }
        "Windows (10|11)|Server (2016|2019|2022)" {
            $ClientApplicationId = 'UpdateOrchestrator'
        }
    }

    $Date = $Searcher.QueryHistory(0, $HistoryCount) | 
                Where-Object { (@($ClientApplicationId, 'ccmexec') -contains $_.ClientApplicationID ) -and ($_.Title -notmatch "Security Intelligence Update|Definition Update") } | 
                Select-Object -ExpandProperty Date | 
                Measure-Latest
    # Reading date from PowerShell Get-Hotfix
    #$now = (Get-Date).ToString("$Script:TimeFormat")
    #$Hotfix = Get-Hotfix | Where-Object {$_.InstalledOn -le $now} | Select-Object -ExpandProperty InstalledOn -ErrorAction SilentlyContinue

    #$Hotfix = Get-Hotfix | Select-Object -ExpandProperty InstalledOn -ErrorAction SilentlyContinue

    $Hotfix = Get-WMIClassInstance -Class Win32_QuickFixEngineering | 
                Select-Object @{Name = "InstalledOn"; Expression = { [DateTime]::Parse($_.InstalledOn, $([System.Globalization.CultureInfo]::GetCultureInfo("en-US"))) } } | 
                Select-Object -ExpandProperty InstalledOn

    $Date2 = $null

    if ($null -ne $hotfix) { 
        $Date2 = Get-Date -Date ($hotfix | Measure-Latest) -ErrorAction SilentlyContinue 
    }

    if (($Date -ge $Date2) -and ($null -ne $Date)) { 
        $Log.OSUpdates = Get-SmallDateTime -Date $Date 
    }
    elseif (($Date2 -gt $Date) -and ($null -ne $Date2)) { 
        $Log.OSUpdates = Get-SmallDateTime -Date $Date2 
    }
}


Function Test-Update {
    Param([Parameter(Mandatory = $true)]$Log)

    #if (($Xml.Configuration.Option | Where-Object {$_.Name -like 'Updates'} | Select-Object -ExpandProperty 'Enable') -like 'True') {

    $UpdateShare = Get-XMLConfigUpdatesShare
    #$UpdateShare = $Xml.Configuration.Option | Where-Object {$_.Name -like 'Updates'} | Select-Object -ExpandProperty 'Share'


    Write-Log -Message "Validating required updates is installed on the client. Required updates will be installed if missing on client."
    $OSName = Get-OperatingSystemFullName

    $Updates = (Join-Path -Path $UpdateShare -ChildPath $OSName)
    If ((Test-Path -Path $Updates) -eq $true) {
        $regex = '(?i)^.+-kb[0-9]{6,}-(?:v[0-9]+-)?x[0-9]+\.msu$'
        $hotfixes = @(Get-ChildItem -Path $Updates | Where-Object { $_.Name -match $regex } | Select-Object -ExpandProperty Name)

        $installedUpdates = @((Get-WMIClassInstance -Class Win32_QuickFixEngineering).HotFixID)

        $count = $hotfixes.count

        if (($count -eq 0) -or ($null -eq $count)) {
            Write-Log -Message 'Updates: No mandatory updates to install.'
            $log.Updates = 'Compliant'
        }
        else {
            $logEntry = $null

            $regex = '\b(?!(KB)+(\d+)\b)\w+'
            foreach ($hotfix in $hotfixes) {
                $kb = $hotfix -replace $regex -replace "\." -replace "-"
                if ($installedUpdates -contains $kb) {
                    Write-Log -Message "Update $hotfix : OK"
                }
                else {
                    if ($null -eq $logEntry) { $logEntry = $kb }
                    else { $logEntry += ", $kb" }

                    $fix = (Get-XMLConfigUpdatesFix).ToLower()
                    if ($fix -eq "true") {
                        $kbfullpath = Join-Path -Path $updates -ChildPath $hotfix
                        Write-Log -Message "Update $hotfix : Missing. Installing now..." -Type 'WARNING'

                        $temppath = Join-Path -Path (Get-LocalFilesPath) -ChildPath "Temp"

                        If ((Test-Path -Path $temppath) -eq $false) { $null = New-Item -Path $temppath -ItemType Directory }

                        Copy-Item -Path $kbfullpath -Destination $temppath
                        $install = Join-Path -Path $temppath -ChildPath $hotfix

                        $Return = Invoke-Executable -FilePath 'wusa.exe' -ArgumentList "$install /quiet /norestart"
                        Write-Log -Message "Installed update '$install'"
                        Remove-Item -Path $install -Force -Recurse

                    }
                    else {
                        Write-Log -Message "Update $hotfix : Missing. Monitor mode only, no remediation." -Type 'WARNING'
                    }
                }

                if ($null -eq $logEntry) { $log.Updates = 'Compliant' }
                else { $log.Updates = $logEntry }
            }
        }
    }
    Else {
        $log.Updates = 'Failed'
        Write-Log -Message "Updates Failed: Could not locate update folder '$($Updates)'." -Type 'WARNING'
    }
}


Function Get-UBR {
    (Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion').UBR
}
#endregion patches


#region reboot

Function Get-LastReboot {
    Param([Parameter(Mandatory = $false)][xml]$Xml)

    # Only run if option in config is enabled
    if (($Xml.Configuration.Option | Where-Object { $_.Name -like 'RebootApplication' } | Select-Object -ExpandProperty 'Enable') -like 'True') { $execute = $true }

    if ($execute -eq $true) {

        [float]$maxRebootDays = Get-XMLConfigMaxRebootDays

        $lastBootTime = Get-LastBootTime

        $uptime = (Get-Date) - ($lastBootTime)
        if ($uptime.TotalDays -lt $maxRebootDays) {
            Write-Log -Message ('Last boot time: ' + $lastBootTime + ': OK')
        }
        elseif (($uptime.TotalDays -ge $maxRebootDays) -and (Get-XMLConfigRebootApplicationEnable -eq $true)) {
            Write-Log -Message ('Last boot time: ' + $lastBootTime + ': More than ' + $maxRebootDays + ' days since last reboot. Starting reboot application.') -Type 'WARNING'
            Start-RebootApplication
        }
        else {
            Write-Log -Message ('Last boot time: ' + $lastBootTime + ': More than ' + $maxRebootDays + ' days since last reboot. Reboot application disabled.') -Type 'WARNING'
        }
    }
}

Function Start-RebootApplication {
    $ReboottaskName = 'ConfigMgr Client Health - Reboot on demand'

    $task = schtasks.exe /query | FIND /I $ReboottaskName
    if (($null -eq $task) -or ($task -match '^\s*$')) { 
        New-RebootTask -RebootTaskName $ReboottaskName 
    }

    $null = Invoke-Executable -FilePath 'schtasks.exe' -ArgumentList "/Run /TN $ReboottaskName"
    Write-Log -Message "Ran task '$ReboottaskName' : $RunTaskLog"
}

Function New-RebootTask {
    Param([Parameter(Mandatory = $true)]$RebootTaskName)
    $rebootApp = Get-XMLConfigRebootApplication

    # $execute is the executable file, $arguement is all the arguments added to it.
    $execute, $arguments = $rebootApp.Split(' ')
    $argument = $arguments -join ' '

    #if ($OS -like "*Windows 7*") {
    $null = Invoke-Executable -FilePath 'schtasks.exe' -ArgumentList "/Create /tn $ReboottaskName /tr `"$execute $argument`" /ru `"BUILTIN\Users`" /sc ONCE /st 00:00 /sd 01/01/1901"
    #}
    <#
        else {
            $action = New-ScheduledTaskAction -Execute $execute -Argument $argument
            $userPrincipal = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545"
            $null = Register-ScheduledTask -Action $action -TaskName $ReboottaskName -Principal $userPrincipal
        }
        #>
}


Function Remove-ScheduledTask {
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [String]$TaskPath,

        [Parameter(Mandatory = $true, Position = 1)]
        [String]$TaskName
    )

    $service = New-Object -ComObject 'Schedule.service'
    $service.Connect($env:COMPUTERNAME)
    Try {
        $TaskPath = "\$TaskPath".TrimEnd('\') -replace '\\+', '\'
        $Folder = $service.GetFolder($TaskPath)
        If ($TaskName -eq '*') {
            $TaskList = $Folder.GetTasks(0)
        }
        Else {
            $TaskList = $Folder.GetTasks(0) | Where-Object {$_.Name -like "$TaskName"}
        }
        Foreach ($Task in $TaskList) {
            If ($null -ne $Task) {
                $Folder.DeleteTask($Task.Name,$null)
                Write-Log -Message "Removed the task '$($Task.Name)'"
            }
        }
    }
    Catch [System.IO.FileNotFoundException] {
        $Error.RemoveAt(0)
    }
}


Function Disable-ScheduledTask {
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [String]$TaskPath,

        [Parameter(Mandatory = $true, Position = 1)]
        [String]$TaskName
    )

    $service = New-Object -ComObject 'Schedule.service'
    $service.Connect($env:COMPUTERNAME)
    Try {
        $TaskPath = "\$TaskPath".TrimEnd('\') -replace '\\+', '\'
        $Folder = $service.GetFolder($TaskPath)
        $Task = $Folder.GetTasks(0) | Where-Object {$_.Name -like "$TaskName*"}
        If ($null -ne $Task) {
            $Task.Enabled = $false
            Write-Log -Message "Disabled the task '$($Task.Name)'"
        }
    }
    Catch [System.IO.FileNotFoundException] {
        $Error.RemoveAt(0)
    }
}


Function Remove-ScheduledTaskFolder {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [String]$TaskPath
    )
    
    $service = New-Object -ComObject 'Schedule.service'
    $service.Connect($env:COMPUTERNAME)
    Write-Verbose -Message "TaskPath : $TaskPath"
    $TaskPath = "\$TaskPath".TrimEnd('\')
    Write-Verbose -Message "TaskPath : $TaskPath"
    $FolderName = $TaskPath.Split('\')[-1]
    Write-Verbose -Message "Folder : $FolderName"
    $ParentFolder = (('\' + $TaskPath) -replace "\\$FolderName$") -replace '\\+', '\'
    Write-Verbose -Message "Parent : $ParentFolder"
    Try {
        $Folder = $service.GetFolder("$ParentFolder")
        $Folder.DeleteFolder($FolderName,$false)
        Write-Log -Message "Removed '$ParentFolder\$FolderName'"
    }
    Catch [System.IO.FileNotFoundException] {
        $Error.RemoveAt(0)
    }
} 

#region Pending Reboot

function Get-PendingReboot {
    $result = @{
        CBSRebootPending            = $false
        WindowsUpdateRebootRequired = $false
        FileRenamePending           = $false
        SCCMRebootPending           = $false
    }

    #Check CBS Registry
    $key = Get-ChildItem "HKLM:Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction SilentlyContinue
    if ($null -ne $key) { $result.CBSRebootPending = $true }

    #Check Windows Update
    $key = Get-Item 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction SilentlyContinue
    if ($null -ne $key) { $result.WindowsUpdateRebootRequired = $true }

    #Check PendingFileRenameOperations
    $prop = Get-ItemProperty 'HKLM:SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
    if ($null -ne $prop) {
        #PendingFileRenameOperations is not *must* to reboot?
        #$result.FileRenamePending = $true
    }

        
    $result.SCCMRebootPending = Test-SCCMRebootPending

    #Return Reboot required
    if ($result.ContainsValue($true)) {
        #$text = 'Pending Reboot: YES'
        $obj = $true
        $log.PendingReboot = 'Pending Reboot'
    }
    else {
        $obj = $false
        $log.PendingReboot = 'Compliant'
    }
    $Error.Clear()
    Return $obj
}



function Test-PendingReboot {
    Param([Parameter(Mandatory = $true)]$Log)
    # Only run pending reboot check if enabled in config
    if (($Xml.Configuration.Option | Where-Object { $_.Name -like 'PendingReboot' } | Select-Object -ExpandProperty 'Enable') -like 'True') {
        $result = @{
            CBSRebootPending            = $false
            WindowsUpdateRebootRequired = $false
            FileRenamePending           = $false
            SCCMRebootPending           = $false
        }

        #Check CBS Registry
        $key = Get-ChildItem "HKLM:Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction SilentlyContinue
        if ($null -ne $key) { $result.CBSRebootPending = $true }

        #Check Windows Update
        $key = Get-Item 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction SilentlyContinue
        if ($null -ne $key) { $result.WindowsUpdateRebootRequired = $true }

        #Check PendingFileRenameOperations
        $prop = Get-ItemProperty 'HKLM:SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
        if ($null -ne $prop) {
            #PendingFileRenameOperations is not *must* to reboot?
            #$result.FileRenamePending = $true
        }
        $Error.Clear()
        $result.SCCMRebootPending = Test-SCCMRebootPending


        #Return Reboot required
        if ($result.ContainsValue($true)) {
            Write-Log -Message 'Pending Reboot: Computer is in pending reboot' -Type 'WARNING'
            $log.PendingReboot = 'Pending Reboot'

            if ((Get-XMLConfigPendingRebootApp) -eq $true) {
                Start-RebootApplication
                $log.RebootApp = Get-SmallDateTime
            }
        }
        elseIf ($log.PendingReboot -eq 'Pending Reboot') {
            Write-Log -Message 'Pending Reboot already detected' -Type 'WARNING'
        }
        Else {
            Write-Log -Message 'Pending Reboot: OK'
            $log.PendingReboot = 'Compliant'
        }
        #Out-LogFile -Xml $xml -Text $text
    }
}
#endregion Pending Reboot
#endregion reboot


#region services

Function Get-ServiceUpTime {
    param([Parameter(Mandatory = $true)]$Name)

    Try { $ServiceDisplayName = (Get-Service -Name $Name -ErrorAction Stop).DisplayName }
    Catch {
        Write-Log -Message "Service '$($Name)' could not be found."
        Return
    }

    #First try and get the service start time based on the last start event message in the system log.
    Try {
        [datetime]$ServiceStartTime = (Get-EventLog -LogName System -Source "Service Control Manager" -EntryType Information -Message "*$($ServiceDisplayName)*running*" -Newest 1).TimeGenerated
        Return (New-TimeSpan -Start $ServiceStartTime -End (Get-Date)).Days
    }
    Catch {
        $Error.RemoveAt(0)
        $ErrorMessage = $_.Exception.Message
        Write-Log -Message "Could not get the uptime time for the '$($Name)' service from the event log.  Relying on the process instead. ($ErrorMessage)" -Type 'WARNING'
    }

    #If the event log doesn't contain a start event then use the start time of the service's process.  Since processes can be shared this is less reliable.
    Try {
        $ServiceProcessID = (Get-WMIClassInstance -Class Win32_Service -Filter "Name='$($Name)'").ProcessID

        [datetime]$ServiceStartTime = (Get-Process -Id $ServiceProcessID).StartTime
        Return (New-TimeSpan -Start $ServiceStartTime -End (Get-Date)).Days

    }
    Catch {
        $Error.RemoveAt(0)
        $ErrorMessage = $_.Exception.Message
        Write-Log -Message "Could not get the uptime time for the '$($Name)' service.  Returning max value. ($ErrorMessage)" -Type 'WARNING'
        Return [int]::MaxValue
    }
}

# Windows Service Functions
Function Test-ServiceList {
    Param([Parameter(Mandatory = $false)]$Xml, $log, $Webservice, $ProfileID)

    $log.Services = 'Compliant'
    $FailedList = New-Object -TypeName System.Collections.ArrayList

    # Test services defined by config.xml
    Write-Log 'Test services from XML configuration file'
    foreach ($service in $Xml.Configuration.Service) {
        $startuptype = ($service.StartupType).ToLower()

        if ($startuptype -like "automatic (delayed start)") { $service.StartupType = "automaticd" }

        $Params = @{
            Name = $service.Name 
            StartupType = $service.StartupType 
            State = $service.State 
            Log = $log 
        }
        if ($service.uptime) {
            $Params.Uptime = ($service.Uptime).ToLower()
        }
        $Result = Test-Service @Params
        If ($Result -eq $false) {
            $null = $FailedList.Add($service.Name)
        }
    }
    If ($FailedList.Count -gt 0) {
        $log.Services = "Failed ($($FailedList -join ', '))"
    }
}



Function Test-Service {
    param(
        [Parameter(Mandatory = $True,
            HelpMessage = 'Name')]
        [string]$Name,
        [Parameter(Mandatory = $True,
            HelpMessage = 'StartupType: Automatic, Automatic (Delayed Start), Manual, Disabled')]
        [string]$StartupType,
        [Parameter(Mandatory = $True,
            HelpMessage = 'State: Running, Stopped')]
        [string]$State,
        [Parameter(Mandatory = $False,
            HelpMessage = 'Updatime in days')]
        [int]$Uptime,
        [Parameter(Mandatory = $True)]$log
    )

    $OSName = Get-OperatingSystemFullName
    $Result = $True

    # Handle all sorts of casing and mispelling of delayed and triggerd start in config.xml services
    $val = $StartupType.ToLower()
    switch -Regex ($val) {
        "automatic\s*\(*d" { $StartupType = "Automatic (Delayed Start)" }
        "automatic\s*\(*t" { $StartupType = "Automatic (Trigger Start)" }
    }

    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"

    $DelayedAutostart = (Get-ItemProperty -Path $path).DelayedAutostart
    if ($DelayedAutostart -ne 1) {
        $DelayedAutostart = 0
    }

    $service = Get-Service -Name $Name
    $WMIService = Get-WMIClassInstance -Class Win32_Service -Property @('Name', 'StartMode', 'ProcessID', 'Status') -Filter "Name='$Name'"
    $StartMode = ([String]$WMIService.StartMode).ToLower()

    switch -Wildcard ($StartMode) {
        "auto*" {
            if ($DelayedAutostart -eq 1) { $serviceStartType = "Automatic (Delayed Start)" }
            else { $serviceStartType = "Automatic" }
        }
        "manual" { $serviceStartType = "Manual" }
        "disabled" { $serviceStartType = "Disabled" }
    }

    Write-Log -Message "Verify startup type"
    if ($serviceStartType -eq $StartupType) {
        Write-Log -Message "Service $Name startup: OK"
    }
    elseif ($StartupType -like "Automatic (Delayed Start)") {
        # Handle Automatic Trigger Start the dirty way for these two services. Implement in a nice way in future version.
        if ( (($name -eq "wuauserv") -or ($name -eq "W32Time")) -and ($OSName -match "Windows (10|11)|Server 2016|Server 2019") ) {
            if ($service.StartType -ne "Automatic") {
                Try {
                    Set-Service -Name $service.Name -StartupType Automatic -ErrorAction Stop
                    $text = "Configuring service $Name StartupType to: Automatic (Trigger Start)..."
                }
                Catch {
                    $Result = $false
                    $text = "Failed to configure service $Name StartupType to: Automatic (Trigger Start)..."
                }
            }
            else { $text = "Service $Name startup: OK" }
            Write-Log -Message $text
        }
        else {
            # Automatic delayed requires the use of sc.exe
            $Process = Invoke-Executable -FilePath 'sc.exe' -ArgumentList "config $($service.Name) start= delayed-auto"
            $log.Services = 'Started'
            If ($Process.ExitCode -ne 0) {
                $Result = $False
                $log.Services = 'Failed'
            }
            Write-Log -Message "Configuring service $Name StartupType to: $StartupType..."
        }
    }
    else {
        try {
            Set-Service -Name $service.Name -StartupType $StartupType
            Write-Log -Message "Configuring service $Name StartupType to: $StartupType..."
            $log.Services = 'Started'
        }
        catch {
            Write-Log -Message "Failed to set $StartupType StartupType on service $Name" -Type 'ERROR'
        }
    }

    Write-Log 'Verify service is running'
    if ($service.Status -eq "Running") {
        Write-Log -Message ('Service ' + $Name + ' running: OK')

        #If we are checking uptime.
        If ($Uptime) {
            Write-Log -Message "Verify the $($Name) service hasn't exceeded uptime of $($Uptime) days."
            $ServiceUptime = Get-ServiceUpTime -Name $Name
            if ($ServiceUptime -ge $Uptime) {
                try {
                    #Before restarting the service wait for some known processes to end.  Restarting the service while an app or updates is installing might cause issues.
                    $Timer = [Diagnostics.Stopwatch]::StartNew()
                    $WaitMinutes = 30
                    $ProcessesStopped = $True
                    While ((Get-Process -Name WUSA, wuauclt, setup, TrustedInstaller, msiexec, TiWorker, ccmsetup -ErrorAction SilentlyContinue).Count -gt 0) {
                        $MinutesLeft = $WaitMinutes - $Timer.Elapsed.Minutes
                        $Error.Clear()

                        If ($MinutesLeft -le 0) {
                            Write-Log -Message "Timed out waiting $($WaitMinutes) minutes for installation processes to complete.  Will not restart the $($Name) service." -Type 'WARNING'
                            $ProcessesStopped = $False
                            Break
                        }
                        Write-Log -Message "Waiting $($MinutesLeft) minutes for installation processes to complete." -Type 'WARNING'
                        Start-Sleep -Seconds 30
                    }
                    $Timer.Stop()
                    
                    #If the processes are not running the restart the service.
                    If ($ProcessesStopped) {
                        Write-Log -Message "Restarting service: $($Name)..."
                        Restart-Service  -Name $service.Name -Force
                        Write-Log -Message "Restarted service: $($Name)..."
                        $log.Services = 'Restarted'
                    }
                }
                catch {
                    Write-Log -Message "Failed to restart service $($Name)" -Type 'ERROR'
                    $Result = $false
                }
            }
            else {
                Write-Log -Message "Service $($Name) uptime: OK"
            }
        }
    }
    else {
        if ($WMIService.Status -eq 'Degraded') {
            try {
                Write-Log -Message "Identified '$Name' service in a 'Degraded' state. Will force '$Name' process to stop." -Type 'WARNING'
                $ServicePID = $WMIService | Select-Object -ExpandProperty ProcessID
                Stop-Process -Id $ServicePID -Force -Confirm:$false -ErrorAction Stop
                Write-Log -Message "Succesfully stopped the $Name service process which was in a degraded state."
            }
            Catch {
                Write-Log -Message "Failed to force $Name process to stop." -Type 'ERROR'
            }
        }
        try {
            $RetryService = $False
            Start-Service -Name $service.Name -ErrorAction Stop
            Write-Log -Message ('Starting service: ' + $Name + '...')
            $log.Services = 'Started'
            $Result = $true
        }
        catch {
            #Error 1290 (-2146233087) indicates that the service is sharing a thread with another service that is protected and cannot share its thread.
            #This is resolved by configuring the service to run on its own thread.
            If ($_.Exception.Hresult -eq '-2146233087') {
                Write-Log -Message "Failed to start service $Name because it's sharing a thread with another process.  Changing to use its own thread."
                $Process = Invoke-Executable -FilePath "$env:ComSpec" -ArgumentList "/c sc config $Name type= own"
                Write-Log -Message "Result : $($Process.ExitCode)"
                $RetryService = $True
            }
            Else {
                Write-Log -Message ('Failed to start service ' + $Name) -Type 'ERROR'
            }
        }

        #If a recoverable error was found, try starting it again.
        If ($RetryService) {
            try {
                Start-Service -Name $service.Name -ErrorAction Stop
                Write-Log -Message "Started service '$($Name)'"
                $log.Services = 'Started'
                $Result = $true
            }
            catch {
                Write-Log -Message ('Failed to start service ' + $Name) -Type 'ERROR'
                $Result = $false
            }
        }
    }
    Return $Result
}
#endregion services


#region Shares
function Test-AdminShare {
    Param([Parameter(Mandatory = $true)]$Log)
    Write-Log -Message "Test the ADMIN$ and C$"
    $share = Get-WMIClassInstance -Class Win32_Share | Where-Object { $_.Name -like 'ADMIN$' }
    #$shareClass = [WMICLASS]"WIN32_Share"  # Depreciated

    if ($null -ne $share) {
        Write-Log -Message 'Adminshare Admin$: OK'
    }
    else { $fix = $true }

    $share = Get-WMIClassInstance -Class Win32_Share | Where-Object { $_.Name -like 'C$' }
    #$shareClass = [WMICLASS]'WIN32_Share'  # Depreciated

    if ($null -ne $share) {
        Write-Log -Message 'Adminshare C$: OK'
    }
    else { $fix = $true }

    if ($fix -eq $true) {
        $log.AdminShare = 'Repaired'
        $ServerSvc = 'lanmanserver'
        Stop-Service $ServerSvc -Force
        Start-Service $ServerSvc
        Write-Log -Message 'Error with Adminshares. Remediating...' -Type 'WARNING'
    }
    else { $log.AdminShare = 'Compliant' }
}
#endregion Shares


#region drivers

Function Test-MissingDrivers {
    Param([Parameter(Mandatory = $true)]$Log)
    #$FileLogLevel = ((Get-XMLConfigLoggingLevel).ToString()).ToLower()
    $DeviceList = Get-WMIClassInstance -Class Win32_PNPEntity |
                    Where-Object { ($_.ConfigManagerErrorCode -ne 0) -and ($_.ConfigManagerErrorCode -ne 22) -and ($_.Name -notlike "*PS/2*") } | 
                    Select-Object Name, DeviceID
    $i = ($DeviceList | Measure-Object).Count

    if ($null -ne $DeviceList) {
        Write-Log -Message "Drivers: $i unknown or faulty device(s)" -Type 'WARNING'
        $log.Drivers = "$i unknown or faulty driver(s)"

        foreach ($device in $DeviceList) {
            Write-Log -Message ('Missing or faulty driver: ' + $device.Name + '. Device ID: ' + $device.DeviceID) -Type 'WARNING'
            #if (-NOT($FileLogLevel -like "clientlocal")) { Out-LogFile -Xml $xml -Text $text -Severity 2 }
        }
    }
    else {
        Write-Log -Message "Drivers: OK"
        $log.Drivers = 'Compliant'
    }
}


Function Test-SoftwareMeteringPrepDriver {
    Param([Parameter(Mandatory = $true)]$Log)
    # To execute function: if (Test-SoftwareMeteringPrepDriver -eq $false) {$restartCCMExec = $true}
    # Thanks to Paul Andrews for letting me know about this issue.
    # And Sherry Kissinger for a nice fix: https://mnscug.org/blogs/sherry-kissinger/481-configmgr-ccmrecentlyusedapps-blank-or-mtrmgr-log-with-startprepdriver-openservice-failed-with-error-issue

    Write-Log -Message "Start Test-SoftwareMeteringPrepDriver"

    
    $mtrmgrlogFile = "$Script:CCMLogDir\mtrmgr.log"
    $content = Get-Content -Path $mtrmgrlogFile
    $error1 = "StartPrepDriver - OpenService Failed with Error"
    $error2 = "Software Metering failed to start PrepDriver"

    if (($null -eq $content) -or ($content -match $error1) -or ($content -match $error2)) {
        $fix = (Get-XMLConfigSoftwareMeteringFix).ToLower()

        if ($fix -eq "true") {
            Write-Log -Message "Software Metering - PrepDriver: Error. Remediating..."
            $CMClientDIR = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SMS\Client\Configuration\Client Properties" -Name 'Local SMS Path').'Local SMS Path'
            $ExePath = "$env:windir\system32\RUNDLL32.EXE"
            $CLine = 'SETUPAPI.DLL,InstallHinfSection DefaultInstall 128 ' + $CMClientDIR + 'prepdrv.inf'
            $null = Invoke-Executable -FilePath $ExePath -ArgumentList "$CLine"
            Write-Log -Message "Invoked '$ExePath $CLine'"

            If ($null -ne $Content) {
                $newContent = $content | Select-String -Pattern $error1, $error2 -NotMatch
                Stop-Service -Name CcmExec
                Out-File -FilePath $mtrmgrlogFile -InputObject $newContent -Encoding utf8 -Force
                Start-Service -Name CcmExec
                $Obj = $false
                $Log.SWMetering = "Remediated"
            }
            Else {
                $Obj = $false
                $Log.SWMetering = "Error"
            }
        }
        else {
            # Set $obj to true as we don't want to do anything with the CM agent.
            $obj = $true
            $Log.SWMetering = "Error"
        }
    }
    else {
        Write-Log -Message "Software Metering - PrepDriver: OK"
        $Obj = $true
        $Log.SWMetering = 'Compliant'
    }
    $content = $null # Clean the variable containing the log file.

    Write-Log -Message "End Test-SoftwareMeteringPrepDriver"
    Return $Obj
}

#endregion drivers


#region Policies
Function Test-RegistryPol {
    Param(
        [datetime]$StartTime = [datetime]::MinValue,
        $Days,
        [Parameter(Mandatory = $true)]$Log
    )
    $log.WUAHandler = "Checking"
    $RepairReason = ""
    $RegistryPol = "$($env:WinDir)\System32\GroupPolicy\Machine\registry.pol"
    $SoftwareDistrib = "$($env:WinDir)\SoftwareDistribution"
    $CatRoot = "$($env:WinDir)\System32\catroot2"

    # Check 1 - Error in WUAHandler.log
    Write-Log -Message "Check WUAHandler.log for errors since $($StartTime)."
    $WUAHandlerlogFile = "$Script:CCMLogDir\WUAHandler.log"
    $logLine = Search-CMLogFile -LogFile $WUAHandlerlogFile -StartTime $StartTime -SearchStrings @('0x80004005', '0x87d00692')
    if ($logLine) { $RepairReason = "WUAHandler Log" }

    # Check 2 - Registry.pol is too old.
    if ($Days -and (Test-Path -Path $RegistryPol)) {
        Write-Log -Message "Check machine registry file to see if it's older than $($Days) days."
        try {
            $fileDate = Get-ChildItem -Path $RegistryPol -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty LastWriteTime
            If ($null -ne $fileDate) {
                $regPolDate = $fileDate
            }
            Else {
                $regPolDate = [datetime]::MinValue
            }
            $now = Get-Date
            if (($now - $regPolDate).Days -ge $Days) { $RepairReason = "File Age" }
        }
        catch { Write-Log -Message "GPO Cache: Failed to check machine policy age."  -Type 'WARNING' }
    }

    # Check 3 - Look back through the last 7 days for group policy processing errors.
    #Event IDs documented here: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-vista/cc749336(v=ws.10)#troubleshooting-group-policy-using-event-logs-1
    try {
        Write-Log -Message "Checking the Group Policy event log for errors since $($StartTime)."
        $IdList = ((7000..7007),(7017..7299),1096) | Foreach-Object {$_}
        $FilterHashTable = @{
            LogName = 'Microsoft-Windows-GroupPolicy/Operational'
            Level = 2
            StartTime = $StartTime 
        }
        $numberOfGPOErrors = (Get-WinEvent -Verbose:$false -FilterHashtable $FilterHashTable -ErrorAction SilentlyContinue | Where-Object { $IdList -contains $_.ID }).Count
        if ($numberOfGPOErrors -gt 0) { $RepairReason = "Event Log" }
        $Error.Clear()

    }
    catch { 
        If ($_.Exception.Message -match 'no events') {
            $Error.RemoveAt(0)
        }
        Write-Log -Message "GPO Cache: Failed to check the event log for policy errors."  -Type 'WARNING' 
    }

    #If we need to repart the policy files then do so.
    if ($RepairReason -ne "") {
        $log.WUAHandler = "Broken ($RepairReason)"
        Write-Log -Message "GPO Cache: Broken ($RepairReason). Deleting registry.pol and running gpupdate... This can take a few minutes" -Type 'WARNING'

        try { 
            if (Test-Path -Path $RegistryPol) { 
                Remove-Item $RegistryPol -Force 
                Write-Log -Message "Removed '$RegistryPol'"
            } 
        }
        catch { Write-Log -Message "GPO Cache: Failed to remove the registry file ($($RegistryPol))." -Type 'WARNING' }

        Stop-Service -Name 'wuauserv' -Force
        If (Test-Path -Path "$SoftwareDistrib.bak") { Remove-Item -Path "$SoftwareDistrib.bak" -Force -Recurse}
        If (Test-Path -Path $SoftwareDistrib) {
            Rename-Item -Path $SoftwareDistrib -NewName 'SoftwareDistribution.bak' -Force -Verbose
            Write-Log -Message "Renamed '$SoftwareDistrib' to 'SoftwareDistribution.bak'"
        }
        If (Test-Path -Path "$CatRoot.bak") { Remove-Item -Path "$CatRoot.bak" -Force -Recurse}
        If (Test-Path -Path $CatRoot) {
            Rename-Item -Path $CatRoot -NewName 'catroot2.bak' -Force -Verbose
            Write-Log -Message "Renamed '$CatRoot' to 'catroot2.bak'"
        }
        Start-Service -Name 'wuauserv'
        
        Start-Sleep -Second 5
        
        $Return = Invoke-Executable -FilePath 'gpupdate.exe' -ArgumentList "/force /target:computer"
        $GPUpdateResult = ''
        If ($Return.ExitCode -ne 0) {
            $GPUpdateResult = "$($Return.StdOut)`r`n$($Return.StdErr)"
        }
        Write-Log -Message "GPUpdate result : ($($Return.ExitCode)) $GPUpdateResult"

        $Return = Invoke-Executable -FilePath 'wuauclt.exe' -ArgumentList "/detectnow"
        $ResultMsg = ''
        If ($Return.ExitCode -ne 0) {
            $ResultMsg = "$($Return.StdOut)`r`n$($Return.StdErr)"
        }
        Write-Log -Message "'wuauclt.exe /detectnow' result : ($($Return.ExitCode)) $ResultMsg"

        Start-Sleep -Second 5
        
        $Return = Invoke-Executable -FilePath 'wuauclt.exe' -ArgumentList "/resetauthorization /detectnow"
        $ResultMsg = ''
        If ($Return.ExitCode -ne 0) {
            $ResultMsg = "$($Return.StdOut)`r`n$($Return.StdErr)"
        }
        Write-Log -Message "'wuauclt.exe /resetauthorization /detectnow' result : ($($Return.ExitCode)) $ResultMsg"

        Restart-Service -Name ccmexec -Force -Verbose

        #Write-Log 'Sleeping for 1 minute to allow for group policy to refresh'
        #Start-Sleep -Seconds 60

        Write-Log -Message 'Refreshing update policy'
        Invoke-SCCMClientAction -ClientAction 'Machine Policy Assignments Request'
        Start-Sleep -Seconds 30

        Invoke-SCCMClientAction -ClientAction 'Machine Policy Evaluation'
        Start-Sleep -Seconds 30
        
        Invoke-SCCMClientAction -ClientAction 'Scan By Update Source'
        Invoke-SCCMClientAction -ClientAction 'Source Update Message'

        $log.WUAHandler = "Repaired ($RepairReason)"
        Write-Log -Message "GPO Cache: $($log.WUAHandler)"
    }
    else {
        $log.WUAHandler = 'Compliant'
        Write-Log -Message "GPO Cache: OK"
    }
}


# TODO: Implement so result of this remediation is stored in WMI log object, next to result of previous WMI check. This do not require db or webservice update
# ref: https://social.technet.microsoft.com/Forums/de-DE/1f48e8d8-4e13-47b5-ae1b-dcb831c0a93b/setup-was-unable-to-compile-the-file-discoverystatusmof-the-error-code-is-8004100e?forum=configmanagerdeployment
Function Test-PolicyPlatform {
    Param([Parameter(Mandatory = $true)]$Log)
    try {
        if (Get-WMIClassInstance -Namespace 'root/Microsoft' -Class '__Namespace' -Filter 'Name = "PolicyPlatform"') { Write-Log -Message "PolicyPlatform: OK" }
        else {
            Write-Log -Message "PolicyPlatform: Not found, recompiling WMI 'Microsoft Policy Platform\ExtendedStatus.mof'" -Type 'WARNING'

            # 32 or 64?
            if ($WMIOperatingSystem.OSArchitecture -match '64') { 
                $MofPath = "$env:ProgramW6432\Microsoft Policy Platform\ExtendedStatus.mof"
            }
            else { 
                $MofPath = "$env:ProgramFiles\Microsoft Policy Platform\ExtendedStatus.mof"
            }
            $null = Invoke-Executable -FilePath 'mofcomp' -ArgumentList "$MofPath"
            Write-Log -Message "Launched 'mofcomp $MofPath'"

            # Update WMI log object
            $text = 'PolicyPlatform Recompiled.'
            if (-NOT($Log.WMI -eq 'Compliant')) { $Log.WMI += ". $text" }
            else { $Log.WMI = $text }
        }
    }
    catch { Write-Log -Message "PolicyPlatform: RecompilePolicyPlatform failed!"  -Type 'WARNING' }
}
#endregion Policies

#region XML

# Start Getters - XML config file
Function Get-LocalFilesPath {
    if ($config) {
        $obj = $Xml.Configuration.LocalFiles
    }
    $obj = $ExecutionContext.InvokeCommand.ExpandString($obj)
    if ($null -eq $obj) { $obj = Join-Path -Path "$env:Temp" -ChildPath "ConfigMgrClientHealth" }
    Return $obj
}

Function Get-XMLConfigClientVersion {
    if ($config) {
        $obj = $Xml.Configuration.Client | Where-Object { $_.Name -like 'Version' } | Select-Object -ExpandProperty '#text'
    }

    Return $obj
}

Function Get-XMLConfigClientSitecode {
    if ($config) {
        $obj = $Xml.Configuration.Client | Where-Object { $_.Name -like 'SiteCode' } | Select-Object -ExpandProperty '#text'
    }

    Return $obj
}

Function Get-XMLConfigClientDomain {
    if ($config) {
        $obj = $Xml.Configuration.Client | Where-Object { $_.Name -like 'Domain' } | Select-Object -ExpandProperty '#text'
    }
    Return $obj
}

Function Get-XMLConfigClientAutoUpgrade {
    if ($config) {
        $obj = $Xml.Configuration.Client | Where-Object { $_.Name -like 'AutoUpgrade' } | Select-Object -ExpandProperty '#text'
    }
    Return $obj
}

Function Get-XMLConfigClientMaxLogSize {
    if ($config) {
        $obj = $Xml.Configuration.Client | Where-Object { $_.Name -like 'Log' } | Select-Object -ExpandProperty 'MaxLogSize'
    }
    Return $obj
}

Function Get-XMLConfigClientMaxLogHistory {
    if ($config) {
        $obj = $Xml.Configuration.Client | Where-Object { $_.Name -like 'Log' } | Select-Object -ExpandProperty 'MaxLogHistory'
    }
    Return $obj
}

Function Get-XMLConfigClientMaxLogSizeEnabled {
    if ($config) {
        $obj = $Xml.Configuration.Client | Where-Object { $_.Name -like 'Log' } | Select-Object -ExpandProperty 'Enable'
    }
    Return $obj
}

Function Get-XMLConfigClientCache {
    if ($config) {
        $obj = $Xml.Configuration.Client | Where-Object { $_.Name -like 'CacheSize' } | Select-Object -ExpandProperty 'Value'
    }
    Return $obj
}

Function Get-XMLConfigClientCacheDeleteOrphanedData {
    if ($config) {
        $obj = $Xml.Configuration.Client | Where-Object { $_.Name -like 'CacheSize' } | Select-Object -ExpandProperty 'DeleteOrphanedData'
    }
    Return $obj
}

Function Get-XMLConfigClientCacheEnable {
    if ($config) {
        $obj = $Xml.Configuration.Client | Where-Object { $_.Name -like 'CacheSize' } | Select-Object -ExpandProperty 'Enable'
    }
    Return $obj
}

Function Get-XMLConfigClientShare {
    if ($config) {
        $obj = $Xml.Configuration.Client | Where-Object { $_.Name -like 'Share' } | Select-Object -ExpandProperty '#text'
    }
    $Error.Clear()
    if (!($obj)) { $obj = "$Script:ScriptPath\CMClient" } #If Client share is empty, default to the script folder.
    Return $obj
}

Function Get-XMLConfigUpdatesShare {
    if ($config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -like 'Updates' } | Select-Object -ExpandProperty 'Share'
    }
    $Error.Clear()

    If (!($obj)) { $obj = Join-Path -Path $Script:ScriptPath -ChildPath "Updates" }
    Return $obj
}

Function Get-XMLConfigUpdatesEnable {
    if ($config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -like 'Updates' } | Select-Object -ExpandProperty 'Enable'
    }
    Return $obj
}

Function Get-XMLConfigUpdatesFix {
    if ($config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -like 'Updates' } | Select-Object -ExpandProperty 'Fix' 
    }
    Return $obj
}

Function Get-XMLConfigCMGEnabled {
    if ($config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -eq 'CMG' } | Select-Object -ExpandProperty 'Enable' 
    }
    Return $obj
}

Function Get-XMLConfigCMGFQDN {
    if ($config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -eq 'CMG' } | Select-Object -ExpandProperty 'FQDN' 
    }
    Return $obj
}

Function Get-XMLConfigClientAuthCertEnabled {
    If ($Config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -eq 'ClientAuthCert' } | Select-Object -ExpandProperty 'Enable' 
    }
    Return $obj
}

Function Get-XMLConfigClientAuthCertTemplate {
    If ($Config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -eq 'ClientAuthCert' } | Select-Object -ExpandProperty 'Template' 
    }
    Return ($obj -split '\s*,\s*')
}

Function Get-XMLConfigClientAuthCertFix {
    If ($Config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -eq 'ClientAuthCert' } | Select-Object -ExpandProperty 'Fix' 
    }
    Return $obj
}

Function Get-XMLConfigLoggingShare {
    if ($config) {
        $obj = $Xml.Configuration.Log | Where-Object { $_.Name -like 'File' } | Select-Object -ExpandProperty 'Share'
    }
    $Error.Clear()

    $obj = $ExecutionContext.InvokeCommand.ExpandString($obj)
    Return $obj
}

Function Get-XMLConfigLoggingLocalFile {
    if ($config) {
        $obj = $Xml.Configuration.Log | Where-Object { $_.Name -like 'File' } | Select-Object -ExpandProperty 'LocalLogFile'
    }
    Return $obj
}

Function Get-XMLConfigLoggingEnable {
    if ($config) {
        $obj = $Xml.Configuration.Log | Where-Object { $_.Name -like 'File' } | Select-Object -ExpandProperty 'Enable'
    }
    Return $obj
}

Function Get-XMLConfigLoggingMaxHistory {
    # Currently not configurable through console extension and webservice. TODO
    if ($config) {
        $obj = $Xml.Configuration.Log | Where-Object { $_.Name -like 'File' } | Select-Object -ExpandProperty 'MaxLogHistory'
    }
    Return $obj
}

Function Get-XMLConfigLoggingLevel {
    if ($config) {
        $obj = $Xml.Configuration.Log | Where-Object { $_.Name -like 'File' } | Select-Object -ExpandProperty 'Level'
    }
    Return $obj
}

Function Get-XMLConfigLoggingTimeFormat {
    if ($config) {
        $obj = $Xml.Configuration.Log | Where-Object { $_.Name -like 'Time' } | Select-Object -ExpandProperty 'Format'
    }
    Return $obj
}

Function Get-XMLConfigPendingRebootApp {
    # TODO verify this function
    if ($config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -like 'PendingReboot' } | Select-Object -ExpandProperty 'StartRebootApplication'
    }
    Return $obj
}

Function Get-XMLConfigMaxRebootDays {
    if ($config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -like 'MaxRebootDays' } | Select-Object -ExpandProperty 'Days'
    }
    Return $obj
}

Function Get-XMLConfigRebootApplication {
    if ($config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -like 'RebootApplication' } | Select-Object -ExpandProperty 'Application'
    }
    Return $obj
}

Function Get-XMLConfigRebootApplicationEnable {
    ### TODO implement in webservice
    if ($config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -like 'RebootApplication' } | Select-Object -ExpandProperty 'Enable'
    }
    Return $obj
}

Function Get-XMLConfigDNSCheck {
    # TODO verify switch, skip test and monitor for console extension
    if ($config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -like 'DNSCheck' } | Select-Object -ExpandProperty 'Enable'
    }
    Return $obj
}

Function Get-XMLConfigCcmSQLCELog {
    # TODO implement monitor mode
    if ($config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -like 'CcmSQLCELog' } | Select-Object -ExpandProperty 'Enable'
    }

    Return $obj
}

Function Get-XMLConfigDNSFix {
    if ($config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -like 'DNSCheck' } | Select-Object -ExpandProperty 'Fix'
    }
    Return $obj
}

Function Get-XMLConfigDrivers {
    if ($config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -like 'Drivers' } | Select-Object -ExpandProperty 'Enable'
    }
    Return $obj
}

Function Get-XMLConfigPatchLevel {
    if ($config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -like 'PatchLevel' } | Select-Object -ExpandProperty 'Enable'
    }
    Return $obj
}

Function Get-XMLConfigOSDiskFreeSpace {
    if ($config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -like 'OSDiskFreeSpace' } | Select-Object -ExpandProperty '#text'
    }
    Return $obj
}

Function Get-XMLConfigHardwareInventoryEnable {
    if ($config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -like 'HardwareInventory' } | Select-Object -ExpandProperty 'Enable'
    }
    Return $obj
}

Function Get-XMLConfigHardwareInventoryFix {
    if ($config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -like 'HardwareInventory' } | Select-Object -ExpandProperty 'Fix'
    }
    Return $obj
}

Function Get-XMLConfigSoftwareMeteringEnable {
    if ($config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -like 'SoftwareMetering' } | Select-Object -ExpandProperty 'Enable'
    }
    Return $obj
}

Function Get-XMLConfigSoftwareMeteringFix {
    # TODO implement this check in console extension and webservice
    if ($config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -like 'SoftwareMetering' } | Select-Object -ExpandProperty 'Fix'
    }
    Return $obj
}

Function Get-XMLConfigHardwareInventoryDays {
    # TODO implement this check in console extension and webservice
    if ($config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -like 'HardwareInventory' } | Select-Object -ExpandProperty 'Days'
    }
    Return $obj
}

Function Get-XMLConfigRemediationAdminShare {
    if ($config) {
        $obj = $Xml.Configuration.Remediation | Where-Object { $_.Name -like 'AdminShare' } | Select-Object -ExpandProperty 'Fix'
    }
    Return $obj
}

Function Get-XMLConfigRemediationClientProvisioningMode {
    if ($config) {
        $obj = $Xml.Configuration.Remediation | Where-Object { $_.Name -like 'ClientProvisioningMode' } | Select-Object -ExpandProperty 'Fix'
    }
    Return $obj
}

Function Get-XMLConfigRemediationClientStateMessages {
    if ($config) {
        $obj = $Xml.Configuration.Remediation | Where-Object { $_.Name -like 'ClientStateMessages' } | Select-Object -ExpandProperty 'Fix'
    }
    Return $obj
}

Function Get-XMLConfigRemediationClientWUAHandler {
    if ($config) {
        $obj = $Xml.Configuration.Remediation | Where-Object { $_.Name -like 'ClientWUAHandler' } | Select-Object -ExpandProperty 'Fix'
    }
    Return $obj
}

Function Get-XMLConfigRemediationClientWUAHandlerDays {
    # TODO implement days in console extension and webservice
    if ($config) {
        $obj = $Xml.Configuration.Remediation | Where-Object { $_.Name -like 'ClientWUAHandler' } | Select-Object -ExpandProperty 'Days'
    }
    Return $obj
}

Function Get-XMLConfigBITSCheck {
    if ($config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -like 'BITSCheck' } | Select-Object -ExpandProperty 'Enable'
    }
    Return $obj
}

Function Get-XMLConfigBITSCheckFix {
    if ($config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -like 'BITSCheck' } | Select-Object -ExpandProperty 'Fix'
    }
    Return $obj
}

Function Get-XMLConfigClientSettingsCheck {
    # TODO implement in console extension and webservice
    $obj = $Xml.Configuration.Option | Where-Object { $_.Name -like 'ClientSettingsCheck' } | Select-Object -ExpandProperty 'Enable'
    Return $obj
}

Function Get-XMLConfigClientSettingsCheckFix {
    # TODO implement in console extension and webservice
    $obj = $Xml.Configuration.Option | Where-Object { $_.Name -like 'ClientSettingsCheck' } | Select-Object -ExpandProperty 'Fix'
    Return $obj
}

Function Get-XMLConfigWMI {
    if ($config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -like 'WMI' } | Select-Object -ExpandProperty 'Enable'
    }
    Return $obj
}

Function Get-XMLConfigWMIRepairEnable {
    if ($config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -like 'WMI' } | Select-Object -ExpandProperty 'Fix'
    }
    Return $obj
}

Function Get-XMLConfigRefreshComplianceState {
    # Measured in days
    if ($config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -like 'RefreshComplianceState' } | Select-Object -ExpandProperty 'Enable'
    }
    Return $obj
}

Function Get-XMLConfigRefreshComplianceStateDays {
    if ($config) {
        $obj = $Xml.Configuration.Option | Where-Object { $_.Name -like 'RefreshComplianceState' } | Select-Object -ExpandProperty 'Days'
    }
    Return $obj
}

Function Get-XMLConfigRemediationClientCertificate {
    if ($config) {
        $obj = $Xml.Configuration.Remediation | Where-Object { $_.Name -like 'ClientCertificate' } | Select-Object -ExpandProperty 'Fix'
    }
    Return $obj
}

Function Get-XMLConfigSQLServer {
    $obj = $Xml.Configuration.Log | Where-Object { $_.Name -like 'SQL' } | Select-Object -ExpandProperty 'Server'
    Return $obj
}

Function Get-XMLConfigSQLLoggingEnable {
    $obj = $Xml.Configuration.Log | Where-Object { $_.Name -like 'SQL' } | Select-Object -ExpandProperty 'Enable'
    Return $obj
}

#endregion XML


#region misc

Function Get-SmallDateTime {
    Param([Parameter(Mandatory = $false)]$Date)
    #Write-Log -Message "Start Get-SmallDateTime"

    If ($null -eq $Date) { $Date = Get-Date }
    $format = (Get-XMLConfigLoggingTimeFormat).ToLower()

    Switch -Regex ($format) {
        'utc' {
            $DateString = $Date.ToUniversalTime().ToString("$Script:TimeFormat")
            break
        }
        Default {
            # ClientLocal
            $DateString = ($Date).ToString("$Script:TimeFormat")
            break
        }
    }
    $DateString -replace '\.', ':'
    #Write-Log -Message "End Get-SmallDateTime"
}


Function Get-DSRegCmd {
    # https://learn.microsoft.com/en-us/azure/active-directory/devices/troubleshoot-device-dsregcmd
    $ResultObject = New-Object -TypeName PSObject
    dsregcmd /status | 
        Select-String -Pattern '\s*(?<Key>[^:]+):\s*(?<Value>.*)' | 
        Select-Object -Property @{l = 'key'; Expression = { "$($_.Matches.groups.where({$_.Name -eq 'key'}).Value)".Trim() } },
                                @{l = 'value'; Expression = {
                                        $Value = "$($_.Matches.groups.where({$_.Name -eq 'value'}).Value)".Trim()
                                        Switch ($Value) {
                                            'Yes' { $true }
                                            'No' { $false }
                                            Default { $_ }
                                        }
                                    }
                                } |
        ForEach-Object {
            Add-Member -InputObject $ResultObject -MemberType NoteProperty -Name ($_.Key -replace ' ') -Value $_.Value -Force
        }

    Return $ResultObject
}


function Invoke-Executable {
    <#
.SYNOPSIS
    Fonction d'exécution d'une commande en mode synchrone avec ou sans arguments.

.DESCRIPTION
    Fonction d'exécution d'une commande en mode synchrone avec ou sans arguments retournant un objet contenant :
        - La commande
        - les arguments
        - le code de sortie
        - le flux de sortie standard
        - le flux d'erreur

    Les extensions supportées sont .ps1, .vbs, .wsf et .exe. Les autres type d'exécutables peuvent fonctionner mais n'ont pas été testés.

    Par défaut les scripts vbs et wsf sont lancés avec cscript.exe. Pour utiliser wscript.exe il faut utiliser cet exécutable et passer le script en argument.

.PARAMETER FilePath
    Chemin vers l'exécutable ou le script (sans arguments)

.PARAMETER ArgumentList
    Arguments utilisés par l'exécutable ou le script passé avec le paramètre Command

.PARAMETER WorkingDirectory
    Chemin à partir duquel l'exécutable ou le script va être lancé.

.PARAMETER Verb
    Verbe utilisé par le processus pour effectuer une action particulière.

    Par exemple, le verbe RunAs permet à certains exécutables de se lancer en tant qu'administrateur.

    Pour trouver la liste des verbes disponibles pour un exécutable, il faut utiliser les commandes ci-dessous :

        PS C:> $Psi = New-Object -TypeName System.Diagnostics.ProcessStartInfo
        PS C:> $psi.FileName = 'CHEMIN_VERS_L'EXECUTABLE'
        PS C:> $psi.Verbs

.PARAMETER WindowStyle
    Etat de la fenêtre hôte du processus au lancement de celui-ci
    Les différentes valeurs possibles sont :
        - Maximized (Agrandie)
        - Minimized (Réduite)
        - Normal
        - Hidden (Cachée)

.PARAMETER IgnoreExitCode
    Liste des codes de sortie du processus à ne pas considérer comme une erreur.

.EXAMPLE
    PS C:> Invoke-Executable -FilePath '\\serv\Test\Install.ps1' -ArgumentList '-NoLog','-NoTag' -WindowStyle Maximized

    Lance le script Install.ps1 avec les paramètres -NoLog et -NoTag. La fenêtre de l'hôte (Powershell.exe dans ce cas) sera agrandie au maximum.

.EXAMPLE
    PS C:> Invoke-Executable -FilePath 'wscript.exe' -ArgumentList 'C:\temp\script.wsf //job:Job1' -WindowStyle Minimized

.EXAMPLE
    PS C:> Invoke-Executable -FilePath 'msiexec' -ArgumentList '/x {00f1ede2-eafe-4c99-a114-c944c702ffa4} /qn' -IgnoreExitCode 0,3010,1605

.NOTES
    AUTHOR : Marc-Antoine ROBIN (Metsys)
    CREATION : 03/03/2017
    VERSION : 1.0
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
            HelpMessage = "Chemin vers l'exécutable ou le script (sans arguments)",
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('Command', 'FullName')]
        [String]$FilePath,

        [Parameter(Position = 1)]
        [AllowNull()]
        [Alias('Arguments')]
        [String[]]$ArgumentList,

        [Parameter(Position = 2)]
        [String]$WorkingDirectory,

        [Parameter(Position = 3)]
        [AllowNull()]
        [String]$Verb,

        [Parameter(Position = 4)]
        [ValidateSet('Maximized', 'Minimized', 'Normal', 'Hidden')]
        [string]$WindowStyle = 'Hidden',

        [Parameter(Position = 5)]
        [Int64[]]$IgnoreExitCode = @()
    )

    $FunctionName = $MyInvocation.MyCommand.Name
    Write-Verbose -Message "[$FunctionName] Début de fonction"
    Switch -Regex ($FilePath) {
        '\.ps1$' {
            $ArgumentList = "-NoLogo -NoProfile -WindowStyle $WindowStyle -Command $FilePath $($ArgumentList -join ' ')"
            $FilePath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
            break
        }
        '\.(vbs|wsf)$' {
            $ArgumentList = "//NoLogo $FilePath $($ArgumentList -join ' ')"
            If ($WindowStyle -eq 'Hidden') {
                $ArgumentList = "//B $ArgumentList"
            }
            $FilePath = 'cscript.exe'
            break
        }
        Default {
            $ArgumentList = $ArgumentList -join ' '
        }
    }
    Write-Verbose -Message "Command : $FilePath $ArgumentList [Working Directory : $WorkingDirectory]"

    $Psi = New-Object -TypeName System.Diagnostics.ProcessStartInfo
    $Psi.CreateNoWindow = $false
    $Psi.UseShellExecute = $false
    $Psi.RedirectStandardOutput = $true
    $Psi.RedirectStandardError = $true
    $Psi.FileName = $FilePath
    $psi.WindowStyle = $WindowStyle

    If (-not ($WorkingDirectory -notmatch '^\s*$')) { $Psi.WorkingDirectory = $WorkingDirectory }
    if ($null -ne $ArgumentList) { $Psi.Arguments = $ArgumentList }
    if (-not ($Verb -notmatch '^\s*$')) { $Psi.Verb = $Verb }

    # Création de l'objet processus
    $Process = New-Object -TypeName System.Diagnostics.Process
    $Process.StartInfo = $Psi

    # Création d'objets StringBuilder pour stocker la sortie standard et la sortie erreur
    $StdOutBuilder = New-Object -TypeName System.Text.StringBuilder
    $StdErrBuilder = New-Object -TypeName System.Text.StringBuilder

    # Ajout d'observateur d'évènements pour le changement des sorties standard et d'erreur
    $ScriptBlock = {
        if (-not ($EventArgs.Data -notmatch '^\s*$')) {
            $Event.MessageData.AppendLine($EventArgs.Data)
        }
    }
    $StdOutEvent = Register-ObjectEvent -InputObject $Process `
                                        -Action $ScriptBlock `
                                        -EventName 'OutputDataReceived' `
                                        -MessageData $StdOutBuilder

    $StdErrEvent = Register-ObjectEvent -InputObject $Process `
                                        -Action $ScriptBlock `
                                        -EventName 'ErrorDataReceived' `
                                        -MessageData $StdErrBuilder

    # Nettoyage de la mémoire pour éviter l'erreur 1073741502
    [gc]::Collect()
    # Démarrage du processus
    $null = $Process.Start()
    $Process.BeginOutputReadLine()
    $Process.BeginErrorReadLine()
    $null = $Process.WaitForExit()

    # Désinscription des évènements de récupération de la sortie standard et d'erreur
    Unregister-Event -SourceIdentifier $StdOutEvent.Name
    Unregister-Event -SourceIdentifier $StdErrEvent.Name
    
    If ($IgnoreExitCode -notcontains $Process.ExitCode) {
        # Si le code d'erreur ne se trouve pas dans la liste des codes d'erreurs à ignorer, 
        # on défini les variables ErrNumber et ErrMsg pour qu'elles soient utilisées par Write-Log
        $Script:ErrNumber = $Process.ExitCode
        $Script:ErrMsg = $StdErrBuilder.ToString().Trim()
    }

    New-Object -TypeName PSObject -Property @{
        FilePath     = $FilePath
        ArgumentList = $ArgumentList
        ExitCode     = $Process.ExitCode
        StdOut       = $StdOutBuilder.ToString().Trim()
        StdErr       = $StdErrBuilder.ToString().Trim()
    }
    Write-Verbose -Message "[$FunctionName] Fin de fonction"
}


function Measure-Latest {
    BEGIN { 
        $latest = $null 
    }
    PROCESS { 
        if (($null -ne $_) -and (($null -eq $latest) -or ($_ -gt $latest))) { 
            $latest = $_ 
        } 
    }
    END { 
        $latest 
    }
}


Function CleanUp {
    $clientpath = (Get-LocalFilesPath).ToLower()
    $forbidden = "$env:SystemDrive", "$env:SystemDrive\", "$env:SystemDrive\windows", "$env:SystemDrive\windows\"
    $NoDelete = $false
    foreach ($item in $forbidden) { if ($clientpath -like $item) { $NoDelete = $true } }

    if (((Test-Path -Path "$clientpath\Temp" -ErrorAction SilentlyContinue) -eq $True) -and ($NoDelete -eq $false) ) {
        $null = Remove-Item "$clientpath\Temp" -Recurse -Force
        Write-Log -Message "Cleaning up temporary files in $clientpath\ClientHealth"
    }

    $LocalLogging = ((Get-XMLConfigLoggingLocalFile).ToString()).ToLower()
    if (($LocalLogging -ne "true") -and ($NoDelete -eq $false)) {
        $null = Remove-Item "$clientpath\Temp" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Local logging disabled. Removing $clientpath\ClientHealth"
    }
}


function Register-DLLFile {
    [CmdletBinding()]
    param ([string[]]$FilePath)
 
    # https://devblogs.microsoft.com/oldnewthing/20180920-00/?p=99785
    Foreach ($Path in $FilePath) {
        $DLLSplat = @{
            FilePath     = 'regsvr32.exe' 
            ArgumentList = "/s `"$Path`"" 
        }
        $Process = Invoke-Executable @DLLSplat
        Switch ($Process.ExitCode) {
            0 {$ErrMessage = 'Success'}
            1 {$ErrMessage = 'Error parsing command line'}
            2 {$ErrMessage = 'OleInitialize failed'}
            3 {$ErrMessage = 'LoadLibrary failed'}
            4 {$ErrMessage = 'GetProcAddress failed'}
            5 {$ErrMessage = 'Registration function failed'}

        }
        Write-Log -Message "Register DLL '$Path' [$ErrMessage]"
    }
}


Function Test-DNSConfiguration {
    Param([Parameter(Mandatory = $true)]$Log)
    #$dnsdomain = (Get-WMIClassInstance -Class Win32_NetworkAdapterConfiguration -filter "ipenabled = 'true'").DNSDomain
    $fqdn = [System.Net.Dns]::GetHostEntry("localhost").HostName
    $localIPs = Get-WMIClassInstance -Class Win32_NetworkAdapterConfiguration | 
                    Where-Object { $_.IPEnabled -Match "True" } | 
                    Select-Object -ExpandProperty IPAddress
    $dnscheck = [System.Net.DNS]::GetHostByName($fqdn)

    $OSName = Get-OperatingSystemFullName
    if (($OSName -notmatch 'Windows 7|Server 2008')) {
        # This method is supported on Windows 8 / Server 2012 and higher. More acurate than using .NET object method
        try {
            $ActiveAdapters = (Get-NetAdapter | Where-Object { $_.Status -like "Up" }).Name
            $dnsServers = Get-DnsClientServerAddress | Where-Object { $ActiveAdapters -contains $_.InterfaceAlias } | Where-Object { $_.AddressFamily -eq 2 } | Select-Object -ExpandProperty ServerAddresses
            $dnsAddressList = Resolve-DnsName -Name $fqdn -Server ($dnsServers | Select-Object -First 1) -Type A -DnsOnly | Select-Object -ExpandProperty IPAddress
        }
        catch {
            $Error.RemoveAt(0)
            # Fallback to depreciated method
            $dnsAddressList = $dnscheck.AddressList | Select-Object -ExpandProperty IPAddressToString
            $dnsAddressList = $dnsAddressList -replace ("%(.*)", "")
        }
    }

    else {
        # This method cannot guarantee to only resolve against DNS sever. Local cache can be used in some circumstances.
        # For Windows 7 only

        $dnsAddressList = $dnscheck.AddressList | Select-Object -ExpandProperty IPAddressToString
        $dnsAddressList = $dnsAddressList -replace ("%(.*)", "")
    }

    $dnsFail = ''
    $logFail = ''

    Write-Log 'Verify that local machines FQDN matches DNS'
    if ($dnscheck.HostName -like $fqdn) {
        $obj = $true
        Write-Log 'Checking if one local IP matches on IP from DNS'
        Write-Log 'Loop through each IP address published in DNS'
        foreach ($dnsIP in $dnsAddressList) {
            #Write-Log -Message "Testing if IP address: $dnsIP published in DNS exist in local IP configuration."
            ##if ($dnsIP -notin $localIPs) { ## Requires PowerShell 3. Works fine :(
            if ($localIPs -notcontains $dnsIP) {
                $dnsFail += "IP '$dnsIP' in DNS record do not exist locally`n"
                $logFail += "$dnsIP "
                $obj = $false
            }
        }
    }
    else {
        $hn = $dnscheck.HostName
        $dnsFail = 'DNS name: ' + $hn + ' local fqdn: ' + $fqdn + ' DNS IPs: ' + $dnsAddressList + ' Local IPs: ' + $localIPs
        $obj = $false
        Write-Log -Message $dnsFail
    }

    #$FileLogLevel = ((Get-XMLConfigLoggingLevel).ToString()).ToLower()

    switch ($obj) {
        $false {
            $fix = (Get-XMLConfigDNSFix).ToLower()
            if ($fix -eq "true") {
                if ($PowerShellVersion -ge 4) { $null = Register-DnsClient }
                else { $null = ipconfig /registerdns }
                Write-Log -Message 'DNS Check: FAILED. IP address published in DNS do not match IP address on local machine. Trying to resolve by registerting with DNS server' -Type 'WARNING'
                $log.DNS = 'Repaired'
<#                 if (-NOT($FileLogLevel -like "clientlocal")) {
                    Out-LogFile -Xml $xml -Text $text -Severity 2
                    Out-LogFile -Xml $xml -Text $dnsFail -Severity 2
                } #>
            }
            else {
                $log.DNS = 'Skipped'
                #if (-NOT($FileLogLevel -like "clientlocal")) { Out-LogFile -Xml $xml -Text $text  -Severity 2 }
                Write-Log -Message 'DNS Check: FAILED. IP address published in DNS do not match IP address on local machine. Monitor mode only, no remediation' -Type 'WARNING'
            }

        }
        $true {
            Write-Log -Message 'DNS Check: OK'
            $log.DNS = 'Compliant'
        }
    }
    #Return $obj
}
#endregion misc

#endregion Functions