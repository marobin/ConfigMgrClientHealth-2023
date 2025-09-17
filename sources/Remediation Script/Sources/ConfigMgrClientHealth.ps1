<#
.SYNOPSIS
    ConfigMgr Client Health is a tool that validates and automatically fixes errors on Windows computers managed by Microsoft Configuration Manager.
.EXAMPLE
   .\ConfigMgrClientHealth.ps1 -Config .\Config.Xml
.EXAMPLE
    \\cm01.rodland.lab\ClientHealth$\ConfigMgrClientHealth.ps1 -Config \\cm01.rodland.lab\ClientHealth$\Config.Xml -Webservice https://cm01.rodland.lab/ConfigMgrClientHealth
.PARAMETER Config
    A single parameter specifying the path to the configuration XML file.
.PARAMETER Webservice
    A single parameter specifying the URI to the ConfigMgr Client Health Webservice.
.DESCRIPTION
    ConfigMgr Client Health detects and fixes following errors:
        * ConfigMgr client is not installed.
        * ConfigMgr client is assigned the correct site code.
        * ConfigMgr client is upgraded to current version if not at specified minimum version.
        * ConfigMgr client not able to forward state messages to management point.
        * ConfigMgr client stuck in provisioning mode.
        * ConfigMgr client maximum log file size.
        * ConfigMgr client cache size.
        * Corrupt WMI.
        * Services for ConfigMgr client is not running or disabled.
        * Other services can be specified to start and run and specific state.
        * Hardware inventory is running at correct schedule
        * Group Policy failes to update registry.pol
        * Pending reboot blocking updates from installing
        * ConfigMgr Client Update Handler is working correctly with registry.pol
        * Windows Update Agent not working correctly, causing client not to receive patches.
        * Windows Update Agent missing patches that fixes known bugs.
        * EntraID or Intune enrollment misconfiguration
        * Comanagement issues
        * Metered network connection

.NOTES
    You should run this with at least local administrator rights. It is recommended to run this script under the SYSTEM context.

    DO NOT GIVE USERS WRITE ACCESS TO THIS FILE. LOCK IT DOWN !

    Author: Anders Rødland
    Blog: https://www.andersrodland.com
    Twitter: @AndersRodland
.LINK
    Full documentation: https://www.andersrodland.com/configmgr-client-health/

    Related documentations :
        https://damgoodadmin.com/2018/11/01/how-i-learned-to-love-the-client-health-script/

#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(HelpMessage = 'Path to XML Configuration File')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [ValidatePattern('\.xml$')]
    [string]$Config,

    [Parameter(HelpMessage = 'URI to ConfigMgr Client Health Webservice')]
    [string]$Webservice,

    [Parameter(Mandatory = $false)]
    [String]$TaskPath = '\',

    [Parameter(Mandatory = $true)]
    [String]$taskName = 'ConfigMgr Client Health Remediation Script',

    [Parameter(Mandatory = $true)]
    [String]$LogFolder = "$Env:ProgramData\ConfigMgrClientHealth\Logs",

    [Switch]$Force
)

#region INIT
# ConfigMgr Client Health Version
$Version = '2.4.0'
$PowerShellVersion = [int]$PSVersionTable.PSVersion.Major
$ScriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
. "$ScriptPath\ConfigMgrClientHealth-Functions.ps1"

$TaskPath = "$TaskPath\" -replace '\\+','\'
#$LogFolder = Get-LocalFilesPath

if (! (Test-Path -Path $LogFolder)) {
    $null = New-Item -Path $LogFolder -ItemType Directory -Force -Verbose
}
# Variable used in the Write-Log function
$ClientHealthLogFile = "$LogFolder\ClientHealth_$(Get-Date -Format 'dd-MM-yyyy').log"  # _$(Get-Date -Format 'ddMMyyyy-HHmmss')

Backup-ClientHealthLog # zip and remove old logs to keep log folder clean

Write-Log -Message ('=' * 80)

Write-Log -Message "Script version: $Version"
Write-Log -Message "PowerShell version: $PowerShellVersion"

#If no config file was passed in, use the default.
if ((!$PSBoundParameters.ContainsKey('Config')) -and (!$PSBoundParameters.ContainsKey('Webservice'))) {
    $Config = Join-Path -Path ($Script:ScriptPath) -ChildPath 'Config.xml'
    Write-Log -Message "No config provided, defaulting to $Config" -Type 'WARNING'
}

# Read configuration from XML file
if ("$config" -ne '') {
    if (! (Test-Path -Path $Config)) {
        Write-Log -Message "Error, could not access $Config. Check file location and share/ntfs permissions. Did you misspell the name?" -Type 'ERROR'
        Write-Log -Message ('=' * 80)
        exit 1
    }

    # Load XML file into variable
    try { $Xml = [xml]((Get-Content -Path $Config)) }
    catch {
        Write-Log -Message "Error, could not read $Config. Check file location and share/ntfs permissions. Is XML config file damaged?" -Type 'ERROR'
        Write-Log -Message ('=' * 80)
        exit 1
    }

}

# Variable used in the Write-Log function
Write-Log -Message ('=' * 80)

$TimeFormat = 'yyyy-MM-dd HH:mm:ss' # Time format used throughout the script
$SMSClientSplat = @{
    Namespace = 'root\ccm'
    Class     = 'SMS_Client'
}

$ClientHealthTaskName = $TaskName.Trim('\')
$CMRegKey = 'HKLM:\SOFTWARE\Microsoft\CCM'
$SCCMLoggingKey = "$CMRegKey\Logging\@GLOBAL"

<# # Installation validation => Don't install if not hybrid joined
$InstallationNeeded = Test-InstallationNeeded
If ($InstallationNeeded -eq $false) {
    #Remove the scheduled task
    Remove-ScheduledTask -TaskPath $TaskPath -TaskName "$ClientHealthTaskName*"
    Write-Log -Message ('=' * 80)
    Exit 1
}
 #>
$WMIOperatingSystem = Get-OperatingSystem
$WMIComputerSystem = Get-ComputerSystem
$ComputerDomainFromReg = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'Domain').Domain
Write-Log -Message 'Querying Win32_OperatingSystem and Win32_ComputerSystem'

$WindowBuildHash = @{
    # Windows 10
    '10240' = '1507'
    '10586' = '1511'
    '14393' = '1607'
    '15063' = '1703'
    '16299' = '1709'
    '17134' = '1803'
    '17763' = '1809'
    '18362' = '1903'
    '18363' = '1909'
    '19041' = '2004'
    '19042' = '20H2'
    '19043' = '21H1'
    '19044' = '21H2'
    '19045' = '22H2'
    # Windows 11
    '22000' = '21H2'
    '22621' = '22H2'
    '22631' = '23H2'
    '26100' = '24H2'
}

# Import Modules
# Import BitsTransfer Module (Does not work on PowerShell Core (6), disable check if module fails to import.)
$BitsCheckEnabled = $false
if (Get-Module -ListAvailable -Name BitsTransfer) {
    try {
        Import-Module -Name BitsTransfer -ErrorAction stop
        $BitsCheckEnabled = $true
    }
    catch {
        $Error.RemoveAt(0)
        $BitsCheckEnabled = $false
    }
}
$Error.Clear()

# Set default restart values to false
$newinstall = $false
$restartCCMExec = $false
$Reinstall = $false

# If config.xml is used
if ($Config) {
    # Build the ConfigMgr Client Install Property string
    $propertyString = $Xml.Configuration.ClientInstallProperty -join ' '
    # Get the current MP list to compare against the MP list specified in the configuration file
    [String[]]$ConfigMPList = $(
        $Xml.Configuration.ClientInstallProperty |
            Select-String -Pattern 'SMSMP(LIST)*="*(?<MPList>[^" ]+)' |
            Select-Object @{Label = 'MPList'; Expression = { $_.Matches.Groups.where({ $_.Name -eq 'MPLIST' }).Value -replace 'https*://' -split ';' } }
        ) |
            Select-Object -ExpandProperty MPList |
            ForEach-Object { "$_".ToLower() } |
            Select-Object -Unique

    $clientCacheSize = Get-XMLConfigClientCache
    #replace to account for multiple skipreqs and escape the character
    $clientInstallProperties = $propertyString -replace '%CHInstallPath%',"$ScriptPath"
    $clientAutoUpgrade = (Get-XMLConfigClientAutoUpgrade).ToLower()
    $AdminShare = Get-XMLConfigRemediationAdminShare
    $ClientProvisioningMode = Get-XMLConfigRemediationClientProvisioningMode
    $ClientStateMessages = Get-XMLConfigRemediationClientStateMessages
    $ClientWUAHandler = Get-XMLConfigRemediationClientWUAHandler
    $LogShare = Get-XMLConfigLoggingShare
    [String[]]$ClientDomain = (Get-XMLConfigClientDomain) -split ';' -replace '\s+'
}

# Create a DataTable to store all changes to log files to be processed later. This to prevent false positives to remediate the next time script runs if error is already remediated.
$SCCMLogJobs = New-Object System.Data.DataTable
[Void]$SCCMLogJobs.Columns.Add('File')
[Void]$SCCMLogJobs.Columns.Add('Text')

#endregion INIT

#region MAIN
Write-Log -Message 'Starting precheck. Determing if script will run or not.'
# Veriy script is running with administrative priveleges.
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Write-Log -Message 'ERROR: Powershell not running as Administrator! Client Health aborting.' -Type 'ERROR'
    Write-Log -Message ('=' * 80)
    exit 1
}
else {
    # Will exit with errorcode 2 if in task sequence
    Test-InTaskSequence

    $StartupText1 = 'PowerShell version: ' + $PSVersionTable.PSVersion + '. Script executing with Administrator rights.'
    Write-Log -Message $StartupText1

    Write-Log -Message 'Determing if a task sequence is running.'
    try { $tsenv = New-Object -ComObject Microsoft.SMS.TSEnvironment }
    catch {
        $Error.RemoveAt(0)
        $tsenv = $null
    }

    if ($null -ne $tsenv) {
        $TSName = $tsenv.Value('_SMSTSAdvertID')
        Write-Log -Message "Task sequence '$TSName' is currently running. ConfigMgr Client Health remediation script will not execute."
        Write-Log -Message ('=' * 80)
        exit 1
    }
    else {
        $StartupText2 = 'ConfigMgr Client Health ' + $Version + ' starting.'
        Write-Log -Message $StartupText2
    }
}

$CCMLogDir = Get-CCMLogDirectory
# If config.xml is used
$LocalLogging = ((Get-XMLConfigLoggingLocalFile).ToString()).ToLower()
$FileLogging = ((Get-XMLConfigLoggingEnable).ToString()).ToLower()
$FileLogLevel = ((Get-XMLConfigLoggingLevel).ToString()).ToLower()
$SQLLogging = ((Get-XMLConfigSQLLoggingEnable).ToString()).ToLower()


$CHRegKey = 'HKLM:\Software\ConfigMgrClientHealth'
$LastRunRegistryValueName = 'LastRun'
$ForceExecRegistryValueName = 'ForceExecution'

#Get the last run from the registry, defaulting to the minimum date value if the script has never ran.
$LastRun = [datetime]::MinValue
if (Test-Path -Path $CHRegKey) {
    try {
        [datetime]$LastRun = Get-RegistryValue -Path $CHRegKey -Name $LastRunRegistryValueName
    }
    catch {
        $Error.RemoveAt(0)
    }

    try {
        [Bool]$ForceExecution = (Get-RegistryValue -Path $CHRegKey -Name $ForceExecRegistryValueName) -eq 'True'
    }
    catch {
        $Error.RemoveAt(0)
        $ForceExecution = $false
    }
}
Write-Log -Message "Script last ran: $($LastRun)"

if (($ForceExecution -eq $false) -and ($Force.IsPresent -eq $false)) {
    # Execute the script only if the next run schedule is set in the config and has been reached
    $ExecutionScheduleEnabled = (Get-XMLConfigExecutionScheduleEnabled) -eq 'True'
    $ExecutionSchedule = Get-XMLConfigExecutionSchedule
    if (($ExecutionScheduleEnabled -eq $true) -and ($ExecutionSchedule -match '^(?<Interval>\d+)(?<IntervalType>[hdwm])$')) {
        $Interval = [uint16]$Matches['Interval']
        switch ($Matches['IntervalType']) {
            'h' {
                $NextRun = $LastRun.AddHours($Interval)
            }
            'd' {
                $NextRun = $LastRun.AddDays($Interval).Date
            }
            'w' {
                $NextRun = $LastRun.AddDays(($Interval * 7)).Date
            }
            'm' {
                $NextRun = $LastRun.AddMonths($Interval).Date
            }
        }
    }
    else {
        $NextRun = [datetime]::MinValue
    }

    if (($NextRun -ne [datetime]::MinValue) -and ($NextRun -gt (Get-Date))) {
        Write-Log -Message "The script last ran on $($LastRun.ToString('s').Replace('T',' ')), next run will happen after $($NextRun.ToString('yyyy-MM-dd'))" -Type 'WARNING'
        Write-Log -Message ('=' * 80)
        exit 0
    }
    elseif (($LastRun -ne [datetime]::MinValue) -and ($null -ne $WMIOperatingSystem.LastBootUpTime) -and ($LastRun -gt $WMIOperatingSystem.LastBootUpTime)) {
        Write-Log -Message "Computer hasn't been rebooted since the script last ran: $($LastRun.ToString('s').Replace('T',' ')) (Reboot : $($WMIOperatingSystem.LastBootUpTime.ToString('s').Replace('T',' ')))" -Type 'WARNING'
        Write-Log -Message ('=' * 80)
        exit 3010
    }
}
else {
    Write-Log -Message 'Force switch was used, ignoring last run checks' -Type 'WARNING'
}

if ($ClientDomain -notcontains $ComputerDomainFromReg) {
    #Remove the scheduled task
    Write-Log -Message "Computer domain '$ComputerDomainFromReg' does not match configuration ($($ClientDomain -join ', '))" -Type 'WARNING'
    Remove-ScheduledTask -TaskPath $TaskPath -TaskName "$ClientHealthTaskName*"
    Write-Log -Message ('=' * 80)
    exit 1
}

#Write-Log -Message "Testing if log files are bigger than max history for logfiles."
#Test-ConfigMgrHealthLogging

# Create the log object containing the result of health check
$Log = New-LogObject

# Only test this if not using webservice
if (("$Webservice".Trim() -eq '') -and $config) {
    Write-Log -Message 'Testing SQL Server connection'
    if (($SQLLogging -like 'true') -and ((Test-SQLConnection) -eq $false)) {
        # Failed to create SQL connection. Logging this error to fileshare and aborting script.
        #Exit 1
    }
}


Write-Verbose -Message 'Validating WMI is not corrupt...'
$WMI = Get-XMLConfigWMI
if ($WMI -like 'True') {
    Write-Log -Message 'Checking if WMI is corrupt. Will reinstall configmgr client if WMI is rebuilt.'
    if ((Test-WMI -log $Log) -eq $true) {
        $reinstall = $true
        New-ClientInstalledReason -Log $Log -Message 'Corrupt WMI.'
        $WMIOperatingSystem = Get-OperatingSystem
        $WMIComputerSystem = Get-ComputerSystem
        Write-Log -Message 'Querying Win32_OperatingSystem and Win32_ComputerSystem again'
        $Result = Resolve-Client -Xml $xml -ClientInstallProperties $ClientInstallProperties -Uninstall $true
        Write-Log -Message "Installed CMClient ($Result)"
        if ($Result -eq $true) { $Reinstall -eq $false }
    }
}

Test-ClientAuthCert -Log $Log

Write-Log -Message 'Testing if ConfigMgr client is installed. Installing if not.'
Test-ConfigMgrClient -Log $Log

Write-Log -Message 'Checking if current MP list matches at least one in the configuration file.'
[String[]]$CurrentMPList = Get-MPList
if (($CurrentMPList.Count -gt 0)) {
    $Compare = Compare-Object -ReferenceObject $CurrentMPList -DifferenceObject $ConfigMPList -IncludeEqual | Where-Object { $_.SideIndicator -eq '==' }
    if ($null -eq $Compare) {
        Write-Log -Message ('Found {0} current MP ({1}) but none matches the configuration ({2}). Reparing the client' -f $CurrentMPList.Count, ($CurrentMPList -join ', '), ($ConfigMPList -join ', ')) -Type WARNING
        New-ClientInstalledReason -Log $Log -Message 'MPList mismatch'
        $Result = Resolve-Client -Xml $xml -ClientInstallProperties $ClientInstallProperties -Uninstall $true
        Write-Log -Message "Installed CMClient ($Result)"
        if ($Result -eq $true) { $Reinstall -eq $false }
    }
    else {
        Write-Log -Message ('Found {0} current MP ({1}) and at least one matches the configuration ({2})' -f $CurrentMPList.Count, ($CurrentMPList -join ', '), ($ConfigMPList -join ', '))
    }
}
else {
    Write-Log -Message 'Could not find the current MP list' -Type WARNING
}


Write-Verbose -Message 'Determining if compliance state should be resent...'
$RefreshComplianceState = Get-XMLConfigRefreshComplianceState
if ( ($RefreshComplianceState -like 'True') -or ($RefreshComplianceState -ge 1)) {
    $RefreshComplianceStateDays = Get-XMLConfigRefreshComplianceStateDays

    Write-Log -Message "Checking if compliance state should be resent after $($RefreshComplianceStateDays) days."
    Test-RefreshComplianceState -Days $RefreshComplianceStateDays -RegistryKey $CHRegKey -log $Log
}


Write-Log -Message 'Validating if ConfigMgr client is running the minimum version...'
if ((Test-ClientVersion -Log $log) -eq $true) {
    if ($clientAutoUpgrade -like 'true') {
        $reinstall = $true
        New-ClientInstalledReason -Log $Log -Message 'Below minimum verison.'
    }
}

<#
Write-Log -Message 'Validate that ConfigMgr client do not have CcmSQLCE.log and are not in debug mode'
if (Test-CcmSQLCELog -eq $true) {
    # This is a very bad situation. ConfigMgr agent is fubar. Local SDF files are deleted by the test itself, now reinstalling client immediatly. Waiting 10 minutes before continuing with health check.
    Resolve-Client -Xml $xml -ClientInstallProperties $ClientInstallProperties -Uninstall $true
    Start-Sleep -Seconds 600
}
#>

Write-Log -Message 'Validating services...'
Test-ServiceList -Xml $Xml -log $log

Write-Log -Message 'Validating SMSTSMgr service is dependent on CCMExec service...'
Test-SMSTSMgr

Write-Log -Message 'Validating ConfigMgr SiteCode...'
Test-ClientSiteCode -Log $Log

Write-Log -Message 'Validating client cache size. Will restart configmgr client if cache size is changed'

$CacheCheckEnabled = Get-XMLConfigClientCacheEnable
if ($CacheCheckEnabled -like 'True') {
    $TestClientCacheSzie = Test-ClientCacheSize -Log $Log
    # This check is now able to set ClientCacheSize without restarting CCMExec service.
    if ($TestClientCacheSzie -eq $true) { $restartCCMExec = $false }
}


if ((Get-XMLConfigClientMaxLogSizeEnabled -like 'True') -eq $true) {
    Write-Log -Message 'Validating Max CCMClient Log Size...'
    $TestClientLogSize = Test-ClientLogSize -Log $Log
    if ($TestClientLogSize -eq $true) { $restartCCMExec = $true }
}

Write-Log -Message 'Validating CCMClient provisioning mode...'
if (($ClientProvisioningMode -like 'True') -eq $true) { Test-ProvisioningMode -log $log }
Write-Log -Message 'Validating CCMClient certificate...'

if ((Get-XMLConfigRemediationSMSCertificate -like 'True') -eq $true) { Test-CCMCertificateError -Log $Log }
if (Get-XMLConfigHardwareInventoryEnable -like 'True') { Test-SCCMHardwareInventoryScan -Log $log }


if (Get-XMLConfigSoftwareMeteringEnable -like 'True') {
    Write-Log -Message 'Testing software metering prep driver check'
    if ((Test-SoftwareMeteringPrepDriver -Log $Log) -eq $false) { $restartCCMExec = $true }
}

Write-Log -Message 'Validating DNS...'
if ((Get-XMLConfigDNSCheck -like 'True' ) -eq $true) { Test-DNSConfiguration -Log $log }

Write-Log -Message 'Validating BITS'
if (Get-XMLConfigBITSCheck -like 'True') {
    if ((Test-BITS -Log $Log) -eq $true) {
        #$Reinstall = $true
    }
}

Write-Log -Message 'Validating ClientSettings'
if (Get-XMLConfigClientSettingsCheck -like 'True') {
    Test-ClientSettingsConfiguration -Log $log
}

if (($ClientWUAHandler -like 'True') -eq $true) {
    Write-Log -Message 'Validating Windows Update Scan not broken by bad group policy...'
    $days = Get-XMLConfigRemediationClientWUAHandlerDays
    Test-RegistryPol -Days $days -log $log -StartTime $LastRun
}


if (($ClientStateMessages -like 'True') -eq $true) {
    Write-Log -Message 'Validating that CCMClient is sending state messages...'
    Test-StateMessage -log $log
}

Write-Log -Message 'Validating Admin$ and C$ are shared...'
if (($AdminShare -like 'True') -eq $true) { Test-AdminShare -log $log }

Write-Log -Message 'Testing that all devices have functional drivers.'
if ((Get-XMLConfigDrivers -like 'True') -eq $true) { Test-MissingDrivers -Log $log }

$UpdatesEnabled = Get-XMLConfigUpdatesEnable
if ($UpdatesEnabled -like 'True') {
    Write-Log -Message 'Validating required updates are installed...'
    Test-Update -Log $log
}

Write-Log -Message "Validating $env:SystemDrive free diskspace (Only warning, no remediation)..."
Test-DiskSpace
Write-Log -Message 'Getting install date of last OS patch for SQL log'
Get-LastInstalledPatches -Log $log
Write-Log -Message 'Sending unsent state messages if any'
Invoke-SCCMClientAction -ClientAction 'Send Unsent State Message'
Write-Log -Message 'Getting Source Update Message policy and policy to trigger scan update source'

if ($newinstall -eq $false) {
    Invoke-SCCMClientAction -ClientAction 'Source Update Message'
    Invoke-SCCMClientAction -ClientAction 'Scan by Update Source'
    Invoke-SCCMClientAction -ClientAction 'Send Unsent State Message'
}
Invoke-SCCMClientAction -ClientAction 'Machine Policy Evaluation'

# Restart ConfigMgr client if tagged for restart and no reinstall tag
if (($restartCCMExec -eq $true) -and ($Reinstall -eq $false)) {
    Write-Log -Message 'Restarting service CcmExec...'

    if ($SCCMLogJobs.Rows.Count -ge 1) {
        Stop-Service -Name CcmExec
        Write-Log -Message 'Processing changes to SCCM logfiles after remediation to prevent remediation again next time script runs.'
        Update-SCCMLogFile
        Start-Service -Name CcmExec
    }
    else { Restart-Service -Name CcmExec -Force }
    Write-Log -Message 'Restarted ccmexec service'

    $Log.MaxLogSize = Get-ClientMaxLogSize
    $Log.MaxLogHistory = Get-ClientMaxLogHistory
    $log.CacheSize = Get-ClientCache
}

# Updating SQL Log object with current version number
$log.Version = $Version

Write-Log -Message 'Cleaning up after healthcheck'
#CleanUp
Write-Log -Message 'Validating pending reboot...'
Test-PendingReboot -log $log
Write-Log -Message 'Getting last reboot time'
Get-LastReboot -Xml $xml

if (Get-XMLConfigClientCacheDeleteOrphanedData -like 'true') {
    Write-Log -Message 'Removing orphaned ccm client cache items.'
    Remove-CCMOrphanedCache
}

# Reinstall client if tagged for reinstall and configmgr client is not already installing
$proc = Get-Process -Name 'ccmsetup' -ErrorAction Ignore

if (($reinstall -eq $true) -and ($null -ne $proc) ) { Write-Log -Message 'ConfigMgr Client set to reinstall, but ccmsetup.exe is already running.' -Type 'WARNING' }
elseif (($Reinstall -eq $true) -and ($null -eq $proc)) {
    # Avoid executing client installation if done already earlier in the script (See Test-ConfigMgrClient)
    if ("$($log.ClientInstalled)" -eq '') {
        Write-Log -Message 'Reinstalling ConfigMgr Client'
        $InstallResult = Resolve-Client -Xml $Xml -ClientInstallProperties $ClientInstallProperties -Uninstall $false
        # Add smalldate timestamp in SQL for when client was installed by Client Health.
        if ($InstallResult -ne $false) {
            $log.ClientInstalled = Get-SmallDateTime
        }
    }
    else {
        Write-Log -Message "Client was installed ealier, no need to run the installation again : $($log.ClientInstalled)" -Type 'WARNING'
    }
    $Log.MaxLogSize = Get-ClientMaxLogSize
    $Log.MaxLogHistory = Get-ClientMaxLogHistory
    $log.CacheSize = Get-ClientCache

    # Verify that installed client version is now equal or better that minimum required client version
    $NewClientVersion = Get-ClientVersion
    $MinimumClientVersion = Get-XMLConfigClientVersion

    if ( ([version]$NewClientVersion) -lt ([version]$MinimumClientVersion)) {
        # ConfigMgr client version is still not at expected level.
        # Log for now, remediation is comming
        $Log.ClientInstalledReason += ' Upgrade failed.'
    }
}

Write-Log -Message 'Testing if the network connection is metered (could block all client communications after first install)'
Test-NetConnectionMetered

# Test and remediate the EntraID and Intune enrollments
Test-EntraIDEnrollment
Test-CoMgmtStatus

# Get the latest client version in case it was reinstalled by the script
$log.ClientVersion = Get-ClientVersion

# Trigger default Microsoft CM client health evaluation
Start-Ccmeval
Write-Log -Message 'End Process'
#endregion MAIN


#region END
Invoke-SCCMClientAction -ClientAction 'Data Discovery Record'
Write-Log -Message 'Send Data Discovery Record to server'

# Update database and logfile with results

#Set the last run.
$Date = Get-Date
Set-RegistryValue -Path $CHRegKey -Name $LastRunRegistryValueName -Value $Date
Write-Log -Message "Setting last ran to $($Date)"

if ($LocalLogging -like 'true') {
    Update-LogFile -Log $log -Mode 'Local'
    Write-Log -Message 'Updating local logfile with results'
}
<#
if (($FileLogging -like 'true') -and ($FileLogLevel -like 'full')) {
    Update-LogFile -Log $log
    Write-Log -Message 'Updating fileshare logfile with results'
} #>

if (($SQLLogging -eq 'true') -and -not $PSBoundParameters.ContainsKey('Webservice')) {
    Update-SQL -Log $log
    Write-Log -Message 'Updating SQL database with results'
}

if ($PSBoundParameters.ContainsKey('Webservice')) {
    Update-Webservice -URI $Webservice -Log $Log
    Write-Log -Message 'Updating SQL database with results using webservice'
}

# Disable the scheduled task once the client is healthy
if ((Test-IsClientHealthy) -and ((Get-XMLConfigDisableTaskWhenCompliant) -eq 'True')) {
    Disable-ScheduledTask -TaskPath $TaskPath -TaskName "$ClientHealthTaskName*"
    Write-Log -Message 'Client is healthy, disabling the scheduled task'
}

if ($ForceExecution -eq $true) {
    $null = New-ItemProperty -Path $CHRegKey -Name $ForceExecRegistryValueName -Value 'False' -PropertyType String -Force
    Write-Log -Message ('Reset the {0} value in {1}' -f $ForceExecRegistryValueName, $CHRegKey)
}

Write-Log -Message 'Client Health script finished'
#endregion END
