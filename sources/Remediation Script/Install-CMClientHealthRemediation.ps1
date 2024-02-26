<#
.SYNOPSIS
    Installation script for the Configuration Manager Client Health Remediation Script.
.DESCRIPTION
    Installation script for the Configuration Manager Client Health Remediation Script.

    This script can be used as a startup script in a GPO, as an Intune Win32App, or with any other deployment solution.
    
    The script will exit right away if the source folder, the scheduled task, and the registry key already exist.

    An installation log is created either on the web service server (\\WebSvcSrv\CMClientHealth\Logs) or locally (%TEMP%)

    The following variable needs to be filled out : 
        DomainTranslationTable : Domain translation table
            Name : Short description of the domain
            NetBIOS : Domain NetBIOS
            Domain : Domain FQDN
            WebSvcSrv : URI of the server hosting the ConfigMgrClientHealth web service
            Env : Name of the environment (i.g. Production/PreProduction/... )
    
    The following variables need to be filled out only if using a ConfigMgr exclusion collection
        https://learn.microsoft.com/en-us/mem/configmgr/develop/adminservice/usage
        SMSProvider : FQDN of the ConfigMgr server with the SMS Provider role
        SvcAccountName : Name of the service account with read only rights to the ConfigMgr database
        SvcAccountPassword : Password of the service account
        CollectionName : Name of the exclusion collection

    The server hosting the web service and the xml configuration file are chosen according to the computer's domain.

    Configuration Manager can then be queried to check whether the device belongs to the exclusion collection.

    The remediation script parameters are built using the webservice uri and the configuration file name.

    Read/write access to the source folder and the log folder is blocked for standard users.

    Finally, the scheduled task is registered.

.PARAMETER TaskName
    Name of the scheduled task which will be used to launch the remediation script.

.PARAMETER Source
    Folder containing the remediation script and its dependencies.

.PARAMETER Destination
    Installation path were the source files will be copied if not the same as the "Source" foldder.

.PARAMETER LogFolder
    Folder containing the logs.

.PARAMETER Force
    Bypass the exclusion test and force installation of the schedule task.

.NOTES
    AUTHOR : Marc-Antoine ROBIN
    VERSION : 2.0.0
    CREATION : 12/06/2023
    MODIFICATIONS :  
        - M-A. ROBIN (26/02/2024) : Added comments and reviewed the installation process
.EXAMPLE
    
#>


[CmdletBinding()]
Param (
    [String]$TaskName = "ConfigMgr Client Health Remediation Script",

    [String]$Source = "$Env:ProgramData\ConfigMgrClientHealth",
    
    [String]$Destination = "$Env:ProgramData\ConfigMgrClientHealth",

    [String]$LogFolder = "$Env:ProgramData\ConfigMgrClientHealth\Logs",

    [Switch]$Force
)

If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Throw 'Powershell not running in an elevated session'
    Exit 1
}

############################ Fill out the following variables ################################
# This hashtable collection can be used to restrict the installation to the specified domains
# The WebSvcSrv property is usualy the FQDN name of the IIS server where the web service is installed
# Management Points can be used to avoid setting up a dedicated server
$DomainTranslationTable = @(
    @{Name = 'Domain Name'; Netbios = 'NETBIOS'; Domain = 'domain.com'; WebSvcSrv = 'https://WebSvcSrv.domain.com'; Env = 'Prod' }
)


            ####### ONLY IF USING AN EXCLUSION COLLECTION (ConfigMgr) ########
$SMSProvider = '' # SMS Provider

# /!\ The service account used here is not the same as the service account used by the ConfigMgr Client Health web service /!\
# Use the credentials of an account which has read access only to the Configuration Manager site
$SvcAccountName = '' 
$SvcAccountPassword = ''


# Prevent the scheduled task from being installed on devices belonging to the following collection
$CollectionName = 'LDC CMClients SystemHealth RemediationExclusion'
##############################################################################################

$DateTimeFormat = 'yyyy-MM-dd HH:mm:ss.fff'
$CHRegKey = 'HKLM:\SOFTWARE\ConfigMgrClientHealth'
$ScriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition

Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - START"
If ((Test-Path -Path $Destination) -and (Test-Path -Path "$env:SystemRoot\System32\Tasks\$TaskName") -and (Test-Path -Path $CHRegKey)) {
    Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Already installed"
    # Already installed
    Exit 0
}
$Error.Clear()

#region WebService
# Get web service server from domain
$ComputerDomain = Get-WmiObject -Class Win32_ComputerSystem -Property Domain | Select-Object -ExpandProperty Domain
Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Computer domain : $ComputerDomain"

$TargetedDomain = $DomainTranslationTable.Where({ $_.Domain -eq $ComputerDomain })
If ($TargetedDomain.count -eq 1) {
    [String]$WebSvcSrv = $TargetedDomain.WebSvcSrv -replace 'https*://'
}
Else {
    Write-Warning -Message "$(Get-Date -Format $DateTimeFormat) - Domain not found"
    Exit 1
}

If ($WebSvcSrv -eq '') { Exit 1 }
#endregion WebService

$Date = Get-Date
$LogPath = "\\$WebSvcSrv\CMClientHealth\Logs"
$OutFileSplat = @{
    FilePath    = "$LogPath\$env:COMPUTERNAME.$($TargetedDomain.Domain).log" 
    Append      = $true
    Force       = $true
    ErrorAction = 'SilentlyContinue'
}
If (! (Test-Path -Path $LogPath -EA Ignore)) {
    $LogPath = "$env:TEMP"
    $OutFileSplat.FilePath = "$LogPath\ConfigMgrClientHealth-Install.log"
}
If (! (Test-Path -Path $Source)) {
    Write-Warning -Message "$(Get-Date -Format $DateTimeFormat) - Folder '$Source' does not exists"
    Exit 1
}

If ($Source -ne $Destination) {
    If (! (Test-Path -Path $Destination)) {
        $null = New-Item -Path $Destination -ItemType Directory -Force
    }
    Copy-Item -Path "$Source\*" -Destination $Destination -Force -Recurse
}
$DestinationSources = "$Destination\Sources"

$ClientFolder = "$DestinationSources\CMClient"
$TaskXmlName = "ConfigMgrClientHealth.xml"
$TaskXml = "$DestinationSources\Tasks\$TaskXmlName"
$WebService = "https://$WebSvcSrv/ConfigMgrClientHealth"
$Execute = "$PSHOME\powershell.exe"

Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Script path : $ScriptPath"
Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Log path : $LogPath"
Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Webservice : $WebService"
Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Web Service Server : $WebSvcSrv"
Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Environment : $($TargetedDomain.Env)"

#region Exclusion check
# Bypassing the collection exclusion check if one of the variables has no value
$BypassCheck = (Get-Variable -Name 'SMSProvider','SvcAccountName','SvcAccountPassword' -ValueOnly -ErrorAction Ignore | Where-Object {"$_" -ne ''} | Measure-Object).Count -lt 3
If (($Force.IsPresent -eq $false) -and ($BypassCheck -eq $false)) {
    Switch ($TargetedDomain.Env) {
        'Prod' {
            <#         $Searcher = [adsisearcher]"(&(objectcategory=computer)(CN=$env:COMPUTERNAME))"
            $SearchRoot = "DC=$ComputerDomain".Replace('.',',DC=')
            $Searcher.SearchRoot = "LDAP://$SearchRoot"
            $ComputerAccount = $Searcher.FindOne().properties
            $ComputerSID = New-Object System.Security.Principal.SecurityIdentifier($ComputerAccount.objectsid[0], 0) | Select-Object -ExpandProperty Value 
            #>
            $ComputerSID = [System.Security.Principal.NTAccount]::new("$env:COMPUTERNAME$").Translate([System.Security.Principal.SecurityIdentifier]).Value
            Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Computer SID : $ComputerSID"
            
            # Query the Configuration Manager administration service to check if the device belongs to the exclusion collection
            $CMAdminServiceURI = "https://$SMSProvider/adminService"
            $cmAdminserviceCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $SvcAccountName, (ConvertTo-SecureString -String $SvcAccountPassword -AsPlainText -Force)
            $URI = '{0}/wmi/SMS_R_System?$filter=SID eq ''{1}''&$select=ResourceId' -f $CMAdminServiceURI, $ComputerSID
            Try {
                $IRMResult = (Invoke-RestMethod -Uri $URI -Credential $cmAdminserviceCredentials -EA Stop).Value
            }
            Catch {
                Exit 1
            }
            If ($IRMResult.count -gt 0) {
                $ResourceId = $IRMResult.ResourceID
                Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Resource ID : $ResourceId"
                $URI = '{0}/v1.0/Device({1})/ResourceCollectionMembership?$expand=Collection&$select=Collection' -f $CMAdminServiceURI, $ResourceID
                $IRMResult = (Invoke-RestMethod -Uri $URI -Credential $cmAdminserviceCredentials).Value
                If (($IRMResult.count -gt 0) -and ($IRMResult.Collection.CollectionName -contains $CollectionName)) {
                    Exit 0
                }
            }
        }
        'PreProd' {
            # Aucune exclusion en pre production
        }
    }
}
#endregion Exclusion check

#region Configuration File
# Select the config file linked to the current domain using the "domain" attribute
<# 
<?xml version="1.0" encoding="utf-8"?>
<Configuration>
	<LocalFiles></LocalFiles>
	<Client Name="Version"></Client>
	<Client Name="SiteCode"></Client>
	<Client Name="Domain">######Specify a semi-colon separated list of domains here######</Client>
#>
$ConfigFile = Get-ChildItem -Path $DestinationSources -Filter 'config-*.xml' | 
Where-Object {
    ((([xml](Get-Content -Path $_.FullName -Raw)).Configuration.Client | 
        Where-Object { $_.Name -like 'Domain' } | 
        Select-Object -ExpandProperty InnerText
    ) -split ';') -contains $ComputerDomain
}
If ($null -eq $ConfigFile) {
    "$($Date.ToString('dd/MM/yyyy HH:mm:ss')) (UTC$UTCDateDiff) - [$ComputerDomain|$($TargetedDomain.Env)] $env:COMPUTERNAME - Web Service Server $($WebSvcSrv) : ERROR cannot find xml config file for the domain" | Out-File @OutFileSplat
    Exit 1
}
Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Configuration file : $ConfigFile"


# Scheduled task argument list
$ArgumentList = "-ExecutionPolicy Bypass -NoProfile -NoLogo -Command `".\ConfigMgrClientHealth.ps1 -WebService '$WebService' -Config '.\$($ConfigFile.Name)' -TaskName '$TaskName' -LogFolder '$LogFolder' -Verbose`""


# Modify the %CHInstallPath% in the config file using the script installation path
(Get-Content -Path $ConfigFile.FullName) -replace '%CHInstallPath%', $DestinationSources | Set-Content -Path $ConfigFile.FullName -Force
Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Replace variable 'CHInstallPath' in '$($ConfigFile.FullName)' with '$DestinationSources'"

[xml]$xml = Get-Content -Path "$TaskXml"
$xml.Task.Actions.Exec.Command = $Execute
$xml.Task.Actions.Exec.Arguments = $argumentList
$xml.Task.Actions.Exec.WorkingDirectory = $DestinationSources
$xml.Save($TaskXml)
Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Configured '$TaskXml'"
#endregion Configuration File

#region file system and registry
If (! (Test-Path -Path "$ClientFolder")) {
    $null = New-Item -Path "$ClientFolder" -ItemType Directory -Force
    Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Create folder '$ClientFolder'"
}
If (! (Test-Path -Path "$LogFolder")) {
    $null = New-Item -Path "$LogFolder" -ItemType Directory -Force
    Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Create folder '$LogFolder'"
}
If (! (Test-Path -Path "$CHRegKey")) {
    $null = New-Item -Path "$CHRegKey" -Force
    Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Create registry key '$CHRegKey'"
}

# Block read access for standard users
foreach ($folder in ($Destination, $LogFolder)) {
    $acl = Get-Acl -Path $folder
    # https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.objectsecurity.setaccessruleprotection?view=netframework-4.8
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetSecurityDescriptorSddlForm('D:PAI(A;OICIIO;FA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)', 'Access')
    Set-Acl -Path $folder -AclObject $acl
    Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Block read access for standard user on '$folder'"
}

#endregion file system and registry

# Register scheduled task
$ProcessSplat = @{
    FilePath     = 'schtasks.exe' 
    ArgumentList = "/Create /XML `"$TaskXml`" /TN `"$TaskName`" /F" 
    Wait         = $true
    PassThru     = $true
    WindowStyle  = 'Hidden'
}
$Process = Start-Process @ProcessSplat
Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Imported task '$TaskName' with exit code $($Process.ExitCode)"

[long]$ExitCode = $Process.ExitCode

If ($Error.Count -gt 0) {
    Write-Warning -Message "$($Error.Count) errors : `r`n$($Error.Exception.Message -join "`r`n")"
    $ExitCode += $Error.Count
}

$UTCDateDiff = "+$(($Date - $Date.ToUniversalTime()).TotalHours)" -replace '\+-', '-'
"$($Date.ToString('dd/MM/yyyy HH:mm:ss')) (UTC$UTCDateDiff) - [$ComputerDomain] $env:COMPUTERNAME ($ExitCode)" | Out-File @OutFileSplat

Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - END"

Exit $ExitCode