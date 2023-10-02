[CmdletBinding()]
Param (
    [String]$TaskName = "ConfigMgr Client Health Remediation Script",

    [String]$InstallFolder = "$Env:ProgramData\ConfigMgrClientHealth",

    [String]$LogFolder = "$Env:ProgramData\ConfigMgrClientHealth\Logs",

    [Switch]$Force
)

If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Throw 'Powershell not running as Administrator'
    Exit 1
}

$PrimaryServer = ''
$SvcAccountName = ''
$SvcAccountPassword = ''

$DateTimeFormat = 'yyyy-MM-dd HH:mm:ss.fff'
$CHRegKey = 'HKLM:\SOFTWARE\ConfigMgrClientHealth'
$Sources = "$InstallFolder\Sources"
$ScriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition

Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - START"
If ((Test-Path -Path $Sources) -and (Test-Path -Path "$env:SystemRoot\System32\Tasks\$TaskName") -and (Test-Path -Path $CHRegKey)) {
    Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Already installed"
    # Already installed
    Exit 0
}
$Error.Clear()

# Get management point from domain
$DomainTranslationTable = @(
    @{Name = 'Domain Name'; Netbios = 'NETBIOS'; Domain = 'domain.com'; MP = 'https://MP.domain.com'; Env = 'Prod'}
)
$ComputerDomain = Get-WmiObject -Class Win32_ComputerSystem -Property Domain | Select-Object -ExpandProperty Domain
Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Computer domain : $ComputerDomain"

$TargetedDomain = $DomainTranslationTable.Where({$_.Domain -eq $ComputerDomain})
If ($TargetedDomain.count -eq 1) {
    [String]$ManagementPoint = $TargetedDomain.MP -replace 'https*://'
}
Else {
    Write-Warning -Message "$(Get-Date -Format $DateTimeFormat) - Domain not found"
    Exit 1
}

If ($ManagementPoint -eq '') { Exit 1 }

$Date = Get-Date
$LogPath = "\\$ManagementPoint\CMClientHealth$\Logs"
$OutFileSplat = @{
    FilePath = "$LogPath\GPODeployment.log" 
    Append = $true
    Force = $true
    ErrorAction = 'SilentlyContinue'
}
If (! (Test-Path -Path $LogPath -EA Ignore)) {
    $LogPath = "$env:TEMP"
    $OutFileSplat.FilePath = "$LogPath\ConfigMgrClientHealth-Install.log"
}
If (! (Test-Path -Path $Sources)) {
    Write-Warning -Message "$(Get-Date -Format $DateTimeFormat) - Folder '$Sources' does not exists"
    Exit 1
}
$ClientFolder = "$Sources\CMClient"
$TaskXmlName = "ConfigMgrClientHealth.xml"
$TaskXml = "$Sources\Tasks\$TaskXmlName"
$WebService = "https://$ManagementPoint/ConfigMgrClientHealth"
$Execute = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$CollectionName = 'LDC CMClients SystemHealth RemediationExclusion'
Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Script path : $ScriptPath"
Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Log path : $LogPath"
Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Webservice : $WebService"
Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Management Point : $ManagementPoint"
Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Environment : $($TargetedDomain.Env)"

If ($Force.IsPresent -eq $false) {
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
    
            $CMAdminServiceURI = "https://$PrimaryServer/adminService"
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
                $URI = '{0}/v1.0/Device({1})/ResourceCollectionMembership?$expand=Collection&$select=Collection' -f $CMAdminServiceURI,$ResourceID
                $IRMResult = (Invoke-RestMethod -Uri $URI -Credential $cmAdminserviceCredentials).Value
                If (($IRMResult.count -gt 0) -and ($IRMResult.Collection.CollectionName -contains $CollectionName)) {
                    Exit 0
                }
            }
        }
        'HorsProd' {
            # Aucun test pour la hors prod
        }
    }
}

$ConfigFile = Get-ChildItem -Path $Sources -Filter 'config-*.xml' | 
                    Where-Object {
                        ((([xml](Get-Content -Path $_.FullName -Raw)).Configuration.Client | 
                            Where-Object { $_.Name -like 'Domain' } | 
                            Select-Object -ExpandProperty '#text'
                        ) -split ';') -contains $ComputerDomain
                    }
If ($null -eq $ConfigFile) {
    "$($Date.ToString('dd/MM/yyyy HH:mm:ss')) (UTC$UTCDateDiff) - [$ComputerDomain|$($TargetedDomain.Env)] $env:COMPUTERNAME - MP $($ManagementPoint) : ERROR cannot find xml config file for the domain" | Out-File @OutFileSplat
    Exit 1
}
Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Configuration file : $ConfigFile"
$ArgumentList = "-ExecutionPolicy Bypass -NoProfile -NoLogo -Command `".\ConfigMgrClientHealth.ps1 -WebService '$WebService' -Config '.\$($ConfigFile.Name)' -TaskName '$TaskName' -LogFolder '$LogFolder' -Verbose`""


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
foreach ($folder in ($InstallFolder, $LogFolder)) {
    $acl = Get-Acl -Path $folder
    # https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.objectsecurity.setaccessruleprotection?view=netframework-4.8
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetSecurityDescriptorSddlForm('D:PAI(A;OICIIO;FA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)','Access')
    Set-Acl -Path $folder -AclObject $acl
    Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Block read access for standard user on '$folder'"
}

(Get-Content -Path $ConfigFile.FullName) -replace '%CHInstallPath%', $Sources | Set-Content -Path $ConfigFile.FullName -Force
Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Replace variable 'CHInstallPath' in '$($ConfigFile.FullName)' with '$Sources'"

[xml]$xml = Get-Content -Path "$TaskXml"
$xml.Task.Actions.Exec.Command = $Execute
$xml.Task.Actions.Exec.Arguments = $argumentList
$xml.Task.Actions.Exec.WorkingDirectory = $Sources
$xml.Save($TaskXml)
Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Configured '$TaskXml'"

$ProcessSplat = @{
    FilePath = 'schtasks.exe' 
    ArgumentList = "/Create /XML `"$TaskXml`" /TN `"$TaskName`" /F" 
    Wait = $true
    PassThru = $true
    WindowStyle = 'Hidden'
}
$Process = Start-Process @ProcessSplat
Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - Imported task '$TaskName' with exit code $($Process.ExitCode)"

[long]$ExitCode = $Process.ExitCode

If ($Error.Count -gt 0) {
    Write-Warning -Message "$($Error.Count) errors : `r`n$($Error.Exception.Message -join "`r`n")"
    $ExitCode += $Error.Count
}

$UTCDateDiff = "+$(($Date - $Date.ToUniversalTime()).TotalHours)" -replace '\+-','-'
"$($Date.ToString('dd/MM/yyyy HH:mm:ss')) (UTC$UTCDateDiff) - [$ComputerDomain] $env:COMPUTERNAME ($ExitCode)" | Out-File @OutFileSplat

Write-Verbose -Message "$(Get-Date -Format $DateTimeFormat) - END"

Exit $ExitCode