[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)]
    [String]$Server,

    [Parameter()]
    [String[]]$DomainList = ('corp.contoso.com'),

    [Parameter()]
    [String]$BaseName = 'Test',

    [Parameter()]
    [int]$StartIndex = 1,

    [Parameter()]
    [int]$EndIndex = 1000
)

Function Update-Webservice {
    Param(
        [Parameter(Mandatory = $true)][String]$URI, 
        $Log,
        [Parameter(Mandatory = $true)]
        [String]$HostName
    )

    $Obj = $Log | ConvertTo-Json
    $DebugFile = "$Script:ScriptPath\webservice-$Hostname.json"
    
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
        Write-Error -Message "Error Invoking RestMethod $Method on URI $URI. Failed to update database using webservice.`r`n$($_.Exception.Message)"
    }
}

Function Get-SmallDateTime {
    Param([Parameter(Mandatory = $false)]$Date)
    #Write-Log -Message "Start Get-SmallDateTime"

    If ($null -eq $Date) { $Date = Get-Date }
    $format = 'ClientLocal'
    $TimeFormat = 'yyyy-MM-dd HH:mm:ss'
    Switch -Regex ($format) {
        'utc' {
            $DateString = $Date.ToUniversalTime().ToString("$TimeFormat")
            break
        }
        Default {
            # ClientLocal
            $DateString = ($Date).ToString("$TimeFormat")
            break
        }
    }
    $DateString -replace '\.', ':'
    #Write-Log -Message "End Get-SmallDateTime"
}

Function Get-RandomDate {
    (Get-Date).AddHours(-(Get-Random -Minimum 1 -Maximum 23)).AddDays(-(Get-RAndom -Minimum 1 -Maximum 364)).AddMinutes(-(Get-Random -Minimum 1 -Maximum 59)).AddSeconds(-(Get-Random -Minimum 1 -Maximum 59))
}

Function Get-OSDiskSpace {
    Get-CimInstance -Class Win32_LogicalDisk | 
        Where-Object { $_.DeviceID -eq "$env:SystemDrive" } | 
        Select-Object FreeSpace, 
                      Size, 
                      @{Label = 'FreeSpacePct'; Expression = { [math]::Round((($_.FreeSpace / $_.Size) * 100), 2) } }
}

Function New-LogObject {
    Param (
        $HostName
    )
    # Write-Log -Message "Start New-LogObject"

    # Handles different OS languages
    #$ComputerSID = [System.Security.Principal.NTAccount]::new("$env:COMPUTERNAME$").Translate([System.Security.Principal.SecurityIdentifier]).Value
    
    $OperatingSystem = Get-Random -InputObject ('Microsoft Windows 10 Entreprise','Microsoft Windows 11 Entreprise','Microsoft Windows 10 Professional', 'Microsoft Windows 11 Professional')
    $Architecture = Get-Random -InputObject ('64-Bit','32-Bit')
    $Build = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').BuildLabEx
    $Manufacturer = Get-Random -InputObject ('Dell','HP', 'Lenovo')
    $Model = 'model'
    $ClientVersion = '5.00.{0}.{1}' -f (Get-Random -InputObject (9000..9098)), (Get-Random -INputObject (1000..1025))
    $Sitecode = 'EDT'
    $Domain = Get-Random -InputObject $Script:DomainList
    [int]$MaxLogSize = Get-Random -InputObject (1KB..5KB)
    $MaxLogHistory = Get-Random -InputObject (1..5)
    $InstallDate = Get-SmallDateTime -Date ((Get-Date).AddDays(-(Get-Random -InputObject (10..1000))))
    $InstallDate = $InstallDate -replace '\.', ':'
    $LastLoggedOnUser = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\').LastLoggedOnUser
    $CacheSize = Get-Random -InputObject (1KB..20KB)
    $Services = Get-Random -InputObject ('Compliant', 'Started', 'Restarted')
    $Updates = Get-Random -InputObject ('Compliant', 'Failed' , ('KB{0}' -f (Get-Random -InputObject (5020000..5022000))))
    $DNS = Get-Random -InputObject ('Compliant', 'Repaired', 'Skipped')
    $Drivers = Get-Random -InputObject ('Compliant', 'unknown or faulty driver(s)')
    $ClientAuthCertificate = Get-Random -InputObject ('Compliant', 'Missing', 'Server rejected registration')
    $SMSCertificate = Get-Random -InputObject ('Compliant', 'Missing', 'Server rejected registration')
    $PendingReboot = Get-Random -InputObject ('Compliant', 'Pending Reboot')
    $RebootApp = 'Unknown'
    $LastBootTime = Get-SmallDateTime -Date ((Get-Date).AddHours(-(Get-Random -InputObject (25..300))))
    $LastBootTime = $LastBootTime -replace '\.', ':'
    $OSDiskFreeSpace = Get-Random -InputObject ((Get-OSDiskSpace | Select-Object -ExpandProperty FreeSpacePct),-1)
    $AdminShare = Get-Random -InputObject ('Compliant', 'Repaired')
    $ProvisioningMode = Get-Random -InputObject ('Compliant', 'Repaired')
    $StateMessages = Get-Random -InputObject ('Compliant', 'Repaired')
    $WUAHandler = Get-Random -InputObject ('Compliant', 'Repaired (WUAHandler Log)', 'Repaired (File Age)', 'Repaired (Event Log)', 'Broken (WUAHandler Log)', 'Broken (File Age)', 'Broken (Event Log)')
    $WMI = Get-Random -InputObject ('Compliant', 'Repaired', 'Corrupt', 'PolicyPlatform Recompiled.')
    $RefreshComplianceState = Get-SmallDateTime -Date (Get-RandomDate)
    $smallDateTime = Get-SmallDateTime -Date (Get-RandomDate)
    $smallDateTime = $smallDateTime -replace '\.', ':'
    [float]$PSVersion = [float]$psVersion = [float]$PSVersionTable.PSVersion.Major + ([float]$PSVersionTable.PSVersion.Minor / 10)
    [int]$PSBuild = Get-Random -InputObject (18363,19041,19042,19043,19044,19045,22000,22621)
    $UBR = Get-Random -InputObject (100..5000)
    $BITS = Get-Random -InputObject ('Compliant', 'Remediated', 'Error', 'PS Module BitsTransfer missing')
    $ClientSettings = Get-Random -InputObject ('Compliant', 'Remediated', 'Error')
    $IsCompliant = Get-Random -InputObject ($True, $false)

    [PSCustomObject]@{
        #ComputerSID            = $ComputerSID
        Hostname               = $Hostname
        Operatingsystem        = $OperatingSystem
        Architecture           = $Architecture
        Build                  = $Build
        Manufacturer           = $Manufacturer
        Model                  = $Model 
        InstallDate            = $InstallDate
        OSUpdates              = Get-SmallDateTime -Date (Get-RandomDate)
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
        SMSCertificate         = $SMSCertificate
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
        ClientInstalled        = Get-SmallDateTime -Date (Get-RandomDate)
        Version                = '2.0'
        Timestamp              = $smallDateTime
        HWInventory            = Get-SmallDateTime -Date (Get-RandomDate)
        SWMetering             = Get-Random ('Compliant', 'Remediated', 'Error')
        ClientSettings         = $ClientSettings
        BITS                   = $BITS
        PatchLevel             = $UBR
        ClientInstalledReason  = Get-Random ('ConfigMgr Client database files missing (%WINDIR%\CCM*.sdf)', "ConfigMgr Client database corrupt (CcmSQLCELog)", "Service not running, failed to start (ccmexec)", "Failed to connect to SMS_Client WMI class (root/ccm:SMS_Client)", "No agent found", "Corrupt WMI", "Below minimum verison" ,"Upgrade failed")
        RebootApp              = $RebootApp
        Compliant              = $IsCompliant
    }
}

$ScriptPath = "$PSScriptRoot"
$URi = "https://$Server/ConfigMgrClientHealth"

For ($i = $StartIndex; $i -lt $EndIndex; $i++) {
    $HostName = '{0}{1:D5}' -f $BaseName, $i
    $Log = New-LogObject -HostName $Hostname
    Update-Webservice -URI $uri -Log $Log -HostName $Hostname -Verbose
}