### WMI
| Fonction | Description |
| -------- | ----------- |
|Get-WMIClassInstance ||
|Get-Info ||
|GetComputerInfo ||
|Get-OperatingSystem ||
|Get-ComputerSystem ||
|Get-OperatingSystemFullName ||
|Get-Domain ||
|Get-OSDiskSpace ||
|Get-Computername ||
|Get-LastBootTime ||
|Test-WMI ||
|Repair-WMI ||
|Test-DiskSpace ||


### WebService
| Fonction | Description |
| -------- | ----------- |
|Update-Webservice||
|Get-ConfigFromWebservice||
|Get-ConfigClientInstallPropertiesFromWebService||
|Get-ConfigServicesFromWebservice||

### SQL
| Fonction | Description |
| -------- | ----------- |
|Test-SQLConnection||
|Invoke-Sqlcmd2||
|Get-SQLRow||
|Update-SQL||


### Logging
| Fonction | Description |
| -------- | ----------- |
|Search-CMLogFile||
|Test-LocalLogging||
|Get-LogFileName||
|Test-LogFileHistory||
|Test-ConfigMgrHealthLogging||
|New-LogObject||
|Test-ValuesBeforeLogUpdate||
|Update-LogFile||
|Write-Log||
|Backup-ClientHealtLog||


### Registry
| Fonction | Description |
| -------- | ----------- |
|Get-RegistryValue||
|Set-RegistryValue||


### CCM
| Fonction | Description |
| -------- | ----------- |
|Test-InstallationNeeded||
|Get-Sitecode||
|Get-ClientVersion||
|Get-ClientCache||
|Get-ClientMaxLogSize||
|Get-ClientLogLevel||
|Get-ClientMaxLogHistory||
|Get-CCMLogDirectory||
|Get-CCMDirectory||
|Test-CcmSDF||
|Test-CcmSQLCELog||
|Test-CCMCertificateError||
|Test-InTaskSequence||
|Test-BITS||
|Test-ClientSettingsConfiguration||
|New-ClientInstalledReason||
|Get-ProvisioningMode||
|Test-CCMSetup1||
|Test-ConfigMgrClient||
|Invoke-SCCMClientCleanup||
|Test-ClientCacheSize||
|Test-ClientVersion||
|Test-ClientSiteCode||
|Test-ProvisioningMode||
|Update-State||
|Test-UpdateStore||
|Test-ClientLogSize||
|Remove-CCMOrphanedCache||
|Resolve-Client||
|Test-RefreshComplianceState||
|Test-SCCMService||
|Test-SMSTSMgr||
|Test-CCMSoftwareDistribution||
|Start-Ccmeval||
|New-SCCMLogFileJob||
|Update-SCCMLogFile||
|Invoke-SCCMClientAction||
|Set-ClientProvisioningMode||
|Test-SCCMRebootPending||
|Get-SCCMHardwareInventoryDate||
|Test-SCCMHardwareInventoryScan||
|Get-ClientSiteName||

### Patches
| Fonction | Description |
| -------- | ----------- |
|Get-MissingUpdates||
|Get-LastInstalledPatches||
|Test-Update||
|Get-UBR||

### Reboot
| Fonction | Description |
| -------- | ----------- |
|Get-LastReboot||
|Start-RebootApplication||
|New-RebootTask||
|Remove-ScheduledTask||
|Disable-ScheduledTask||
|Remove-ScheduledTaskFolder||
|Get-PendingReboot||
|Test-PendingReboot||

### Services
| Fonction | Description |
| -------- | ----------- |
|Get-ServiceUpTime||
|Test-ServiceList||
|Test-Service||

### Shares
| Fonction | Description |
| -------- | ----------- |
|Test-AdminShare||

### Drivers
| Fonction | Description |
| -------- | ----------- |
|Test-MissingDrivers||
|Test-SoftwareMeteringPrepDriver||

### Policies
| Fonction | Description |
| -------- | ----------- |
|Test-RegistryPol||
|Test-PolicyPlatform||

### XML
| Fonction | Description |
| -------- | ----------- |
|Get-LocalFilesPath||
|Get-XMLConfigClientVersion||
|Get-XMLConfigClientSitecode||
|Get-XMLConfigClientDomain||
|Get-XMLConfigClientAutoUpgrade||
|Get-XMLConfigClientMaxLogSize||
|Get-XMLConfigClientMaxLogHistory||
|Get-XMLConfigClientMaxLogSizeEnabled||
|Get-XMLConfigClientCache||
|Get-XMLConfigClientCacheDeleteOrphanedData||
|Get-XMLConfigClientCacheEnable||
|Get-XMLConfigClientShare||
|Get-XMLConfigUpdatesShare||
|Get-XMLConfigUpdatesEnable||
|Get-XMLConfigUpdatesFix||
|Get-XMLConfigLoggingShare||
|Get-XMLConfigLoggingLocalFile||
|Get-XMLConfigLoggingEnable||
|Get-XMLConfigLoggingMaxHistory||
|Get-XMLConfigLoggingLevel||
|Get-XMLConfigLoggingTimeFormat||
|Get-XMLConfigPendingRebootApp||
|Get-XMLConfigMaxRebootDays||
|Get-XMLConfigRebootApplication||
|Get-XMLConfigRebootApplicationEnable||
|Get-XMLConfigDNSCheck||
|Get-XMLConfigCcmSQLCELog||
|Get-XMLConfigDNSFix||
|Get-XMLConfigDrivers||
|Get-XMLConfigPatchLevel||
|Get-XMLConfigOSDiskFreeSpace||
|Get-XMLConfigHardwareInventoryEnable||
|Get-XMLConfigHardwareInventoryFix||
|Get-XMLConfigSoftwareMeteringEnable||
|Get-XMLConfigSoftwareMeteringFix||
|Get-XMLConfigHardwareInventoryDays||
|Get-XMLConfigRemediationAdminShare||
|Get-XMLConfigRemediationClientProvisioningMode||
|Get-XMLConfigRemediationClientStateMessages||
|Get-XMLConfigRemediationClientWUAHandler||
|Get-XMLConfigRemediationClientWUAHandlerDays||
|Get-XMLConfigBITSCheck||
|Get-XMLConfigBITSCheckFix||
|Get-XMLConfigClientSettingsCheck||
|Get-XMLConfigClientSettingsCheckFix||
|Get-XMLConfigWMI||
|Get-XMLConfigWMIRepairEnable||
|Get-XMLConfigRefreshComplianceState||
|Get-XMLConfigRefreshComplianceStateDays||
|Get-XMLConfigRemediationClientCertificate||
|Get-XMLConfigSQLServer||
|Get-XMLConfigSQLLoggingEnable||

### Misc
| Fonction | Description |
| -------- | ----------- |
|Get-SmallDateTime||
|Get-DSRegCmd||
|Invoke-Executable||
|Measure-Latest||
|CleanUp||
|Register-DLLFile||
|Test-DNSConfiguration||
