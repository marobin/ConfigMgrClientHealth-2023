ConfigMgr Client Health Version: 0.8.3
Author: Anders Rødland

License: Creative Commons 4.0 (CC BY-ND). You are free to:
Share — copy and redistribute the material in any medium or format for any purpose, even commercially.
The licensor cannot revoke these freedoms as long as you follow the license terms.

Install or upgrade database
* Open SQL Management Studio on your SQL server and execute the query in "CreateDatabase.sql"

Webservice
* Read the installation documentation in the webservice folder to install and configure the webserivce.
* The script communicates with the webservice, and the webservice updates the database with the results.


Configure ConfigMgr Client Health.
Edit config.xml to specify SQL Server, and enable and disable checks.

Executing ConfigMgr Client Health. 
Run Powershell with at least administrator rights.
ConfigMgrClientHealth.ps1 -Config Config.xml

Full documentation available at: https://www.andersrodland.com/configmgr-client-health/

Note: Script version 0.8.3 requires database version 0.7.5. Execute query in CreateDatabase.sql to create or update the database if database is at a lower level.
SQL Query to get database version: SELECT Name, Version FROM Configuration

Changelog:
0.8.3
Client Health now successfully sets the client max log history.
Client Health now successfully sets the client cache size.
Fixed an issue with <ClientInstallProperty> using /skipprereq and specifying multiple components while separating with ";" would break the script.
Enabled debug logging in the webservice by default to make troubleshooting easier. Debug logs are stored in the "logs" folder.

0.8.2
Fixed a bug where logging directly to SQL database would not work.
Fixed an issue with BITS test.
Fixed a bug where service uptime test didn't work properly.
ClientCacheSize check no longer need to restart CM Agent when changing the cache size.
ClientCacheSize max limit 99999.
Fixes errors where configuration baselines fails because script is not signed even when bypass is set as execution policy in client settings.
Script will now stop services that are in a degraded state.
Improved code to detect last installed patched.
Updated database to allow null for LastLoggedOnUser.
Check client version is now run at end of script in case client was upgraded by script.
Script will no longer run if it detects a task sequence already running on the computer.
Script will not restart services if another installation is running.
Hostname is now read from environmental variable and not WMI.
Several bugfixes to script.
Add Windows Server 2019 support.
Improved WMI test and fix.
Will only log to webservice if parameter is specificed.
Improved the error message when script fails to update SQL.
Logfiles are now compatible with CMTrace.

0.8.1 - Script will now update database correctly when connecting directly to SQL server. Fixed an issue with BITS test. Fixing ClientCache no longer restarts SCCM agent. Fixed a bug where service uptime test didn't work properly.
0.8.0 - New feature: Webservice for improved communication with database. Fixed bug that could cause Test-Registrypol function to loop. Removed last bit of hardcoded paths in the script. Fixed and enhanced service tests. Script will now validate if Config.xml is valid before executing script.
0.7.6 - Changed test to verify SMSTSMgr is not dependent on CCMExec service, and only WMI service. Script will now abort and not run any health checks if an active task sequence is running on the system.
0.7.5 - Script will now test if service SMSTSMgr is dependent on CCMExec service. Added option to refresh compliance state every XX days. Uptime on services is now configurable in config.xml. Changed DNS test to only lookup DNS servers from active network adapters. Fixed a bug in Remove-CCMOrphanedCache function that potentially could be harmful. Other minor bug fixes. Removed support for PowerShell version 2 and 3.
0.7.4 - Support for PowerShell Core (PowerShell version 6). Improved detection and remediation of corrupt ConfigMgr Client database files. Corrupt WMI check now works on Finnish OS language. Localfiles defaults to C:\ClientHealth if not specified in config.xml. DNS errors, driver errors and failed connections to SQL server will no longer write to logfile if LogLevel is set to ClientInstall. Script will use COM object to assign correct sitecode, and no longer reinstall ConfigMgr client if sitecode is wrong.
0.7.3.1 - Fixed a bug in the function cleaning up localfiles on the computer.
0.7.3 - Test on CcmSQLCE.log is now optional and configurable in config.xml. Fixed a bug where script could hang on Windows 7 computers running Powershell version 2. Client Health will now log the reason why it reinstalled the ConfigMgr client. Added option to store time as UTC or client local time. LocalFiles is now configurable in config.xml (default C:\ClientHealth). Script will now remove localfiles directory if locallogging is disabled.
0.7.2 - Bugfixes: Local log file will now honor MaxLogHistory, services automatic (delayed start) should now detect and configure correctly. Improved DNS check for Windows 8.1 / Server 2012 R2 and higher. Implemented another check on the CM client health. Improved testing on WUAHandler.log. BITS check, DNS, hardware inventory, software metering and updates check can now run in monitor only mode (fix="false" in config.xml) Script will now triger the built in CM client health check (ccmeval) at the end of the script.
0.7.1 - Fixed a bug where the script would fail to configure services to automatic delayed start
0.7.0 - Added a test and fix for Software Metering. Fixed bug where script would fail to update SQL database. Script will now remove errors from the logfiles where the error is fixed to false positives next time script runs. Added PatchLevel to easily discover which clients are not fully patched. Improved the installation of SCCM agent. Added fix for BITS error that would cause downloads to be stuck at 0%. ClientHealth now use c:\clienthealth as directory for temporary files. Local logging logs to c:\clienthealth\clienthealth.log if enabled.
0.6.8 - Added a test and fix for registry issue that could prevent ccmsetup from installing the sccm client. OSBuild now displays the full build number. Several bug fixes: MaxLogSize now rounds decimals, OSUpdates should no longer mix up day and month, fixed a bug with right click tool showing a parsing error.
0.6.7 - Added a right click tool to the configuration manager console to remotly start client health on devices. Detection and remediation on configmgr client no longer use hardcoded paths, added windows time services in config.xml as service to enforce as automatic. Lenovo models finally reporting correct models name. Fixed a bug where reboot application would not always start on Windows 7 with PowerShell 2.
0.6.6 - ConfigMgr Client cache check is now optional and can be enabled or disabled in config.xml Log files are no longer stored in OS specific directories. Use multiple config.xml files if you need to seperate file logs on OS. Added option to run WMI check without fixing anything. Reboot app now works fine on Windows 7, fixed a bug where DNS check did not work fully in environments where FQDN did not match AD DNS domain. Fixed a bug where ConfigMgr client cache size, max logsize and max log history would report old values instead of the remediated values to database and log files.
0.6.5 - Improved check on registry.pol file. Standard PS/2 drivers no longer reports as error. More effective logging code. Fixed bug where hardware inventory would not always trigger when supposed to.  Added support to seperate updates between Windows 10 builds. Lenovo computers now report more friendly modelname.
0.6.4 - Disabled drivers no longer reports as error. Fixed so reboot application is visible for user when running script as system. ClientInstalled in file log now contain a timestamp if sccm agent is installed. Moved WMI check to start before ConfigMgr agent check. Added check for hardware inventory.
0.6.3 - Bug fixes: sccm client autoupgrade did not work correctly, SQL ClientInstalled filend would not update with correct timestamp when the script decided to install or uppgrade the sccm agent, and a bug where check for mandatory hotfixes returned an error if no patches or hotfixes was installed on the computer.
0.6.2 - Logging to file share is back with a better log engine. File logs now contains the same information as SQL. Improved detection of corrupt WMI. Client Health will no longer try to install ConfigMgr agent if ccmsetup.exe is already running on the system.
0.6.1 - Fixed a bug where ConfigMgr agent would not install or auto-upgrade.
0.6.0 - Changed logging SQL database instead of fileshare. Fixed a bug with DNS check and IPv6, and a bug with reboot application and paramters. Other minor bugfixes.
0.5.7 - Added check and fix for ConfigMgr Client certificate error. Support for ConfigMgr Client cache to use percentage of diskspace. Fixed several bugs reported by the community, and a bug when running the script on non-english operating systems.
0.5.6 - Fixed a bug that made this script fail when running on servers.
0.5.5 - Added option to check for missing or faulty drivers, and DNS server records matches local IPs. SCCM client max log size is now set with a WMI method and not registry key. Fixed a bug with initial sccm client installation and a warning message when log file did not exist.
0.5.4 - Set MaxLogHistory to avoid unlimited growth on logfiles. Added option for reboot application. Made code much cleaner.
0.5.3 - Now supports logging to fileshare.
0.5.2 - Minor bug fixes. Ongoing project to make code cleaner and easier to understand.
0.5.1 - ConfigMgr Client Health can now be used to install ConfigMgr client on computers missing ConfigMgr client installation.
0.5.0 - Added option to check if patches stored on updates share is installed on computer, and install if not.
0.4.2 - Minor bug fixes.
0.4.0 - First release on technet galleries.


This software is provided "AS IS" with no warranties. Use at your own risk.