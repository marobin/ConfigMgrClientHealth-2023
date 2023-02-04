# ConfigMgr Client Health

Version: 0.9

This is the master branch of ConfigMgr Client Health and is ready for production.

Up to date souces can be found [here](\\SRV\CMClientHealth$).



This script is based on the work of Anders Rodland : [ConfigMgr Client Health 0.8.3](https://github.com/AndersRodland/ConfigMgrClientHealth/raw/master/Download/ConfigMgrClientHealth-0.8.3.zip)

It has been modified to suit the needs of .............

[ConfigMgr Client Health Full documentation](https://www.andersrodland.com/configmgr-client-health/)

Note: Script version 0.8.3+ requires database version 0.7.5.


# How does it work?

Script is launched through a scheduled task "**ConfigMgr Client Health - Client**" triggered by a network connexion to the CORP network.  

This is done by subscribing to the event **ID 10000** in the "**Microsoft-Windows-NetworkProfile/Operational**" event log.  

The script remediate as many issues as can be and send a report to a webservice.  

The webservice then populates an SQL database which is used as a report source.  

This report can be viewed in Configuration Manager in the "**Monitoring\Reports"** node : "**CM Client Health Detailed Report-2016".**  


## Install.ps1

1. Create folder C:\ProgramData\ConfigMgrClientHealth with subfolder Logs
2. Remove standard users read right to the folder
3. Copy scripts, CMClient folder (containing the latest client) and `Config-Client.xml` in the folder
4. Modify `Config-Client.xml` to set the scheduled task action
5. Create the scheduled task

## Uninstall.ps1

1. Backup **C:\ProgramData\ConfigMgrClientHealth\Logs\ClientHealth.log** to **C:\Windows\Temp**
2. Remove the scheduled task
3. Remove the installation folder

## ConfigMgrClientHealth.ps1

This is the main script which is launched by the scheduled task.

See official documentation to get details about the script parameters.

1. Test if the installation is required on the device
   * Client is already installed
   * Or CoManagement flags are set
   * Or Device is Azure AD Hybrid Joined
    **The scheduled tasks is removed and script is exited if none of the above are true**
2. Is the script launch with elevated permissions? Exit if not.
3. Is there a task sequence running? Exit if yes.
4. Get the script last execution time. Exit if not first run and computer hasn't been rebooted since.
5. Test logs size.
6. Create an object to keep track of each test. This object will be used to report the the webservice.
7. See if SQL database can be contacted directly (see `Config-Client.xml`).
8. Check if WMI database is coherent, fix if not.
9. Test if device compliance.
10. Check if the client is already installed. Install if not.
11. Check the client version. Reinstall if current version is below the required one (see `Config-Client.xml`).
12. Check services state (see `Config-Client.xml`).
13. Check if site code matches the required site code (see `Config-Client.xml`).
14. Check if client cache size matches the requirements (see `Config-Client.xml`).
15. Check if client is in provisioning mode, fix if it is the case.
16. Check if certificates errors are present in ClientIDManagerStartup.log and remediate if needed.
17. Check if hardware inventory is ok.
18. Check the Software Metering Driver state (mtrmgr.log)
19. Check the DNS records, remediate if needed.
20. Check BITS state.
21. Check agent configuration.
22. Check policies (registry.pol) and updates (WUAHandler.log)
23. Check the update store state.
24. Check the state of administrative shares (Admin$ and C$)
25. Check is there is a missing or misinstalled driver.
26. Update the device if defined in `Config-Client.xml`.
27. Check disk space (see `Config-Client.xml`).
28. Send unsent state messages.
29. Restart ccmexec service if needed.
30. Remove orphaned items in ccmcache.
31. Reinstall the client if needed (corrupted WMI, version mismatch).
32. Execute the native "ClientHealth" task.
33. Update the script execution date in the registry.
34. Update the SQL database directly or using the webservice with results.
35. Deactivate the scheduled task linked with the script if all tests succeeded.



# Deployment

## Intune
The script has been packaged as a Windows app (Win32) in Intune under the name "**Configuration Manager Client Health**".  
  
This application is deployed on a Azure group named "**G-OS-CONFIGMGR-CLIENT-REMEDIATION**".  
Members of this group are synched from a Configuration Manager collection named "**CH_ClientVersion-RemediationNeeded-CORP**" (_\Assets and Compliance\Overview\Device Collections\Operational\Client Health_).  

:warning: Co-management workload "Client apps" needs to be set to Intune for this to work.  
Since most of the targeted devices don't have a client installed they might not be able to install this app as their co-management workload for client apps is still linked to Configuration Manager.  

## GPO

